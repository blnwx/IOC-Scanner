package endpoints

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	storage "iocscanner/src/db"
	"iocscanner/src/feeds"
	"iocscanner/src/logging"
	"iocscanner/src/parse"
	scanner "iocscanner/src/scan"
	targetcfg "iocscanner/src/targets"

	jarm "github.com/hdm/jarm-go"
)

// dashboardAssets reads the same production output embedded by main.
var dashboardAssets = os.DirFS("../web")

// safeBuffer collects log output for a test to assert on. setupLogger installs the handler
// process-wide and slog.SetDefault redirects the standard log package into it too, so the writer
// is reached from goroutines this test never started: an httptest server reporting the handshake
// a probe walked away from writes a line long after probePorts returned. compactHandler holds its
// own lock across the write, but nothing guards a test reading the buffer back, which is the race
// the detector reported. Production writes to os.Stderr and needs none of this.
type safeBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *safeBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

const (
	// The last row of each feed is a real sample from the live list. The rows above it are
	// synthetic, covering the entries each parser must drop.
	// The beta row carries no first_seen on purpose. The stamp is the one optional field, so a
	// feed that omits it must still yield the indicator.
	threatFoxBody = `{"query_status":"ok","data":[
		{"id":"101","ioc":"192.0.2.1:443","threat_type":"botnet_cc","ioc_type":"ip:port","malware":"alpha","first_seen":"2024-03-01 09:15:00 UTC","confidence_level":75},
		{"id":"102","ioc":"192.0.2.9:80","threat_type":"payload_delivery","ioc_type":"ip:port","malware":"beta","confidence_level":0},
		{"id":"103","ioc":"[2001:db8::1]:443","threat_type":"botnet_cc","ioc_type":"ip:port","malware":"gamma"},
		{"id":"104","ioc":"example.com","threat_type":"botnet_cc","ioc_type":"domain","malware":"delta"},
		{"id":"105","ioc":"168.144.45.2:8080","threat_type":"botnet_cc","ioc_type":"ip:port","malware":"CobaltStrike","first_seen":"2024-03-02 11:00:00 UTC"}]}`
	feodoBody = `[{"ip_address":"192.0.2.2","port":8443,"malware":"epsilon","first_seen":"2024-02-01 10:00:00"},
		{"ip_address":"2001:db8::2","port":8443,"malware":"zeta"},
		{"ip_address":"50.16.16.211","port":443,"malware":"QakBot","first_seen":"2024-02-02 12:30:00"}]`
	sslblBody = "# Firstseen,DstIP,DstPort\n2024-01-01 00:00:00,192.0.2.3,443\n"
	// The first fingerprint is uppercase on purpose. Fingerprints must be lowercased to match
	// what the scanner computes. The second is a real listing, already lowercase.
	sslblCertBody = "# Firstseen,SHA1,Listingreason\n" +
		"2024-01-01 00:00:00,AABBCCDDEEFF00112233445566778899AABBCCDD,Dridex C&C\n" +
		"2024-01-01 00:00:00,283042355c89f2c59e260246d1488a73a8bef7b2,PureLogsStealer C&C\n"
	// Include an untagged record to exercise the poster fallback.
	tweetFeedBody = `[{"date":"2026-08-04 09:00:00","user":"reporter","type":"ip","value":"192.0.2.6","tags":["#C2","#stealer"],"tweet":"https://x.com/reporter/status/1"},
		{"date":"2026-08-04 09:01:00","user":"reporter","type":"ip","value":"192.0.2.7","tags":[],"tweet":"https://x.com/reporter/status/2"},
		{"date":"2026-08-04 09:02:00","user":"reporter","type":"ip","value":"2001:db8::6","tags":["#C2"],"tweet":"https://x.com/reporter/status/3"},
		{"date":"2026-08-04 00:40:00","user":"skocherhan","type":"ip","value":"217.156.122.129","tags":["#C2"],"tweet":"https://x.com/skocherhan/status/2084439291992629379"},
		{"date":"2026-08-04 09:03:00","user":"reporter","type":"domain","value":"Evil.Example.","tags":["#phishing"],"tweet":"https://x.com/reporter/status/4"},
		{"date":"2026-08-04 09:04:00","user":"reporter","type":"domain","value":"cn.example","tags":["#C2"],"tweet":"https://x.com/reporter/status/5"},
		{"date":"2026-08-04 01:04:00","user":"skocherhan","type":"domain","value":"txpfproxy.vip","tags":[],"tweet":"https://x.com/skocherhan/status/2084445425428484357"},
		{"date":"2026-08-04 09:05:00","user":"reporter","type":"url","value":"http://192.0.2.8:8080/payload","tags":["#malware"],"tweet":"https://x.com/reporter/status/6"},
		{"date":"2026-08-04 09:06:00","user":"reporter","type":"url","value":"https://URL.Example/login","tags":["#phishing"],"tweet":"https://x.com/reporter/status/7"},
		{"date":"2026-08-04 09:07:00","user":"reporter","type":"url","value":"https://[2001:db8::7]/payload","tags":["#C2"],"tweet":"https://x.com/reporter/status/8"}]`
	phishingArmyBody = "# Phishing Army\nLogin.Bad.Example.CO.UK.\napi.example.co.uk\n"
	urlHausBody      = `{
		"202":[{"url":"https://Drop.Bad.Example.ORG/payload","url_status":"online","last_online":"2026-08-20 10:00:00 UTC","threat":"malware_download","tags":null}],
		"201":[{"url":"http://192.0.2.10:8080/i","url_status":"online","last_online":"2026-08-20 09:00:00 UTC","threat":"malware_download","tags":["elf","Mozi"]}],
		"200":[{"url":"http://192.0.2.11/i","url_status":"offline","last_online":null,"threat":"malware_download","tags":null}]}`
	c2IntelBody      = "#domain,ioc,uri_path,ip\nbeacon.evil.example.com,Possible Cobalt Strike C2 Domain,/jquery.js,192.0.2.12\n"
	threatViewC2Body = "#IP,Date of Detection,Host,Protocol,Beacon Config,Comment\n" +
		`192.0.2.13,20 August 2026 03:26 PM UTC,c2.bad.example.net,https,"c2.bad.example.net,/fwlink",Generated by Threatview[.]io` + "\n" +
		`googlesupportacc.top,27 March 2024 01:37 PM UTC,googlesupportacc.top,https,""googlesupportacc.top,/bg"",Generated by Threatview[.]io` + "\n" +
		`192.0.2.14,20 August 2026 03:27 PM UTC,192.0.2.14,https,"192.0.2.14,/ca",Generated by Threatview[.]io` + "\n"
	threatViewDomainBody = "# ThreatView domains\n0000153.0000255.0000011.0000125\nlogin.bad.example.edu\napi.example.edu\n"
	threatViewURLBody    = "# ThreatView URLs\nhttp://192.0.2.15:9090/i\nhttp://39.34.166.041:34595/Mozi.m\nhttps://payload.bad.example.io/file\n"
)

// stubFeeds points the feed URLs at a server replying with status and installs a fresh
// Current with a ThreatFox key in the store, restoring all of them after.
func stubFeeds(t *testing.T, status int) *feeds.Cache {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		switch r.URL.Path {
		case "/threatfox":
			fmt.Fprint(w, threatFoxBody)
		case "/feodo":
			fmt.Fprint(w, feodoBody)
		case "/sslbl":
			fmt.Fprint(w, sslblBody)
		case "/sslblcert":
			fmt.Fprint(w, sslblCertBody)
		case "/tweetfeed":
			fmt.Fprint(w, tweetFeedBody)
		case "/phishing-army":
			fmt.Fprint(w, phishingArmyBody)
		case "/urlhaus":
			fmt.Fprint(w, urlHausBody)
		case "/c2intel":
			fmt.Fprint(w, c2IntelBody)
		case "/threatview-c2":
			fmt.Fprint(w, threatViewC2Body)
		case "/threatview-domain":
			fmt.Fprint(w, threatViewDomainBody)
		case "/threatview-url":
			fmt.Fprint(w, threatViewURLBody)
		}
	}))
	original := [11]string{feeds.ThreatFoxURL, feeds.FeodoURL, feeds.SSLBLIPURL, feeds.SSLBLCertURL, feeds.TweetFeedURL, feeds.PhishingArmyURL,
		feeds.URLHausURL, feeds.C2IntelURL, feeds.ThreatViewC2URL, feeds.ThreatViewDomainURL, feeds.ThreatViewURL}
	previous, previousKey := feeds.Current, targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey
	t.Cleanup(func() {
		server.Close()
		feeds.ThreatFoxURL, feeds.FeodoURL, feeds.SSLBLIPURL, feeds.SSLBLCertURL = original[0], original[1], original[2], original[3]
		feeds.TweetFeedURL = original[4]
		feeds.PhishingArmyURL = original[5]
		feeds.URLHausURL, feeds.C2IntelURL, feeds.ThreatViewC2URL = original[6], original[7], original[8]
		feeds.ThreatViewDomainURL, feeds.ThreatViewURL = original[9], original[10]
		feeds.Current, targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey = previous, previousKey
	})
	feeds.ThreatFoxURL, feeds.FeodoURL, feeds.SSLBLIPURL, feeds.SSLBLCertURL = server.URL+"/threatfox", server.URL+"/feodo",
		server.URL+"/sslbl", server.URL+"/sslblcert"
	feeds.TweetFeedURL = server.URL + "/tweetfeed"
	feeds.PhishingArmyURL = server.URL + "/phishing-army"
	feeds.URLHausURL, feeds.C2IntelURL = server.URL+"/urlhaus", server.URL+"/c2intel"
	feeds.ThreatViewC2URL, feeds.ThreatViewDomainURL, feeds.ThreatViewURL = server.URL+"/threatview-c2",
		server.URL+"/threatview-domain", server.URL+"/threatview-url"
	// Direct field write. No goroutine is reading the store during a test.
	targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey = "secret"
	feeds.Current = &feeds.Cache{Client: server.Client(), LastGood: map[string][]feeds.Indicator{}}
	return feeds.Current
}

// Each feed normalises to a value the scanner can match.
func TestRefreshNormalizesFeeds(t *testing.T) {
	f := stubFeeds(t, http.StatusOK)
	got := f.Refresh(context.Background())
	confidence75, confidence0 := 75, 0
	want := []feeds.Indicator{
		{Source: "threatfox", Value: "192.0.2.1:443", Tag: "alpha", FirstSeen: "2024-03-01T09:15:00Z", Link: "https://threatfox.abuse.ch/ioc/101/", ConfidenceLevel: &confidence75, Soft: false},
		{Source: "threatfox", Value: "192.0.2.9:80", Tag: "beta", FirstSeen: "", Link: "https://threatfox.abuse.ch/ioc/102/", ConfidenceLevel: &confidence0, Soft: false},
		{Source: "threatfox", Value: "168.144.45.2:8080", Tag: "CobaltStrike", FirstSeen: "2024-03-02T11:00:00Z", Link: "https://threatfox.abuse.ch/ioc/105/", ConfidenceLevel: nil, Soft: false},
		{Source: "feodo", Value: "192.0.2.2:8443", Tag: "epsilon", FirstSeen: "2024-02-01T10:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "feodo", Value: "50.16.16.211:443", Tag: "QakBot", FirstSeen: "2024-02-02T12:30:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "sslbl", Value: "192.0.2.3:443", Tag: "botnet_cc", FirstSeen: "2024-01-01T00:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "sslbl_cert", Value: "aabbccddeeff00112233445566778899aabbccdd", Tag: "Dridex C&C", FirstSeen: "2024-01-01T00:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "sslbl_cert", Value: "283042355c89f2c59e260246d1488a73a8bef7b2", Tag: "PureLogsStealer C&C", FirstSeen: "2024-01-01T00:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "192.0.2.6", Tag: "ip — C2, stealer", FirstSeen: "2026-08-04T09:00:00Z", Link: "https://x.com/reporter/status/1", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "192.0.2.7", Tag: "ip — @reporter", FirstSeen: "2026-08-04T09:01:00Z", Link: "https://x.com/reporter/status/2", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "217.156.122.129", Tag: "ip — C2", FirstSeen: "2026-08-04T00:40:00Z", Link: "https://x.com/skocherhan/status/2084439291992629379", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "evil.example", Tag: "domain — phishing", FirstSeen: "2026-08-04T09:03:00Z", Link: "https://x.com/reporter/status/4", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "cn.example", Tag: "domain — C2", FirstSeen: "2026-08-04T09:04:00Z", Link: "https://x.com/reporter/status/5", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "txpfproxy.vip", Tag: "domain — @skocherhan", FirstSeen: "2026-08-04T01:04:00Z", Link: "https://x.com/skocherhan/status/2084445425428484357", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "192.0.2.8:8080", Tag: "url — malware", FirstSeen: "2026-08-04T09:05:00Z", Link: "https://x.com/reporter/status/6", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "url.example", Tag: "url — phishing", FirstSeen: "2026-08-04T09:06:00Z", Link: "https://x.com/reporter/status/7", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.PhishingArmySource, Value: "example.co.uk", Tag: "phishing", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.URLHausSource, Value: "192.0.2.10:8080", Tag: "malware_download — elf, Mozi", FirstSeen: "2026-08-20T09:00:00Z", Link: "https://urlhaus.abuse.ch/url/201/", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.URLHausSource, Value: "example.org", Tag: "malware_download", FirstSeen: "2026-08-20T10:00:00Z", Link: "https://urlhaus.abuse.ch/url/202/", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.C2IntelSource, Value: "192.0.2.12", Tag: "IP — Possible Cobalt Strike C2 Domain — domain example.com", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.C2IntelSource, Value: "example.com", Tag: "Domain — Possible Cobalt Strike C2 Domain — IP 192.0.2.12", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.ThreatViewSource, Value: "192.0.2.13", Tag: "C2", FirstSeen: "2026-08-20T15:26:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.ThreatViewSource, Value: "example.net", Tag: "C2", FirstSeen: "2026-08-20T15:26:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.ThreatViewSource, Value: "192.0.2.14", Tag: "C2", FirstSeen: "2026-08-20T15:27:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.ThreatViewSource, Value: "example.edu", Tag: "Phishing/Malware", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.ThreatViewSource, Value: "192.0.2.15:9090", Tag: "Phishing/Malware", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.ThreatViewSource, Value: "example.io", Tag: "Phishing/Malware", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fetchAllFeeds = %v, want %v", got, want)
	}
	if got := f.Counts()[feeds.ThreatViewSource]; got != 6 {
		t.Fatalf("combined ThreatView indicator count = %d, want 6", got)
	}
}

func TestThreatFoxConfidenceValidationAndJSON(t *testing.T) {
	body := `{"query_status":"ok","data":[
		{"id":"1","ioc":"192.0.2.1:443","threat_type":"c2","ioc_type":"ip:port","malware":"one","confidence_level":75},
		{"id":"2","ioc":"192.0.2.2:443","threat_type":"c2","ioc_type":"ip:port","malware":"two","confidence_level":0},
		{"id":"3","ioc":"192.0.2.3:443","threat_type":"c2","ioc_type":"ip:port","malware":"three"},
		{"id":"4","ioc":"192.0.2.4:443","threat_type":"c2","ioc_type":"ip:port","malware":"four","confidence_level":101}]}`
	f := &feeds.Cache{Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
	got, err := f.FetchThreatFox(context.Background())
	if err != nil || len(got) != 4 {
		t.Fatalf("decoded confidence records = %+v, %v; want four kept", got, err)
	}
	// The last record's score is out of range. The indicator survives without one.
	if got[0].ConfidenceLevel == nil || *got[0].ConfidenceLevel != 75 || got[1].ConfidenceLevel == nil ||
		*got[1].ConfidenceLevel != 0 || got[2].ConfidenceLevel != nil || got[3].ConfidenceLevel != nil {
		t.Fatalf("confidence values = %+v; want 75, 0, missing, missing", got)
	}
	for i, want := range []string{`"confidence_level":75`, `"confidence_level":0`, "", ""} {
		encoded, marshalErr := json.Marshal(got[i])
		if marshalErr != nil || want != "" && !bytes.Contains(encoded, []byte(want)) || want == "" && bytes.Contains(encoded, []byte("confidence_level")) {
			t.Fatalf("indicator %d JSON = %s, %v", i, encoded, marshalErr)
		}
	}
}

func TestIndicatorConfidenceDeduplicatesByValue(t *testing.T) {
	one, same, other := 75, 75, 50
	base := feeds.Indicator{Source: "threatfox", Value: "192.0.2.1:443", Tag: "C2", ConfidenceLevel: &one}
	duplicate, changed := base, base
	duplicate.ConfidenceLevel, changed.ConfidenceLevel = &same, &other
	if got := scanner.UniqueIndicators([]feeds.Indicator{base, duplicate}); len(got) != 1 {
		t.Fatalf("equal confidence pointers produced %d indicators, want 1", len(got))
	}
	if got := scanner.UniqueIndicators([]feeds.Indicator{base, changed}); len(got) != 2 {
		t.Fatalf("different confidence values produced %d indicators, want 2", len(got))
	}
}

func TestRegularHostRestoresStoredConfidenceMissingFromFeedCache(t *testing.T) {
	previousConfig, previousScope := targetcfg.Current.Config()
	previousFeeds := feeds.Current
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		feeds.Current = previousFeeds
	})
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)
	indicator := feeds.Indicator{Source: "threatfox", Value: "192.0.2.1:443", Tag: "C2"}
	feeds.Current = &feeds.Cache{Index: feeds.BuildIndex([]feeds.Indicator{indicator})}
	confidence := 75
	hosts, _ := scanner.Project(storage.HostData{
		Scans:   []storage.Scan{{IP: "192.0.2.1", Port: 443, IsOpen: true, ScannedAt: 1}},
		Matches: []storage.Match{{IP: "192.0.2.1", Source: indicator.Source, Value: indicator.Value, Tag: indicator.Tag, ConfidenceLevel: &confidence, SeenAt: 1}},
	}, scanner.ActiveOpen)
	if len(hosts) != 1 || len(hosts[0].Signals) != 1 || hosts[0].Signals[0].ConfidenceLevel == nil || *hosts[0].Signals[0].ConfidenceLevel != 75 {
		t.Fatalf("regular host signals = %+v, want stored 75%% confidence", hosts)
	}
}

// The port scan looks feed entries up by bare address or by certificate fingerprint, so ip:port
// indicators must be keyed on the address alone and fingerprints on themselves.
func TestIndexKeysHitsByAddressAndFingerprint(t *testing.T) {
	f := stubFeeds(t, http.StatusOK)
	f.Refresh(context.Background())

	if hits := f.Lookup("192.0.2.1"); len(hits) != 1 || hits[0].Source != "threatfox" {
		t.Fatalf("hit by address = %v, want the threatfox entry", hits)
	}
	if hits := f.Lookup("aabbccddeeff00112233445566778899aabbccdd"); len(hits) != 1 || hits[0].Tag != "Dridex C&C" {
		t.Fatalf("hit by fingerprint = %v, want the SSLBL entry", hits)
	}
	// The port must not be part of the key, and an unknown value must not match.
	if hits := f.Lookup("192.0.2.1:443"); len(hits) != 0 {
		t.Fatalf("hit by ip:port = %v, want none", hits)
	}
	if hits := f.Lookup("198.51.100.1"); len(hits) != 0 {
		t.Fatalf("hit on an unlisted address = %v, want none", hits)
	}
	if hits := f.Lookup("192.0.2.8"); len(hits) != 1 || hits[0].Source != "tweetfeed" ||
		hits[0].Value != "192.0.2.8:8080" {
		t.Fatalf("hit by URL address = %v, want the TweetFeed URL entry", hits)
	}
}

// Certificate feed hits include its fingerprint, SANs, and common name.
func TestProbeSignalsMatchesFingerprintNamesAndJARM(t *testing.T) {
	stubFeeds(t, http.StatusOK).Refresh(context.Background())

	got := scanner.ProbeSignals(storage.Scan{
		IP:          "192.0.2.1",
		Port:        443,
		Fingerprint: "aabbccddeeff00112233445566778899aabbccdd",
		DNSNames:    "*.Evil.example,URL.EXAMPLE",
		Subject:     "cn.example",
	})
	want := []feeds.Indicator{
		{Source: "sslbl_cert", Value: "aabbccddeeff00112233445566778899aabbccdd", Tag: "Dridex C&C", FirstSeen: "2024-01-01T00:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "evil.example", Tag: "domain — phishing", FirstSeen: "2026-08-04T09:03:00Z", Link: "https://x.com/reporter/status/4", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "url.example", Tag: "url — phishing", FirstSeen: "2026-08-04T09:06:00Z", Link: "https://x.com/reporter/status/7", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "cn.example", Tag: "domain — C2", FirstSeen: "2026-08-04T09:04:00Z", Link: "https://x.com/reporter/status/5", ConfidenceLevel: nil, Soft: false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("probeSignals = %v, want %v", got, want)
	}
	// Empty probe fields must not match.
	if hits := scanner.ProbeSignals(storage.Scan{IP: "192.0.2.1", Port: 80}); len(hits) != 0 {
		t.Fatalf("probeSignals on a port with no certificate = %v, want none", hits)
	}
}

func TestPhishingArmyMatchesRegistrableCertDomains(t *testing.T) {
	previous := feeds.Current
	t.Cleanup(func() { feeds.Current = previous })
	feeds.Current = &feeds.Cache{Index: feeds.BuildIndex([]feeds.Indicator{
		{Source: feeds.PhishingArmySource, Value: "example.co.uk", Tag: "phishing", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "example.com", Tag: "domain — phishing", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
	})}

	for _, row := range []storage.Scan{
		{Subject: "panel.example.co.uk"},
		{DNSNames: "login.example.co.uk"},
	} {
		got := scanner.ProbeSignals(row)
		if len(got) != 1 || got[0].Source != feeds.PhishingArmySource || scanner.Band(got) != "high" {
			t.Errorf("probeSignals(%+v) = %v (%s), want one HIGH Phishing Army hit", row, got, scanner.Band(got))
		}
	}
	if got := scanner.ProbeSignals(storage.Scan{Subject: "api.example.com"}); len(got) != 0 {
		t.Fatalf("registrable lookup broadened another feed: %v", got)
	}
}

func TestNewFeedsMatchRegistrableCertDomains(t *testing.T) {
	previous := feeds.Current
	t.Cleanup(func() { feeds.Current = previous })
	feeds.Current = &feeds.Cache{Index: feeds.BuildIndex([]feeds.Indicator{
		{Source: feeds.URLHausSource, Value: "example.com", Tag: "URL", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.C2IntelSource, Value: "example.com", Tag: "Domain — IP 192.0.2.12", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: feeds.ThreatViewSource, Value: "example.com", Tag: "Domain", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "example.com", Tag: "domain", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
	})}

	got := scanner.ProbeSignals(storage.Scan{IP: "192.0.2.12", Subject: "panel.example.com"})
	if len(got) != 3 {
		t.Fatalf("registrable domain hits = %v, want the three new curated sources", got)
	}
	if slices.ContainsFunc(got, func(hit feeds.Indicator) bool { return hit.Source == "tweetfeed" }) {
		t.Fatalf("registrable lookup broadened TweetFeed: %v", got)
	}
	got = scanner.ProbeSignals(storage.Scan{IP: "192.0.2.99", Subject: "panel.example.com"})
	if slices.ContainsFunc(got, func(hit feeds.Indicator) bool { return hit.Source == feeds.C2IntelSource }) {
		t.Fatalf("C2Intel domain matched the wrong IP: %v", got)
	}
}

func TestDashboardRejectsC2IntelDomainOnDifferentIP(t *testing.T) {
	previous := feeds.Current
	t.Cleanup(func() { feeds.Current = previous })
	feeds.Current = &feeds.Cache{Index: map[string][]feeds.Indicator{}}

	row := storage.Scan{IP: "192.0.2.99", Port: 443, IsOpen: true, Subject: "panel.example.com"}
	match := storage.Match{IP: row.IP, Source: feeds.C2IntelSource, Value: "example.com",
		Tag: "Domain — IP 192.0.2.12"}
	hosts, _ := scanner.Project(storage.HostData{Scans: []storage.Scan{row}, Matches: []storage.Match{match}}, scanner.ActiveOpen)
	if len(hosts) != 1 || len(hosts[0].Signals) != 0 || hosts[0].Band != "" {
		t.Fatalf("mismatched C2Intel domain remained visible: %+v", hosts)
	}
}

func TestCleanHostSignalsSerializeAsArray(t *testing.T) {
	previous := feeds.Current
	t.Cleanup(func() { feeds.Current = previous })
	feeds.Current = &feeds.Cache{Index: map[string][]feeds.Indicator{}}
	hosts, _ := scanner.Project(storage.HostData{Scans: []storage.Scan{{
		IP: "192.0.2.9", Port: 443, IsOpen: true,
	}}}, scanner.ActiveOpen)
	data, err := json.Marshal(hosts[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"signals":[]`)) {
		t.Fatalf("clean host signals are nullable on the wire: %s", data)
	}
}

func TestDashboardDeduplicatesPhishingArmyHitAcrossCertNames(t *testing.T) {
	previous := feeds.Current
	t.Cleanup(func() { feeds.Current = previous })
	feeds.Current = &feeds.Cache{Index: feeds.BuildIndex([]feeds.Indicator{
		{Source: feeds.PhishingArmySource, Value: "example.co.uk", Tag: "phishing", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
	})}

	now := time.Now()
	row := storage.Scan{IP: "192.0.2.9", Port: 443, IsOpen: true, NotBefore: now.Unix(), NotAfter: now.AddDate(1, 0, 0).Unix(),
		Fingerprint: "1111111111111111111111111111111111111111",
		Subject:     "login.example.co.uk", DNSNames: "login.example.co.uk,cdn.example.co.uk"}
	match := storage.Match{IP: row.IP, Source: feeds.PhishingArmySource, Value: "example.co.uk", Tag: "phishing"}
	hosts, _ := scanner.Project(storage.HostData{Scans: []storage.Scan{row}, Matches: []storage.Match{match}}, scanner.ActiveOpen)
	if got := hosts[0].Ports[0].Signals; len(got) != 1 {
		t.Fatalf("dashboard returned %d copies of one Phishing Army hit: %v", len(got), got)
	}
}

func TestPhishingArmyRejectsMalformedDomain(t *testing.T) {
	if _, err := feeds.DecodeDomainFeed(strings.NewReader("valid.example\nnot a domain\n"), feeds.PhishingArmySource, "phishing"); err == nil {
		t.Fatal("malformed domain was accepted")
	}
	got, err := feeds.DecodeDomainFeed(strings.NewReader("from-ia.com\n"), feeds.PhishingArmySource, "phishing")
	if err != nil || len(got) != 1 || got[0].Value != "from-ia.com" {
		t.Fatalf("listed public suffix = %v, %v; want an exact indicator", got, err)
	}
}

// Reject empty values at parsing and lookup boundaries.
func TestEmptyValuesNeverMatch(t *testing.T) {
	if _, err := feeds.DecodeTweetFeed(strings.NewReader(
		`[{"date":"2026-08-04 09:00:00","user":"reporter","type":"domain","value":".","tags":["#C2"]}]`)); err == nil {
		t.Fatal("a domain of \".\" was accepted, want an error")
	}
	if _, err := feeds.DecodeTweetFeed(strings.NewReader(
		`[{"date":"2026-08-04 09:00:00","user":"reporter","type":"url","value":"not-a-url","tags":["#C2"]}]`)); err == nil {
		t.Fatal("a URL without a host was accepted, want an error")
	}
	f := &feeds.Cache{LastGood: map[string][]feeds.Indicator{}}
	f.Index = feeds.BuildIndex([]feeds.Indicator{{Source: "tweetfeed", Value: "", Tag: "C2", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false}})
	if hits := f.Lookup(""); len(hits) != 0 {
		t.Fatalf("lookup for an empty key = %v, want none", hits)
	}
}

func TestTweetFeedOnlyLinksSafeTweetURLs(t *testing.T) {
	got, err := feeds.DecodeTweetFeed(strings.NewReader(`[
		{"date":"2026-08-04 09:00:00","user":"reporter","type":"ip","value":"192.0.2.1","tweet":"http://x.com/reporter/status/1"},
		{"date":"2026-08-04 09:01:00","user":"reporter","type":"ip","value":"192.0.2.2","tweet":"https://example.com/reporter/status/2"}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Link != "" || got[1].Link != "" {
		t.Fatalf("unsafe tweet links were retained: %+v", got)
	}
}

func TestTweetFeedValidatesIPURLPorts(t *testing.T) {
	got, err := feeds.DecodeTweetFeed(strings.NewReader(`[
		{"date":"2026-08-04 09:00:00","user":"reporter","type":"url","value":"http://192.0.2.8/path"}]`))
	if err != nil || len(got) != 1 || got[0].Value != "192.0.2.8" {
		t.Fatalf("portless IP URL = %v, %v; want bare IP", got, err)
	}
	for _, port := range []string{"0", "65536"} {
		body := fmt.Sprintf(`[{"date":"2026-08-04 09:00:00","user":"reporter","type":"url","value":"http://192.0.2.8:%s/path"}]`, port)
		if _, err := feeds.DecodeTweetFeed(strings.NewReader(body)); err == nil {
			t.Errorf("URL port %s was accepted, want an error", port)
		}
	}
}

func TestURLFeedDomainContractsStayDistinct(t *testing.T) {
	got, err := feeds.DecodeTweetFeed(strings.NewReader(`[
		{"date":"2026-08-04 09:00:00","user":"reporter","type":"url","value":"ftp://INTERNAL."}]`))
	if err != nil || len(got) != 1 || got[0].Value != "internal" {
		t.Fatalf("TweetFeed URL = %v, %v; want its loose domain contract", got, err)
	}
	if _, _, err := feeds.FeedURLValue("ftp://INTERNAL."); err == nil {
		t.Fatal("strict URL feed accepted a non-HTTP scheme and unregistrable domain")
	}
}

func TestRefreshKeepsLastGoodOnFailure(t *testing.T) {
	f := stubFeeds(t, http.StatusOK)
	want := f.Refresh(context.Background())
	if len(want) != 27 {
		t.Fatalf("primed with %d indicators, want 27", len(want))
	}
	if reachable, attempted := f.Reachability(); reachable != 11 || attempted != 11 {
		t.Fatalf("reachability = %d/%d, want 11/11", reachable, attempted)
	}
	stubFeeds(t, http.StatusInternalServerError) // repoints the feed URLs at a failing server
	if got := f.Refresh(context.Background()); !reflect.DeepEqual(got, want) {
		t.Fatalf("after failure = %v, want last good %v", got, want)
	}
	// Every feed served its last good result, but none of them answered.
	if reachable, attempted := f.Reachability(); reachable != 0 || attempted != 11 {
		t.Fatalf("reachability after failure = %d/%d, want 0/11", reachable, attempted)
	}
}

func TestMissingAuthKeySkipsThreatFox(t *testing.T) {
	f := stubFeeds(t, http.StatusOK)
	targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey = ""
	for _, got := range f.Refresh(context.Background()) {
		if got.Source == "threatfox" {
			t.Fatalf("fetched threatfox without an auth key: %v", got)
		}
	}
	// A feed skipped for want of a key was never attempted, so it counts against neither figure.
	if reachable, attempted := f.Reachability(); reachable != 10 || attempted != 10 {
		t.Fatalf("reachability = %d/%d, want 10/10", reachable, attempted)
	}
}

// SSLBL's IP blocklist is empty upstream, so a body of nothing but comments is normal, not a
// failure. Otherwise every refresh logs an error over nothing.
func TestSSLBLEmptyListIsNotAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "# Firstseen,DstIP,DstPort\n")
	}))
	defer server.Close()
	original := feeds.SSLBLIPURL
	defer func() { feeds.SSLBLIPURL = original }()
	feeds.SSLBLIPURL = server.URL

	f := &feeds.Cache{Client: server.Client(), LastGood: map[string][]feeds.Indicator{}}
	got, err := f.FetchSSLBL(context.Background())
	if err != nil || len(got) != 0 {
		t.Fatalf("empty list = %v, %v; want no indicators and no error", got, err)
	}
}

func TestFeedDecodersKeepValidRecordsAroundInvalidOnes(t *testing.T) {
	previousKey := targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey
	targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey = "secret"
	t.Cleanup(func() { targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey = previousKey })

	httpDecoder := func(fetch func(*feeds.Cache) ([]feeds.Indicator, error)) func(string) ([]feeds.Indicator, error) {
		return func(body string) ([]feeds.Indicator, error) {
			f := &feeds.Cache{Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK",
					Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			return fetch(f)
		}
	}
	ctx := context.Background()
	tests := []struct {
		name   string
		body   string
		decode func(string) ([]feeds.Indicator, error)
		want   int
	}{
		{"threatfox", `{"query_status":"ok","data":[{"id":"1","ioc":"192.0.2.1:443","threat_type":"c2","ioc_type":"ip:port","malware":"one"},{"id":"","ioc":"bad","threat_type":"","ioc_type":"ip:port","malware":""},{"id":"2","ioc":"192.0.2.2:443","threat_type":"c2","ioc_type":"ip:port","malware":"two"}]}`,
			httpDecoder(func(f *feeds.Cache) ([]feeds.Indicator, error) { return f.FetchThreatFox(ctx) }), 2},
		{"feodo", `[{"ip_address":"192.0.2.1","port":443,"malware":"one"},{"ip_address":"bad","port":443,"malware":"bad"},{"ip_address":"192.0.2.2","port":443,"malware":"two"}]`,
			httpDecoder(func(f *feeds.Cache) ([]feeds.Indicator, error) { return f.FetchFeodo(ctx) }), 2},
		{"sslbl", "2026-01-01,192.0.2.1,443\nbroken\n2026-01-01,192.0.2.2,443\n",
			httpDecoder(func(f *feeds.Cache) ([]feeds.Indicator, error) { return f.FetchSSLBL(ctx) }), 2},
		{"sslbl cert", "2026-01-01,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,one\nbroken\n2026-01-01,bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,two\n",
			httpDecoder(func(f *feeds.Cache) ([]feeds.Indicator, error) { return f.FetchSSLBLCerts(ctx) }), 2},
		{"tweetfeed", `[{"date":"2026-01-01","user":"a","type":"ip","value":"192.0.2.1"},{"date":"2026-01-01","user":"a","type":"ip","value":"bad"},{"date":"2026-01-01","user":"a","type":"ip","value":"192.0.2.2"}]`,
			func(body string) ([]feeds.Indicator, error) {
				return feeds.DecodeTweetFeed(strings.NewReader(body))
			}, 2},
		{"phishing army", "one.example\nnot a domain\ntwo.example\n",
			func(body string) ([]feeds.Indicator, error) {
				return feeds.DecodeDomainFeed(strings.NewReader(body), feeds.PhishingArmySource, "phishing")
			}, 2},
		{"urlhaus", `{"1":[{"url":"https://one.example/a","url_status":"online","last_online":"2026-01-01 00:00:00 UTC","threat":"one"}],"2":[{"url":"bad","url_status":"online","last_online":"2026-01-01 00:00:00 UTC","threat":"bad"}],"3":[{"url":"https://two.example/b","url_status":"online","last_online":"2026-01-01 00:00:00 UTC","threat":"two"}]}`,
			func(body string) ([]feeds.Indicator, error) { return feeds.DecodeURLHaus(strings.NewReader(body)) }, 2},
		{"c2intel", "one.example,one,/a,192.0.2.1\ncheck1.judicicaß1n,bad,/b,192.0.2.9\ntwo.example,two,/c,192.0.2.2\n",
			func(body string) ([]feeds.Indicator, error) { return feeds.DecodeC2Intel(strings.NewReader(body)) }, 4},
		{"threatview c2", "192.0.2.1,01 January 2026 01:00 PM UTC,192.0.2.1,x,x,x\nbroken\n192.0.2.2,01 January 2026 01:00 PM UTC,192.0.2.2,x,x,x\n",
			func(body string) ([]feeds.Indicator, error) {
				return feeds.DecodeThreatViewC2(strings.NewReader(body))
			}, 2},
		{"threatview domains", "one.example\nnot a domain\ntwo.example\n",
			func(body string) ([]feeds.Indicator, error) {
				return feeds.DecodeDomainFeed(strings.NewReader(body), feeds.ThreatViewSource, "tag")
			}, 2},
		{"threatview urls", "https://one.example/a\nbad\nhttps://two.example/b\n",
			func(body string) ([]feeds.Indicator, error) {
				return feeds.DecodeThreatViewURLs(strings.NewReader(body))
			}, 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.decode(test.body)
			var partial *feeds.FeedValidation
			if !errors.As(err, &partial) || partial.Skipped != 1 || len(got) != test.want {
				t.Fatalf("decoded %d indicators with %v; want %d and one skipped record", len(got), err, test.want)
			}
		})
	}
}

func TestPartialRefreshReplacesSnapshotAndCompleteFailureKeepsLastGood(t *testing.T) {
	previousKey := targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey
	targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey = "secret"
	t.Cleanup(func() { targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey = previousKey })
	bodies := map[string]string{
		feeds.ThreatFoxURL: threatFoxBody, feeds.FeodoURL: feodoBody, feeds.SSLBLIPURL: sslblBody,
		feeds.SSLBLCertURL: sslblCertBody, feeds.TweetFeedURL: `{`, feeds.PhishingArmyURL: phishingArmyBody,
		feeds.URLHausURL:      urlHausBody,
		feeds.C2IntelURL:      "one.example,one,/a,192.0.2.1\ncheck1.judicicaß1n,bad,/b,192.0.2.9\ntwo.example,two,/c,192.0.2.2\n",
		feeds.ThreatViewC2URL: threatViewC2Body, feeds.ThreatViewDomainURL: threatViewDomainBody,
		feeds.ThreatViewURL: threatViewURLBody,
	}
	f := &feeds.Cache{Client: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK",
			Body: io.NopCloser(strings.NewReader(bodies[req.URL.String()]))}, nil
	})}, LastGood: map[string][]feeds.Indicator{
		"tweetfeed":         {{Source: "tweetfeed", Value: "198.51.100.1", Tag: "old"}},
		feeds.C2IntelSource: {{Source: feeds.C2IntelSource, Value: "198.51.100.2", Tag: "stale"}},
	}}
	var out safeBuffer
	logging.SetupLogger(&out, 2, false)
	got := f.Refresh(context.Background())
	if reachable, attempted := f.Reachability(); reachable != 10 || attempted != 11 {
		t.Fatalf("reachability = %d/%d, want 10/11", reachable, attempted)
	}
	for _, value := range []string{"192.0.2.1", "192.0.2.2", "198.51.100.1", "192.0.2.15:9090"} {
		if !slices.ContainsFunc(got, func(indicator feeds.Indicator) bool { return indicator.Value == value }) {
			t.Errorf("refreshed indicators missing %q", value)
		}
	}
	if slices.ContainsFunc(got, func(indicator feeds.Indicator) bool { return indicator.Value == "198.51.100.2" }) {
		t.Error("partial refresh retained the stale C2Intel snapshot")
	}
	logged := out.String()
	if strings.Count(logged, "feed=c2intel skipped=1") != 1 ||
		!strings.Contains(logged, "feed refresh partially accepted") ||
		!strings.Contains(logged, "feed refresh failed  feed=tweetfeed") {
		t.Fatalf("refresh logs do not distinguish partial and complete failures:\n%s", logged)
	}
}

func TestNonEmptyAllInvalidFeedIsACompleteFailure(t *testing.T) {
	got, err := feeds.DecodeC2Intel(strings.NewReader("bad\nbroken\n"))
	var partial *feeds.FeedValidation
	if err == nil || errors.As(err, &partial) || got != nil {
		t.Fatalf("all-invalid feed = %v, %v; want complete failure", got, err)
	}
	for name, decode := range map[string]func() ([]feeds.Indicator, error){
		"empty JSON": func() ([]feeds.Indicator, error) { return feeds.DecodeTweetFeed(strings.NewReader(`[]`)) },
		"comments": func() ([]feeds.Indicator, error) {
			return feeds.DecodeDomainFeed(strings.NewReader("# empty\n\n"), feeds.PhishingArmySource, "phishing")
		},
	} {
		if got, err := decode(); err != nil || len(got) != 0 {
			t.Errorf("%s = %v, %v; want accepted empty feed", name, got, err)
		}
	}
}

// writeConfig writes a config file with every required setting present, after applying any
// old→new substitutions. Tests vary only the setting they exercise. An empty replacement drops
// the line entirely, which is how a missing key is expressed.
func writeConfig(t *testing.T, targetsFile string, edits ...[2]string) string {
	t.Helper()
	config := fmt.Sprintf(`[config]
refresh_seconds = 60
retain_days = 30

[feeds]
threatfox_auth_key = "sekrit"

[scan]
allow = ["192.0.2.0/24"]
targets_file = %q
asn_refresh_minutes = 60
scans_per_day = 2
common_ports = [22, 443]
max_workers = 8
dial_timeout_ms = 250
tls_timeout_ms = 2000
jarm_timeout_ms = 500
`, targetsFile)
	for _, edit := range edits {
		config = strings.Replace(config, edit[0], edit[1], 1)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The ThreatFox key comes from the config file and must reach the request header.
func TestThreatFoxAuthKeyFromConfig(t *testing.T) {
	cfg, err := targetcfg.LoadConfig(writeConfig(t, "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Feeds.ThreatFoxAuthKey != "sekrit" {
		t.Fatalf("auth key = %q, want %q", cfg.Feeds.ThreatFoxAuthKey, "sekrit")
	}

	var sent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent = r.Header.Get("Auth-Key")
		fmt.Fprint(w, `{"query_status":"ok","data":[]}`)
	}))
	defer server.Close()
	original, originalKey := feeds.ThreatFoxURL, targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey
	defer func() { feeds.ThreatFoxURL, targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey = original, originalKey }()
	feeds.ThreatFoxURL = server.URL
	targetcfg.Current.Cfg.Feeds.ThreatFoxAuthKey = cfg.Feeds.ThreatFoxAuthKey

	f := &feeds.Cache{Client: server.Client(), LastGood: map[string][]feeds.Indicator{}}
	if _, err := f.FetchThreatFox(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sent != "sekrit" {
		t.Fatalf("Auth-Key header = %q, want %q", sent, "sekrit")
	}
}

func mustPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	prefixes, err := targetcfg.ParsePrefixes(values)
	if err != nil {
		t.Fatal(err)
	}
	return prefixes
}

func TestScopeContains(t *testing.T) {
	s := targetcfg.Scope{
		Targets: mustPrefixes(t, "192.0.2.0/24"),
		Allow:   mustPrefixes(t, "192.0.2.0/25"),
		Deny:    mustPrefixes(t, "192.0.2.1"),
	}
	for _, test := range []struct {
		addr string
		want bool
	}{
		{"192.0.2.2", true},
		{"192.0.2.1", false},   // denied
		{"192.0.2.200", false}, // outside allow
		{"198.51.100.1", false},
		{"2001:db8::1", false}, // IPv6 is never in scope
	} {
		if got := s.Contains(netip.MustParseAddr(test.addr)); got != test.want {
			t.Errorf("contains(%s) = %v, want %v", test.addr, got, test.want)
		}
	}
}

func TestHostCountIgnoresOverlap(t *testing.T) {
	for _, test := range []struct {
		values []string
		want   int
	}{
		{nil, 0},
		{[]string{"192.0.2.1"}, 1},
		{[]string{"192.0.2.0/24"}, 256},
		{[]string{"192.0.2.0/24", "198.51.100.0/24"}, 512},
		{[]string{"10.0.0.0/8", "10.0.0.0/32", "10.1.0.0/16"}, 1 << 24}, // nested entries counted once
		{[]string{"10.0.0.0/32", "10.1.0.0/16", "10.0.0.0/8"}, 1 << 24}, // order must not matter
	} {
		if got := parse.HostCount(mustPrefixes(t, test.values...)); got != test.want {
			t.Errorf("hostCount(%v) = %d, want %d", test.values, got, test.want)
		}
	}
}

func TestScannableHostsAppliesAllowAndDeny(t *testing.T) {
	s := targetcfg.Scope{
		Targets: mustPrefixes(t, "10.0.0.0/24"),
		Allow:   mustPrefixes(t, "10.0.0.0/24"),
		Deny:    mustPrefixes(t, "10.0.0.128/25"),
	}
	if got := targetcfg.ScannableHosts(s); got != 128 {
		t.Errorf("scannableHosts = %d, want 128", got)
	}
}

// Overlapping targets must be walked once, not once per containing prefix.
func TestScannableHostsIgnoresOverlap(t *testing.T) {
	targets := mustPrefixes(t, "192.0.2.0/24", "192.0.2.128/25")
	s := targetcfg.Scope{Targets: targets, Allow: mustPrefixes(t, "192.0.2.0/24")}
	if got := targetcfg.ScannableHosts(s); got != 256 {
		t.Errorf("scannableHosts = %d, want 256", got)
	}
}

func TestScopeRejectsAndReportsTargetsFullyCoveredByDeny(t *testing.T) {
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{
		Allow: []string{"192.0.2.0/25"},
		Deny:  []string{"192.0.2.0/26", "192.0.2.64/26"},
	}}
	targets := mustPrefixes(t, "192.0.2.0/24")
	if _, err := targetcfg.NewScope(cfg, targets); err == nil {
		t.Fatal("a target with no scannable address was accepted")
	}
	s := targetcfg.Scope{Targets: targets, Allow: mustPrefixes(t, cfg.Scan.Allow...), Deny: mustPrefixes(t, cfg.Scan.Deny...)}
	if got := s.Status(targets[0]); got != "denied" {
		t.Errorf("status = %q, want denied", got)
	}
	// Rejection is decided with prefix arithmetic, not by walking every address. If newScope falls
	// back to scannableHosts before the guard, this case attempts four billion iterations.
	all := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"0.0.0.0/0"}, Deny: []string{"0.0.0.0/0"}}}
	if _, err := targetcfg.NewScope(all, mustPrefixes(t, "0.0.0.0/0")); err == nil {
		t.Fatal("a fully denied IPv4 range was accepted")
	}
}

func TestManualScopeRequiresEveryAddressToBeAuthorized(t *testing.T) {
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{
		Allow: []string{"192.0.2.0/25", "198.51.100.0/24"},
		Deny:  []string{"192.0.2.64/26"},
	}}
	if _, err := targetcfg.NewManualScope(cfg, mustPrefixes(t, "198.51.100.7")); err != nil {
		t.Fatalf("authorized ad-hoc target rejected: %v", err)
	}
	for _, target := range []string{"192.0.2.0/24", "192.0.2.64/26", "203.0.113.7"} {
		if _, err := targetcfg.NewManualScope(cfg, mustPrefixes(t, target)); err == nil {
			t.Errorf("unauthorized target %s accepted", target)
		}
	}
}

// LoadScope must refuse to run when the targets fall outside the allowlist.
func TestLoadScopeGuardsAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(path, []byte(`["192.0.2.2","198.51.100.0/24"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}, TargetsFile: path}}
	if _, err := targetcfg.LoadScope(cfg); err != nil {
		t.Fatalf("in-scope targets rejected: %v", err)
	}

	cfg.Scan.Allow = []string{"203.0.113.0/24"}
	if _, err := targetcfg.LoadScope(cfg); err == nil {
		t.Fatal("out-of-scope targets accepted")
	}
}

// -scan takes the whole scope from the command line and ignores the targets file. The file here
// does not exist, so reading it would fail the run. The allowlist guardrail must still reject an
// out-of-scope argument, and do it before anything is dialled.
func TestScanFlagScopesTheRunAndGuardsAllowlist(t *testing.T) {
	config := writeConfig(t, filepath.Join(t.TempDir(), "no-such-targets.json"))
	if err := targetcfg.LoadTargets(config, "192.0.2.128/25", false); err != nil {
		t.Fatalf("in-scope -scan rejected: %v", err)
	}
	_, s := targetcfg.Current.Config()
	if got := parse.HostCount(s.Targets); got != 128 {
		t.Errorf("targets = %v (%d hosts), want the 128 of the -scan argument", s.Targets, got)
	}

	err := targetcfg.LoadTargets(config, "8.8.8.8", false)
	if err == nil || !strings.Contains(err.Error(), "out of scope") {
		t.Fatalf("out-of-scope -scan error = %v, want one naming \"out of scope\"", err)
	}
}

// On-demand mode is one pass and out, so the pass itself has to leave the report on disk. There
// is no later iteration of the loop to write it.
func TestSweepOnceProbesAndWritesTheReport(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	live, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	target, err := netip.ParseAddrPort(live.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	scanner.ReportPath = filepath.Join(t.TempDir(), "report.json")
	defer func() { scanner.ReportPath = "" }()
	cfg := targetcfg.Config{Base: targetcfg.BaseConfig{RetainDays: 30}, Scan: targetcfg.ScanConfig{
		Allow:       []string{"127.0.0.1/32"},
		CommonPorts: []int{int(target.Port())},
		MaxWorkers:  4, DialTimeoutMS: 500, TLSTimeoutMS: 500,
	}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.1", Port: 1, ScannedAt: 1}}); err != nil {
		t.Fatal(err)
	}

	scanner.SweepOnce(ctx, true, false, nil)

	data, err := storage.LoadHostData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows := data.Scans
	if len(rows) != 2 || !slices.ContainsFunc(rows, func(row storage.Scan) bool { return row.ScannedAt == 1 }) {
		t.Fatalf("scans = %+v, want the new scan and the old retained row", rows)
	}
	reportData, err := os.ReadFile(scanner.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	var hosts []scanner.ReportHost
	if err := json.Unmarshal(reportData, &hosts); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
}

// A failed reload must leave the previously loaded config and scope in place.
func TestStoreReloadKeepsLastGood(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(targets, []byte(`["192.0.2.2"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, targets)

	var configs targetcfg.Store
	if err := configs.Load(path); err != nil {
		t.Fatal(err)
	}
	if _, s := configs.Config(); !s.Contains(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("loaded scope does not contain its target")
	}

	// A target outside the allowlist trips the guardrail, so the reload must be rejected.
	if err := os.WriteFile(targets, []byte(`["198.51.100.2"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configs.Load(path); err == nil {
		t.Fatal("out-of-scope reload accepted")
	}
	if cfg, s := configs.Config(); !s.Contains(netip.MustParseAddr("192.0.2.2")) || cfg.Feeds.ThreatFoxAuthKey != "sekrit" {
		t.Fatal("failed reload discarded the last good config")
	}
}

// A reload that changed something must say so; one that changed nothing must stay silent.
func TestReloadOnceLogsRealChanges(t *testing.T) {
	targets := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(targets, []byte(`["192.0.2.2"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	write := func(edits ...[2]string) {
		t.Helper()
		data, err := os.ReadFile(writeConfig(t, targets, edits...))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var configs targetcfg.Store
	write()
	if err := configs.Load(path); err != nil {
		t.Fatal(err)
	}

	var out safeBuffer
	logging.SetupLogger(&out, 1, false)
	if got := scanner.ReloadOnce(&configs, path); got != 60*time.Second {
		t.Errorf("interval = %v, want 60s", got)
	}
	if out.String() != "" {
		t.Errorf("unchanged reload logged %q", out.String())
	}

	// Only scan.allow changes: the interval is untouched, so it must not be in the line.
	write([2]string{`allow = ["192.0.2.0/24"]`, `allow = ["192.0.2.0/25"]`})
	scanner.ReloadOnce(&configs, path)
	if got := out.String(); !strings.Contains(got, "config reloaded  targets=1 allow=128 deny=0\n") ||
		strings.Contains(got, "interval") {
		t.Errorf("allow edit logged %q", got)
	}

	out.Reset()
	write([2]string{"refresh_seconds = 60", "refresh_seconds = 30"})
	if got := scanner.ReloadOnce(&configs, path); got != 30*time.Second {
		t.Errorf("interval = %v, want 30s", got)
	}
	if got := out.String(); !strings.Contains(got, "interval=30s") {
		t.Errorf("refresh_seconds edit logged %q", got)
	}
}

// Every setting must come from the config file. There are no defaults, so an omitted key
// has to fail startup rather than be silently filled in.
func TestLoadConfigRequiresEverySetting(t *testing.T) {
	cfg, err := targetcfg.LoadConfig(writeConfig(t, "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := targetcfg.ScanConfig{
		Allow: []string{"192.0.2.0/24"}, TargetsFile: "targets.json",
		ASNRefreshMinutes: 60,
		CommonPorts:       []int{22, 443}, ScansPerDay: 2, MaxWorkers: 8, DialTimeoutMS: 250,
		TLSTimeoutMS: 2000, JARMTimeoutMS: 500,
	}
	if !reflect.DeepEqual(cfg.Base, targetcfg.BaseConfig{RefreshSeconds: 60, RetainDays: 30}) ||
		!reflect.DeepEqual(cfg.Scan, want) {
		t.Fatalf("config = %+v %+v, want refresh_seconds 60, retain_days 30 and %+v",
			cfg.Base, cfg.Scan, want)
	}

	for _, edit := range [][2]string{
		{"refresh_seconds = 60", ""}, // omitted
		{"refresh_seconds = 60", "refresh_seconds = 0"},
		{"asn_refresh_minutes = 60", ""},
		{"asn_refresh_minutes = 60", "asn_refresh_minutes = 14"},
		{"scans_per_day = 2", ""},
		{"scans_per_day = 2", "scans_per_day = 25"},
		{"common_ports = [22, 443]", ""},
		{"common_ports = [22, 443]", "common_ports = []"},
		{"common_ports = [22, 443]", "common_ports = [0]"},
		{"common_ports = [22, 443]", "common_ports = [65536]"},
		{"common_ports = [22, 443]", "common_ports = [22, 22]"},
		{"max_workers = 8", ""},
		{"max_workers = 8", "max_workers = -1"},
		{"dial_timeout_ms = 250", ""},
		{"tls_timeout_ms = 2000", ""},
		{"tls_timeout_ms = 2000", "tls_timeout_ms = 0"},
		{"jarm_timeout_ms = 500", ""},
		{"jarm_timeout_ms = 500", "jarm_timeout_ms = 0"},
	} {
		if _, err := targetcfg.LoadConfig(writeConfig(t, "targets.json", edit)); err == nil {
			t.Errorf("accepted %q -> %q", edit[0], edit[1])
		}
	}
}

func TestValidateConfigRejectsDurationOverflow(t *testing.T) {
	cfg, err := targetcfg.LoadConfig(writeConfig(t, "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	maxDuration := time.Duration(1<<63 - 1)
	for name, breakIt := range map[string]func(*targetcfg.Config){
		"refresh seconds": func(cfg *targetcfg.Config) { cfg.Base.RefreshSeconds = int(maxDuration/time.Second) + 1 },
		"ASN refresh":     func(cfg *targetcfg.Config) { cfg.Scan.ASNRefreshMinutes = int(maxDuration/time.Minute) + 1 },
		"dial timeout":    func(cfg *targetcfg.Config) { cfg.Scan.DialTimeoutMS = int(maxDuration/time.Millisecond) + 1 },
		"TLS timeout":     func(cfg *targetcfg.Config) { cfg.Scan.TLSTimeoutMS = int(maxDuration/time.Millisecond) + 1 },
		"JARM timeout":    func(cfg *targetcfg.Config) { cfg.Scan.JARMTimeoutMS = int(maxDuration/time.Millisecond) + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			broken := cfg
			breakIt(&broken)
			if err := targetcfg.ValidateConfig(broken); err == nil {
				t.Error("accepted a value that wraps when converted to time.Duration")
			}
		})
	}
}

// reportProbe classifies a probe and announces it — the pair probePorts runs on every open port,
// which it keeps apart so the classification happens outside its lock.
func reportProbe(row storage.Scan) scanner.ProbeVerdict {
	verdict := scanner.ClassifyProbe(row)
	scanner.AlertProbe(row, verdict)
	return verdict
}

// A scan whose address or certificate is in a feed must log an ALERT carrying the reason and the
// certificate detail. Anything else stays a DEBUG line, and empty details are dropped.
func TestReportProbeResultFlagsFeedHits(t *testing.T) {
	f := stubFeeds(t, http.StatusOK)
	f.Refresh(context.Background())

	var out safeBuffer
	logging.SetupLogger(&out, 2, false)
	reportProbe(storage.Scan{IP: "192.0.2.1", Port: 443, Subject: "Major Cobalt Strike",
		NotAfter: 1700000000, SignatureAlgorithm: "SHA256-RSA",
		JARM: "27d40d40d29d40d21c42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"}) // address is in threatfox
	// Dated well outside the validity heuristics, so only the SSLBL hit is a reason here.
	reportProbe(storage.Scan{IP: "203.0.113.9", Port: 8443,
		Fingerprint: "aabbccddeeff00112233445566778899aabbccdd",
		NotBefore:   time.Now().AddDate(-2, 0, 0).Unix(),
		NotAfter:    time.Now().AddDate(1, 0, 0).Unix()}) // certificate is in SSLBL
	reportProbe(storage.Scan{IP: "203.0.113.9", Port: 22}) // in no feed at all

	got := out.String()
	for _, want := range []string{
		`ALERT  suspicious host  target=192.0.2.1:443 band=high reasons="threatfox (alpha) first seen 2024-03-01T09:15:00Z"`,
		`subject="Major Cobalt Strike"`,
		`jarm=27d40d40d29d40d21c42d43d00041d4689ee210389f4f6b4b5b1b93f92252d`,
		`expires="2023-11-14 (expired)"`,
		`ALERT  suspicious host  target=203.0.113.9:8443 band=high reasons="sslbl_cert (Dridex C&C) first seen 2024-01-01T00:00:00Z"`,
		"DEBUG  open port  ip=203.0.113.9 port=22\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q, got:\n%s", want, got)
		}
	}
	// The first row has no SANs and the second no subject. Neither may log an empty key.
	if strings.Contains(got, "sans") || strings.Contains(got, "issuer") {
		t.Errorf("empty details were logged:\n%s", got)
	}
}

func TestReportProbeResultShowsAUnixEpochExpiry(t *testing.T) {
	previous := feeds.Current
	t.Cleanup(func() { feeds.Current = previous })
	feeds.Current = &feeds.Cache{LastGood: map[string][]feeds.Indicator{}, Index: map[string][]feeds.Indicator{}}
	var out safeBuffer
	logging.SetupLogger(&out, 1, false)
	reportProbe(storage.Scan{IP: "192.0.2.1", Port: 443, SelfSigned: true,
		Fingerprint: "aabbccddeeff00112233445566778899aabbccdd", NotBefore: -86400})
	if got := out.String(); !strings.Contains(got, `expires="1970-01-01 (expired)"`) {
		t.Errorf("epoch expiry omitted from alert: %s", got)
	}
}

// A feed listing one host on several ports keys every one of those entries on the bare address,
// so the alert would otherwise repeat the same source and tag once per port. They must collapse
// to one reason carrying the earliest date the feed listed the host.
func TestReportProbeResultCollapsesRepeatedReasons(t *testing.T) {
	f := stubFeeds(t, http.StatusOK)
	f.Index = feeds.BuildIndex([]feeds.Indicator{
		{Source: "threatfox", Value: "192.0.2.1:8081", Tag: "win.cobalt_strike", FirstSeen: "2026-07-02T10:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "threatfox", Value: "192.0.2.1:12443", Tag: "win.cobalt_strike", FirstSeen: "2026-07-01T09:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "threatfox", Value: "192.0.2.1:443", Tag: "win.cobalt_strike", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "feodo", Value: "192.0.2.1:443", Tag: "QakBot", FirstSeen: "2026-06-30T08:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
	})

	var out safeBuffer
	logging.SetupLogger(&out, 2, false)
	reportProbe(storage.Scan{IP: "192.0.2.1", Port: 8081})

	want := `reasons="threatfox (win.cobalt_strike) first seen 2026-07-01T09:00:00Z, ` +
		`feodo (QakBot) first seen 2026-06-30T08:00:00Z"`
	if !strings.Contains(out.String(), want) {
		t.Errorf("output missing %q, got:\n%s", want, out.String())
	}
}

// Every alert carries a band, so 400 flagged hosts have a triage order. A heuristic alone is
// Low. Anything a feed named is High, including a host with both.
func TestReportProbeResultBandsHits(t *testing.T) {
	f := stubFeeds(t, http.StatusOK)
	f.Refresh(context.Background())

	var out safeBuffer
	logging.SetupLogger(&out, 2, false)
	// Self-signed with no domain, dated outside the validity heuristics.
	soft := storage.Scan{IP: "203.0.113.9", Port: 4444, SelfSigned: true,
		Fingerprint: "00112233445566778899aabbccddeeff00112233",
		NotBefore:   time.Now().AddDate(-2, 0, 0).Unix(),
		NotAfter:    time.Now().AddDate(1, 0, 0).Unix()}
	reportProbe(soft)
	// The same certificate on an address threatfox lists. The feed hit outranks the heuristic.
	both := soft
	both.IP = "192.0.2.1"
	reportProbe(both)

	got := out.String()
	for _, want := range []string{
		"target=203.0.113.9:4444 band=low",
		"target=192.0.2.1:4444 band=high",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q, got:\n%s", want, got)
		}
	}
}

// The certificate checks must fire on the rows they describe and stay silent on the rest.
func TestCertSignals(t *testing.T) {
	// Nothing in the checks may fire on this. Long-lived, domain-bearing, on 443, CA-signed.
	base := storage.Scan{
		Port: 443, DNSNames: "example.com", SerialNumber: "12345",
		Subject: "example.com", Issuer: "Example CA",
		NotBefore:   time.Now().AddDate(-2, 0, 0).Unix(),
		NotAfter:    time.Now().AddDate(1, 0, 0).Unix(),
		Fingerprint: "aabbccddeeff00112233445566778899aabbccdd",
	}
	edit := func(changes func(*storage.Scan)) storage.Scan {
		row := base
		changes(&row)
		return row
	}

	for _, tc := range []struct {
		name string
		row  storage.Scan
		want []string
	}{
		{"ordinary certificate", base, nil},
		{"self-signed on an odd port", edit(func(r *storage.Scan) {
			r.SelfSigned, r.DNSNames, r.Port = true, "", 4444
		}), []string{"self_signed"}},
		// The port is not part of the check. A self-signed certificate with no domain on 443 or
		// 8443 is the same signal as one on 4444, and was exempt until standardTLSPorts went.
		{"self-signed on a standard port", edit(func(r *storage.Scan) {
			r.SelfSigned, r.DNSNames, r.Port = true, "", 8443
		}), []string{"self_signed"}},
		{"self-signed with a domain", edit(func(r *storage.Scan) {
			r.SelfSigned, r.Issuer, r.Port = true, r.Subject, 4444
		}), []string{"self_signed"}},
		{"short validity", edit(func(r *storage.Scan) {
			r.DNSNames, r.NotAfter = "", r.NotBefore+int64((24*time.Hour).Seconds())
		}), []string{"expired_cert", "cert_validity"}},
		{"freshly issued", edit(func(r *storage.Scan) {
			r.DNSNames, r.NotBefore = "", time.Now().Add(-time.Hour).Unix()
		}), []string{"cert_validity"}},
		{"expired with a domain", edit(func(r *storage.Scan) {
			r.NotAfter = time.Now().Add(-time.Hour).Unix()
		}), []string{"expired_cert"}},
		{"centuries-long validity", edit(func(r *storage.Scan) {
			r.NotBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
			r.NotAfter = time.Date(2400, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
		}), []string{"long_validity"}},
		{"exactly ten years", edit(func(r *storage.Scan) {
			start := time.Now().AddDate(1, 0, 0)
			r.NotBefore, r.NotAfter = start.Unix(), start.AddDate(10, 0, 0).Unix()
		}), nil},
		{"expired after long validity", edit(func(r *storage.Scan) {
			r.NotBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
			r.NotAfter = time.Date(2011, 1, 2, 0, 0, 0, 0, time.UTC).Unix()
		}), []string{"expired_cert", "long_validity"}},
		{"not valid yet", edit(func(r *storage.Scan) {
			r.DNSNames = ""
			r.NotBefore = time.Now().Add(time.Hour).Unix()
			r.NotAfter = time.Now().AddDate(1, 0, 0).Unix()
		}), nil},
		{"short validity with a domain", edit(func(r *storage.Scan) {
			r.NotAfter = r.NotBefore + int64((24 * time.Hour).Seconds())
		}), []string{"expired_cert"}},
		// A plain TCP port collects no certificate. Its zeroed dates must not read as a
		// zero-length validity window.
		{"no certificate", storage.Scan{IP: "192.0.2.1", Port: 4444}, nil},
	} {
		signals := scanner.CertSignals(tc.row)
		var got []string
		for _, signal := range signals {
			got = append(got, signal.Source)
			if signal.Value != tc.row.Fingerprint || signal.Tag == "" {
				t.Errorf("%s: signal = %+v, want the fingerprint and a reason", tc.name, signal)
			}
			// Every certificate check is a heuristic and says so on the signal itself. band reads
			// the weight off the value, so a check added here cannot be banded High by being left
			// off a list somewhere else.
			if !signal.Soft {
				t.Errorf("%s: %s is not marked soft", tc.name, signal.Source)
			}
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: signals = %v, want %v", tc.name, got, tc.want)
		}
		if len(signals) > 0 {
			if got := scanner.Band(signals); got != "low" {
				t.Errorf("%s: band = %q, want low from heuristics alone", tc.name, got)
			}
		}
	}
}

// An open port is DEBUG noise, so it must vanish at the default level while an alert on the same
// result still prints. ALERT outranks every filter.
func TestAlertsSurviveTheDefaultLevel(t *testing.T) {
	stubFeeds(t, http.StatusOK).Refresh(context.Background())

	var out safeBuffer
	logging.SetupLogger(&out, 1, false)
	reportProbe(storage.Scan{IP: "203.0.113.9", Port: 22}) // in no feed at all
	reportProbe(storage.Scan{IP: "192.0.2.1", Port: 443})  // address is in threatfox
	if got := out.String(); strings.Contains(got, "open port") || !strings.Contains(got, "ALERT") {
		t.Errorf("want the alert but no debug line, got:\n%s", got)
	}
}

// SaveScans must round-trip the certificate columns, and a later scan of the same port must
// Replace all of them. A host that stopped serving TLS must not keep its old certificate.
func TestSaveScansRoundTrip(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	rows := []storage.Scan{{IP: "192.0.2.1", Port: 443, ScannedAt: 100, Subject: "cs", Issuer: "ca",
		DNSNames: "a.example,b.example", NotBefore: 800, NotAfter: 900,
		SignatureAlgorithm: "SHA256-RSA", SerialNumber: "146473198", SelfSigned: true,
		Fingerprint: "aabbccddeeff00112233445566778899aabbccdd",
		JARM:        "27d40d40d29d40d21c42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"}}
	if err := storage.SaveScans(ctx, rows); err != nil {
		t.Fatal(err)
	}
	rows[0] = storage.Scan{IP: "192.0.2.1", Port: 443, ScannedAt: 200, Manual: true}
	if err := storage.SaveScans(ctx, rows); err != nil {
		t.Fatal(err)
	}
	// Concurrent passes may finish out of order. An older scheduled result must not overwrite the
	// newer manual result and make the dashboard's origin move backwards.
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.1", Port: 443, ScannedAt: 150}}); err != nil {
		t.Fatal(err)
	}

	data, err := storage.LoadHostData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stored := data.Scans
	if !reflect.DeepEqual(stored, rows) {
		t.Fatalf("stored = %+v, want %+v", stored, rows)
	}
}

// ProbePorts must save each open port as it finds it, and ignore the closed ones.
func TestProbePortsSavesAsFound(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	live, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	target, err := netip.ParseAddrPort(live.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	shut, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	shut.Close()
	closed, err := netip.ParseAddrPort(shut.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	targetcfg.Current.Cfg.Scan = targetcfg.ScanConfig{MaxWorkers: 4, DialTimeoutMS: 500, TLSTimeoutMS: 500}
	ports := []int{int(closed.Port()), int(target.Port()), 1}
	if m := scanner.ProbePorts(ctx, []netip.Addr{target.Addr()}, ports, true, nil); m.Open.Load() != 1 {
		t.Fatalf("open = %d, want 1", m.Open.Load())
	}

	data, err := storage.LoadHostData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stored := data.Scans
	if len(stored) != 1 || stored[0].Port != int(target.Port()) || !stored[0].Manual {
		t.Fatalf("stored = %+v, want just the live port %d", stored, target.Port())
	}
}

// A certificate listed by SSLBL must land in matches as well as in the alert. The scans row
// records the fingerprint but not the fact that a feed named it.
func TestProbePortsSavesCertificateMatches(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	target, err := netip.ParseAddrPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(server.Certificate().Raw)
	fingerprint := hex.EncodeToString(sum[:])

	// stubFeeds is here for its feedCache cleanup. The index is the listener's own fingerprint,
	// which no fixed feed body could carry.
	f := stubFeeds(t, http.StatusOK)
	f.Index = feeds.BuildIndex([]feeds.Indicator{{Source: "sslbl_cert", Value: fingerprint, Tag: "Dridex C&C", FirstSeen: "2024-01-01T00:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false}})

	var out safeBuffer
	logging.SetupLogger(&out, 2, false)
	targetcfg.Current.Cfg.Scan = targetcfg.ScanConfig{MaxWorkers: 4, DialTimeoutMS: 500, TLSTimeoutMS: 500}
	pass := scanner.ProbePorts(ctx, []netip.Addr{target.Addr()}, []int{int(target.Port())}, false, nil).Summary

	// The pass counts this host once: live on TLS, and high because a feed named its certificate.
	if want := (scanner.ReportSummary{LiveTLSHosts: 1, High: 1}); pass != want {
		t.Errorf("pass tally = %+v, want %+v", pass, want)
	}
	if !strings.Contains(out.String(), "ALERT") {
		t.Errorf("no alert logged, got:\n%s", out.String())
	}
	data, err := storage.LoadHostData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stored := data.Matches
	if len(stored) != 1 || stored[0].SeenAt == 0 {
		t.Fatalf("stored = %+v, want one timestamped match", stored)
	}
	stored[0].SeenAt = 0
	want := storage.Match{IP: target.Addr().String(), Source: "sslbl_cert", Value: fingerprint,
		Tag: "Dridex C&C", FirstSeen: "2024-01-01T00:00:00Z"}
	if stored[0] != want {
		t.Fatalf("stored = %+v, want %+v", stored[0], want)
	}
}

// SweepLoop no longer dedupes its address list, parsePrefixes does it. Overlapping targets must
// still probe each address exactly once, or the open count doubles.
func TestSweepAddrsAreUniqueAcrossOverlappingTargets(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	live, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	target, err := netip.ParseAddrPort(live.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	var s targetcfg.Scope
	if s.Targets, err = targetcfg.ParsePrefixes([]string{"127.0.0.1/32", "127.0.0.0/30"}); err != nil {
		t.Fatal(err)
	}
	if s.Allow, err = targetcfg.ParsePrefixes([]string{"127.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	addrs := slices.Collect(s.AuthorizedAddrs)
	if len(addrs) != 1 {
		t.Fatalf("addrs = %v, want just 127.0.0.1", addrs)
	}

	targetcfg.Current.Cfg.Scan = targetcfg.ScanConfig{MaxWorkers: 4, DialTimeoutMS: 500, TLSTimeoutMS: 500}
	if m := scanner.ProbePorts(ctx, addrs, []int{int(target.Port())}, false, nil); m.Open.Load() != 1 {
		t.Fatalf("open = %d, want 1", m.Open.Load())
	}
}

// The buffered semaphore is the whole of the rate limiting, so no more than max_workers dials
// may ever be in flight. The listener holds every connection open and the dial timeout outlasts
// the test, so a slot is only freed by the cap being broken.
func TestProbePortsCapsDialsInFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 16)
	go func() {
		var held []net.Conn // never answered, and kept alive so nothing closes early
		for {
			conn, err := listener.Accept()
			if err != nil {
				for _, conn := range held {
					conn.Close()
				}
				return
			}
			held = append(held, conn)
			accepted <- struct{}{}
		}
	}()

	target, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Ten jobs at the one listener. Repeated addresses, since probePorts scans what it is given.
	addrs := make([]netip.Addr, 10)
	for i := range addrs {
		addrs[i] = target.Addr()
	}
	targetcfg.Current.Cfg.Scan = targetcfg.ScanConfig{MaxWorkers: 2, DialTimeoutMS: 30000, TLSTimeoutMS: 30000}
	done := make(chan struct{})
	go func() { defer close(done); scanner.ProbePorts(ctx, addrs, []int{int(target.Port())}, false, nil) }()

	<-accepted
	<-accepted
	select {
	case <-accepted:
		t.Error("a third dial was in flight with max_workers = 2")
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	<-done
}

func TestManualSweepChecksCachedFeeds(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	scanner.ReportPath = filepath.Join(t.TempDir(), "report.json")
	t.Cleanup(func() { scanner.ReportPath = "" })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target, err := netip.ParseAddrPort(listener.Addr().String())
	listener.Close()
	if err != nil {
		t.Fatal(err)
	}
	cfg := targetcfg.Config{Base: targetcfg.BaseConfig{RetainDays: 30}, Scan: targetcfg.ScanConfig{
		Allow: []string{"127.0.0.0/8"}, CommonPorts: []int{int(target.Port())},
		MaxWorkers: 1, DialTimeoutMS: 200, TLSTimeoutMS: 200,
	}}
	configured, err := targetcfg.NewScope(cfg, mustPrefixes(t, "127.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	previousConfig, previousScope := targetcfg.Current.Config()
	previousFeeds := feeds.Current
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		feeds.Current = previousFeeds
	})
	targetcfg.Current.Set(cfg, configured)
	feeds.Current = &feeds.Cache{Index: feeds.BuildIndex([]feeds.Indicator{{
		Source: "cached", Value: target.Addr().String() + ":443", Tag: "known C2", FirstSeen: "2026-08-18T00:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false,
	}})}
	logging.SetupLogger(io.Discard, 1, false)

	// The manual target is not in the configured target list and its only scanned port is closed.
	// Its match can therefore come only from checking the existing cache for the manual scope.
	scanner.SweepOnce(ctx, true, true, mustPrefixes(t, target.Addr().String()))

	data, err := storage.LoadHostData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	matches := data.Matches
	if len(matches) != 1 || matches[0].IP != target.Addr().String() || matches[0].Source != "cached" {
		t.Fatalf("matches = %+v, want the cached hit for the temporary manual target", matches)
	}
}

func TestSweepPortsCommonOnly(t *testing.T) {
	want := []int{443, 22, 8080}
	kind, ports := scanner.SweepPorts(true, want)
	if kind != "common" || !slices.Equal(ports, want) {
		t.Fatalf("sweepPorts = %q, %v, want common ports %v", kind, ports, want)
	}
}

func TestSweepPortsFullStartsWithCommonAndContainsEveryPortOnce(t *testing.T) {
	common := []int{443, 22, 8080}
	kind, ports := scanner.SweepPorts(false, common)
	if kind != "full" || len(ports) != 65535 || !slices.Equal(ports[:len(common)], common) {
		t.Fatalf("sweepPorts = %q with %d ports starting %v", kind, len(ports), ports[:min(len(ports), len(common))])
	}
	seen := make([]bool, 65536)
	for _, port := range ports {
		if port < 1 || port > 65535 || seen[port] {
			t.Fatalf("port %d is invalid or duplicated", port)
		}
		seen[port] = true
	}
	for port := 1; port <= 65535; port++ {
		if !seen[port] {
			t.Fatalf("port %d is missing", port)
		}
	}
}

// drainManualSweep empties the request channel, which is package state shared by every test.
func drainManualSweep(t *testing.T) {
	t.Helper()
	for {
		select {
		case <-scanner.ManualSweep:
		default:
			scanner.SweepState.Mu.Lock()
			scanner.SweepState.Requested = false
			scanner.SweepState.Mu.Unlock()
			return
		}
	}
}

// probe must report a closed port as nothing, an open non-TLS port as a bare row, and an
// Open TLS port as a row carrying the leaf certificate. A refused connection is a real answer
// about the port, so it must come back as a nil row with no error.
func TestProbe(t *testing.T) {
	ctx, timeout := context.Background(), 2*time.Second
	addrPort := func(hostPort string) netip.AddrPort {
		t.Helper()
		target, err := netip.ParseAddrPort(hostPort)
		if err != nil {
			t.Fatal(err)
		}
		return target
	}

	// Nothing listening. No row at all.
	shut, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	shut.Close()
	// Refused, not a local failure. An error here would count the port as untested and put the
	// whole sweep under a dial_failures warning.
	if out := scanner.ProbePort(ctx, addrPort(shut.Addr().String()), scanner.ScanTimeouts{Dial: timeout, TLS: timeout, JARM: timeout}); out.Row != nil || out.Err != nil || out.State != scanner.ProbeClosed {
		t.Fatalf("closed port = %+v, %v, state %d, want no row, no error, probeClosed", out.Row, out.Err, out.State)
	}

	// Open but not TLS. The handshake fails, and the port is still reported.
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	row := scanner.ProbePort(ctx, addrPort(plain.Addr().String()), scanner.ScanTimeouts{Dial: timeout, TLS: timeout, JARM: timeout}).Row
	if row == nil || row.ScannedAt == 0 {
		t.Fatalf("plain TCP port = %+v, want a timestamped row", row)
	}
	if row.Subject != "" || row.NotAfter != 0 {
		t.Fatalf("plain TCP port carried cert fields: %+v", row)
	}

	// Open and TLS. httptest's server presents Go's built-in localhost certificate.
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	tlsTarget := addrPort(strings.TrimPrefix(server.URL, "https://"))
	// Recorded through the fold rather than written by the probe, which is the only path the
	// sweep uses too.
	stages := &scanner.PassMetrics{}
	out := scanner.ProbePort(ctx, tlsTarget, scanner.ScanTimeouts{Dial: timeout, TLS: timeout, JARM: timeout})
	stages.Record(out)
	row = out.Row
	if row == nil || row.NotAfter == 0 {
		t.Fatalf("TLS port = %+v, want a row with a certificate", row)
	}
	// A port that spoke TLS is fingerprinted in the same call that collected its certificate.
	if len(row.JARM) != 62 {
		t.Fatalf("TLS port jarm = %q, want a 62-character fingerprint", row.JARM)
	}
	// The handshake must be governed by its own budget, not by whatever the dial left over.
	// An exhausted tls timeout loses the certificate but must still report the open port. No
	// fingerprint either: a port that failed the handshake is never probed, so ten more dials
	// are never spent on a port that has already said it does not speak TLS.
	starvedOut := scanner.ProbePort(ctx, tlsTarget, scanner.ScanTimeouts{Dial: timeout, TLS: time.Nanosecond, JARM: timeout})
	stages.Record(starvedOut)
	starved := starvedOut.Row
	if starved == nil || starved.NotAfter != 0 {
		t.Fatalf("TLS port with no handshake budget = %+v, want an open row with no certificate", starved)
	}
	if starved.JARM != "" {
		t.Fatalf("failed handshake still fingerprinted: jarm = %q, want empty", starved.JARM)
	}
	// Both probes dialled an open port; only the one that reached a fingerprint ran every stage,
	// so a port that stopped at the handshake must not enter the end-to-end timing.
	if len(stages.DialSamples.Values) != 2 || len(stages.CompleteSamples.Values) != 1 {
		t.Fatalf("stage samples = %d dials, %d complete, want 2 and 1",
			len(stages.DialSamples.Values), len(stages.CompleteSamples.Values))
	}
	// That certificate carries an Organization but no Common Name, so Subject and Issuer are
	// legitimately empty here. Only a CN-bearing certificate fills them.
	if row.DNSNames != "example.com,*.example.com" || row.SignatureAlgorithm != "SHA256-RSA" {
		t.Fatalf("certificate fields not collected: %+v", row)
	}
	// The fields the certificate checks are built on, against a certificate of our own. Go's
	// built-in localhost one starts at the Unix epoch, so a collected NotBefore and an unset one
	// look the same there.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(146473198), // the Cobalt Strike default
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	selfSigned := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	selfSigned.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{der}, PrivateKey: key,
	}}}
	selfSigned.StartTLS()
	defer selfSigned.Close()

	row = scanner.ProbePort(ctx, addrPort(strings.TrimPrefix(selfSigned.URL, "https://")),
		scanner.ScanTimeouts{Dial: timeout, TLS: timeout, JARM: timeout}).Row
	if row == nil {
		t.Fatal("self-signed TLS port = nil, want a row")
	}
	if !row.SelfSigned || row.NotBefore != notBefore.Unix() || row.SerialNumber != "146473198" {
		t.Fatalf("self_signed = %v, not_before = %d, serial = %q, want true, %d, \"146473198\"",
			row.SelfSigned, row.NotBefore, row.SerialNumber, notBefore.Unix())
	}
}

func TestRDP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	serverErr := make(chan error, 1)
	go func() {
		request := make([]byte, 19)
		if _, err := io.ReadFull(server, request); err != nil {
			serverErr <- err
			return
		}
		want := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0, 0, 0, 0, 0, 0x01, 0, 0x08, 0, 0x03, 0, 0, 0}
		if !bytes.Equal(request, want) {
			serverErr <- fmt.Errorf("request = %x, want %x", request, want)
			return
		}
		for _, fragment := range [][]byte{{0x03, 0x00}, {0x00, 0x13, 0x0e}, {0xd0, 0x00}} {
			if _, err := server.Write(fragment); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()
	if rdp, err := scanner.IsRDP(client); !rdp || err != nil {
		t.Fatalf("fragmented RDP response = %v, %v, want true, nil", rdp, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}

	for name, response := range map[string][]byte{
		"bad TPKT":  {0x04, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00},
		"not X.224": {0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() {
				io.ReadFull(server, make([]byte, 19))
				server.Write(response)
			}()
			if rdp, err := scanner.IsRDP(client); rdp || err != nil {
				t.Fatalf("isRDP = %v, %v, want false, nil", rdp, err)
			}
		})
	}
}

// Matches must drop duplicate (ip, source, value) rows and keep them ordered, so the
// upsert batch is deterministic and the logged match count isn't inflated.
func TestMatchesDedupesAndStores(t *testing.T) {
	s := targetcfg.Scope{
		Targets: mustPrefixes(t, "192.0.2.0/24"),
		Allow:   mustPrefixes(t, "192.0.2.0/24"),
		Deny:    mustPrefixes(t, "192.0.2.5"),
	}
	rows := scanner.FeedHitsInScope(s, []feeds.Indicator{
		{Source: "feodo", Value: "192.0.2.1:443", Tag: "alpha", FirstSeen: "2024-02-01T10:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "feodo", Value: "192.0.2.1:443", Tag: "alpha", FirstSeen: "2024-02-01T10:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false}, // duplicate
		{Source: "threatfox", Value: "192.0.2.1:8443", Tag: "zeta", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "feodo", Value: "192.0.2.5:443", Tag: "denied", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},   // denied
		{Source: "feodo", Value: "198.51.100.9:443", Tag: "outer", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false}, // out of scope
		{Source: "feodo", Value: "not-an-address", Tag: "junk", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "192.0.2.2", Tag: "C2", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
		{Source: "tweetfeed", Value: "198.51.100.9", Tag: "outer", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false}, // out of scope
		{Source: "tweetfeed", Value: "evil.example", Tag: "phishing", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false},
	}, 100)

	want := []storage.Match{
		{IP: "192.0.2.1", Source: "feodo", Value: "192.0.2.1:443", Tag: "alpha",
			FirstSeen: "2024-02-01T10:00:00Z", SeenAt: 100},
		{IP: "192.0.2.1", Source: "threatfox", Value: "192.0.2.1:8443", Tag: "zeta", SeenAt: 100},
		{IP: "192.0.2.2", Source: "tweetfeed", Value: "192.0.2.2", Tag: "C2", SeenAt: 100},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("matches = %v, want %v", rows, want)
	}

	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	if err := storage.SaveMatches(ctx, rows); err != nil {
		t.Fatal(err)
	}
	// Re-saving the same keys upserts, so seen_at updates and no duplicate rows appear.
	rows[0].SeenAt, rows[1].SeenAt = 200, 200
	if err := storage.SaveMatches(ctx, rows); err != nil {
		t.Fatal(err)
	}
	data, err := storage.LoadHostData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stored := data.Matches
	if !reflect.DeepEqual(stored, rows) {
		t.Fatalf("stored = %v, want %v", stored, rows)
	}
}

// The report carries one entry per flagged host with the documented keys, drops the hosts
// nothing fired on, counts a per-address feed hit once however many ports the host has open,
// and goes to stdout when no path is given.
func TestReportFlagsHostsAndWritesJSON(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
	}}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1", "198.51.100.7", "203.0.113.9"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)
	f := stubFeeds(t, http.StatusOK)
	f.Refresh(ctx)

	// Dated well outside the validity heuristics, so only the intended signals fire.
	issued, expires := time.Now().AddDate(-2, 0, 0).Unix(), time.Now().AddDate(1, 0, 0).Unix()
	rows := []storage.Scan{
		// Listed by threatfox. The second port is open but not TLS, so no port in the report,
		// and the address hit must not be repeated for it.
		{IP: "192.0.2.1", Port: 443, ScannedAt: 100, DNSNames: "a.example", NotBefore: issued,
			NotAfter: expires, Fingerprint: "1111111111111111111111111111111111111111",
			JARM: "27d40d40d29d40d21c42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"},
		{IP: "192.0.2.1", Port: 22, ScannedAt: 200},
		// Self-signed with no domain. A soft heuristic on its own.
		{IP: "203.0.113.9", Port: 4444, ScannedAt: 300, SelfSigned: true, NotBefore: issued,
			NotAfter: expires, Fingerprint: "2222222222222222222222222222222222222222"},
		// In no feed, on a standard port, with a domain and a long life. Nothing fires.
		{IP: "198.51.100.7", Port: 443, ScannedAt: 400, DNSNames: "b.example", NotBefore: issued,
			NotAfter: expires, Fingerprint: "3333333333333333333333333333333333333333"},
	}
	if err := storage.SaveScans(ctx, rows); err != nil {
		t.Fatal(err)
	}

	// Written to a path first. The file must be complete and parseable after the rename.
	path := filepath.Join(t.TempDir(), "report.json")
	summary, err := scanner.WriteReport(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	// The summary the sweep line quotes must match the JSON. Three hosts completed a handshake
	// (192.0.2.1:22 answered but did not), one banded high and one low.
	if want := (scanner.ReportSummary{LiveTLSHosts: 3, High: 1, Low: 1}); summary != want {
		t.Fatalf("summary = %+v, want %+v", summary, want)
	}
	fromFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Then with no path at all, which must put the same JSON on stdout and nothing else.
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = write
	_, err = scanner.WriteReport(ctx, "")
	os.Stdout = stdout
	write.Close()
	if err != nil {
		t.Fatal(err)
	}
	fromStdout, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromFile, fromStdout) {
		t.Fatalf("file and stdout differ:\n%s\n%s", fromFile, fromStdout)
	}
	if bytes.Contains(fromStdout, []byte(`"jarm"`)) {
		t.Fatalf("report JSON gained a JARM field:\n%s", fromStdout)
	}

	confidence := 75
	want := []scanner.ReportHost{
		{IP: "192.0.2.1", OpenTLSPorts: []int{443},
			Signals: []feeds.Indicator{{Source: "threatfox", Value: "192.0.2.1:443", Tag: "alpha", FirstSeen: "2024-03-01T09:15:00Z",
				Link: "https://threatfox.abuse.ch/ioc/101/", ConfidenceLevel: &confidence, Soft: false}},
			Band:      "high",
			CheckedAt: time.Unix(200, 0).UTC().Format(time.RFC3339)},
		{IP: "203.0.113.9", OpenTLSPorts: []int{4444},
			Signals: []feeds.Indicator{{Source: "self_signed", Value: "2222222222222222222222222222222222222222",
				Tag: "self-signed certificate", FirstSeen: "", Link: "", ConfidenceLevel: nil, Soft: false}},
			Band:      "low",
			CheckedAt: time.Unix(300, 0).UTC().Format(time.RFC3339)},
	}
	var got []scanner.ReportHost
	// Unmarshal, not Contains. It rejects trailing output that is not part of the JSON.
	if err := json.Unmarshal(fromStdout, &got); err != nil {
		t.Fatalf("%v, got:\n%s", err, fromStdout)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("report = %+v, want %+v", got, want)
	}
}

// A fingerprint must identify a real TLS stack, be stable across repeated probes, and come back
// empty for a port that answers no probe. Empty is the one that matters: jarm-go renders that
// case as the all-zero hash, which says nothing about the server and would otherwise become one
// meaningless baseline row that every silent port collapses onto.
func TestFingerprintJARM(t *testing.T) {
	ctx, timeout := context.Background(), 2*time.Second
	target := func(rawURL string) netip.AddrPort {
		t.Helper()
		hostPort := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
		parsed, err := netip.ParseAddrPort(hostPort)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	hash, _, _ := scanner.FingerprintJARM(ctx, target(server.URL), timeout)
	// 62 hex characters is the JARM form. An all-zero result would have been returned as empty
	// and failed here.
	if len(hash) != 62 {
		t.Fatalf("hash = %q, want a 62-character fingerprint", hash)
	}
	// The same stack must fingerprint the same way, or a baseline counts one server many times
	// over and nothing is ever rare.
	if again, _, _ := scanner.FingerprintJARM(ctx, target(server.URL), timeout); again != hash {
		t.Fatalf("second fingerprint = %q, want %q", again, hash)
	}

	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer plain.Close()
	if got, _, _ := scanner.FingerprintJARM(ctx, target(plain.URL), timeout); got != "" {
		t.Fatalf("plain HTTP fingerprint = %q, want empty", got)
	}

	// Ten dials per fingerprint. A cancelled sweep must stop at the current probe, not work
	// through the rest.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if got, _, _ := scanner.FingerprintJARM(cancelled, target(server.URL), timeout); got != "" {
		t.Fatalf("cancelled fingerprint = %q, want empty", got)
	}
}

func TestJARMDialTimeoutIsCounted(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	var timing scanner.StageTiming
	if _, err := scanner.SendJARMProbe(ctx, netip.MustParseAddrPort("192.0.2.1:443"),
		jarm.JarmProbeOptions{}, time.Second, &timing); err != nil {
		t.Fatal(err)
	}
	if got := timing.Timeouts; got != 1 {
		t.Fatalf("jarm timeouts = %d, want 1 for a dial deadline", got)
	}
}

// ProbePort must have let go of the certificate connection before the probes start. A server that
// handles one connection at a time stays blocked on that socket for as long as it is held, so every
// probe behind it times out and the fingerprint comes back all zeroes — stored as empty, which is
// indistinguishable from a port that never spoke TLS at all.
func TestProbePortReleasesTheCertConnectionBeforeJARM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Strictly serial, which is the whole point: one connection handled to completion before the
	// next is accepted. No goroutine per connection.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
			if server.Handshake() == nil {
				// Nothing to serve. Hold the connection until the client hangs up, the way a
				// server waiting on a request that never arrives would.
				io.Copy(io.Discard, server) //nolint:errcheck
			}
			conn.Close()
		}
	}()

	// A short JARM budget so a regression fails in about two seconds instead of thirty.
	out := scanner.ProbePort(context.Background(), netip.MustParseAddrPort(listener.Addr().String()),
		scanner.ScanTimeouts{Dial: 2 * time.Second, TLS: 2 * time.Second, JARM: 200 * time.Millisecond})
	row := out.Row
	if out.Err != nil || row == nil {
		t.Fatalf("probePort = %+v, %v, want a row", row, out.Err)
	}
	if len(row.JARM) != 62 {
		t.Fatalf("jarm = %q, want a 62-character fingerprint; the certificate connection is still "+
			"open while the probes run, so the server never answers them", row.JARM)
	}
}

func TestSendJARMProbeAcceptsPartialResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	target := netip.MustParseAddrPort(listener.Addr().String())
	probe := jarm.GetProbes(target.Addr().String(), int(target.Port()))[0]
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if _, err := conn.Read(make([]byte, 1484)); err != nil {
			serverErr <- err
			return
		}
		// Declares two payload bytes, sends one, then closes.
		_, err = conn.Write([]byte{21, 3, 3, 0, 2, 2})
		serverErr <- err
	}()

	if _, err := scanner.SendJARMProbe(context.Background(), target, probe, time.Second, &scanner.StageTiming{}); err != nil {
		t.Fatalf("partial response: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

// A port that accepts and then says nothing is silence, not a transport failure: benignRead
// counts a deadline as an unanswered probe and records it as "|||", which is what JARM itself
// stores for no response. So the fingerprint is not abandoned — it runs all ten probes and comes
// back all zeroes, which fingerprintJARM turns into an empty string so it is never stored.
//
// This is the cost jarm_timeout_ms is documented against: a silent host pays ten times it.
func TestFingerprintJARMSpendsEveryProbeOnASilentPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := netip.MustParseAddrPort(listener.Addr().String())
	probes := len(jarm.GetProbes(target.Addr().String(), int(target.Port())))
	accepted := make(chan struct{}, probes)
	stop := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			go func() {
				defer conn.Close()
				conn.Read(make([]byte, 1484)) //nolint:errcheck
				// No response: stall through the deadline.
				<-stop
			}()
		}
	}()
	got, _, err := scanner.FingerprintJARM(context.Background(), target, 100*time.Millisecond)
	connections := len(accepted)
	close(stop)
	listener.Close()
	// Empty and an error, so probePort logs it and leaves the column blank rather than storing
	// the all-zero hash every silent port would collapse onto.
	if got != "" || err == nil {
		t.Fatalf("silent port = %q, %v, want empty and an error", got, err)
	}
	if connections != probes {
		t.Fatalf("silent port used %d probes, want all %d attempted", connections, probes)
	}
}

// Rescans widen one endpoint's lifetime instead of inflating it. Host counts are distinct IPs,
// so another port on the same IP stays one host while another IP raises the count.
func TestJARMSightingsAreLifetimeEndpoints(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	const (
		hash   = "27d40d40d29d40d21c42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"
		rare   = "29d29d15d29d29d00029d29d29d29d1af3f8d112f5af1fd47d1d6d4c5dc8a9"
		newest = "00d00d00d00d00d00d00d00d00d00d00d00d00d00d00d00d00d00d00d00d00"
	)
	for scan := range 24 {
		at := int64(200 + scan)
		if scan == 0 {
			at = 300
		} else if scan == 1 {
			at = 100
		}
		if err := storage.SaveJARMSightings(ctx, []storage.JARMSighting{{Hash: hash, IP: "192.0.2.1",
			Port: 443, FirstSeen: at, LastSeen: at}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := storage.SaveJARMSightings(ctx, []storage.JARMSighting{
		{Hash: hash, IP: "192.0.2.1", Port: 8443, FirstSeen: 400, LastSeen: 400},
		{Hash: hash, IP: "192.0.2.2", Port: 443, FirstSeen: 500, LastSeen: 500},
		{Hash: rare, IP: "192.0.2.3", Port: 443, FirstSeen: 600, LastSeen: 600},
	}); err != nil {
		t.Fatal(err)
	}

	stored, err := storage.LoadJARMRows(ctx, "hash", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 || stored[0].Hash != hash || stored[0].Hosts != 2 ||
		stored[0].FirstSeen != 100 || stored[0].LastSeen != 500 {
		t.Fatalf("JARM rows = %+v, want widened lifetime and two distinct hosts", stored)
	}

	if err := storage.SaveJARMSightings(ctx, []storage.JARMSighting{{Hash: newest, IP: "192.0.2.4",
		Port: 443, FirstSeen: 700, LastSeen: 700}}); err != nil {
		t.Fatal(err)
	}

	get := func(query string) []storage.JARMRow {
		t.Helper()
		recorder := httptest.NewRecorder()
		handleJARM(recorder, httptest.NewRequest(http.MethodGet, "/api/jarm?"+query, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", recorder.Code, recorder.Body)
		}
		var rows []storage.JARMRow
		if err := json.Unmarshal(recorder.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	for _, tc := range []struct {
		query string
		want  []string
	}{
		{"", []string{newest, rare, hash}},
		{"sort=hosts", []string{newest, rare, hash}},
		{"sort=-hosts", []string{hash, newest, rare}},
		{"sort=recent", []string{hash, rare, newest}},
		{"sort=-recent", []string{newest, rare, hash}},
		{"sort=first", []string{hash, rare, newest}},
		{"sort=-first", []string{newest, rare, hash}},
		{"sort=hash", []string{newest, hash, rare}},
		{"sort=-hash", []string{rare, hash, newest}},
		{"sort=-nonsense", []string{newest, rare, hash}},
	} {
		rows := get(tc.query)
		got := make([]string, 0, len(rows))
		for _, row := range rows {
			got = append(got, row.Hash)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("JARM order for %q = %v, want %v", tc.query, got, tc.want)
		}
	}
	rows := get("")
	if rows[2] != (storage.JARMRow{Hash: hash, Hosts: 2, FirstSeen: 100, LastSeen: 500}) {
		t.Fatalf("two-host JARM row = %+v, want lifetime bounds and host count", rows[2])
	}
	if rows := get("q=27d40d"); len(rows) != 1 || rows[0].Hash != hash {
		t.Fatalf("searched JARM rows = %+v, want only %s", rows, hash)
	}
}

// Concurrent enqueues must all land, and the flush barrier must be enough for a caller to read
// its own rows back. Matches repeat the same primary key on purpose: one host serving the same
// flagged certificate on several ports puts that key in the batch more than once, and the whole
// batch goes out as one statement. Every row carries the same JARM hash on another endpoint.
func TestWriteLoopBatchesConcurrentEnqueues(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	const hash = "27d40d40d29d40d21c42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"
	// Over maxBatch, so the size-triggered flush fires mid-run as well as the barrier at the end.
	const ports = 600
	var wg sync.WaitGroup
	for port := 1; port <= ports; port++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			storage.Enqueue(
				[]storage.Scan{{IP: "192.0.2.1", Port: port, ScannedAt: int64(port), Fingerprint: "abc", JARM: hash}},
				// Same (ip, source, value) from every port. One row must survive.
				[]storage.Match{{IP: "192.0.2.1", Source: "sslbl", Value: "abc", Tag: "cobalt", SeenAt: 1}},
			)
		}()
	}
	wg.Wait()
	storage.FlushWrites()

	data, err := storage.LoadHostData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scans := data.Scans
	if len(scans) != ports {
		t.Fatalf("scans = %d, want %d", len(scans), ports)
	}
	matches := data.Matches
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
	sightings, err := storage.LoadJARMRows(ctx, "", false, hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(sightings) != 1 || sightings[0].Hosts != 1 || sightings[0].FirstSeen != 1 || sightings[0].LastSeen != ports {
		t.Fatalf("JARM sightings = %+v, want the batched host lifetime", sightings)
	}
}

// seedDashboard opens a temp database holding one host of every band: a feed hit, two heuristic
// hits, and one clean certificate.
// seedDashboard returns the instant the fixtures were dated from. A test that rescans a seeded
// endpoint has to reissue its certificate with the same NotBefore and NotAfter, and a second
// time.Now() can land a second later — enough to change the acknowledgement signature and retire
// an ack the case expected to hold.
func seedDashboard(t *testing.T) int64 {
	t.Helper()
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)

	previous := feeds.Current
	t.Cleanup(func() { feeds.Current = previous })
	feeds.Current = &feeds.Cache{LastGood: map[string][]feeds.Indicator{},
		Index: feeds.BuildIndex([]feeds.Indicator{{Source: "feodo", Value: "192.0.2.50", Tag: "botnet_cc"}})}

	now := time.Now().Unix()
	if err := storage.SaveScans(ctx, []storage.Scan{
		// Clean. A real domain on 443 with a year of validity, so neither check fires.
		{IP: "192.0.2.9", Port: 443, ScannedAt: now - 100, DNSNames: "a.example",
			Subject: "CN=a.example", Issuer: "CN=Example CA", NotBefore: now - 200*86400,
			NotAfter: now + 165*86400, Fingerprint: "1111111111111111111111111111111111111111",
			JARM: "27d40d40d29d40d21c42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"},
		// Open but not speaking TLS. Still a port, carrying no certificate.
		{IP: "192.0.2.9", Port: 22, ScannedAt: now - 100},
		// Self-signed with no domain, freshly issued. Low.
		{IP: "192.0.2.10", Port: 9443, ScannedAt: now - 300, SelfSigned: true,
			NotBefore: now - 3600, NotAfter: now + 20*86400,
			Fingerprint: "2222222222222222222222222222222222222222"},
		// The same heuristics, scanned longest ago.
		{IP: "192.0.2.200", Port: 9001, ScannedAt: now - 9000, SelfSigned: true,
			NotBefore: now - 3600, NotAfter: now + 20*86400,
			Fingerprint: "3333333333333333333333333333333333333333"},
		// Named by a feed, so high whatever the certificate looks like.
		{IP: "192.0.2.50", Port: 443, ScannedAt: now - 200, DNSNames: "c2.example",
			NotBefore: now - 200*86400, NotAfter: now + 165*86400,
			Fingerprint: "4444444444444444444444444444444444444444"},
	}); err != nil {
		t.Fatal(err)
	}
	return now
}

// getHosts calls the host endpoint with a raw query string and decodes what came back.
func getHosts(t *testing.T, query string) hostsResponse {
	t.Helper()
	recorder := httptest.NewRecorder()
	handleHosts(recorder, httptest.NewRequest(http.MethodGet, "/api/hosts?"+query, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	var body hostsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func addressesOf(hosts []scanner.HostView) []string {
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, host.IP)
	}
	return out
}

func TestHostsEndpointCountsEveryHostAndSortsByRecency(t *testing.T) {
	seedDashboard(t)

	body := getHosts(t, "")
	want := []string{"192.0.2.9", "192.0.2.50", "192.0.2.10", "192.0.2.200"}
	if got := addressesOf(body.Hosts); !slices.Equal(got, want) {
		t.Errorf("default order = %v, want most recently scanned first %v", got, want)
	}
	if body.Scanned != 4 || body.LiveTLS != 4 || body.High != 1 || body.Low != 2 || body.Matched != 4 {
		t.Errorf("tallies = scanned %d live %d high %d low %d matched %d, want 4/4/1/2/4",
			body.Scanned, body.LiveTLS, body.High, body.Low, body.Matched)
	}
	// The clean host's two ports are both listed, and only the TLS one carries a certificate.
	clean := body.Hosts[0]
	if len(clean.Ports) != 2 || clean.Ports[0].Port != 22 || clean.Ports[1].Fingerprint == "" {
		t.Errorf("ports of %s = %+v, want 22 listed alongside the TLS port", clean.IP, clean.Ports)
	}
	if clean.Ports[1].JARM == "" {
		t.Errorf("ports of %s hide the JARM fingerprint: %+v", clean.IP, clean.Ports)
	}
	if len(clean.Signals) != 0 || clean.Band != "" {
		t.Errorf("%s fired %v at band %q, want nothing", clean.IP, clean.Signals, clean.Band)
	}
	// The flagged host attributes its reasons to the port they fired on.
	flagged := body.Hosts[2]
	if len(flagged.Ports) != 1 || len(flagged.Ports[0].Signals) != 2 {
		t.Errorf("port signals of %s = %+v, want both certificate checks", flagged.IP, flagged.Ports)
	}
}

func TestFeedOnlyMatchBehavesLikeAnObservedHost(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })

	previousFeeds := feeds.Current
	t.Cleanup(func() { feeds.Current = previousFeeds })
	feeds.Current = &feeds.Cache{Index: map[string][]feeds.Indicator{}}

	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)

	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.1", Port: 80, ScannedAt: 100}}); err != nil {
		t.Fatal(err)
	}
	confidence := 75
	match := storage.Match{IP: "192.0.2.77", Source: "threatfox", Value: "192.0.2.77:8443",
		Tag: "nightmare", FirstSeen: "2026-08-19T12:00:00Z", ConfidenceLevel: &confidence, SeenAt: 200}
	if err := storage.SaveMatches(ctx, []storage.Match{match}); err != nil {
		t.Fatal(err)
	}

	body := getHosts(t, "")
	if got := addressesOf(body.Hosts); !slices.Equal(got, []string{"192.0.2.77", "192.0.2.1"}) {
		t.Fatalf("default order = %v, want the newest feed observation first", got)
	}
	if body.Scanned != 2 || body.High != 1 || body.Matched != 2 {
		t.Fatalf("tallies = scanned %d high %d matched %d, want 2/1/2",
			body.Scanned, body.High, body.Matched)
	}
	host := body.Hosts[0]
	wantSignal := feeds.Indicator{Source: match.Source, Value: match.Value, Tag: match.Tag,
		FirstSeen: match.FirstSeen, ConfidenceLevel: match.ConfidenceLevel}
	if host.PortCount != 0 || host.Ports == nil || len(host.Ports) != 0 || host.Band != "high" ||
		host.CheckedAt != match.SeenAt || !reflect.DeepEqual(host.Signals, []feeds.Indicator{wantSignal}) {
		t.Fatalf("feed-only host = %+v, want a zero-port High host with signal %+v", host, wantSignal)
	}
	if got := addressesOf(getHosts(t, "q=nightmare&band=high").Hosts); !slices.Equal(got, []string{match.IP}) {
		t.Errorf("filtered hosts = %v, want the feed-only match", got)
	}
	if got := addressesOf(getHosts(t, "sort=-ports").Hosts); !slices.Equal(got, []string{"192.0.2.1", match.IP}) {
		t.Errorf("port order = %v, want the zero-port host last", got)
	}

	report, summary, err := scanner.BuildReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.High != 1 || len(report) != 1 || report[0].IP != match.IP ||
		report[0].OpenTLSPorts == nil || len(report[0].OpenTLSPorts) != 0 || report[0].Band != "high" ||
		report[0].CheckedAt != time.Unix(match.SeenAt, 0).UTC().Format(time.RFC3339) ||
		!reflect.DeepEqual(report[0].Signals, []feeds.Indicator{wantSignal}) {
		t.Fatalf("report = %+v, summary = %+v, want the feed-only High finding", report, summary)
	}

	if got := postAck(t, match.IP, "application/json").Code; got != http.StatusOK {
		t.Fatalf("individual acknowledgement status = %d, want 200", got)
	}
	if got := bandOf(t, match.IP); got != "ack" {
		t.Fatalf("individual acknowledgement band = %q, want ack", got)
	}
	if got := postAck(t, match.IP, "application/json").Code; got != http.StatusOK {
		t.Fatalf("individual reset status = %d, want 200", got)
	}
	bulk := postAckBody(t, `{"ips":["192.0.2.77"],"acked":true}`, "application/json")
	if bulk.Code != http.StatusOK || updatedCount(t, bulk) != 1 || bandOf(t, match.IP) != "ack" {
		t.Fatal("bulk acknowledgement did not acknowledge the feed-only host")
	}
	updatedConfidence := 50
	match.ConfidenceLevel = &updatedConfidence
	if err := storage.SaveMatches(ctx, []storage.Match{match}); err != nil {
		t.Fatal(err)
	}
	if got := bandOf(t, match.IP); got != "ack" {
		t.Fatalf("confidence-only update changed acknowledgement band to %q", got)
	}

}

func TestHostsEndpointIncludesAndAcknowledgesRowsOutsideCurrentScope(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	if err := storage.SaveScans(ctx, []storage.Scan{
		{IP: "192.0.2.1", Port: 443, ScannedAt: 1, Manual: true},
		{IP: "192.0.2.1", Port: 8443, ScannedAt: 2},
		{IP: "192.0.2.2", Port: 443, ScannedAt: 3, Manual: true},
	}); err != nil {
		t.Fatal(err)
	}
	previousFeeds := feeds.Current
	t.Cleanup(func() { feeds.Current = previousFeeds })
	feeds.Current = &feeds.Cache{Index: map[string][]feeds.Indicator{}}

	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if scope.Contains(netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("192.0.2.2 is unexpectedly in the current scope")
	}
	targetcfg.Current.Set(cfg, scope)

	body := getHosts(t, "")
	if body.InScope != 1 || body.Scanned != 2 {
		t.Fatalf("dashboard counts = %d in scope, %d with open ports; want 1/2", body.InScope, body.Scanned)
	}
	if got := addressesOf(body.Hosts); !slices.Equal(got, []string{"192.0.2.2", "192.0.2.1"}) {
		t.Fatalf("dashboard hosts = %v, want both stored scans", got)
	}
	if !body.Hosts[0].Manual || body.Hosts[1].Manual {
		t.Fatalf("scan origins = %v/%v, want most recent manual/scheduled",
			body.Hosts[0].Manual, body.Hosts[1].Manual)
	}
	if got := addressesOf(getHosts(t, "origin=manual").Hosts); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Fatalf("manual hosts = %v, want only the newest manual result", got)
	}
	if got := addressesOf(getHosts(t, "origin=scheduled").Hosts); !slices.Equal(got, []string{"192.0.2.1"}) {
		t.Fatalf("scheduled hosts = %v, want only the newest scheduled result", got)
	}
	if got := postAck(t, "192.0.2.2", "application/json").Code; got != http.StatusOK {
		t.Fatalf("out-of-scope ACK status = %d, want 200", got)
	}
	if got := bandOf(t, "192.0.2.2"); got != "ack" {
		t.Fatalf("out-of-scope band = %q after ACK, want ack", got)
	}
	if got := postAckBody(t, `{"ips":["192.0.2.2"],"acked":false}`, "application/json").Code; got != http.StatusOK {
		t.Fatalf("out-of-scope bulk reset status = %d, want 200", got)
	}
}

func TestHostsEndpointBandsEachPortByItsOwnReasons(t *testing.T) {
	seedDashboard(t)
	feeds.Current.Index = feeds.BuildIndex([]feeds.Indicator{
		{Source: "feodo", Value: "192.0.2.50", Tag: "botnet_cc"},
		{Source: "threatfox", Value: "192.0.2.50:8443", Tag: "c2"},
	})
	now := time.Now().Unix()
	issued, expires := now-100*86400, now+265*86400
	if err := storage.SaveScans(context.Background(), []storage.Scan{
		{IP: "192.0.2.50", Port: 8443, ScannedAt: now, SelfSigned: true,
			Subject: "service.example", Issuer: "service.example", DNSNames: "service.example",
			NotBefore: issued, NotAfter: expires,
			Fingerprint: "6666666666666666666666666666666666666666"},
		{IP: "192.0.2.50", Port: 9443, ScannedAt: now, SelfSigned: true,
			NotBefore: issued, NotAfter: expires,
			Fingerprint: "5555555555555555555555555555555555555555"},
	}); err != nil {
		t.Fatal(err)
	}

	var got scanner.HostView
	for _, host := range getHosts(t, "").Hosts {
		if host.IP == "192.0.2.50" {
			got = host
			break
		}
	}
	if got.Band != "high" {
		t.Fatalf("host band = %q, want high", got.Band)
	}
	want := map[int]string{443: "", 8443: "high", 9443: "low"}
	reasons := map[int][]string{443: nil, 8443: {"threatfox", "self_signed"}, 9443: {"self_signed"}}
	for _, port := range got.Ports {
		if port.Band != want[port.Port] {
			t.Errorf("port %d band = %q, want %q", port.Port, port.Band, want[port.Port])
		}
		sources := make([]string, 0, len(port.Signals))
		for _, signal := range port.Signals {
			sources = append(sources, signal.Source)
		}
		if !slices.Equal(sources, reasons[port.Port]) {
			t.Errorf("port %d reasons = %v, want %v", port.Port, sources, reasons[port.Port])
		}
		delete(want, port.Port)
	}
	if len(want) != 0 {
		t.Fatalf("missing ports: %v", want)
	}
}

func TestTweetFeedURLBandsItsExplicitPort(t *testing.T) {
	seedDashboard(t)
	indicators, err := feeds.DecodeTweetFeed(strings.NewReader(`[
		{"date":"2026-08-20 09:00:00","user":"reporter","type":"url",
		 "value":"http://192.0.2.8:8080/payload","tags":["#malware"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	feeds.Current.Index = feeds.BuildIndex(indicators)
	if err := storage.SaveScans(context.Background(), []storage.Scan{
		{IP: "192.0.2.8", Port: 8080, ScannedAt: 2},
		{IP: "192.0.2.8", Port: 8081, ScannedAt: 2},
	}); err != nil {
		t.Fatal(err)
	}

	var got scanner.HostView
	for _, host := range getHosts(t, "").Hosts {
		if host.IP == "192.0.2.8" {
			got = host
			break
		}
	}
	if got.Band != "high" || len(got.Ports) != 2 {
		t.Fatalf("host = %+v, want a High host with two ports", got)
	}
	if got.Ports[0].Port != 8080 || got.Ports[0].Band != "high" ||
		len(got.Ports[0].Signals) != 1 || got.Ports[0].Signals[0].Value != "192.0.2.8:8080" {
		t.Errorf("listed URL port = %+v, want the TweetFeed hit", got.Ports[0])
	}
	if got.Ports[1].Port != 8081 || got.Ports[1].Band != "" || len(got.Ports[1].Signals) != 0 {
		t.Errorf("unlisted port = %+v, want clean", got.Ports[1])
	}
}

// asset reads one of the generated dashboard files out of the embedded tree.
func asset(t *testing.T, name string) string {
	t.Helper()
	data, err := fs.ReadFile(dashboardAssets, name)
	if err != nil {
		t.Fatalf("the dashboard has no %s: %v", name, err)
	}
	return string(data)
}

// Every generated asset referenced by the page must be embedded and served with the dashboard's
// security policy. Vite owns the hashed filenames, so the test discovers them from index.html.
func TestDashboardServesEveryFileItAsksFor(t *testing.T) {
	index := asset(t, "index.html")
	refs := regexp.MustCompile(`(?:src|href)="/([^"]+)"`).FindAllStringSubmatch(index, -1)
	if len(refs) < 3 {
		t.Fatalf("found %d references in index.html; the markup is not being read", len(refs))
	}
	wanted := map[string]bool{}
	for _, ref := range refs {
		wanted[ref[1]] = true
	}

	mux := dashboardMux(dashboardAssets)
	for name := range wanted {
		request := httptest.NewRequest(http.MethodGet, "/"+name, nil)
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200: index.html asks for a file that is not served", name, recorder.Code)
		}
		// The page needs same-origin scripts, styles and favicon images allowed.
		if policy := recorder.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "script-src 'self'") ||
			!strings.Contains(policy, "img-src 'self';") ||
			!strings.Contains(policy, "style-src 'self'") || !strings.Contains(policy, "default-src 'none'") {
			t.Errorf("%s policy = %q", name, policy)
		}
		if policy := recorder.Header().Get("Content-Security-Policy"); strings.Contains(policy, "script-src 'self' 'unsafe-inline'") {
			t.Errorf("%s policy allows inline scripts: %q", name, policy)
		}
		if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s can be framed even though the dashboard can write settings", name)
		}
		wantCache := "no-store"
		if strings.HasPrefix(name, "assets/") {
			wantCache = "public, max-age=31536000, immutable"
		}
		if got := recorder.Header().Get("Cache-Control"); got != wantCache {
			t.Errorf("%s Cache-Control = %q, want %q", name, got, wantCache)
		}
	}

	// Page routes fall back to the React entry point so direct links and refreshes work.
	for _, route := range []string{"/", "/hosts", "/settings"} {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route, nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "<title>IOC Scanner</title>") {
			t.Fatalf("GET %s = %d, want the dashboard", route, recorder.Code)
		}
		if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s Cache-Control = %q, want no-store", route, got)
		}
	}
}

// The theme bootstrap has to run before the first paint, and a module would not: modules are
// deferred, so the page would paint the wrong ground and correct it.
func TestDashboardLoadsTheThemeBeforeItPaints(t *testing.T) {
	index := asset(t, "index.html")
	theme := strings.Index(index, `<script src="/theme.js"></script>`)
	if theme < 0 {
		t.Fatal("theme.js is not loaded as a classic script in the head")
	}
	if body := strings.Index(index, "<body"); theme > body {
		t.Error("theme.js loads after the body starts, so the page paints before the theme applies")
	}
}

func TestDashboardMountsReact(t *testing.T) {
	index := asset(t, "index.html")
	if !strings.Contains(index, `<div id="root"></div>`) {
		t.Fatal("the generated dashboard has no React root")
	}
}

func TestDashboardShipsSonnerStylesAllowedByCSP(t *testing.T) {
	index := asset(t, "index.html")
	cssRef := regexp.MustCompile(`href="/([^"]+\.css)"`).FindStringSubmatch(index)
	if len(cssRef) != 2 || !strings.Contains(asset(t, cssRef[1]), "[data-sonner-toaster]") {
		t.Fatal("Sonner styles are not in the external stylesheet allowed by the dashboard CSP")
	}
}

func TestHostsEndpointFiltersAndSearches(t *testing.T) {
	seedDashboard(t)

	for _, tc := range []struct {
		name, query string
		want        []string
	}{
		{"port number", "q=9443", []string{"192.0.2.10"}},
		{"reason", "q=self_signed", []string{"192.0.2.10", "192.0.2.200"}},
		{"feed tag", "q=botnet_cc", []string{"192.0.2.50"}},
		{"fingerprint", "q=2222222222222222222222222222222222222222", []string{"192.0.2.10"}},
		{"JARM", "q=27d40d40d29d40d21c42d43d", []string{"192.0.2.9"}},
		{"certificate issuer", "q=example+ca", []string{"192.0.2.9"}},
		{"address fragment", "q=2.20", []string{"192.0.2.200"}},
		{"nothing matches", "q=nosuchthing", []string{}},
		{"band high", "band=high", []string{"192.0.2.50"}},
		{"band low", "band=low", []string{"192.0.2.10", "192.0.2.200"}},
		{"band clean", "band=clean", []string{"192.0.2.9"}},
		{"open port", "port=22", []string{"192.0.2.9"}},
		{"address ascending", "sort=ip", []string{"192.0.2.9", "192.0.2.10", "192.0.2.50", "192.0.2.200"}},
		{"address descending", "sort=-ip", []string{"192.0.2.200", "192.0.2.50", "192.0.2.10", "192.0.2.9"}},
		{"band ascending", "sort=band", []string{"192.0.2.50", "192.0.2.10", "192.0.2.200", "192.0.2.9"}},
		{"band descending", "sort=-band", []string{"192.0.2.9", "192.0.2.10", "192.0.2.200", "192.0.2.50"}},
		{"open ports ascending", "sort=ports", []string{"192.0.2.50", "192.0.2.10", "192.0.2.200", "192.0.2.9"}},
		{"open ports descending", "sort=-ports", []string{"192.0.2.9", "192.0.2.50", "192.0.2.10", "192.0.2.200"}},
		{"reasons ascending", "sort=reasons", []string{"192.0.2.9", "192.0.2.50", "192.0.2.10", "192.0.2.200"}},
		{"reasons descending", "sort=-reasons", []string{"192.0.2.10", "192.0.2.200", "192.0.2.50", "192.0.2.9"}},
		{"observed ascending", "sort=recent", []string{"192.0.2.200", "192.0.2.10", "192.0.2.50", "192.0.2.9"}},
		{"observed descending", "sort=-recent", []string{"192.0.2.9", "192.0.2.50", "192.0.2.10", "192.0.2.200"}},
		{"unrecognised sort", "sort=-nonsense", []string{"192.0.2.9", "192.0.2.50", "192.0.2.10", "192.0.2.200"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := getHosts(t, tc.query)
			if got := addressesOf(body.Hosts); !slices.Equal(got, tc.want) {
				t.Errorf("hosts = %v, want %v", got, tc.want)
			}
			if body.Matched != len(tc.want) {
				t.Errorf("matched = %d, want %d", body.Matched, len(tc.want))
			}
			// Filtering never moves the summary figures.
			if body.Scanned != 4 || body.High != 1 || body.Low != 2 {
				t.Errorf("tallies moved: scanned %d high %d low %d, want 4/1/2",
					body.Scanned, body.High, body.Low)
			}
		})
	}

	var paged []string
	for page := 1; page <= 4; page++ {
		paged = append(paged, addressesOf(getHosts(t, fmt.Sprintf("sort=ports&size=1&page=%d", page)).Hosts)...)
	}
	if want := []string{"192.0.2.50", "192.0.2.10", "192.0.2.200", "192.0.2.9"}; !slices.Equal(paged, want) {
		t.Errorf("stable paged order = %v, want %v", paged, want)
	}
}

// The reason sort follows the badges the dashboard draws: one per source. A host with three hits
// from one feed shows one badge and must sort below a host with two hits from two feeds.
func TestSortHostsByReasonCountsDistinctSources(t *testing.T) {
	fewBadges := scanner.HostView{IP: "192.0.2.1", Signals: []feeds.Indicator{
		{Source: "threatfox", Value: "a"}, {Source: "feodo", Value: "b"}}}
	manySignals := scanner.HostView{IP: "192.0.2.2", Signals: []feeds.Indicator{
		{Source: "threatfox", Value: "c"}, {Source: "threatfox", Value: "d"}, {Source: "threatfox", Value: "e"}}}
	hosts := []scanner.HostView{manySignals, fewBadges}
	sortHosts(hosts, "-reasons")
	if got := addressesOf(hosts); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Errorf("reason sort = %v, want the two-badge host first", got)
	}
}

// postAck calls the acknowledgement endpoint the way the dashboard does.
func postAck(t *testing.T, ip, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	return postAckBody(t, `{"ip":"`+ip+`"}`, contentType)
}

func postAckBody(t *testing.T, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/ack", strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	recorder := httptest.NewRecorder()
	handleAck(recorder, request)
	return recorder
}

// bandOf reads one host's band back off the host table.
func bandOf(t *testing.T, ip string) string {
	t.Helper()
	for _, host := range getHosts(t, "").Hosts {
		if host.IP == ip {
			return host.Band
		}
	}
	t.Fatalf("%s missing from the host table", ip)
	return ""
}

// updatedCount reads the number of rows a bulk acknowledgement says it changed.
func updatedCount(t *testing.T, recorder *httptest.ResponseRecorder) int {
	t.Helper()
	var body struct {
		Updated int `json:"updated"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Updated
}

func ackCount(t *testing.T) int {
	t.Helper()
	data, err := storage.LoadHostData(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(data.Acks)
}

// An acknowledgement stands only while the observed target state is unchanged.
func TestAcknowledgementTracksTheWholeTargetState(t *testing.T) {
	now := seedDashboard(t)
	ctx := context.Background()

	if got := postAck(t, "192.0.2.10", "application/json").Code; got != http.StatusOK {
		t.Fatalf("ack status = %d, want 200", got)
	}
	if got := bandOf(t, "192.0.2.10"); got != "ack" {
		t.Fatalf("band = %q, want ack", got)
	}

	// The next sweep finds the same certificate on the same port. Nothing new, so it holds.
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.10", Port: 9443, ScannedAt: now, SelfSigned: true,
		NotBefore: now - 3600, NotAfter: now + 20*86400,
		Fingerprint: "2222222222222222222222222222222222222222"}}); err != nil {
		t.Fatal(err)
	}
	if got := bandOf(t, "192.0.2.10"); got != "ack" {
		t.Errorf("band after an unchanged rescan = %q, want ack", got)
	}
	if err := scanner.RetireStaleAcks(ctx); err != nil {
		t.Fatal(err)
	}
	if ackCount(t) != 1 {
		t.Fatal("an unchanged rescan retired the acknowledgement")
	}

	// Going clean is still a state change.
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.10", Port: 9443, ScannedAt: now, DNSNames: "a.example",
		NotBefore: now - 200*86400, NotAfter: now + 165*86400,
		Fingerprint: "2222222222222222222222222222222222222222"}}); err != nil {
		t.Fatal(err)
	}
	if err := scanner.RetireStaleAcks(ctx); err != nil {
		t.Fatal(err)
	}
	if got := bandOf(t, "192.0.2.10"); got != "" {
		t.Errorf("band once the host went clean = %q, want clean", got)
	}
	if ackCount(t) != 0 {
		t.Fatal("going clean did not retire the acknowledgement")
	}

	if got := postAck(t, "192.0.2.10", "application/json").Code; got != http.StatusOK {
		t.Fatalf("clean ack status = %d, want 200", got)
	}
	// A different clean certificate is also a changed target state.
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.10", Port: 9443, ScannedAt: now + 1,
		DNSNames: "b.example", NotBefore: now - 200*86400, NotAfter: now + 165*86400,
		Fingerprint: "7777777777777777777777777777777777777777"}}); err != nil {
		t.Fatal(err)
	}
	if err := scanner.RetireStaleAcks(ctx); err != nil {
		t.Fatal(err)
	}
	if ackCount(t) != 0 {
		t.Error("a changed clean certificate did not retire the acknowledgement")
	}
}

// Anything unclean that is not what was acknowledged puts the host back in the queue, and takes
// the row with it so it cannot re-apply later.
func TestAcknowledgementClearsWhenTheHostChanges(t *testing.T) {
	now := time.Now().Unix()
	for _, tc := range []struct {
		name   string
		change []storage.Scan
	}{
		{"another port opens with a band", []storage.Scan{
			{IP: "192.0.2.200", Port: 9002, ScannedAt: now, SelfSigned: true,
				NotBefore: now - 3600, NotAfter: now + 20*86400,
				Fingerprint: "4444444444444444444444444444444444444444"},
		}},
		{"one flagged port goes clean while another stays", []storage.Scan{
			{IP: "192.0.2.200", Port: 9001, ScannedAt: now, DNSNames: "a.example",
				NotBefore: now - 200*86400, NotAfter: now + 165*86400,
				Fingerprint: "3333333333333333333333333333333333333333"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seedDashboard(t)
			ctx := context.Background()
			// A second flagged port, so the "goes clean" case leaves something behind.
			if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.200", Port: 9010, ScannedAt: now,
				SelfSigned: true, NotBefore: now - 3600, NotAfter: now + 20*86400,
				Fingerprint: "6666666666666666666666666666666666666666"}}); err != nil {
				t.Fatal(err)
			}
			if got := postAck(t, "192.0.2.200", "application/json").Code; got != http.StatusOK {
				t.Fatalf("ack status = %d, want 200", got)
			}
			if got := bandOf(t, "192.0.2.200"); got != "ack" {
				t.Fatalf("band = %q, want ack", got)
			}

			if err := storage.SaveScans(ctx, tc.change); err != nil {
				t.Fatal(err)
			}
			if got := bandOf(t, "192.0.2.200"); got != "low" {
				t.Errorf("band = %q, want the host back at low", got)
			}
			// bandOf is a dashboard read, and reads do not write. The row is still there.
			if ackCount(t) != 1 {
				t.Errorf("acks = %d, want a dashboard read to leave the row alone", ackCount(t))
			}
			// Retired by the sweep, not merely ignored: left in place it would re-apply if the
			// host ever returned to the shape it was acknowledged in.
			if err := scanner.RetireStaleAcks(ctx); err != nil {
				t.Fatal(err)
			}
			if ackCount(t) != 0 {
				t.Error("the stale acknowledgement is still in the table")
			}
			if got := bandOf(t, "192.0.2.200"); got != "low" {
				t.Errorf("band after retiring = %q, want low", got)
			}
		})
	}
}

// Every write in the process goes through writeMu, so the writers can overlap freely: the
// queue's flush, the retirement pass, and a dashboard acknowledgement. None of
// them may fail on a busy database or lose a row, and reads run against the same file throughout.
func TestConcurrentWritersDoNotCollideOrLoseRows(t *testing.T) {
	seedDashboard(t)
	ctx := context.Background()
	now := time.Now().Unix()

	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, 8*writers)
	for i := range writers {
		ip := "192.0.2." + strconv.Itoa(100+i)
		wg.Add(4)
		// The probe fan-out's path, one flush at a time in production.
		go func() {
			defer wg.Done()
			errs <- storage.SaveScans(ctx, []storage.Scan{{IP: ip, Port: 443, ScannedAt: now, SelfSigned: true,
				NotBefore: now - 3600, NotAfter: now + 20*86400,
				Fingerprint: "5555555555555555555555555555555555555555"}})
		}()
		go func() { defer wg.Done(); errs <- scanner.RetireStaleAcks(ctx) }()
		// A dashboard acknowledgement against a host that already has scan rows.
		go func() {
			defer wg.Done()
			errs <- storage.SaveAck(ctx, storage.Ack{IP: "192.0.2.10", AckedAt: now, Signature: "held"})
		}()
		// A reader throughout, which WAL is meant to keep out of the writers' way.
		go func() {
			defer wg.Done()
			_, _, err := scanner.Findings(ctx, scanner.ActiveOpen)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a concurrent write failed: %v", err)
		}
	}

	// Every row survived. A dropped SQLITE_BUSY would show up here as a missing address.
	hosts, _, err := scanner.Findings(ctx, scanner.ActiveOpen)
	if err != nil {
		t.Fatal(err)
	}
	for i := range writers {
		ip := "192.0.2." + strconv.Itoa(100+i)
		if !slices.ContainsFunc(hosts, func(host scanner.HostView) bool { return host.IP == ip }) {
			t.Errorf("%s is missing: a concurrent write was lost", ip)
		}
	}
}

// The retirement pass keeps only acknowledgements whose observed host state is unchanged.
func TestRetireStaleAcksRemovesOnlyTheRowsThatNoLongerDescribeTheirHost(t *testing.T) {
	seedDashboard(t)
	ctx := context.Background()
	now := time.Now().Unix()

	for _, ip := range []string{"192.0.2.10", "192.0.2.50"} {
		if got := postAck(t, ip, "application/json").Code; got != http.StatusOK {
			t.Fatalf("ack %s status = %d, want 200", ip, got)
		}
	}
	// An acknowledgement whose host has no scan rows at all.
	if err := storage.SaveAck(ctx, storage.Ack{IP: "192.0.2.77", AckedAt: 1, Signature: "unscanned"}); err != nil {
		t.Fatal(err)
	}
	// Only 192.0.2.50 changes, by opening a flagged port.
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.50", Port: 9002, ScannedAt: now,
		SelfSigned: true, NotBefore: now - 3600, NotAfter: now + 20*86400,
		Fingerprint: "4444444444444444444444444444444444444444"}}); err != nil {
		t.Fatal(err)
	}

	survivors := func() []string {
		t.Helper()
		data, err := storage.LoadHostData(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(data.Acks))
		for _, row := range data.Acks {
			out = append(out, row.IP)
		}
		return out
	}

	if err := scanner.RetireStaleAcks(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.10"}
	if got := survivors(); !slices.Equal(got, want) {
		t.Fatalf("acks = %v, want %v", got, want)
	}
	if got := bandOf(t, "192.0.2.10"); got != "ack" {
		t.Errorf("band of the untouched host = %q, want ack", got)
	}
	if got := bandOf(t, "192.0.2.50"); got != "high" {
		t.Errorf("band of the changed host = %q, want high", got)
	}
	// Idempotent: nothing is stale the second time round.
	if err := scanner.RetireStaleAcks(ctx); err != nil {
		t.Fatal(err)
	}
	if got := survivors(); !slices.Equal(got, want) {
		t.Fatalf("acks after a second pass = %v, want %v", got, want)
	}
}

// A sweep can decide an acknowledgement is stale and then be overtaken by the operator
// acknowledging the host afresh from the dashboard. The retirement it had already queued must not
// take that new row with it.
func TestRetiringAStaleAcknowledgementSparesAFreshOne(t *testing.T) {
	seedDashboard(t)
	ctx := context.Background()

	// What the sweep holds: the row as it stood when the comparison was made.
	if err := storage.SaveAck(ctx, storage.Ack{IP: "192.0.2.10", AckedAt: 1, Signature: "the-old-state"}); err != nil {
		t.Fatal(err)
	}
	observed := []storage.Ack{{IP: "192.0.2.10", Signature: "the-old-state"}}

	// The operator gets in first, so the row now describes the host as it is today.
	if err := storage.SaveAck(ctx, storage.Ack{IP: "192.0.2.10", AckedAt: 2, Signature: "the-new-state"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.RetireAcks(ctx, observed); err != nil {
		t.Fatal(err)
	}
	data, err := storage.LoadHostData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows := data.Acks
	if len(rows) != 1 || rows[0].Signature != "the-new-state" {
		t.Fatalf("acks = %+v, want the fresh acknowledgement left alone", rows)
	}

	// The row it was actually asked to retire still goes.
	if err := storage.RetireAcks(ctx, []storage.Ack{{IP: "192.0.2.10", Signature: "the-new-state"}}); err != nil {
		t.Fatal(err)
	}
	if ackCount(t) != 0 {
		t.Error("a matching signature was not retired")
	}
}

func TestAckEndpointTogglesAndRejectsBadRequests(t *testing.T) {
	seedDashboard(t)

	// Acknowledging twice puts the host back, so a mis-click is recoverable.
	if got := postAck(t, "192.0.2.50", "application/json").Code; got != http.StatusOK {
		t.Fatalf("ack status = %d, want 200", got)
	}
	if got := bandOf(t, "192.0.2.50"); got != "ack" {
		t.Fatalf("band = %q, want ack", got)
	}
	// The acknowledged host leaves the High tally and joins its own.
	body := getHosts(t, "")
	if body.High != 0 || body.Acked != 1 {
		t.Errorf("tallies = high %d acked %d, want 0/1", body.High, body.Acked)
	}
	if got := postAck(t, "192.0.2.50", "application/json").Code; got != http.StatusOK {
		t.Fatalf("clear status = %d, want 200", got)
	}
	if got := bandOf(t, "192.0.2.50"); got != "high" {
		t.Errorf("band after clearing = %q, want high", got)
	}
	if ackCount(t) != 0 {
		t.Error("clearing left the row behind")
	}

	for _, tc := range []struct {
		name, ip, contentType string
		want                  int
	}{
		// A cross-origin form post cannot set the JSON content type, which is the only thing
		// standing between this endpoint and any page the operator happens to have open.
		{"form content type", "192.0.2.50", "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"not an address", "not-an-ip", "application/json", http.StatusBadRequest},
		{"unscanned outside scope", "198.51.100.4", "application/json", http.StatusNotFound},
		{"never scanned", "192.0.2.111", "application/json", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := postAck(t, tc.ip, tc.contentType).Code; got != tc.want {
				t.Errorf("status = %d, want %d", got, tc.want)
			}
			if ackCount(t) != 0 {
				t.Error("a rejected request still wrote a row")
			}
		})
	}

	// The single-host form only toggles. Naming one address and a state is the bulk form's job, and
	// mixing the two would silently ignore the state that was asked for.
	if got := postAckBody(t, `{"ip":"192.0.2.50","acked":true}`, "application/json").Code; got != http.StatusBadRequest {
		t.Errorf("single-host ack with a state = %d, want 400", got)
	}
	if ackCount(t) != 0 {
		t.Error("a rejected request still wrote a row")
	}
}

func TestAckEndpointUpdatesABatchWithoutToggling(t *testing.T) {
	seedDashboard(t)
	body := `{"ips":["192.0.2.10","192.0.2.50"],"acked":true}`
	response := postAckBody(t, body, "application/json")
	if response.Code != http.StatusOK {
		t.Fatalf("bulk ack status = %d, want 200", response.Code)
	}
	if got := updatedCount(t, response); got != 2 {
		t.Errorf("updated = %d, want the 2 rows written", got)
	}
	if bandOf(t, "192.0.2.10") != "ack" || bandOf(t, "192.0.2.50") != "ack" || ackCount(t) != 2 {
		t.Fatal("bulk acknowledgement did not acknowledge both hosts")
	}
	// A repeat writes nothing, and has to say so rather than counting the addresses it was given.
	response = postAckBody(t, body, "application/json")
	if response.Code != http.StatusOK || ackCount(t) != 2 {
		t.Fatalf("repeated bulk ack toggled rows: status %d, rows %d", response.Code, ackCount(t))
	}
	if got := updatedCount(t, response); got != 0 {
		t.Errorf("updated = %d on a repeated ack, want 0", got)
	}

	body = `{"ips":["192.0.2.10","192.0.2.9"],"acked":false}`
	response = postAckBody(t, body, "application/json")
	if response.Code != http.StatusOK {
		t.Fatalf("bulk reset status = %d, want 200", response.Code)
	}
	// Only one of the two named hosts was acknowledged.
	if got := updatedCount(t, response); got != 1 {
		t.Errorf("updated = %d on a mixed reset, want 1", got)
	}
	if bandOf(t, "192.0.2.10") != "low" || bandOf(t, "192.0.2.50") != "ack" || ackCount(t) != 1 {
		t.Fatal("bulk reset did not reset only the requested acknowledged host")
	}

	before := ackCount(t)
	body = `{"ips":["192.0.2.50","192.0.2.111"],"acked":false}`
	if got := postAckBody(t, body, "application/json").Code; got != http.StatusNotFound || ackCount(t) != before {
		t.Fatalf("invalid batch partially wrote: status %d, rows %d", got, ackCount(t))
	}
	if got := postAckBody(t, `{"ips":[],"acked":true}`, "application/json").Code; got != http.StatusBadRequest {
		t.Fatalf("empty batch status = %d, want 400", got)
	}
}

// The band boxes are a whitelist: what is ticked is what is shown, and nothing ticked shows
// nothing. Only an absent parameter means no filter at all.
func TestHostsEndpointFiltersByEveryTickedBand(t *testing.T) {
	seedDashboard(t)

	for _, tc := range []struct {
		name, query string
		want        []string
	}{
		{"two bands", "band=high&band=low", []string{"192.0.2.50", "192.0.2.10", "192.0.2.200"}},
		{"band and clean", "band=high&band=clean", []string{"192.0.2.9", "192.0.2.50"}},
		{"nothing ticked", "band=", []string{}},
		{"unknown value", "band=nonsense", []string{}},
		{"no parameter", "", []string{"192.0.2.9", "192.0.2.50", "192.0.2.10", "192.0.2.200"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := addressesOf(getHosts(t, tc.query).Hosts); !slices.Equal(got, tc.want) {
				t.Errorf("hosts = %v, want %v", got, tc.want)
			}
		})
	}

	// Acknowledged hosts are their own band, which is how the dashboard hides them by default.
	if got := postAck(t, "192.0.2.50", "application/json").Code; got != http.StatusOK {
		t.Fatalf("ack status = %d, want 200", got)
	}
	if got := addressesOf(getHosts(t, "band=high&band=low&band=clean").Hosts); slices.Contains(got, "192.0.2.50") {
		t.Errorf("hosts = %v, want the acknowledged host left out", got)
	}
	if got := addressesOf(getHosts(t, "band=ack").Hosts); !slices.Equal(got, []string{"192.0.2.50"}) {
		t.Errorf("hosts = %v, want only the acknowledged host", got)
	}
}

func TestHostsEndpointPagesAndClampsBadInput(t *testing.T) {
	seedDashboard(t)

	second := getHosts(t, "size=1&page=2")
	if got := addressesOf(second.Hosts); !slices.Equal(got, []string{"192.0.2.50"}) {
		t.Errorf("page 2 of 1 = %v, want the second most recently scanned host", got)
	}
	if second.Pages != 4 {
		t.Errorf("pages = %d, want 4", second.Pages)
	}
	// Junk paging shows the first page rather than an error, and an unparseable port is no filter.
	// The band boxes are not in that class: they are a whitelist, so an unknown value there means
	// nothing is shown rather than everything. TestHostsEndpointFiltersByEveryTickedBand covers it.
	clamped := getHosts(t, "page=0&size=99999&port=notaport")
	if clamped.Page != 1 || clamped.Pages != 1 || len(clamped.Hosts) != 4 {
		t.Errorf("clamped = page %d of %d with %d hosts, want page 1 of 1 with 4",
			clamped.Page, clamped.Pages, len(clamped.Hosts))
	}
	// A page past the end lands on the last one instead of returning nothing.
	last := getHosts(t, "size=1&page=99")
	if last.Page != 4 || len(last.Hosts) != 1 {
		t.Errorf("past the end = page %d with %d hosts, want page 4 with 1", last.Page, len(last.Hosts))
	}
}

// A host answering on more ports than the response carries must still arrive with the ports that
// explain it: the one filtered on, and the ones something fired on. Both sit past the cap here.
func TestHostsEndpointKeepsTheInterestingPortsWithinTheCap(t *testing.T) {
	seedDashboard(t)

	now := time.Now().Unix()
	rows := make([]storage.Scan, 0, maxPortsShown+11)
	// Enough quiet ports to fill the cap on their own. Ordered by port, so every one of these
	// comes back ahead of the two below before any reordering.
	for port := 1; port <= maxPortsShown+10; port++ {
		rows = append(rows, storage.Scan{IP: "192.0.2.77", Port: port, ScannedAt: now})
	}
	// Self-signed, no domain, freshly issued: both certificate checks fire.
	rows = append(rows, storage.Scan{IP: "192.0.2.77", Port: 9999, ScannedAt: now, SelfSigned: true,
		NotBefore: now - 3600, NotAfter: now + 20*86400,
		Fingerprint: "5555555555555555555555555555555555555555"})
	if err := storage.SaveScans(context.Background(), rows); err != nil {
		t.Fatal(err)
	}

	ports := func(t *testing.T, query string) (int, []int) {
		t.Helper()
		for _, host := range getHosts(t, query).Hosts {
			if host.IP != "192.0.2.77" {
				continue
			}
			out := make([]int, 0, len(host.Ports))
			for _, port := range host.Ports {
				out = append(out, port.Port)
			}
			return host.PortCount, out
		}
		t.Fatalf("192.0.2.77 missing from the response for %q", query)
		return 0, nil
	}

	count, shown := ports(t, "")
	if count != maxPortsShown+11 {
		t.Errorf("port_count = %d, want the real figure %d", count, maxPortsShown+11)
	}
	if len(shown) != maxPortsShown {
		t.Errorf("ports carried = %d, want the cap %d", len(shown), maxPortsShown)
	}
	// The flagged port sorts last by number and would fall outside a plain first-50 cut.
	if !slices.Contains(shown, 9999) {
		t.Errorf("ports = %v, want the flagged port 9999 kept", shown)
	}

	// Filtering by a port past the cap has to show that port, or the row arrives with nothing to
	// explain why it matched.
	filtered := maxPortsShown + 5
	if _, shown := ports(t, "port="+strconv.Itoa(filtered)); !slices.Contains(shown, filtered) {
		t.Errorf("ports = %v, want the filtered port %d kept", shown, filtered)
	}
}

func TestServeDashboardBindsBeforeItReportsSuccess(t *testing.T) {
	var logged safeBuffer
	logging.SetupLogger(&logged, 1, false)

	// Hold the port, so the bind below cannot succeed.
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()

	if err := Serve(context.Background(), taken.Addr().String(), dashboardAssets); err == nil {
		t.Fatal("serveDashboard on a taken port returned nil, want the bind error")
	}
	if strings.Contains(logged.String(), "dashboard listening") {
		t.Errorf("logged %q, want no claim of listening when the bind failed", logged.String())
	}
}

func TestServeDashboardReturnsOnlyAfterShutdown(t *testing.T) {
	logging.SetupLogger(io.Discard, 1, false)
	ctx, cancel := context.WithCancel(context.Background())

	returned := make(chan error, 1)
	go func() { returned <- Serve(ctx, "127.0.0.1:0", dashboardAssets) }()

	// Nothing should come back while the context is live.
	select {
	case err := <-returned:
		t.Fatalf("serveDashboard returned %v before the context was cancelled", err)
	case <-time.After(100 * time.Millisecond):
	}

	// Once cancelled it drains and returns nil. A return that raced the shutdown would leave
	// runScanner free to close the database underneath a handler still running.
	cancel()
	select {
	case err := <-returned:
		if err != nil {
			t.Errorf("serveDashboard = %v, want nil on a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveDashboard did not return after the context was cancelled")
	}
}

func TestLogRingKeepsTheNewestEntries(t *testing.T) {
	logging.SetupLogger(io.Discard, 1, false)
	for i := range len(logging.LogRing.Buf) + 10 {
		slog.Info("ring entry", "n", i)
	}

	entries := logging.LogRing.Recent()
	if len(entries) != len(logging.LogRing.Buf) {
		t.Fatalf("held = %d, want the ring size %d", len(entries), len(logging.LogRing.Buf))
	}
	if newest := fmt.Sprintf("n=%d", len(logging.LogRing.Buf)+9); entries[0].Attrs != newest {
		t.Errorf("first entry = %q, want the newest %q", entries[0].Attrs, newest)
	}
	if entries[0].Level != "INFO" || entries[0].Msg != "ring entry" {
		t.Errorf("first entry = %+v, want the level and message carried through", entries[0])
	}
	if oldest := fmt.Sprintf("n=%d", len(logging.LogRing.Buf)+10-len(entries)); entries[len(entries)-1].Attrs != oldest {
		t.Errorf("last entry = %q, want %q; older ones should have been overwritten",
			entries[len(entries)-1].Attrs, oldest)
	}
}

func TestLogsEndpointFiltersByLevel(t *testing.T) {
	logging.SetupLogger(io.Discard, 1, false)
	slog.Warn("dashboard test warning", "detail", "unmistakable-warning")
	slog.Info("dashboard test info", "detail", "unmistakable-info")

	recorder := httptest.NewRecorder()
	handleLogs(recorder, httptest.NewRequest(http.MethodGet, "/api/logs?level=WARN&q=unmistakable", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var entries []logging.LogEntry
	if err := json.Unmarshal(recorder.Body.Bytes(), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Msg != "dashboard test warning" {
		t.Fatalf("entries = %+v, want only the warning", entries)
	}
}

// The ThreatFox auth key is a credential and the dashboard serves it with no authentication, so
// the config endpoint must report only whether one is set. The raw body is checked as well as the
// decoded row: a future field carrying the key anywhere in the response has to fail here.
// seedSettings points the process at a writable config and targets file, loads them, and puts
// everything back afterwards. It returns the config path.
func seedSettings(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(targets, []byte(`["192.0.2.0/25"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(writeConfig(t, targets))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	previousConfig, previousScope := targetcfg.Current.Config()
	previousPath := targetcfg.Path
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope); targetcfg.Path = previousPath })
	targetcfg.Path = path
	if err := targetcfg.Current.Load(path); err != nil {
		t.Fatal(err)
	}
	return path
}

// getSettings reads the settings endpoint and returns the raw body alongside the config in it.
func getSettings(t *testing.T) (targetcfg.Config, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handleSettings(recorder, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var body struct {
		Config targetcfg.Config `json:"config"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Config, recorder.Body.String()
}

func putSettings(t *testing.T, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	recorder := httptest.NewRecorder()
	handleSaveSettings(recorder, request)
	return recorder
}

// The form reads and writes the same shape, so saving what was read back must change nothing —
// including the auth key, which the browser is never given and so can never return.
func TestSettingsRoundTripKeepsTheAuthKey(t *testing.T) {
	path := seedSettings(t)
	before, raw := getSettings(t)
	if strings.Contains(raw, "sekrit") {
		t.Fatalf("the response carries the auth key: %s", raw)
	}
	if before.Feeds.ThreatFoxAuthKey != "" {
		t.Fatal("the decoded config carries the auth key")
	}

	edited, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	if recorder := putSettings(t, string(edited), "application/json"); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}

	// Read from the file, not from memory: a save the scanner is running has to survive a restart.
	saved, err := targetcfg.LoadConfig(path)
	if err != nil {
		t.Fatalf("the config just written does not load: %v", err)
	}
	if saved.Feeds.ThreatFoxAuthKey != "sekrit" {
		t.Errorf("auth key = %q, want it kept", saved.Feeds.ThreatFoxAuthKey)
	}
	// Everything else must be exactly what was read, so an untouched form is a no-op save.
	saved.Feeds.ThreatFoxAuthKey = ""
	if !reflect.DeepEqual(saved, before) {
		t.Errorf("round trip changed the config:\n got %+v\nwant %+v", saved, before)
	}
}

// An edited setting has to reach both the file and the running scanner.
func TestSettingsSaveInstallsTheNewConfig(t *testing.T) {
	path := seedSettings(t)
	cfg, _ := getSettings(t)
	cfg.Scan.MaxWorkers = 64
	cfg.Scan.CommonPorts = []int{22, 443, 8443}
	cfg.Feeds.DomainIgnorelist = []string{" *.GitHub.COM. "}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if recorder := putSettings(t, string(body), "application/json"); recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}

	saved, err := targetcfg.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Scan.MaxWorkers != 64 || len(saved.Scan.CommonPorts) != 3 ||
		!slices.Equal(saved.Feeds.DomainIgnorelist, []string{"github.com"}) {
		t.Errorf("file = %+v, want the edit", saved)
	}
	if live, _ := targetcfg.Current.Config(); live.Scan.MaxWorkers != 64 ||
		!slices.Equal(live.Feeds.DomainIgnorelist, []string{"github.com"}) {
		t.Errorf("running config = %+v, want the scanner to pick the edit up", live)
	}
}

// A refused save must leave the file and the running scanner exactly as they were. The allowlist
// case is the one that matters: it is the guardrail, and this endpoint can rewrite it.
func TestSettingsSaveRefusesWithoutTouchingTheFile(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*targetcfg.Config)
		body string
		want int
	}{
		{name: "missing setting", edit: func(c *targetcfg.Config) { c.Scan.MaxWorkers = 0 }, want: http.StatusBadRequest},
		{name: "out of range", edit: func(c *targetcfg.Config) { c.Scan.ScansPerDay = 48 }, want: http.StatusBadRequest},
		{name: "not a port", edit: func(c *targetcfg.Config) { c.Scan.CommonPorts = []int{0} }, want: http.StatusBadRequest},
		// The targets file falls outside the new allowlist, so the scanner would have nothing
		// left in scope.
		{name: "allowlist excludes every target",
			edit: func(c *targetcfg.Config) { c.Scan.Allow = []string{"198.51.100.0/24"} }, want: http.StatusBadRequest},
		// A typoed field is an error, the same as an unknown key in the file.
		{name: "unknown field", body: `{"config":{"refresh_seconds":60},"scan_evrything":true}`,
			want: http.StatusBadRequest},
		{name: "partial body", body: `{"config":{"refresh_seconds":60}}`, want: http.StatusBadRequest},
		{name: "form post", body: `{}`, want: http.StatusUnsupportedMediaType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := seedSettings(t)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := targetcfg.Current.Config()

			body, contentType := tc.body, "application/json"
			if tc.edit != nil {
				cfg, _ := getSettings(t)
				tc.edit(&cfg)
				encoded, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				body = string(encoded)
			}
			if tc.want == http.StatusUnsupportedMediaType {
				contentType = "application/x-www-form-urlencoded"
			}
			if recorder := putSettings(t, body, contentType); recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, tc.want, recorder.Body)
			}

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(original, after) {
				t.Error("a refused save rewrote the config file")
			}
			if live, _ := targetcfg.Current.Config(); !reflect.DeepEqual(live, before) {
				t.Error("a refused save changed the running config")
			}
		})
	}
}

func getTargets(t *testing.T) (rows []targetRow, scannable int) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handleTargets(recorder, httptest.NewRequest(http.MethodGet, "/api/targets", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var body struct {
		Targets   []targetRow `json:"targets"`
		Scannable int         `json:"scannable"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Targets, body.Scannable
}

func putTargets(t *testing.T, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/api/targets", strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	recorder := httptest.NewRecorder()
	handleSaveTargets(recorder, request)
	return recorder
}

// The allow and deny lists narrow the targets file, so the page has to say which entries the
// sweep would actually reach — that is invisible in the file itself.
func TestTargetsReportWhatTheSweepWouldReach(t *testing.T) {
	seedSettings(t)
	cfg, _ := targetcfg.Current.Config()
	cfg.Scan.Deny = []string{"192.0.2.64/26"}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.0/26", "192.0.2.64/26", "198.51.100.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)

	want := map[string]string{
		"192.0.2.0/26":    "in scope",
		"192.0.2.64/26":   "denied",       // inside the allowlist, but explicitly denied
		"198.51.100.0/24": "out of scope", // never in the allowlist to begin with
	}
	rows, _ := getTargets(t)
	if len(rows) != len(want) {
		t.Fatalf("rows = %+v, want %d", rows, len(want))
	}
	for _, row := range rows {
		if row.Status != want[row.Value] {
			t.Errorf("%s = %q, want %q", row.Value, row.Status, want[row.Value])
		}
	}
	// The count is what a sweep would probe, not what is listed.
	if _, scannable := getTargets(t); scannable != 64 {
		t.Errorf("scannable = %d, want the 64 addresses left after allow and deny", scannable)
	}
}

// A saved target has to reach the file and the running scope, normalized to what is swept.
func TestTargetsSaveWritesNormalizedEntries(t *testing.T) {
	seedSettings(t)
	cfg, _ := targetcfg.Current.Config()

	// A bare address, a CIDR needing masking, and a duplicate already covered by the CIDR.
	recorder := putTargets(t, `{"targets":["192.0.2.7","192.0.2.128/25","192.0.2.130"]}`, "application/json")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}

	data, err := os.ReadFile(cfg.Scan.TargetsFile)
	if err != nil {
		t.Fatal(err)
	}
	var written []string
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatalf("the targets file is not valid JSON: %v", err)
	}
	// The /25 swallows the address inside it, and the bare one becomes a /32.
	if want := []string{"192.0.2.7/32", "192.0.2.128/25"}; !reflect.DeepEqual(written, want) {
		t.Errorf("file = %v, want %v", written, want)
	}
	if _, scope := targetcfg.Current.Config(); !scope.Contains(netip.MustParseAddr("192.0.2.130")) {
		t.Error("the running scope did not pick the saved targets up")
	}
	// And the file the scanner would read at startup agrees with what is running.
	reloaded, err := targetcfg.LoadScope(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Scannable != 129 {
		t.Errorf("reloaded scannable = %d, want 129", reloaded.Scannable)
	}
}

// A refused save must leave the targets file exactly as it was: this is the address space the
// scanner points at, and a half-applied edit is how it ends up pointed somewhere else.
func TestTargetsSaveRefusesWithoutTouchingTheFile(t *testing.T) {
	for _, tc := range []struct {
		name, body, contentType string
		want                    int
	}{
		{"empty", `{"targets":[]}`, "application/json", http.StatusBadRequest},
		{"not an address", `{"targets":["not-an-address"]}`, "application/json", http.StatusBadRequest},
		{"ipv6", `{"targets":["2001:db8::1"]}`, "application/json", http.StatusBadRequest},
		// Nothing left inside the allowlist, so the sweep would have no work and the next reload
		// would refuse to start.
		{"all out of scope", `{"targets":["198.51.100.0/24"]}`, "application/json", http.StatusBadRequest},
		{"unknown field", `{"targets":["192.0.2.5"],"force":true}`, "application/json", http.StatusBadRequest},
		{"form post", `{"targets":["192.0.2.5"]}`, "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seedSettings(t)
			cfg, before := targetcfg.Current.Config()
			original, err := os.ReadFile(cfg.Scan.TargetsFile)
			if err != nil {
				t.Fatal(err)
			}

			if recorder := putTargets(t, tc.body, tc.contentType); recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, tc.want, recorder.Body)
			}

			after, err := os.ReadFile(cfg.Scan.TargetsFile)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(original, after) {
				t.Error("a refused save rewrote the targets file")
			}
			if _, live := targetcfg.Current.Config(); !reflect.DeepEqual(live, before) {
				t.Error("a refused save changed the running scope")
			}
		})
	}
}

// manualScanBody asks for a scan of the address seedManualScope authorizes.
const manualScanBody = `{"kind":"common","targets":"198.51.100.7"}`

// seedManualScope installs an allowlist the manual scan targets in these tests fall inside. Targets
// are required now, so a scan test cannot lean on whatever scope another test happened to leave.
func seedManualScope(t *testing.T) {
	t.Helper()
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24", "198.51.100.0/24"}}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	targetcfg.Current.Set(cfg, scope)
}

// postScan calls the scan endpoint with a raw body and content type.
func postScan(t *testing.T, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	recorder := httptest.NewRecorder()
	handleScan(recorder, request)
	return recorder
}

// scanStatusNow reads the scan endpoint the way the dashboard polls it.
func scanStatusNow(t *testing.T) scanner.Status {
	t.Helper()
	recorder := httptest.NewRecorder()
	handleScanStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/scan", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var body scanner.Status
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// A request has to reach the manual loop and be visible to the dashboard while it waits.
func TestScanEndpointQueuesTheRequest(t *testing.T) {
	drainManualSweep(t)
	t.Cleanup(func() { drainManualSweep(t) })
	seedManualScope(t)

	recorder := postScan(t, `{"kind":"full","targets":"198.51.100.7"}`, "application/json")
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body)
	}
	if !scanStatusNow(t).Manual.Queued {
		t.Error("queued = false; the dashboard cannot tell the request landed")
	}
	select {
	case request := <-scanner.ManualSweep:
		if request.Common {
			t.Error("asked for a full sweep, the loop was handed a common one")
		}
		if got := parse.HostCount(request.Targets); got != 1 {
			t.Errorf("queued %d addresses, want the one asked for", got)
		}
	default:
		t.Fatal("nothing reached the manual loop")
	}
}

// Targets are required: sweeping the saved targets is what the schedule already does.
func TestScanEndpointRequiresTargets(t *testing.T) {
	drainManualSweep(t)
	t.Cleanup(func() { drainManualSweep(t) })
	seedManualScope(t)

	for _, body := range []string{`{"kind":"common"}`, `{"kind":"common","targets":""}`,
		`{"kind":"common","targets":"   "}`} {
		if recorder := postScan(t, body, "application/json"); recorder.Code != http.StatusBadRequest {
			t.Errorf("%s status = %d, want 400: %s", body, recorder.Code, recorder.Body)
		}
	}
	if len(scanner.ManualSweep) != 0 {
		t.Error("a targetless request still reached the manual loop")
	}
}

func TestQueuedScanStatusDescribesTheRequestedScan(t *testing.T) {
	drainManualSweep(t)
	t.Cleanup(func() { drainManualSweep(t) })

	seedManualScope(t)
	scanner.SweepState.Mu.Lock()
	scanner.SweepState.Scheduled = scanner.SweepStatus{Running: true, Kind: "common", TargetCount: 99}
	scanner.SweepState.Mu.Unlock()
	t.Cleanup(func() {
		scanner.SweepState.Mu.Lock()
		scanner.SweepState.Scheduled, scanner.SweepState.Manual, scanner.SweepState.Requested = scanner.SweepStatus{}, scanner.SweepStatus{}, false
		scanner.SweepState.Mu.Unlock()
	})

	if recorder := postScan(t, `{"kind":"full","targets":"198.51.100.7"}`, "application/json"); recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body)
	}
	status := scanStatusNow(t)
	if status.Manual.Kind != "full" {
		t.Errorf("queued kind = %q, want full", status.Manual.Kind)
	}
	if !status.Scheduled.Running || status.Scheduled.Kind != "common" || status.Scheduled.TargetCount != 99 {
		t.Errorf("scheduled status = %+v, want the running common scan kept separately", status.Scheduled)
	}
}

func TestCurrentScanReportsCompletedPortProgress(t *testing.T) {
	metrics := &scanner.PassMetrics{}
	metrics.Completed.Store(117963)
	scanner.SweepState.Mu.Lock()
	scanner.SweepState.Scheduled = scanner.SweepStatus{Running: true, Kind: "full", TargetCount: 5,
		TotalPorts: 327675, Metrics: metrics}
	scanner.SweepState.Mu.Unlock()
	t.Cleanup(func() {
		scanner.SweepState.Mu.Lock()
		scanner.SweepState.Scheduled = scanner.SweepStatus{}
		scanner.SweepState.Mu.Unlock()
	})

	status := scanStatusNow(t).Scheduled
	if status.Progress != 36 {
		t.Errorf("progress = %.1f, want 36.0", status.Progress)
	}
}

func TestScanEndpointQueuesATemporaryTargetList(t *testing.T) {
	drainManualSweep(t)
	t.Cleanup(func() { drainManualSweep(t) })
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{
		Allow: []string{"192.0.2.0/24", "198.51.100.0/24"},
	}}
	configured, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	targetcfg.Current.Set(cfg, configured)

	recorder := postScan(t, `{"kind":"full","targets":" 198.51.100.0/31, 198.51.100.1 "}`, "application/json")
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body)
	}
	if got := scanStatusNow(t).Manual.TargetCount; got != 2 {
		t.Errorf("target_count = %d, want 2", got)
	}
	select {
	case request := <-scanner.ManualSweep:
		if request.Common {
			t.Error("asked for a full sweep, the loop was handed a common one")
		}
		if got := parse.HostCount(request.Targets); got != 2 || len(request.Targets) != 1 {
			t.Errorf("queued targets = %v (%d addresses), want one deduplicated /31", request.Targets, got)
		}
	default:
		t.Fatal("nothing reached the sweep loop")
	}
	_, live := targetcfg.Current.Config()
	if got := live.Targets[0].String(); got != "192.0.2.7/32" {
		t.Errorf("configured target changed to %s", got)
	}
}

func TestScanEndpointRejectsAnyUnauthorizedTemporaryTarget(t *testing.T) {
	drainManualSweep(t)
	t.Cleanup(func() { drainManualSweep(t) })
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{
		Allow: []string{"192.0.2.0/25"},
		Deny:  []string{"192.0.2.64/26"},
	}}
	configured, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	targetcfg.Current.Set(cfg, configured)

	for _, tc := range []struct {
		name, targets string
		want          int
	}{
		{"malformed", "not-an-ip", http.StatusBadRequest},
		{"empty entry", "192.0.2.7,", http.StatusBadRequest},
		{"IPv6", "2001:db8::1", http.StatusBadRequest},
		{"outside allow", "203.0.113.7", http.StatusForbidden},
		{"partially allowed CIDR", "192.0.2.0/24", http.StatusForbidden},
		{"denied", "192.0.2.64/26", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"kind":"common","targets":%q}`, tc.targets)
			if recorder := postScan(t, body, "application/json"); recorder.Code != tc.want {
				t.Errorf("status = %d, want %d: %s", recorder.Code, tc.want, recorder.Body)
			}
			if len(scanner.ManualSweep) != 0 {
				t.Error("a refused target list still reached the sweep loop")
			}
		})
	}
}

func TestManualSweepRechecksTargetScopeBeforeRunning(t *testing.T) {
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}}}
	configured, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	targetcfg.Current.Set(cfg, configured)

	scanner.SweepState.Mu.Lock()
	scanner.SweepState.Requested = true
	scanner.SweepState.Mu.Unlock()
	t.Cleanup(func() {
		scanner.SweepState.Mu.Lock()
		scanner.SweepState.Requested = false
		scanner.SweepState.Mu.Unlock()
	})
	scanner.SweepOnce(context.Background(), true, true, mustPrefixes(t, "198.51.100.7"))
	if scanStatusNow(t).Manual.Queued {
		t.Error("request stayed queued after its targets became unauthorized")
	}
}

// The disabled buttons are a courtesy; the endpoint has to refuse a second request itself.
func TestScanEndpointRefusesASecondRequest(t *testing.T) {
	drainManualSweep(t)
	t.Cleanup(func() { drainManualSweep(t) })
	seedManualScope(t)

	if recorder := postScan(t, manualScanBody, "application/json"); recorder.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202", recorder.Code)
	}
	if recorder := postScan(t, manualScanBody, "application/json"); recorder.Code != http.StatusConflict {
		t.Fatalf("second status = %d, want 409", recorder.Code)
	}
	// One request, not two: the second must not have displaced or joined the first.
	if len(scanner.ManualSweep) != 1 {
		t.Errorf("queued = %d, want 1", len(scanner.ManualSweep))
	}
}

func TestScanEndpointRefusesAfterTheLoopReceivesTheFirstRequest(t *testing.T) {
	drainManualSweep(t)
	t.Cleanup(func() { drainManualSweep(t) })
	seedManualScope(t)

	if recorder := postScan(t, manualScanBody, "application/json"); recorder.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202", recorder.Code)
	}
	<-scanner.ManualSweep // reproduce the receive-to-sweepOnce gap
	if recorder := postScan(t, `{"kind":"full","targets":"198.51.100.7"}`, "application/json"); recorder.Code != http.StatusConflict {
		t.Fatalf("second status = %d, want 409", recorder.Code)
	}
}

// A manual sweep already running refuses the next request, the same as one already queued. A
// Scheduled sweep does not: interrupting one is the point.
func TestScanEndpointRefusesOnlyWhileAManualSweepRuns(t *testing.T) {
	drainManualSweep(t)
	t.Cleanup(func() { drainManualSweep(t) })
	seedManualScope(t)

	scanner.SweepState.Mu.Lock()
	scanner.SweepState.Manual = scanner.SweepStatus{Running: true, Kind: "full"}
	scanner.SweepState.Mu.Unlock()
	t.Cleanup(func() {
		scanner.SweepState.Mu.Lock()
		scanner.SweepState.Scheduled, scanner.SweepState.Manual = scanner.SweepStatus{}, scanner.SweepStatus{}
		scanner.SweepState.Mu.Unlock()
	})
	if recorder := postScan(t, manualScanBody, "application/json"); recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d during a manual sweep, want 409", recorder.Code)
	}

	scanner.SweepState.Mu.Lock()
	scanner.SweepState.Manual.Running = false
	scanner.SweepState.Scheduled.Running = true
	scanner.SweepState.Mu.Unlock()
	if recorder := postScan(t, manualScanBody, "application/json"); recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d during a scheduled sweep, want 202: %s", recorder.Code, recorder.Body)
	}
}

func TestScanEndpointRejectsWhatItCannotAct(t *testing.T) {
	drainManualSweep(t)
	t.Cleanup(func() { drainManualSweep(t) })

	for _, tc := range []struct {
		name, body, contentType string
		want                    int
	}{
		// A cross-origin form post cannot set this header, so requiring it makes the browser
		// preflight the request and refuse it.
		{"form post", `{"kind":"common"}`, "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"unknown kind", `{"kind":"quick"}`, "application/json", http.StatusBadRequest},
		{"no kind", `{}`, "application/json", http.StatusBadRequest},
		{"not json", `kind=common`, "application/json", http.StatusBadRequest},
		{"second JSON value", `{"kind":"common"}{}`, "application/json", http.StatusBadRequest},
		{"no targets", `{"kind":"common"}`, "application/json", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if recorder := postScan(t, tc.body, tc.contentType); recorder.Code != tc.want {
				t.Errorf("status = %d, want %d", recorder.Code, tc.want)
			}
			if len(scanner.ManualSweep) != 0 {
				t.Error("a refused request still reached the sweep loop")
			}
		})
	}
}

// The settings page reads the whole config, on a server with no authentication. The auth key must
// never be in that response — not redacted, not present. This is the fence; keep it strict.
func TestSettingsEndpointNeverCarriesTheAuthKey(t *testing.T) {
	const secret = "unmistakable-threatfox-key"
	cfg := targetcfg.Config{
		Base:  targetcfg.BaseConfig{RefreshSeconds: 60, RetainDays: 30},
		Feeds: targetcfg.FeedsConfig{ThreatFoxAuthKey: secret},
		Scan: targetcfg.ScanConfig{
			Allow: []string{"192.0.2.0/24"}, Deny: []string{"192.0.2.192/26"},
			TargetsFile: "targets.json", CommonPorts: []int{22, 443},
			ScansPerDay: 2, MaxWorkers: 8, DialTimeoutMS: 250, TLSTimeoutMS: 2000,
			JARMTimeoutMS: 500,
		},
	}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.0/25"))
	if err != nil {
		t.Fatal(err)
	}
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	targetcfg.Current.Set(cfg, scope)

	body := func() map[string]any {
		t.Helper()
		recorder := httptest.NewRecorder()
		handleSettings(recorder, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", recorder.Code)
		}
		// The raw bytes, not the decoded shape: a key leaking under a field name nobody thought
		// to decode still leaks.
		if raw := recorder.Body.String(); strings.Contains(raw, secret) {
			t.Fatalf("the response carries the auth key: %s", raw)
		}
		var decoded map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}

	current := body()
	// Whether one is set changes what the scanner does, so that much is reported.
	if current["threatfox_auth_key_set"] != true {
		t.Fatalf("threatfox_auth_key_set = %v, want true", current["threatfox_auth_key_set"])
	}
	settings, _ := getSettings(t)
	if !slices.Equal(settings.Scan.Allow, []string{"192.0.2.0/24"}) {
		t.Fatalf("allow = %v, want the configured entry verbatim", settings.Scan.Allow)
	}
	if settings.Scan.JARMTimeoutMS != 500 {
		t.Fatalf("jarm_timeout_ms = %d, want 500", settings.Scan.JARMTimeoutMS)
	}

	// An empty key has to read as not set, or a silently skipped ThreatFox feed has no explanation.
	cfg.Feeds.ThreatFoxAuthKey = ""
	targetcfg.Current.Set(cfg, scope)
	if got := body()["threatfox_auth_key_set"]; got != false {
		t.Fatalf("empty threatfox_auth_key_set = %v, want false", got)
	}
}

// A pending manual request used to stop the pass in flight. It must not any more: the two run
// alongside each other, which is the only reason a manual scan is worth pressing during a sweep.
func TestAPendingManualRequestDoesNotStopTheSweep(t *testing.T) {
	drainManualSweep(t)
	t.Cleanup(func() { drainManualSweep(t) })
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	target, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	targetcfg.Current.Cfg.Scan = targetcfg.ScanConfig{MaxWorkers: 2, DialTimeoutMS: 2000, TLSTimeoutMS: 2000, JARMTimeoutMS: 500}

	// Left on the channel for manualLoop to take. The sweep must ignore it entirely.
	scanner.ManualSweep <- scanner.ManualRequest{Common: true}
	addrs := make([]netip.Addr, 8)
	for i := range addrs {
		addrs[i] = target.Addr()
	}
	open := scanner.ProbePorts(ctx, addrs, []int{int(target.Port())}, false, nil).Open.Load()
	if open != int64(len(addrs)) {
		t.Errorf("probed %d of %d addresses with a request waiting, want all of them", open, len(addrs))
	}
}

// Both passes run at once, so one finishing must not report the other as idle.
func TestAFinishingManualPassLeavesTheScheduledOneRunning(t *testing.T) {
	drainManualSweep(t)
	t.Cleanup(func() { drainManualSweep(t) })
	scanner.SweepState.Mu.Lock()
	scanner.SweepState.Scheduled.Running, scanner.SweepState.Manual.Running = true, true
	scanner.SweepState.Mu.Unlock()
	t.Cleanup(func() {
		scanner.SweepState.Mu.Lock()
		scanner.SweepState.Scheduled, scanner.SweepState.Manual = scanner.SweepStatus{}, scanner.SweepStatus{}
		scanner.SweepState.Mu.Unlock()
	})

	// What sweepOnce's deferred cleanup does at the end of a manual pass.
	scanner.SweepState.Mu.Lock()
	scanner.SweepState.Manual.Running, scanner.SweepState.Requested = false, false
	scanner.SweepState.Mu.Unlock()

	status := scanner.CurrentStatus()
	if !status.Scheduled.Running {
		t.Error("scheduled running = false while its sweep is still going")
	}
	if status.Manual.Running {
		t.Error("manual running = true after its pass ended")
	}
}

// The page reads a history, not a single pass, so common scans must stay out and exact full-scan
// timings must combine without losing their spread.
func TestLatencySamplesRoundTripQuartiles(t *testing.T) {
	var stored scanner.LatencySamples
	for _, duration := range []time.Duration{time.Millisecond, time.Millisecond, 3 * time.Millisecond, 9 * time.Millisecond} {
		stored.Add(duration)
	}
	var decoded []int64
	addSamples(&decoded, stored.String())
	var view latencyView
	latencyQuantiles(&view, decoded)
	if want := (latencyView{Successes: 4, MedianUS: 2_000, P90US: 9_000,
		AverageUS: 3_500, MinUS: 1_000, MaxUS: 9_000, Q1US: 1_000, Q3US: 3_000}); view != want {
		t.Fatalf("latency view = %+v, want %+v", view, want)
	}
}

// The coverage table answers two questions at once: it keeps the strongest unconfigured
// replacements and every configured port, including when nothing answered.
func TestCoveragePortsKeepsEveryConfiguredPort(t *testing.T) {
	counts := map[int]portCount{}
	for port := 1; port <= 12; port++ {
		counts[port] = portCount{Port: port, Hosts: 100 - port}
	}
	counts[9000] = portCount{Port: 9000, Hosts: 1, High: 1}
	counts[9100] = portCount{Port: 9100, Hosts: 1, High: 5}
	counts[9200] = portCount{Port: 9200, Hosts: 1, High: 4, Low: 100}
	rows := coveragePorts(counts, []int{9000, 65000})
	var ports []int
	for _, row := range rows {
		ports = append(ports, row.Port)
	}
	// 9100 stays ahead of 9200 because HIGH findings take priority over any number of LOW findings.
	// Ports 1-10 fill the other contender slots, and both configured ports stay.
	want := []int{9100, 9200, 9000, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 65000}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("coverage ports = %v, want %v", ports, want)
	}
	if last := rows[len(rows)-1]; last.Hosts != 0 || !last.Configured {
		t.Errorf("unanswered configured port = %+v, want an empty configured row", last)
	}
}

func TestAnalyticsAggregatesPassesWithinThePeriod(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	targetcfg.Current.Cfg.Scan = targetcfg.ScanConfig{MaxWorkers: 100, DialTimeoutMS: 500, TLSTimeoutMS: 1000,
		JARMTimeoutMS: 200, CommonPorts: []int{443}}
	now := time.Now()
	previousFeeds := feeds.Current
	t.Cleanup(func() { feeds.Current = previousFeeds })
	feeds.Current = &feeds.Cache{LastGood: map[string][]feeds.Indicator{
		"feodo":                  {{Source: "feodo", Value: "192.0.2.9:443"}},
		"threatfox":              {{Source: "threatfox", Value: "192.0.2.1"}},
		feeds.PhishingArmySource: {{Source: feeds.PhishingArmySource, Value: "example.co.uk"}},
	}, Index: map[string][]feeds.Indicator{
		"high-fp": {{Source: "threatfox", Value: "high-fp", Tag: "C2 certificate"}},
	}}
	storage.JARMBlacklist.Replace([]storage.JARMBlacklistEntry{{Hash: "jarm-hit", Label: "Beacon"}})
	t.Cleanup(func() { storage.JARMBlacklist.Replace(nil) })
	if err := storage.SaveScans(ctx, []storage.Scan{
		{IP: "192.0.2.1", Port: 443, ScannedAt: now.Unix(), FullScannedAt: now.Unix(),
			Fingerprint: "low-fp", SelfSigned: true},
		{IP: "192.0.2.2", Port: 8443, ScannedAt: now.Unix(), FullScannedAt: now.Unix(),
			Fingerprint: "high-fp", JARM: "jarm-hit"},
		// A common-only result must not enter any analytics port ranking.
		{IP: "192.0.2.3", Port: 9443, ScannedAt: now.Unix(), Manual: true,
			Fingerprint: "common-only", SelfSigned: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveMatches(ctx, []storage.Match{
		{IP: "192.0.2.1", Source: "threatfox", Value: "192.0.2.1", SeenAt: now.Unix()},
		// Direct feed hits need no open-port row; a full sweep stores only ports that answered.
		{IP: "192.0.2.9", Source: "feodo", Value: "192.0.2.9:443", SeenAt: now.Unix()},
	}); err != nil {
		t.Fatal(err)
	}
	data, err := storage.LoadHostData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, match := range data.Matches {
		if match.Source == "feodo" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("stored Feodo matches = %d, want the one direct hit", count)
	}
	views, _, err := scanner.Findings(ctx, scanner.ActiveOpen)
	if err != nil || !slices.ContainsFunc(views, func(host scanner.HostView) bool {
		return slices.ContainsFunc(host.Ports, func(port scanner.PortView) bool {
			return slices.ContainsFunc(port.Signals, func(signal feeds.Indicator) bool { return signal.Source == storage.JARMBlacklistSource })
		})
	}) {
		t.Fatalf("live host view does not contain the JARM-list hit: %v", err)
	}

	rows := []storage.ScanPass{
		{StartedAt: now.Add(-2 * time.Hour).Unix(), Source: "scheduled", ElapsedMS: 10_000,
			Targets: 4, Ports: 65535, MaxWorkers: 100, DialTimeoutMS: 500, TLSTimeoutMS: 1000,
			JARMTimeoutMS: 200, Closed: 300, Filtered: 100, Open: 10, Untested: 1,
			ClosedSlotMS: 3_000, FilteredSlotMS: 50_000, OpenSlotMS: 40_000,
			TimingVersion: 3, TLSSamplesUS: "10000,30000,50000,70000", TLSFailures: 4, TLSTimeouts: 2,
			JARMSamplesUS: "1000,2000,3000", JARMFailures: 1, JARMTimeouts: 4,
			DialSamplesUS: "1000,4000,7000", CompleteSamplesUS: "20000,40000,90000"},
		{StartedAt: now.Add(-time.Hour).Unix(), Source: "manual", ElapsedMS: 1_000,
			Targets: 1, Ports: 1, MaxWorkers: 100, DialTimeoutMS: 500, TLSTimeoutMS: 1000,
			JARMTimeoutMS: 200, Closed: 100, Filtered: 0, Open: 10, Untested: 0,
			ClosedSlotMS: 1_000, FilteredSlotMS: 0, OpenSlotMS: 10_000,
			TimingVersion: 3, TLSSamplesUS: "900000", TLSFailures: 100, TLSTimeouts: 100,
			JARMSamplesUS: "900000", JARMFailures: 100, JARMTimeouts: 100,
			DialSamplesUS: "900000", CompleteSamplesUS: "900000"},
		// Outside every period the page offers but "all".
		{StartedAt: now.AddDate(0, 0, -120).Unix(), Source: "scheduled", ElapsedMS: 999_999,
			Targets: 900, Ports: 65535, MaxWorkers: 100, DialTimeoutMS: 500, TLSTimeoutMS: 1000,
			JARMTimeoutMS: 200, Closed: 9_000, Open: 1, ClosedSlotMS: 9_000, OpenSlotMS: 1,
			TimingVersion: 3, TLSSamplesUS: "1000", JARMSamplesUS: "1000",
			DialSamplesUS: "1000", CompleteSamplesUS: "1000"},
	}
	for _, row := range rows {
		if err := storage.SaveScanPass(ctx, row); err != nil {
			t.Fatal(err)
		}
	}

	body := getAnalytics(t, "period=30d")
	if body.Comparison == nil {
		t.Fatal("comparison = nil, want the latest two full scans")
	}
	if body.Comparison.Latest.StartedAt != rows[0].StartedAt ||
		body.Comparison.Previous.StartedAt != rows[2].StartedAt {
		t.Errorf("comparison scans = %d / %d, want latest in-period full pass and previous full pass even outside the period",
			body.Comparison.Latest.StartedAt, body.Comparison.Previous.StartedAt)
	}
	if latest := body.Comparison.Latest; latest.Dial.BudgetMS != 500 || latest.Dial.Successes != 3 ||
		latest.Dial.Failures != 300 || latest.Dial.Timeouts != 100 || latest.Dial.BudgetChanged {
		t.Errorf("latest comparison dial = %+v, want that pass's own samples, outcomes and budget", latest.Dial)
	}
	if previous := body.Comparison.Previous; previous.Targets != 900 || previous.Dial.Failures != 9_000 ||
		previous.Dial.Successes != 1 {
		t.Errorf("previous comparison = %+v, want the earlier full pass rather than the newer common pass", previous)
	}
	if body.Cost.Passes != 1 {
		t.Fatalf("passes = %d, want only the full pass inside the period", body.Cost.Passes)
	}
	if want := (costView{Passes: 1, Targets: 4}); body.Cost != want {
		t.Errorf("cost = %+v, want %+v", body.Cost, want)
	}
	// The dial's own outcome counts come from the pass, its timings from that pass's samples.
	if want := (latencyView{Successes: 3, Failures: 300, Timeouts: 100, MedianUS: 4_000, P90US: 7_000,
		AverageUS: 4_000, MinUS: 1_000, MaxUS: 7_000, Q1US: 1_000, Q3US: 7_000, BudgetMS: 500}); body.Dial != want {
		t.Errorf("dial timing = %+v, want %+v", body.Dial, want)
	}
	// Only ports that finished the dial, the handshake and the fingerprint.
	if body.Complete.Successes != 3 || body.Complete.MedianUS != 40_000 ||
		body.Complete.Q1US != 20_000 || body.Complete.Q3US != 90_000 {
		t.Errorf("complete timing = %+v, want the end-to-end samples of the in-period pass", body.Complete)
	}
	if body.TLS.Successes != 4 || body.TLS.MedianUS != 40_000 || body.TLS.P90US != 70_000 ||
		body.TLS.Failures != 4 || body.TLS.Timeouts != 2 {
		t.Errorf("TLS timing = %+v, want exact full-scan outcomes", body.TLS)
	}
	if body.JARM.Successes != 3 || body.JARM.MedianUS != 2_000 || body.JARM.P90US != 3_000 ||
		body.JARM.Failures != 1 || body.JARM.Timeouts != 4 {
		t.Errorf("JARM timing = %+v, want exact full-scan outcomes", body.JARM)
	}
	if body.TLS.BudgetMS != 1000 || body.JARM.BudgetMS != 200 || body.TLS.BudgetChanged {
		t.Errorf("budgets = %+v / %+v, want the live config and no change", body.TLS, body.JARM)
	}
	if body.GeneratedAt == 0 {
		t.Error("generated_at was not set")
	}
	if len(body.Profile.TLSHigh) != 1 || body.Profile.TLSHigh[0].Port != 8443 ||
		len(body.Profile.TLSLow) != 1 || body.Profile.TLSLow[0].Port != 443 ||
		len(body.Profile.TLSFlagged) != 2 {
		t.Errorf("TLS port rankings = %+v, want only full-scanned TLS endpoints", body.Profile)
	}
	// One LOW on 443 and one HIGH on 8443, and common_ports sweeps only 443: the configured scan
	// would have caught half the rated endpoints.
	if want := (coverageView{Flagged: 2, FlaggedCovered: 1,
		Ports: []portCount{{Port: 8443, Hosts: 1, High: 1}, {Port: 443, Hosts: 1, Low: 1, Configured: true}}}); !reflect.DeepEqual(body.Coverage, want) {
		t.Errorf("common-port coverage = %+v, want %+v", body.Coverage, want)
	}
	feedRows := make(map[string]feedYield, len(body.Feeds))
	for _, feed := range body.Feeds {
		feedRows[feed.Source] = feed
	}
	if feedRows["threatfox"].Local || feedRows["threatfox"].Hosts != 1 {
		t.Errorf("threatfox = %+v, want one upstream hit", feedRows["threatfox"])
	}
	if feed := feedRows["feodo"]; feed.Hosts != 1 || feed.Indicators != 1 || feed.Local {
		t.Errorf("feodo = %+v, want its direct IP hit even without an open port", feed)
	}
	if feed := feedRows[feeds.PhishingArmySource]; feed.Hosts != 0 || feed.Indicators != 1 || feed.Local {
		t.Errorf("phishing army = %+v, want its zero-match upstream feed", feed)
	}
	if feed := feedRows[storage.JARMBlacklistSource]; !feed.Local || feed.Hosts != 1 {
		t.Errorf("jarm blacklist = %+v, want the live list match derived from the stored JARM", feed)
	}

	// The out-of-period pass is nine thousand refused dials, so admitting it would swamp the dial
	// outcomes and no assertion above would still hold.
	if all := getAnalytics(t, "period=all"); all.Cost.Passes != 2 || all.Dial.Failures != 9_300 ||
		slices.ContainsFunc(all.Profile.TLSFlagged, func(row portCount) bool { return row.Port == 9443 }) {
		t.Errorf("period=all = %d passes over %d refused dials, want both full passes", all.Cost.Passes,
			all.Dial.Failures)
	}
	if latest := getAnalytics(t, "period=latest"); latest.Period != "latest" || latest.Cost != (costView{Passes: 1, Targets: 4}) ||
		latest.Dial.Failures != 300 {
		t.Errorf("period=latest = %+v with %+v dial, want the most recent completed full pass", latest.Cost, latest.Dial)
	}
	// Junk is the default window, not an error.
	if fallback := getAnalytics(t, "period=nonsense"); fallback.Period != "30d" || fallback.Cost.Passes != 1 {
		t.Errorf("period=nonsense = %q with %d passes, want the 30d default", fallback.Period,
			fallback.Cost.Passes)
	}
	// The retired parameter is deliberately ignored rather than translated.
	if legacy := getAnalytics(t, "span=all"); legacy.Period != "30d" || legacy.Cost.Passes != 1 {
		t.Errorf("legacy span = %q with %d passes, want the 30d default", legacy.Period, legacy.Cost.Passes)
	}
}

// ProbePorts returns its partial tallies with no error when the context is cancelled. Stored, an
// interrupted sweep would read as a finished one at a fraction of the elapsed time.
func TestACancelledPassIsNotRecorded(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	scanner.SavePass(cancelled, &scanner.PassMetrics{StartedAt: time.Now().Unix(), ElapsedMS: 5}, "scheduled")
	scanner.SavePass(ctx, nil, "scheduled")

	passes, err := storage.LoadFullScanPasses(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(passes) != 0 {
		t.Errorf("stored %d passes, want none: an interrupted sweep is not a completed one", len(passes))
	}

	scanner.SavePass(ctx, &scanner.PassMetrics{StartedAt: time.Now().Unix(), ElapsedMS: 5, Ports: 65535}, "scheduled")
	if passes, err = storage.LoadFullScanPasses(ctx, 0); err != nil || len(passes) != 1 {
		t.Errorf("stored %d passes (%v), want the completed one", len(passes), err)
	}
	if comparison := getAnalytics(t, "period=all").Comparison; comparison != nil {
		t.Errorf("comparison = %+v, want none until two full scans exist", comparison)
	}
}

func getAnalytics(t *testing.T, query string) analyticsResponse {
	t.Helper()
	recorder := httptest.NewRecorder()
	handleAnalytics(recorder, httptest.NewRequest(http.MethodGet, "/api/analytics?"+query, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	var body analyticsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestNameNormalizationOrdersWhitespaceBeforeWildcard(t *testing.T) {
	if got := parse.NormalizeName(" *.Example.com. "); got != "example.com" {
		t.Fatalf("normalized name = %q, want example.com", got)
	}
	if got, ok := parse.CertName(" *.Example.com. "); !ok || got != "*.example.com" {
		t.Fatalf("certificate name = %q, %t; want displayed wildcard", got, ok)
	}
	if got, ok := parse.RegistrableDomain(" *.Example.com. "); !ok || got != "example.com" {
		t.Fatalf("registrable domain = %q, %t; want example.com", got, ok)
	}
}

func TestCanonicalAddrKeepsRequestIPv6Support(t *testing.T) {
	if got, ok := parse.CanonicalAddr(" 2001:0db8::1 "); !ok || got != "2001:db8::1" {
		t.Fatalf("canonical address = %q, %t; want trimmed IPv6 preserved", got, ok)
	}
}

// The domains table merges the common name with the SANs and drops anything that is not shaped
// like a domain: a self-signed certificate routinely names an IP, a bare label, or the machine.
func TestDomainsMergesCertNamesAndDropsNonDomains(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()

	// What counts as a domain. The last label being letters is what rejects an address without
	// parsing one, and only a leading label may be a wildcard.
	for name, want := range map[string]bool{
		"c2.example.com": true, "*.example.com": true, "under_score.com": true,
		"xn--p1ai.com": true, "www.xn--d1aqfkf.xn--p1ai": true, "example.com.": true, "a.co": true,
		"198.51.100.7": false, "localhost": false, "WIN-DESKTOP": false, "Acme Root CA": false,
		"a.c": false, "a..com": false, "foo*bar.com": false, "**.com": false,
	} {
		if _, got := parse.CertName(name); got != want {
			t.Errorf("certName(%q) = %v, want %v", name, got, want)
		}
	}

	rows := []storage.Scan{
		// The common name leads, a SAN repeating it is dropped, and a wildcard survives.
		{IP: "192.0.2.10", Port: 443, ScannedAt: 1, Subject: "C2.Example.com",
			DNSNames: "c2.example.com,*.example.com,cdn.example.com"},
		// No common name, but the SANs still name the host.
		{IP: "192.0.2.9", Port: 8443, ScannedAt: 2, Subject: "", DNSNames: "panel.badhost.net"},
		// Nothing here is a domain, so the endpoint never reaches the table.
		{IP: "192.0.2.9", Port: 4444, ScannedAt: 1, Subject: "192.0.2.9", DNSNames: "localhost,WIN-DESKTOP"},
		// A subject with a space is not a name, but the SAN beside it is.
		{IP: "198.51.100.1", Port: 993, ScannedAt: 3, Subject: "Acme Root CA", DNSNames: "zulu.acme.test"},
		// No certificate text at all: excluded by the query itself.
		{IP: "198.51.100.2", Port: 22, ScannedAt: 1},
	}
	if err := storage.SaveScans(ctx, rows); err != nil {
		t.Fatal(err)
	}

	get := func(query string) []domainRow {
		t.Helper()
		recorder := httptest.NewRecorder()
		handleDomains(recorder, httptest.NewRequest(http.MethodGet, "/api/domains?"+query, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", recorder.Code, recorder.Body)
		}
		var got []domainRow
		if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	// The default listing is newest first, like the host table.
	got := get("")
	want := []domainRow{
		{IP: "198.51.100.1", Port: 993, ScannedAt: 3, Names: []string{"zulu.acme.test"}},
		{IP: "192.0.2.9", Port: 8443, ScannedAt: 2, Names: []string{"panel.badhost.net"}},
		{IP: "192.0.2.10", Port: 443, ScannedAt: 1, Names: []string{"c2.example.com", "*.example.com", "cdn.example.com"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("domains = %+v, want %+v", got, want)
	}

	for _, tc := range []struct {
		query string
		want  []string
	}{
		// Address order parses rather than compares, so .9 comes before .10.
		{"sort=ip", []string{"192.0.2.9", "192.0.2.10", "198.51.100.1"}},
		{"sort=-ip", []string{"198.51.100.1", "192.0.2.10", "192.0.2.9"}},
		{"sort=port", []string{"192.0.2.10", "198.51.100.1", "192.0.2.9"}},
		{"sort=-port", []string{"192.0.2.9", "198.51.100.1", "192.0.2.10"}},
		{"sort=name", []string{"192.0.2.10", "192.0.2.9", "198.51.100.1"}},
		{"sort=-name", []string{"198.51.100.1", "192.0.2.9", "192.0.2.10"}},
		{"sort=recent", []string{"192.0.2.10", "192.0.2.9", "198.51.100.1"}},
		{"sort=-recent", []string{"198.51.100.1", "192.0.2.9", "192.0.2.10"}},
		{"sort=-nonsense", []string{"198.51.100.1", "192.0.2.9", "192.0.2.10"}},
		// The bounds are half-open, so from includes its instant and before stops short of one.
		{"from=2", []string{"198.51.100.1", "192.0.2.9"}},
		{"before=3", []string{"192.0.2.9", "192.0.2.10"}},
		{"from=2&before=3", []string{"192.0.2.9"}},
		{"from=4", nil},
		// A bound that is not a number is no bound: a hand-edited URL widens rather than empties.
		{"from=yesterday", []string{"198.51.100.1", "192.0.2.9", "192.0.2.10"}},
		{"from=2&q=panel", []string{"192.0.2.9"}},
		{"q=example", []string{"192.0.2.10"}},
		{"q=198.51.100", []string{"198.51.100.1"}},
		{"q=8443", []string{"192.0.2.9"}},
		{"q=localhost", nil},
	} {
		addresses := []string(nil)
		for _, row := range get(tc.query) {
			addresses = append(addresses, row.IP)
		}
		if !slices.Equal(addresses, tc.want) {
			t.Errorf("domains for %q = %v, want %v", tc.query, addresses, tc.want)
		}
	}
}

// The wrapper is tested against a stub rather than the real mux: what it does to a response is the
// same whatever produced it, and a stub keeps the case away from database fixtures.
func gzipProbe(t *testing.T, target, accept string) *httptest.ResponseRecorder {
	t.Helper()
	handler := compressAPI(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"hello": strings.Repeat("world", 200)})
	}))
	request := httptest.NewRequest(http.MethodGet, target, nil)
	if accept != "" {
		request.Header.Set("Accept-Encoding", accept)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestAPIResponsesCompressForClientsThatAskAndNobodyElse(t *testing.T) {
	want := strings.Repeat("world", 200)

	compressed := gzipProbe(t, "/api/hosts?size=50", "gzip, deflate")
	if got := compressed.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	// Without this a shared cache could hand the compressed body to a client that never asked.
	if got := compressed.Header().Get("Vary"); got != "Accept-Encoding" {
		t.Errorf("Vary = %q, want Accept-Encoding", got)
	}
	if compressed.Body.Len() >= len(want) {
		t.Errorf("compressed body is %d bytes, no smaller than the %d it encodes", compressed.Body.Len(), len(want))
	}
	reader, err := gzip.NewReader(compressed.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	if err := json.NewDecoder(reader).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["hello"] != want {
		t.Errorf("decoded %d bytes, want the %d written", len(body["hello"]), len(want))
	}

	// A client that did not offer gzip gets exactly what it always got.
	plain := gzipProbe(t, "/api/hosts?size=50", "")
	if got := plain.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q for a client that did not ask", got)
	}
	var direct map[string]string
	if err := json.Unmarshal(plain.Body.Bytes(), &direct); err != nil {
		t.Fatal(err)
	}
	if direct["hello"] != want {
		t.Error("uncompressed body did not survive the wrapper")
	}

	// The assets are served by a file server that answers Range requests, so they stay untouched.
	asset := gzipProbe(t, "/assets/index-abc123.js", "gzip")
	if got := asset.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q outside /api/", got)
	}
}

// One row longer than bufio.Scanner's default buffer must cost that row, not the whole feed.
func TestCSVFeedSurvivesAnOverlongLine(t *testing.T) {
	long := strings.Repeat("x", 70<<10)
	body := long + "\nbad.example.net,cobaltstrike,beacon,192.0.2.21\n"
	indicators, err := feeds.DecodeC2Intel(strings.NewReader(body))
	var partial *feeds.FeedValidation
	if err != nil && !errors.As(err, &partial) {
		t.Fatalf("overlong line failed the whole feed: %v", err)
	}
	if partial != nil && partial.Skipped != 1 {
		t.Errorf("skipped = %d, want the one overlong row", partial.Skipped)
	}
	if !slices.ContainsFunc(indicators, func(i feeds.Indicator) bool { return i.Value == "192.0.2.21" }) {
		t.Fatalf("record after the overlong line was lost: %v", indicators)
	}
}

// ThreatView keys some rows by domain rather than address. The index cannot use them, but they are
// records the feed publishes, so they must not read as damage. A row whose quoting is actually
// broken still counts as skipped: that one is the feed being wrong, and worth hearing about.
func TestThreatViewC2DomainRowsAreNotCountedAsSkipped(t *testing.T) {
	body := "#IP,Date of Detection,Host,Protocol,Beacon Config,Comment\n" +
		`good.example.net,20 August 2026 03:26 PM UTC,good.example.net,https,"good.example.net,/a",c` + "\n" +
		`192.0.2.31,20 August 2026 03:27 PM UTC,192.0.2.31,https,"192.0.2.31,/b",c` + "\n"
	indicators, err := feeds.DecodeThreatViewC2(strings.NewReader(body))
	if err != nil {
		t.Fatalf("well-formed domain-keyed row reported as an invalid record: %v", err)
	}
	if !slices.ContainsFunc(indicators, func(i feeds.Indicator) bool { return i.Value == "192.0.2.31" }) {
		t.Fatalf("address row lost: %v", indicators)
	}
	// The shipped fixture carries a row with doubled quotes. It stays a rejection, and the rows
	// on either side of it still decode.
	indicators, err = feeds.DecodeThreatViewC2(strings.NewReader(threatViewC2Body))
	var partial *feeds.FeedValidation
	if !errors.As(err, &partial) || partial.Skipped != 1 {
		t.Fatalf("broken-quote row = %v, want exactly one skipped record", err)
	}
	for _, want := range []string{"192.0.2.13", "192.0.2.14"} {
		if !slices.ContainsFunc(indicators, func(i feeds.Indicator) bool { return i.Value == want }) {
			t.Errorf("%s missing from %v", want, indicators)
		}
	}
}

// The stored rows are held between reads and dropped by the writes that change them. writeLoop
// ticks whether or not it holds anything, so an empty save must leave them alone — dropping them
// on a no-op write would keep the cache permanently cold.
func TestHostStateHeldUntilAWriteChangesIt(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	held := func() bool {
		storage.HostState.Mu.Lock()
		defer storage.HostState.Mu.Unlock()
		return storage.HostState.Loaded
	}

	if _, err := storage.CurrentHostState(ctx); err != nil {
		t.Fatal(err)
	}
	if !held() {
		t.Fatal("the first read did not hold the rows")
	}
	if err := storage.SaveScans(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !held() {
		t.Fatal("an empty save dropped the held rows")
	}
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.1", Port: 443, ScannedAt: 1}}); err != nil {
		t.Fatal(err)
	}
	if held() {
		t.Fatal("a write left stale rows held")
	}
	data, err := storage.CurrentHostState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Scans) != 1 {
		t.Fatalf("rows after the write = %d scans, want 1", len(data.Scans))
	}
}

// A one-shot -scan answers for the address it was given. The stored rows are the whole database,
// so without the scope filter a report meant for one address carries every host an earlier sweep
// found.
func TestCommandLineScanReportsOnlyItsTarget(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		scanner.CLIScan = ""
	})

	cfg := feedOnlyConfig(t)
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)

	// 192.0.2.9 is what an earlier sweep left behind: in the database, outside this scan's scope.
	if err := storage.SaveScans(ctx, []storage.Scan{
		{IP: "192.0.2.1", Port: 443, ScannedAt: 100, IsOpen: true},
		{IP: "192.0.2.9", Port: 443, ScannedAt: 100, IsOpen: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveMatches(ctx, []storage.Match{
		{IP: "192.0.2.1", Source: "threatfox", Value: "192.0.2.1:443", Tag: "cobalt", SeenAt: 200},
		{IP: "192.0.2.9", Source: "threatfox", Value: "192.0.2.9:443", Tag: "cobalt", SeenAt: 200},
	}); err != nil {
		t.Fatal(err)
	}

	report, summary, err := scanner.BuildReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(report) != 2 || summary.High != 2 {
		t.Fatalf("sweep report = %+v, summary = %+v, want both stored hosts", report, summary)
	}

	scanner.CLIScan = "192.0.2.1"
	report, summary, err = scanner.BuildReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(report) != 1 || report[0].IP != "192.0.2.1" || summary.High != 1 {
		t.Fatalf("-scan report = %+v, summary = %+v, want the scanned address alone", report, summary)
	}
}

// -scan -feed-only puts the argument on the side the sweep never probes: it is matched against the
// Cache and never dialled. The feed-only side is the flag's own list here, not a configured file,
// and the report still carries the hit.
func TestFeedOnlyScanMatchesWithoutProbing(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		scanner.CLIScan = ""
	})

	// The targets file does not exist: a feed-only scan must not read it any more than -scan does.
	config := writeConfig(t, filepath.Join(t.TempDir(), "no-such-targets.json"))
	if err := targetcfg.LoadTargets(config, "192.0.2.5", true); err != nil {
		t.Fatalf("in-scope -feed-only scan rejected: %v", err)
	}
	cfg, s := targetcfg.Current.Config()
	if cfg.Scan.FeedOnlyTargetsFile != "" {
		t.Fatal("fixture configures a feed-only file; the flag's own list is what is under test")
	}
	if s.Scannable != 0 || s.FeedOnlyScannable != 1 || !s.ContainsFeedOnly(parse.AddrOrZero("192.0.2.5")) {
		t.Fatalf("scope = %d scannable, %d feed-only, want the target matched but never probed",
			s.Scannable, s.FeedOnlyScannable)
	}
	if err := targetcfg.LoadTargets(config, "8.8.8.8", true); err == nil {
		t.Fatal("out-of-scope -feed-only scan accepted, want the allowlist to reject it")
	}

	scanner.CLIScan = "192.0.2.5"
	// 192.0.2.9 is what an earlier sweep left behind: probed, flagged, and none of this scan's business.
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.9", Port: 443, ScannedAt: 100, IsOpen: true}}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveMatches(ctx, []storage.Match{
		{IP: "192.0.2.5", Source: "threatfox", Value: "192.0.2.5:8443", Tag: "cobalt", SeenAt: 200},
		{IP: "192.0.2.9", Source: "threatfox", Value: "192.0.2.9:443", Tag: "cobalt", SeenAt: 200},
	}); err != nil {
		t.Fatal(err)
	}
	report, summary, err := scanner.BuildReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(report) != 1 || report[0].IP != "192.0.2.5" || report[0].Band != "high" ||
		len(report[0].OpenTLSPorts) != 0 || summary.High != 1 {
		t.Fatalf("report = %+v, summary = %+v, want the feed-only target's hit alone", report, summary)
	}
}
