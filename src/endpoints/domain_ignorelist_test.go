package endpoints

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	storage "iocscanner/src/db"
	"iocscanner/src/feeds"
	scanner "iocscanner/src/scan"
	targetcfg "iocscanner/src/targets"
)

func TestDomainIgnorelistConfigIsOptionalAndCanonical(t *testing.T) {
	cfg, err := targetcfg.LoadConfig(writeConfig(t, "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Feeds.DomainIgnorelist) != 0 {
		t.Fatalf("omitted domain ignorelist = %v, want empty", cfg.Feeds.DomainIgnorelist)
	}

	line := `threatfox_auth_key = "sekrit"`
	path := writeConfig(t, "targets.json", [2]string{line, line + `
domain_ignorelist = [" *.GitHub.COM. ", "microsoft.com", "example.notarealtld"]`})
	cfg, err = targetcfg.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Feeds.DomainIgnorelist, []string{"github.com", "microsoft.com", "example.notarealtld"}) {
		t.Fatalf("domain ignorelist = %v, want canonical domains", cfg.Feeds.DomainIgnorelist)
	}

	for _, values := range []string{
		`["api.github.com"]`,
		`["github.com", "*.GITHUB.COM."]`,
		`["co.uk"]`,
		`["api.example.notarealtld"]`,
		`["-github.com"]`,
	} {
		path = writeConfig(t, "targets.json", [2]string{line, line + "\ndomain_ignorelist = " + values})
		if _, err := targetcfg.LoadConfig(path); err == nil {
			t.Errorf("accepted domain_ignorelist = %s", values)
		}
	}
}

func TestTraefikDefaultCertCanBeIgnored(t *testing.T) {
	line := `threatfox_auth_key = "sekrit"`
	path := writeConfig(t, "targets.json", [2]string{line, line + `
domain_ignorelist = ["*.TRAEFIK.DEFAULT."]`})
	cfg, err := targetcfg.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Feeds.DomainIgnorelist, []string{"traefik.default"}) {
		t.Fatalf("domain ignorelist = %v, want traefik.default", cfg.Feeds.DomainIgnorelist)
	}

	previousConfig, previousScope := targetcfg.Current.Config()
	previousFeeds := feeds.Current
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		feeds.Current = previousFeeds
	})
	targetcfg.Current.Set(cfg, previousScope)
	indicator := feeds.Indicator{Source: feeds.ThreatViewSource, Value: "traefik.default", Tag: "domain"}
	feeds.Current = &feeds.Cache{Tried: []string{feeds.ThreatViewSource}, LastGood: map[string][]feeds.Indicator{
		feeds.ThreatViewSource: {indicator},
	}}
	feeds.Current.RebuildIndex()

	now := time.Now()
	row := storage.Scan{IP: "192.0.2.9", Port: 443, IsOpen: true, ScannedAt: now.Unix(),
		Subject: "TRAEFIK DEFAULT CERT", Issuer: "TRAEFIK DEFAULT CERT",
		DNSNames:    "0123456789abcdef.abcdef0123456789.traefik.default",
		Fingerprint: strings.Repeat("a", 40), SelfSigned: true,
		NotBefore: now.Add(-24 * time.Hour).Unix(), NotAfter: now.AddDate(1, 0, 0).Unix()}
	if hits := scanner.ProbeSignals(row); len(hits) != 0 {
		t.Fatalf("ignored Traefik certificate domain produced hits: %+v", hits)
	}

	hosts, _ := scanner.Project(storage.HostData{Scans: []storage.Scan{row}, Matches: []storage.Match{{
		IP: row.IP, Source: indicator.Source, Value: indicator.Value, Tag: indicator.Tag,
	}}}, scanner.ActiveOpen)
	if len(hosts) != 1 || hosts[0].Band != "low" || len(hosts[0].Signals) != 1 ||
		hosts[0].Signals[0].Source != "self_signed" {
		t.Fatalf("ignored Traefik certificate host = %+v, want only the low self-signed signal", hosts)
	}
}

func TestDomainIgnorelistRemovesIndicators(t *testing.T) {
	previousConfig, previousScope := targetcfg.Current.Config()
	previousFeeds := feeds.Current
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		feeds.Current = previousFeeds
	})
	cfg := previousConfig
	cfg.Feeds.DomainIgnorelist = []string{"example.com"}
	targetcfg.Current.Set(cfg, previousScope)

	fingerprint := strings.Repeat("a", 40)
	jarm := strings.Repeat("b", 62)
	indicators := []feeds.Indicator{
		{Source: feeds.URLHausSource, Value: "example.com", Tag: "malware"},
		{Source: "sslbl_cert", Value: fingerprint, Tag: "botnet"},
		{Source: feeds.ThreatViewSource, Value: jarm, Tag: "C2"},
		{Source: "threatfox", Value: "192.0.2.9", Tag: "direct IP"},
		{Source: "feodo", Value: "192.0.2.9:443", Tag: "direct port"},
	}
	feeds.Current = &feeds.Cache{Tried: []string{feeds.URLHausSource, "other"}, LastGood: map[string][]feeds.Indicator{
		feeds.URLHausSource: indicators[:1], "other": indicators[1:],
	}}
	feeds.Current.RebuildIndex()
	if hits := feeds.Current.Lookup("example.com"); len(hits) != 0 {
		t.Fatalf("ignored indicator remained indexed: %+v", hits)
	}
	if counts := feeds.Current.Counts(); counts[feeds.URLHausSource] != 0 {
		t.Fatalf("ignored indicator count = %d, want 0", counts[feeds.URLHausSource])
	}
	if slices.ContainsFunc(feeds.Current.Indicators(), func(hit feeds.Indicator) bool { return hit.Value == "example.com" }) {
		t.Fatal("ignored indicator remained in the active snapshot")
	}

	cfg.Feeds.DomainIgnorelist = nil
	targetcfg.Current.Set(cfg, previousScope)
	feeds.Current.RebuildIndex()
	if hits := feeds.Current.Lookup("example.com"); len(hits) != 1 {
		t.Fatalf("unignored indicator = %+v, want restored cached hit", hits)
	}
	cfg.Feeds.DomainIgnorelist = []string{"example.com"}
	targetcfg.Current.Set(cfg, previousScope)
	feeds.Current.RebuildIndex()

	for _, row := range []storage.Scan{
		{IP: "192.0.2.9", Subject: "example.com"},
		{IP: "192.0.2.9", Subject: "*.example.com"},
		{IP: "192.0.2.9", DNSNames: "panel.example.com"},
	} {
		if hits := scanner.ProbeSignals(row); len(hits) != 0 {
			t.Fatalf("ignored certificate domain produced hits: %+v", hits)
		}
	}

	now := time.Now()
	row := storage.Scan{IP: "192.0.2.9", Port: 443, IsOpen: true, Subject: "panel.example.com",
		DNSNames: "panel.example.com", Fingerprint: fingerprint, JARM: jarm, SelfSigned: true,
		NotBefore: now.AddDate(-2, 0, 0).Unix(), NotAfter: now.AddDate(1, 0, 0).Unix()}
	hosts, _ := scanner.Project(storage.HostData{Scans: []storage.Scan{row}}, scanner.ActiveOpen)
	if len(hosts) != 1 || hosts[0].Band != "high" {
		t.Fatalf("mixed-signal host = %+v, want High from non-domain signals", hosts)
	}
	if slices.ContainsFunc(hosts[0].Signals, func(signal feeds.Indicator) bool { return signal.Value == "example.com" }) {
		t.Fatalf("ignored domain is visible in host signals: %+v", hosts[0].Signals)
	}
	for _, value := range []string{fingerprint, jarm, "192.0.2.9", "192.0.2.9:443"} {
		if !slices.ContainsFunc(hosts[0].Signals, func(signal feeds.Indicator) bool { return signal.Value == value }) {
			t.Errorf("non-domain signal %q was hidden: %+v", value, hosts[0].Signals)
		}
	}

	feeds.Current = &feeds.Cache{Tried: []string{feeds.URLHausSource}, LastGood: map[string][]feeds.Indicator{
		feeds.URLHausSource: {{Source: feeds.URLHausSource, Value: "example.com", Tag: "malware"}},
	}}
	feeds.Current.RebuildIndex()
	row.Fingerprint, row.JARM, row.SelfSigned = strings.Repeat("c", 40), "", false
	hosts, _ = scanner.Project(storage.HostData{Scans: []storage.Scan{row}}, scanner.ActiveOpen)
	if hosts[0].Band != "" || len(hosts[0].Signals) != 0 {
		t.Fatalf("ignored-only host = %+v, want clean with no visible signals", hosts[0])
	}
	if verdict := scanner.ClassifyProbe(row); verdict.Band != "" || len(verdict.Matches) != 0 {
		t.Fatalf("ignored-only probe = band %q, matches %+v; want no alert or match", verdict.Band, verdict.Matches)
	}
}

func TestDomainIgnorelistExcludesStoredHitsFromAnalytics(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	cfg := previousConfig
	cfg.Feeds.DomainIgnorelist = []string{"example.com"}
	targetcfg.Current.Set(cfg, previousScope)

	rows := []storage.Match{
		{IP: "192.0.2.9", Source: feeds.URLHausSource, Value: "panel.example.com", Tag: "malware", SeenAt: 100},
		{IP: "192.0.2.9", Source: "feodo", Value: "192.0.2.9:443", Tag: "C2", SeenAt: 100},
	}
	if err := storage.SaveMatches(ctx, rows); err != nil {
		t.Fatal(err)
	}
	matches, err := storage.LoadFeedMatches(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ = targetcfg.Current.Config()
	yields := feedYields(matches, cfg.Feeds.DomainIgnorelist)
	if len(yields) != 1 || yields[0].Source != "feodo" || yields[0].Hosts != 1 || yields[0].Exclusive != 1 {
		t.Fatalf("feed yields = %+v, want only the direct hit", yields)
	}
}

func TestDomainIgnorelistReloadRefreshesStoredResults(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	path := seedSettings(t)
	previousFeeds := feeds.Current
	previousReportPath := scanner.ReportPath
	indicator := feeds.Indicator{Source: feeds.URLHausSource, Value: "example.com", Tag: "malware"}
	feeds.Current = &feeds.Cache{Tried: []string{feeds.URLHausSource}, Index: feeds.BuildIndex([]feeds.Indicator{indicator}),
		LastGood: map[string][]feeds.Indicator{feeds.URLHausSource: {indicator}}}
	scanner.ReportPath = filepath.Join(t.TempDir(), "report.json")
	t.Cleanup(func() { feeds.Current, scanner.ReportPath = previousFeeds, previousReportPath })

	now := time.Now().Unix()
	row := storage.Scan{IP: "192.0.2.9", Port: 443, ScannedAt: now, Subject: "panel.example.com",
		DNSNames: "panel.example.com", Fingerprint: strings.Repeat("a", 40),
		NotBefore: now - 200*86400, NotAfter: now + 165*86400}
	match := storage.Match{IP: row.IP, Source: feeds.URLHausSource, Value: "example.com", Tag: "malware", SeenAt: now}
	if err := storage.SaveScans(ctx, []storage.Scan{row}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveMatches(ctx, []storage.Match{match}); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.WriteReport(ctx, scanner.ReportPath); err != nil {
		t.Fatal(err)
	}
	if got := postAck(t, row.IP, "application/json").Code; got != 200 {
		t.Fatalf("ack status = %d, want 200", got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `[feeds]`, "[feeds]\ndomain_ignorelist = [\"example.com\"]", 1))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	scanner.ReloadOnce(&targetcfg.Current, path)
	if hits := feeds.Current.Lookup("example.com"); len(hits) != 0 {
		t.Fatalf("config reload left ignored indicator indexed: %+v", hits)
	}

	host := getHosts(t, "").Hosts[0]
	if host.Band != "" || len(host.Signals) != 0 || ackCount(t) != 0 {
		t.Fatalf("host after reload = %+v, acks %d; want clean with stale ACK retired", host, ackCount(t))
	}
	report, err := os.ReadFile(scanner.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	var hosts []scanner.ReportHost
	if err := json.Unmarshal(report, &hosts); err != nil || len(hosts) != 0 {
		t.Fatalf("report after reload = %s, err %v; want []", report, err)
	}
}
