package endpoints

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	storage "iocscanner/src/db"
	"iocscanner/src/feeds"
	scanner "iocscanner/src/scan"
)

const (
	testJARM  = "27d40d40d29d40d21c42d43d00041d4689ee210389f4f6b4b5b1b93f92252d"
	otherJARM = "29d29d15d29d29d00029d29d29d29d1af3f8d112f5af1fd47d1d6d4c5dc8a9"
)

func jarmBlacklistRequest(t *testing.T, method, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, "/api/jarm-blacklist", strings.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	dashboardMux(dashboardAssets).ServeHTTP(recorder, request)
	return recorder
}

func readJARMBlacklist(t *testing.T) []storage.JARMBlacklistEntry {
	t.Helper()
	recorder := jarmBlacklistRequest(t, http.MethodGet, "", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET status = %d: %s", recorder.Code, recorder.Body)
	}
	var rows []storage.JARMBlacklistEntry
	if err := json.Unmarshal(recorder.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestJARMBlacklistCreatesUpsertsLoadsAndDeletes(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "matches.db")
	if err := storage.Open(ctx, path); err != nil {
		t.Fatal(err)
	}

	body := `[{"label":" CobaltStrike ","hash":" 27D40D40D29D40D21C42D43D00041D4689EE210389F4F6B4B5B1B93F92252D "},` +
		`{"label":"Sliver","hash":"` + otherJARM + `"}]`
	if got := jarmBlacklistRequest(t, http.MethodPost, body, "application/json; charset=utf-8").Code; got != http.StatusOK {
		t.Fatalf("POST status = %d, want 200", got)
	}
	rows := readJARMBlacklist(t)
	if len(rows) != 2 || rows[0].Label != "CobaltStrike" || rows[0].Hash != testJARM {
		t.Fatalf("blacklist = %+v, want trimmed labels and lowercase hashes", rows)
	}
	if got := scanner.BlacklistIndicators(testJARM); len(got) != 1 ||
		got[0] != (feeds.Indicator{Source: storage.JARMBlacklistSource, Value: testJARM, Tag: "CobaltStrike"}) {
		t.Fatalf("lookup = %+v, want the local blacklist indicator", got)
	}

	if got := jarmBlacklistRequest(t, http.MethodPost,
		`[{"label":"Beacon","hash":"`+testJARM+`"}]`, "application/json").Code; got != http.StatusOK {
		t.Fatalf("upsert status = %d, want 200", got)
	}
	rows = readJARMBlacklist(t)
	if len(rows) != 2 || !slices.ContainsFunc(rows, func(row storage.JARMBlacklistEntry) bool {
		return row.Hash == testJARM && row.Label == "Beacon"
	}) {
		t.Fatalf("upserted blacklist = %+v, want one updated row", rows)
	}

	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	storage.JARMBlacklist.Replace(nil)
	if err := storage.Open(ctx, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	if got := scanner.BlacklistIndicators(testJARM); len(got) != 1 || got[0].Tag != "Beacon" {
		t.Fatalf("lookup after reopen = %+v, want the stored label", got)
	}

	if got := jarmBlacklistRequest(t, http.MethodDelete,
		`{"hash":" 27D40D40D29D40D21C42D43D00041D4689EE210389F4F6B4B5B1B93F92252D "}`,
		"application/json").Code; got != http.StatusOK {
		t.Fatalf("DELETE status = %d, want 200", got)
	}
	if storage.JARMBlacklist.Contains(testJARM) || len(readJARMBlacklist(t)) != 1 {
		t.Fatal("deleted hash remains in the database or lookup")
	}
}

func TestJARMBlacklistRejectsInvalidArraysAtomically(t *testing.T) {
	if err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	if err := storage.SaveJARMBlacklist(context.Background(), []storage.JARMBlacklistEntry{{Hash: testJARM, Label: "kept"}}); err != nil {
		t.Fatal(err)
	}

	valid := `{"label":"new","hash":"` + otherJARM + `"}`
	cases := map[string]string{
		"missing label":        `[` + valid + `,{"label":" ","hash":"` + strings.Repeat("a", 62) + `"}]`,
		"short hash":           `[` + valid + `,{"label":"bad","hash":"abcd"}]`,
		"non-hex hash":         `[` + valid + `,{"label":"bad","hash":"` + strings.Repeat("g", 62) + `"}]`,
		"all-zero hash":        `[` + valid + `,{"label":"bad","hash":"` + strings.Repeat("0", 62) + `"}]`,
		"normalized duplicate": `[` + valid + `,{"label":"same","hash":"` + strings.ToUpper(otherJARM) + `"}]`,
		"not an array":         `{"label":"bad","hash":"` + otherJARM + `"}`,
		"null":                 `null`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := jarmBlacklistRequest(t, http.MethodPost, body, "application/json")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body)
			}
			rows := readJARMBlacklist(t)
			if len(rows) != 1 || rows[0].Hash != testJARM || rows[0].Label != "kept" {
				t.Fatalf("invalid request changed blacklist to %+v", rows)
			}
		})
	}
	if got := jarmBlacklistRequest(t, http.MethodPost, `[]`, "text/plain").Code; got != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON POST status = %d, want 415", got)
	}
	if got := jarmBlacklistRequest(t, http.MethodDelete, `{"hash":"`+testJARM+`"}`, "text/plain").Code; got != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON DELETE status = %d, want 415", got)
	}
}

func TestJARMBlacklistExportsCSV(t *testing.T) {
	if err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	if err := storage.SaveJARMBlacklist(context.Background(), []storage.JARMBlacklistEntry{
		{Label: `Cobalt, "Strike"`, Hash: testJARM},
	}); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/jarm-blacklist?format=csv", nil)
	recorder := httptest.NewRecorder()
	dashboardMux(dashboardAssets).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/csv; charset=utf-8" ||
		recorder.Header().Get("Content-Disposition") != `attachment; filename="jarm-blacklist.csv"` {
		t.Fatalf("CSV response = status %d, headers %v", recorder.Code, recorder.Header())
	}
	records, err := csv.NewReader(recorder.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || !slices.Equal(records[0], []string{"label", "hash"}) ||
		!slices.Equal(records[1], []string{`Cobalt, "Strike"`, testJARM}) {
		t.Fatalf("CSV records = %q", records)
	}
}

func TestJARMBlacklistAndSightingsStaySeparate(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	if err := storage.SaveJARMBlacklist(ctx, []storage.JARMBlacklistEntry{
		{Hash: testJARM, Label: "seen"}, {Hash: otherJARM, Label: "never seen"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveJARMSightings(ctx, []storage.JARMSighting{{
		Hash: testJARM, IP: "192.0.2.1", Port: 443, FirstSeen: 1, LastSeen: 2,
	}}); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	handleJARM(recorder, httptest.NewRequest(http.MethodGet, "/api/jarm", nil))
	var sightings []storage.JARMRow
	if err := json.Unmarshal(recorder.Body.Bytes(), &sightings); err != nil {
		t.Fatal(err)
	}
	if len(sightings) != 1 || sightings[0].Hash != testJARM || !sightings[0].Blacklisted {
		t.Fatalf("JARM sightings = %+v, want only the observed blacklisted hash", sightings)
	}
	if len(readJARMBlacklist(t)) != 2 {
		t.Fatal("the blacklist does not independently contain its unseen hash")
	}
}

func TestJARMBlacklistImmediatelyRebandsStoredScansAndReports(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousFeeds := feeds.Current
	feeds.Current = &feeds.Cache{LastGood: map[string][]feeds.Indicator{}, Index: map[string][]feeds.Indicator{}}
	t.Cleanup(func() { feeds.Current = previousFeeds })
	previousReportPath := scanner.ReportPath
	scanner.ReportPath = filepath.Join(t.TempDir(), "report.json")
	t.Cleanup(func() { scanner.ReportPath = previousReportPath })

	now := time.Now().Unix()
	issued, expires := now-200*86400, now+165*86400
	if err := storage.SaveScans(ctx, []storage.Scan{
		{IP: "192.0.2.1", Port: 443, ScannedAt: now, DNSNames: "clean.example",
			NotBefore: issued, NotAfter: expires, Fingerprint: strings.Repeat("1", 40), JARM: testJARM},
		{IP: "192.0.2.2", Port: 443, ScannedAt: now, SelfSigned: true, DNSNames: "soft.example",
			NotBefore: issued, NotAfter: expires, Fingerprint: strings.Repeat("2", 40), JARM: testJARM},
	}); err != nil {
		t.Fatal(err)
	}
	if got := postAck(t, "192.0.2.1", "application/json").Code; got != http.StatusOK {
		t.Fatalf("ack status = %d, want 200", got)
	}

	if got := jarmBlacklistRequest(t, http.MethodPost,
		`[{"label":"CobaltStrike","hash":"`+testJARM+`"}]`, "application/json").Code; got != http.StatusOK {
		t.Fatalf("POST status = %d, want 200", got)
	}
	if ackCount(t) != 0 {
		t.Fatal("adding a blacklist signal did not retire the old acknowledgement")
	}
	if bandOf(t, "192.0.2.1") != "high" || bandOf(t, "192.0.2.2") != "high" {
		t.Fatal("stored scans were not immediately raised to High")
	}
	if v := scanner.ClassifyProbe(storage.Scan{IP: "192.0.2.3", Port: 443, ScannedAt: now, JARM: testJARM}); v.Band != "high" || len(v.Matches) != 1 || v.Matches[0].Source != storage.JARMBlacklistSource {
		t.Fatalf("new probe = band %q matches %+v, want one High blacklist match", v.Band, v.Matches)
	}
	assertReportBands(t, map[string]string{"192.0.2.1": "high", "192.0.2.2": "high"})
	if got := postAck(t, "192.0.2.1", "application/json").Code; got != http.StatusOK {
		t.Fatalf("second ack status = %d, want 200", got)
	}
	if got := jarmBlacklistRequest(t, http.MethodPost,
		`[{"label":"Renamed","hash":"`+testJARM+`"}]`, "application/json").Code; got != http.StatusOK {
		t.Fatalf("label update status = %d, want 200", got)
	}
	if ackCount(t) != 0 {
		t.Fatal("changing a blacklist label did not retire the acknowledgement")
	}
	hosts := getHosts(t, "").Hosts
	if !slices.ContainsFunc(hosts, func(host scanner.HostView) bool {
		return host.IP == "192.0.2.1" && slices.ContainsFunc(host.Signals, func(signal feeds.Indicator) bool {
			return signal.Source == storage.JARMBlacklistSource && signal.Tag == "Renamed"
		})
	}) {
		t.Fatal("the updated blacklist label is not visible on the stored scan")
	}

	if got := jarmBlacklistRequest(t, http.MethodDelete, `{"hash":"`+testJARM+`"}`, "application/json").Code; got != http.StatusOK {
		t.Fatalf("DELETE status = %d, want 200", got)
	}
	if bandOf(t, "192.0.2.1") != "" || bandOf(t, "192.0.2.2") != "low" {
		t.Fatal("deletion did not fall back to Clean and the remaining local signal")
	}
	assertReportBands(t, map[string]string{"192.0.2.2": "low"})
}

func assertReportBands(t *testing.T, want map[string]string) {
	t.Helper()
	data, err := os.ReadFile(scanner.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	var rows []scanner.ReportHost
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	got := make(map[string]string, len(rows))
	for _, row := range rows {
		got[row.IP] = row.Band
	}
	if len(got) != len(want) {
		t.Fatalf("report bands = %v, want %v", got, want)
	}
	for ip, band := range want {
		if got[ip] != band {
			t.Fatalf("report bands = %v, want %v", got, want)
		}
	}
}
