package endpoints

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	storage "iocscanner/src/db"
	"iocscanner/src/feeds"
	"iocscanner/src/logging"
	"iocscanner/src/parse"
	scanner "iocscanner/src/scan"
	targetcfg "iocscanner/src/targets"
)

func feedOnlyConfig(t *testing.T) targetcfg.Config {
	t.Helper()
	targets := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(targets, []byte(`["192.0.2.1"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := targetcfg.LoadConfig(writeConfig(t, targets))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestOptionalFeedOnlyTargetFile(t *testing.T) {
	cfg := feedOnlyConfig(t)
	if scope, err := targetcfg.LoadScope(cfg); err != nil || len(scope.FeedOnly) != 0 {
		t.Fatalf("absent feed-only file = %+v, %v", scope.FeedOnly, err)
	}
	cfg.Scan.FeedOnlyTargetsFile = ""
	if _, err := targetcfg.LoadScope(cfg); err != nil {
		t.Fatalf("blank feed-only file: %v", err)
	}
	blankPath := writeConfig(t, cfg.Scan.TargetsFile, [2]string{
		"scans_per_day = 2", "feed_only_targets_file = \"   \"\nscans_per_day = 2",
	})
	blank, err := targetcfg.LoadConfig(blankPath)
	if err != nil || blank.Scan.FeedOnlyTargetsFile != "" {
		t.Fatalf("blank configured path = %q, %v", blank.Scan.FeedOnlyTargetsFile, err)
	}

	for _, tc := range []struct {
		name string
		body *string
		ok   bool
	}{
		{name: "missing"},
		{name: "empty file", body: ptr("")},
		{name: "malformed", body: ptr("{")},
		{name: "invalid target", body: ptr(`["bad"]`)},
		{name: "empty list", body: ptr(`[]`), ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "feed-only.json")
			if tc.body != nil {
				if err := os.WriteFile(path, []byte(*tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cfg.Scan.FeedOnlyTargetsFile = path
			_, err := targetcfg.LoadScope(cfg)
			if (err == nil) != tc.ok {
				t.Fatalf("load error = %v, want success %t", err, tc.ok)
			}
		})
	}
}

func TestFeedOnlyReloadKeepsLastGoodScope(t *testing.T) {
	cfg := feedOnlyConfig(t)
	feedOnly := filepath.Join(t.TempDir(), "feed-only.json")
	if err := os.WriteFile(feedOnly, []byte(`["192.0.2.2"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Scan.FeedOnlyTargetsFile = feedOnly
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := targetcfg.SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	var local targetcfg.Store
	if err := local.Load(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feedOnly, []byte(`[`), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner.ReloadOnce(&local, path)
	live, scope := local.Config()
	if live.Scan.FeedOnlyTargetsFile != feedOnly || len(scope.FeedOnly) != 1 || scope.FeedOnly[0].String() != "192.0.2.2/32" {
		t.Fatalf("failed reload replaced the last good state: %+v, %+v", live.Scan, scope.FeedOnly)
	}
}

func ptr(value string) *string { return &value }

func TestFeedOnlyMatchingNeverEntersScanIterationAndActiveWins(t *testing.T) {
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}, Deny: []string{"192.0.2.3"}}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	scope.FeedOnly = mustPrefixes(t, "192.0.2.1", "192.0.2.2", "192.0.2.3")
	scope.FeedOnlyScannable = targetcfg.FeedOnlyHosts(scope)

	var scanned []netip.Addr
	scope.AuthorizedAddrs(func(addr netip.Addr) bool {
		scanned = append(scanned, addr)
		return true
	})
	if got := strings.Join(addressStrings(scanned), ","); got != "192.0.2.1" {
		t.Fatalf("scan iteration = %s, want active target only", got)
	}
	rows := scanner.FeedHitsInScope(scope, []feeds.Indicator{
		{Source: "one", Value: "192.0.2.1", Tag: "active"},
		{Source: "two", Value: "192.0.2.2:443", Tag: "feed-only"},
		{Source: "three", Value: "192.0.2.3", Tag: "denied"},
		{Source: "domain", Value: "example.com", Tag: "ignored"},
	}, 10)
	if len(rows) != 2 || rows[0].FeedOnly || !rows[1].FeedOnly || scope.FeedOnlyScannable != 1 {
		t.Fatalf("matches = %+v, feed-only count = %d", rows, scope.FeedOnlyScannable)
	}
}

func TestFeedMatchAlertsIncludeStoredProvenance(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	scope.FeedOnly = mustPrefixes(t, "192.0.2.2")
	targetcfg.Current.Set(cfg, scope)
	var out safeBuffer
	logging.SetupLogger(&out, 2, false)
	scanner.MatchFeedHits(ctx, scope, []feeds.Indicator{
		{Source: "one", Value: "192.0.2.1", Tag: "active"},
		{Source: "two", Value: "192.0.2.2", Tag: "feed-only"},
	})
	logged := out.String()
	for _, want := range []string{
		"feed match  ip=192.0.2.1 feed_only=false",
		"feed match  ip=192.0.2.2 feed_only=true",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("alert missing %q:\n%s", want, logged)
		}
	}
}

func addressStrings(addrs []netip.Addr) []string {
	values := make([]string, len(addrs))
	for i, addr := range addrs {
		values[i] = addr.String()
	}
	return values
}

func TestFeedOnlyPersistenceProjectionAndAcknowledgementMode(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousConfig, previousScope := targetcfg.Current.Config()
	previousFeeds := feeds.Current
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		feeds.Current = previousFeeds
	})
	feeds.Current = &feeds.Cache{LastGood: map[string][]feeds.Indicator{}, Index: map[string][]feeds.Indicator{}}
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}, FeedOnlyTargetsFile: "configured.json"}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1", "192.0.2.4"))
	if err != nil {
		t.Fatal(err)
	}
	scope.FeedOnly = mustPrefixes(t, "192.0.2.2", "192.0.2.5")
	scope.FeedOnlyScannable = targetcfg.FeedOnlyHosts(scope)
	targetcfg.Current.Set(cfg, scope)
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.4", Port: 443, IsOpen: true, ScannedAt: 8}}); err != nil {
		t.Fatal(err)
	}
	rows := []storage.Match{
		{IP: "192.0.2.1", Source: "active", Value: "192.0.2.1", Tag: "hit", SeenAt: 9},
		{IP: "192.0.2.2", Source: "feed", Value: "192.0.2.2:8443", Tag: "hit", SeenAt: 10},
		{IP: "192.0.2.5", Source: "feed", Value: "192.0.2.5", Tag: "hit", SeenAt: 11},
	}
	if err := storage.SaveMatches(ctx, rows); err != nil {
		t.Fatal(err)
	}

	complete, _, err := scanner.Findings(ctx, scanner.ActiveOpen)
	if err != nil {
		t.Fatal(err)
	}
	feedOnly, _, err := scanner.Findings(ctx, scanner.FeedOnlyMatches)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(complete); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.4"}) {
		t.Fatalf("complete hosts = %v", got)
	}
	if got := addressesOf(feedOnly); !slices.Equal(got, []string{"192.0.2.2", "192.0.2.5"}) || len(feedOnly[0].Ports) != 0 || !feedOnly[0].FeedOnly {
		t.Fatalf("feed-only hosts = %+v", feedOnly)
	}
	// Clearing the file disables the feature, and the reload that follows installs the scope which
	// goes with it: no file, and nothing left on the feed-only side. Both halves are set here,
	// because an empty feed-only list is what the projection now answers to — a -scan -feed-only
	// run has entries there with no file configured at all.
	disabled, disabledScope := cfg, scope
	disabled.Scan.FeedOnlyTargetsFile = ""
	disabledScope.FeedOnly, disabledScope.FeedOnlyScannable = nil, 0
	targetcfg.Current.Set(disabled, disabledScope)
	if hidden, _, err := scanner.Findings(ctx, scanner.FeedOnlyMatches); err != nil || len(hidden) != 0 {
		t.Fatalf("disabled feed-only hosts = %+v, %v", hidden, err)
	}
	targetcfg.Current.Set(cfg, scope)
	if scanner.AckSignature(complete[0]) == scanner.AckSignature(scanner.HostView{IP: complete[0].IP, Signals: complete[0].Signals, FeedOnly: true}) {
		t.Fatal("projection mode is absent from the acknowledgement signature")
	}
	moved, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.2", "192.0.2.4"))
	if err != nil {
		t.Fatal(err)
	}
	moved.FeedOnly = mustPrefixes(t, "192.0.2.1", "192.0.2.5")
	moved.FeedOnlyScannable = targetcfg.FeedOnlyHosts(moved)
	targetcfg.Current.Set(cfg, moved)
	complete, _, _ = scanner.Findings(ctx, scanner.ActiveOpen)
	feedOnly, _, _ = scanner.Findings(ctx, scanner.FeedOnlyMatches)
	if !slices.Equal(addressesOf(complete), []string{"192.0.2.2", "192.0.2.4"}) || !slices.Equal(addressesOf(feedOnly), []string{"192.0.2.1", "192.0.2.5"}) {
		t.Fatalf("moved projections = complete %v, feed-only %v", addressesOf(complete), addressesOf(feedOnly))
	}
	targetcfg.Current.Set(cfg, scope)

	body := `{"ips":["192.0.2.2","192.0.2.5"],"acked":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/ack?target=feed-only", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handleAck(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("bulk feed-only ACK = %d: %s", recorder.Code, recorder.Body)
	}
	feedOnly, _, _ = scanner.Findings(ctx, scanner.FeedOnlyMatches)
	if feedOnly[0].Band != "ack" || feedOnly[1].Band != "ack" {
		t.Fatalf("feed-only ACK bands = %q, %q", feedOnly[0].Band, feedOnly[1].Band)
	}
	complete, _, _ = scanner.Findings(ctx, scanner.ActiveOpen)
	if complete[0].Band == "ack" {
		t.Fatal("feed-only acknowledgement leaked into the Complete projection")
	}
}

func TestFeedOnlyTargetsAPIIsDisabledOrSavesEmptyList(t *testing.T) {
	cfg := feedOnlyConfig(t)
	scope, err := targetcfg.LoadScope(cfg)
	if err != nil {
		t.Fatal(err)
	}
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	targetcfg.Current.Set(cfg, scope)

	get := httptest.NewRecorder()
	handleTargets(get, httptest.NewRequest(http.MethodGet, "/api/targets?target=feed-only", nil))
	var disabled struct {
		Targets     []targetRow `json:"targets"`
		TargetsFile string      `json:"targets_file"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &disabled); err != nil {
		t.Fatal(err)
	}
	if len(disabled.Targets) != 0 || disabled.TargetsFile != "" {
		t.Fatalf("disabled body = %+v", disabled)
	}
	if got := putFeedOnlyTargets(`{"targets":[]}`).Code; got != http.StatusConflict {
		t.Fatalf("disabled PUT = %d, want 409", got)
	}

	path := filepath.Join(t.TempDir(), "feed-only.json")
	if err := os.WriteFile(path, []byte(`["192.0.2.2"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Scan.FeedOnlyTargetsFile = path
	scope.FeedOnly = mustPrefixes(t, "192.0.2.2")
	scope.FeedOnlyScannable = targetcfg.FeedOnlyHosts(scope)
	targetcfg.Current.Set(cfg, scope)
	if recorder := putFeedOnlyTargets(`{"targets":["192.0.2.3","192.0.2.0/30"]}`); recorder.Code != http.StatusOK {
		t.Fatalf("normalized PUT = %d: %s", recorder.Code, recorder.Body)
	}
	written, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(written)) != "[\n  \"192.0.2.0/30\"\n]" {
		t.Fatalf("normalized file = %q, %v", written, err)
	}
	if recorder := putFeedOnlyTargets(`{"targets":[]}`); recorder.Code != http.StatusOK {
		t.Fatalf("empty PUT = %d: %s", recorder.Code, recorder.Body)
	}
	written, err = os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(written)) != "[]" {
		t.Fatalf("saved file = %q, %v", written, err)
	}
}

func TestSettingsCreatesNewFeedOnlyTargetFile(t *testing.T) {
	seedSettings(t)
	cfg, _ := getSettings(t)
	path := filepath.Join(t.TempDir(), "feed-only.json")
	cfg.Scan.FeedOnlyTargetsFile = path
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	recorder := putSettings(t, string(body), "application/json")
	if recorder.Code != http.StatusOK {
		t.Fatalf("settings status = %d, want 200: %s", recorder.Code, recorder.Body)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) != "[]" {
		t.Fatalf("new feed-only file = %q, %v", data, err)
	}
	if live, _ := targetcfg.Current.Config(); live.Scan.FeedOnlyTargetsFile != path {
		t.Fatalf("live feed-only path = %q, want %q", live.Scan.FeedOnlyTargetsFile, path)
	}
}

// Saving a feed-only target checks it against the cached indicators there and then. The feed
// refresh is 15 minutes apart and a feed-only address is never probed, so without this the table
// stays empty until the next tick even though the hit is already in the cache.
func TestSavingFeedOnlyTargetsMatchesTheCachedFeeds(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousConfig, previousScope := targetcfg.Current.Config()
	previousFeeds := feeds.Current
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		feeds.Current = previousFeeds
	})
	hit := feeds.Indicator{Source: "feed", Value: "192.0.2.2:8443", Tag: "hit"}
	feeds.Current = &feeds.Cache{LastGood: map[string][]feeds.Indicator{"feed": {hit}}}
	feeds.Current.Index = feeds.BuildIndex([]feeds.Indicator{hit})

	cfg := feedOnlyConfig(t)
	cfg.Scan.FeedOnlyTargetsFile = filepath.Join(t.TempDir(), "feed-only.json")
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)
	if recorder := putFeedOnlyTargets(`{"targets":["192.0.2.2"]}`); recorder.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", recorder.Code, recorder.Body)
	}
	hosts, _, err := scanner.Findings(ctx, scanner.FeedOnlyMatches)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(hosts); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Fatalf("feed-only hosts right after the save = %v, want the cached hit", got)
	}
	if recorder := putFeedOnlyTargets(`{"targets":[]}`); recorder.Code != http.StatusOK {
		t.Fatalf("remove PUT = %d: %s", recorder.Code, recorder.Body)
	}
	complete, _, err := scanner.Findings(ctx, scanner.ActiveOpen)
	if err != nil {
		t.Fatal(err)
	}
	feedOnly, _, err := scanner.Findings(ctx, scanner.FeedOnlyMatches)
	if err != nil {
		t.Fatal(err)
	}
	report, _, err := scanner.BuildReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(complete) != 0 || len(feedOnly) != 0 || len(report) != 0 {
		t.Fatalf("removed target remained visible: complete=%v feed-only=%v report=%v", complete, feedOnly, report)
	}
	data, err := storage.LoadHostData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Matches) != 1 || data.Matches[0].IP != "192.0.2.2" {
		t.Fatalf("retained matches = %+v, want the removed target's cached hit", data.Matches)
	}
}

func putFeedOnlyTargets(body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/api/targets?target=feed-only", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handleSaveTargets(recorder, req)
	return recorder
}

// A database written before confidence_level existed still opens, and an upsert refreshes the
// score. feed_only is not stored at all: which side a hit belongs to is asked of the live scope.
func TestLegacyMatchMigrationAndUpsert(t *testing.T) {
	path := filepath.Join(t.TempDir(), "matches.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE matches (ip VARCHAR NOT NULL, source VARCHAR NOT NULL, value VARCHAR NOT NULL, tag VARCHAR NOT NULL, first_seen VARCHAR, seen_at BIGINT NOT NULL, PRIMARY KEY (ip, source, value))`)
	if err == nil {
		_, err = legacy.Exec(`INSERT INTO matches VALUES ('192.0.2.2','feed','192.0.2.2','hit','',1)`)
	}
	legacy.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Open(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	var rows []storage.Match
	if err := storage.Handle.NewSelect().Model(&rows).Scan(context.Background()); err != nil || len(rows) != 1 || rows[0].ConfidenceLevel != nil {
		t.Fatalf("migrated rows = %+v, %v", rows, err)
	}
	confidence := 0
	rows[0].ConfidenceLevel = &confidence
	if err := storage.SaveMatches(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	rows = nil
	if err := storage.Handle.NewSelect().Model(&rows).Scan(context.Background()); err != nil || rows[0].ConfidenceLevel == nil || *rows[0].ConfidenceLevel != 0 {
		t.Fatalf("upserted rows = %+v, %v", rows, err)
	}
	*rows[0].ConfidenceLevel = 75
	if err := storage.SaveMatches(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	rows = nil
	if err := storage.Handle.NewSelect().Model(&rows).Scan(context.Background()); err != nil || rows[0].ConfidenceLevel == nil || *rows[0].ConfidenceLevel != 75 {
		t.Fatalf("updated confidence rows = %+v, %v", rows, err)
	}
}

// Randomised cross-check of the prefix arithmetic against the address walk it replaced. Small
// address space, thousands of scopes, every shape of overlap the generator can produce.
func TestScopeCountsMatchWalkRandomised(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	wide := 24
	randomPrefixes := func(n int) []netip.Prefix {
		out := make([]netip.Prefix, 0, n)
		for range n {
			bits := wide + rng.IntN(33-wide)
			addr := netip.AddrFrom4([4]byte{192, 0, byte(rng.IntN(4)), byte(rng.IntN(256))})
			out = append(out, netip.PrefixFrom(addr, bits).Masked())
		}
		return parse.DedupePrefixes(out)
	}
	for i := range 4600 {
		// The last cases widen to /18 and up, so prefixes nest across octet boundaries rather
		// than only inside one /24.
		if i == 4000 {
			wide = 18
		}
		s := targetcfg.Scope{
			Targets:  randomPrefixes(rng.IntN(4)),
			FeedOnly: randomPrefixes(rng.IntN(4)),
			Allow:    randomPrefixes(1 + rng.IntN(3)),
			Deny:     randomPrefixes(rng.IntN(3)),
		}
		walkScannable := 0
		for range s.AuthorizedAddrs {
			walkScannable++
		}
		walkFeedOnly := 0
		for _, prefix := range s.FeedOnly {
			for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
				if s.ContainsFeedOnly(addr) {
					walkFeedOnly++
				}
			}
		}
		if got := targetcfg.ScannableHosts(s); got != walkScannable {
			t.Fatalf("case %d: scannableHosts = %d, walk = %d\n%+v", i, got, walkScannable, s)
		}
		if got := targetcfg.FeedOnlyHosts(s); got != walkFeedOnly {
			t.Fatalf("case %d: feedOnlyHosts = %d, walk = %d\n%+v", i, got, walkFeedOnly, s)
		}
		// hasAuthorizedAddr must agree with its own count, since newScope gates the sweep on it.
		for _, target := range s.Targets {
			walked := false
			for addr := target.Addr(); target.Contains(addr) && !walked; addr = addr.Next() {
				walked = s.Contains(addr)
			}
			if s.HasAuthorizedAddr(target) != walked {
				t.Fatalf("case %d: hasAuthorizedAddr(%v) = %v, walk = %v\n%+v", i, target, !walked, walked, s)
			}
		}
	}
}

// A feed-only list that can never match is refused rather than saved as a silent no-op, and one
// file cannot serve as both lists: the feed-only editor may save an empty list, and doing that to
// the active targets file would leave the next reload with nothing to sweep.
func TestFeedOnlyGuardrails(t *testing.T) {
	cfg := feedOnlyConfig(t)
	scope, err := targetcfg.LoadScope(cfg)
	if err != nil {
		t.Fatal(err)
	}
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	cfg.Scan.FeedOnlyTargetsFile = filepath.Join(t.TempDir(), "feed-only.json")
	targetcfg.Current.Set(cfg, scope)

	// Outside scan.allow, and already an active target: neither can ever produce a feed-only row.
	for _, body := range []string{`{"targets":["198.51.100.0/24"]}`, `{"targets":["192.0.2.1"]}`} {
		if recorder := putFeedOnlyTargets(body); recorder.Code != http.StatusBadRequest {
			t.Errorf("PUT %s = %d, want 400: %s", body, recorder.Code, recorder.Body)
		}
	}
	// The literal path and a path that merely spells it differently both name one file.
	dir, base := filepath.Dir(cfg.Scan.TargetsFile), filepath.Base(cfg.Scan.TargetsFile)
	for _, alias := range []string{cfg.Scan.TargetsFile, dir + "/./" + base, dir + "//" + base} {
		same := cfg
		same.Scan.FeedOnlyTargetsFile = alias
		if err := targetcfg.ValidateConfig(same); err == nil {
			t.Errorf("%s serving as both target lists was accepted", alias)
		}
	}

	// A file already on disk is loaded as it is, so the Targets page has to say which entries the
	// sweep swallowed rather than reporting them as feed-only entries that will produce rows.
	overlapping := targetcfg.Scope{
		Targets:  mustPrefixes(t, "192.0.2.0/25"),
		FeedOnly: mustPrefixes(t, "192.0.2.0/26", "192.0.2.128/26", "198.51.100.1"),
		Allow:    mustPrefixes(t, "192.0.2.0/24"),
	}
	excluded := overlapping.FeedOnlyExcluded()
	for prefix, want := range map[string]string{
		"192.0.2.0/26":    "actively scanned",
		"192.0.2.128/26":  "in scope",
		"198.51.100.1/32": "out of scope",
	} {
		target := mustPrefixes(t, prefix)[0]
		if got := overlapping.FeedOnlyStatus(target, excluded); got != want {
			t.Errorf("feedOnlyStatus(%s) = %q, want %q", prefix, got, want)
		}
	}
}

// Acknowledgements stored before feed-only existed still hold: only a feed-only host's signature
// carries the marker, so an active host's signature is unchanged by the feature being added.
func TestAckSignatureUnchangedForActiveHosts(t *testing.T) {
	active := scanner.HostView{IP: "192.0.2.1", Signals: []feeds.Indicator{{Source: "feed", Value: "192.0.2.1"}}}
	feedOnly := active
	feedOnly.FeedOnly = true
	if scanner.AckSignature(active) == scanner.AckSignature(feedOnly) {
		t.Error("a host moving to the feed-only list kept its acknowledgement")
	}
	if strings.Contains(scanner.AckSignature(active), "feed_only") {
		t.Errorf("active signature = %q, want no feed-only marker", scanner.AckSignature(active))
	}
}

// A mistyped target selector must not fall through to the active list. The save path is the one
// that matters: writing the feed-only editor's contents over scan.targets_file loses the sweep.
func TestUnknownTargetSelectorIsRejected(t *testing.T) {
	cfg := feedOnlyConfig(t)
	cfg.Scan.FeedOnlyTargetsFile = filepath.Join(t.TempDir(), "feed-only.json")
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)

	req := httptest.NewRequest(http.MethodPut, "/api/targets?target=feedonly", strings.NewReader(`{"targets":["192.0.2.2"]}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handleSaveTargets(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("PUT with a mistyped selector = %d, want 400: %s", recorder.Code, recorder.Body)
	}
	if _, live := targetcfg.Current.Config(); !slices.Equal(live.Targets, scope.Targets) {
		t.Fatalf("active targets = %v, want them untouched at %v", live.Targets, scope.Targets)
	}

	get := httptest.NewRequest(http.MethodGet, "/api/targets?target=feedonly", nil)
	getRecorder := httptest.NewRecorder()
	handleTargets(getRecorder, get)
	if getRecorder.Code != http.StatusBadRequest {
		t.Fatalf("GET with a mistyped selector = %d, want 400", getRecorder.Code)
	}
}

// The two target files are one file whether or not they are spelled the same way.
func TestSameFileCatchesPathAliases(t *testing.T) {
	dir := t.TempDir()
	abs := filepath.Join(dir, "targets.json")
	if !targetcfg.SameFile(abs, abs) || !targetcfg.SameFile("targets.json", "./targets.json") {
		t.Fatal("identical paths read as two files")
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if !targetcfg.SameFile(filepath.Join(cwd, "targets.json"), "targets.json") {
		t.Fatal("an absolute path and its relative spelling read as two files")
	}
	if targetcfg.SameFile(abs, filepath.Join(dir, "feed-only.json")) {
		t.Fatal("distinct paths read as one file")
	}
}

// The sweep leaves feed-only addresses alone, but asking for one by hand is how an operator gets
// Ports and a certificate for it. Only allow and deny gate a manual request.
func TestManualScanAllowsFeedOnlyTargets(t *testing.T) {
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}, Deny: []string{"192.0.2.9"}}}
	for _, target := range []string{"192.0.2.130", "192.0.2.128/25", "192.0.2.1"} {
		if _, err := targetcfg.NewManualScope(cfg, mustPrefixes(t, target)); err != nil {
			t.Errorf("manual scan of %s rejected: %v", target, err)
		}
	}
	if _, err := targetcfg.NewManualScope(cfg, mustPrefixes(t, "192.0.2.9")); err == nil {
		t.Error("denied address accepted for a manual scan")
	}
}

// Scanning an address by hand is what moves it to the complete table. A feed-only target that has
// been hand-scanned has ports and a certificate, which the feed-only table has no column to show,
// so it appears there and not on both. A sweep's rows do not move a host — see
// TestDemotedActiveTargetLeavesTheCompleteTable for the half this exception must not swallow.
func TestManuallyScannedFeedOnlyHostMovesToTheCompleteTable(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousConfig, previousScope := targetcfg.Current.Config()
	previousFeeds := feeds.Current
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		feeds.Current = previousFeeds
	})
	feeds.Current = &feeds.Cache{LastGood: map[string][]feeds.Indicator{}, Index: map[string][]feeds.Indicator{}}
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}, FeedOnlyTargetsFile: "configured.json"}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	scope.FeedOnly = mustPrefixes(t, "192.0.2.2", "192.0.2.3")
	scope.FeedOnlyScannable = targetcfg.FeedOnlyHosts(scope)
	targetcfg.Current.Set(cfg, scope)
	// 192.0.2.2 was scanned by hand; 192.0.2.3 never has been. Both are feed-only targets and
	// both carry a feed hit.
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.2", Port: 8443, IsOpen: true, Manual: true, ScannedAt: 8}}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveMatches(ctx, []storage.Match{
		{IP: "192.0.2.2", Source: "feed", Value: "192.0.2.2:8443", Tag: "hit", SeenAt: 9},
		{IP: "192.0.2.3", Source: "feed", Value: "192.0.2.3", Tag: "hit", SeenAt: 10},
	}); err != nil {
		t.Fatal(err)
	}

	complete, _, err := scanner.Findings(ctx, scanner.ActiveOpen)
	if err != nil {
		t.Fatal(err)
	}
	feedOnly, _, err := scanner.Findings(ctx, scanner.FeedOnlyMatches)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(complete); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Fatalf("complete hosts = %v, want the hand-scanned feed-only target", got)
	}
	if len(complete[0].Ports) != 1 || complete[0].FeedOnly {
		t.Fatalf("hand-scanned host lost its ports or kept the feed-only marker: %+v", complete[0])
	}
	// Its feed hit comes with it, so the reason it was worth scanning is on the same row.
	if len(complete[0].Signals) != 1 || complete[0].Signals[0].Tag != "hit" {
		t.Fatalf("feed hit missing from the scanned host: %+v", complete[0].Signals)
	}
	if got := addressesOf(feedOnly); !slices.Equal(got, []string{"192.0.2.3"}) {
		t.Fatalf("feed-only hosts = %v, want only the target nobody has scanned", got)
	}
}

// A sweep's rows outlive the address's place in the active targets file, and nothing ever deletes
// them, so they must get no say in which table shows the host. Moving a swept address to the
// feed-only list moves the whole host on the next poll, stale ports and all. One stored row is
// enough to reproduce this: neither how long the address was swept nor how long ago is part of the
// question.
func TestDemotedActiveTargetLeavesTheCompleteTable(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousConfig, previousScope := targetcfg.Current.Config()
	previousFeeds := feeds.Current
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		feeds.Current = previousFeeds
	})
	feeds.Current = &feeds.Cache{LastGood: map[string][]feeds.Indicator{}, Index: map[string][]feeds.Indicator{}}
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}, FeedOnlyTargetsFile: "configured.json"}}

	// Sweeping an active target left an open port and a feed hit on it.
	active, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.2"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, active)
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.2", Port: 443, ScannedAt: 8}}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveMatches(ctx, []storage.Match{
		{IP: "192.0.2.2", Source: "feed", Value: "192.0.2.2", Tag: "hit", SeenAt: 9},
	}); err != nil {
		t.Fatal(err)
	}
	if complete, _, _ := scanner.Findings(ctx, scanner.ActiveOpen); !slices.Equal(addressesOf(complete), []string{"192.0.2.2"}) {
		t.Fatalf("while active, complete hosts = %v", addressesOf(complete))
	}

	// The operator moves it out of the targets file and into the feed-only list.
	demoted, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	demoted.FeedOnly = mustPrefixes(t, "192.0.2.2")
	demoted.FeedOnlyScannable = targetcfg.FeedOnlyHosts(demoted)
	targetcfg.Current.Set(cfg, demoted)

	complete, _, err := scanner.Findings(ctx, scanner.ActiveOpen)
	if err != nil {
		t.Fatal(err)
	}
	feedOnly, _, err := scanner.Findings(ctx, scanner.FeedOnlyMatches)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(complete); len(got) != 0 {
		t.Fatalf("complete hosts = %v, want the demoted address gone with its stale sweep ports", got)
	}
	if got := addressesOf(feedOnly); !slices.Equal(got, []string{"192.0.2.2"}) ||
		len(feedOnly[0].Ports) != 0 || !feedOnly[0].FeedOnly || len(feedOnly[0].Signals) != 1 {
		t.Fatalf("feed-only hosts = %+v", feedOnly)
	}

	// Promoting it back restores the ports: the rows were never deleted.
	targetcfg.Current.Set(cfg, active)
	if back, _, _ := scanner.Findings(ctx, scanner.ActiveOpen); len(back) != 1 || len(back[0].Ports) != 1 {
		t.Fatalf("promoted host = %+v, want its stored ports back", back)
	}
}

// The operator's sequence: an active target is swept, retired to the feed-only list, and then
// scanned by hand to look at it. The sweep's rows do not bring it back on their own, but the
// hand-scan does, and it arrives with everything already stored for it.
func TestHandScanningARetiredTargetBringsItBack(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousConfig, previousScope := targetcfg.Current.Config()
	previousFeeds := feeds.Current
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		feeds.Current = previousFeeds
	})
	feeds.Current = &feeds.Cache{LastGood: map[string][]feeds.Indicator{}, Index: map[string][]feeds.Indicator{}}
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}, FeedOnlyTargetsFile: "configured.json"}}
	active, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.2"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, active)
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.2", Port: 443, ScannedAt: 8}}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveMatches(ctx, []storage.Match{
		{IP: "192.0.2.2", Source: "feed", Value: "192.0.2.2", Tag: "hit", SeenAt: 9},
	}); err != nil {
		t.Fatal(err)
	}

	// Retired to the feed-only list: the sweep's rows do not hold it on the host table.
	retired, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	retired.FeedOnly = mustPrefixes(t, "192.0.2.2")
	retired.FeedOnlyScannable = targetcfg.FeedOnlyHosts(retired)
	targetcfg.Current.Set(cfg, retired)
	if complete, _, _ := scanner.Findings(ctx, scanner.ActiveOpen); len(complete) != 0 {
		t.Fatalf("after retiring, complete hosts = %v, want none", addressesOf(complete))
	}
	if feedOnly, _, _ := scanner.Findings(ctx, scanner.FeedOnlyMatches); !slices.Equal(addressesOf(feedOnly), []string{"192.0.2.2"}) {
		t.Fatalf("after retiring, feed-only hosts = %v", addressesOf(feedOnly))
	}

	// The operator scans it by hand. Same scope, no target file touched.
	if err := storage.SaveScans(ctx, []storage.Scan{{IP: "192.0.2.2", Port: 8443, Manual: true, ScannedAt: 20}}); err != nil {
		t.Fatal(err)
	}
	complete, _, err := scanner.Findings(ctx, scanner.ActiveOpen)
	if err != nil {
		t.Fatal(err)
	}
	feedOnly, _, err := scanner.Findings(ctx, scanner.FeedOnlyMatches)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(complete); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Fatalf("after the hand-scan, complete hosts = %v, want the scanned address", got)
	}
	// The sweep's port comes back with it: the rows were never deleted, only disregarded.
	if len(complete[0].Ports) != 2 || complete[0].FeedOnly || !complete[0].Manual {
		t.Fatalf("hand-scanned host = %+v, want both ports, no feed-only marker, manual origin", complete[0])
	}
	if got := addressesOf(feedOnly); len(got) != 0 {
		t.Fatalf("feed-only hosts = %v, want the address on one side only", got)
	}
}

// The historical projection keeps a demoted address's ports. It reports what was measured, and
// analytics applies its own window to them, so an edit to the target files must not retroactively
// rewrite observations that genuinely happened.
func TestDemotedTargetKeepsItsHistoricalPorts(t *testing.T) {
	previousConfig, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() { targetcfg.Current.Set(previousConfig, previousScope) })
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}, FeedOnlyTargetsFile: "configured.json"}}
	demoted, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	demoted.FeedOnly = mustPrefixes(t, "192.0.2.2")
	demoted.FeedOnlyScannable = targetcfg.FeedOnlyHosts(demoted)
	targetcfg.Current.Set(cfg, demoted)

	data := storage.HostData{Scans: []storage.Scan{{IP: "192.0.2.2", Port: 443, IsOpen: true, ScannedAt: 8, FullScannedAt: 8}}}
	if live, _ := scanner.Project(data, scanner.ActiveOpen); len(live) != 0 {
		t.Fatalf("live hosts = %+v, want the demoted address off the host table", live)
	}
	historical, _ := scanner.Project(data, scanner.ActiveHistory)
	if len(historical) != 1 || len(historical[0].Ports) != 1 {
		t.Fatalf("historical hosts = %+v, want the measured port kept", historical)
	}
}

// The settings handler creates a newly configured path, and leaves one an operator already wrote.
func TestCreateEmptyTargetsKeepsAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed-only.json")
	if err := createEmptyTargets(path); err != nil {
		t.Fatal(err)
	}
	if _, err := targetcfg.ReadTargetEntries(path); err != nil {
		t.Fatalf("created file does not parse as a target list: %v", err)
	}
	if err := os.WriteFile(path, []byte(`["192.0.2.9"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := createEmptyTargets(path); err != nil {
		t.Fatal(err)
	}
	entries, err := targetcfg.ReadTargetEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := targetcfg.ParsePrefixes(entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "192.0.2.9/32" {
		t.Fatalf("existing targets file was overwritten: %v", got)
	}
}

// A hand-scan that finds nothing must still move a feed-only host onto the complete table. The
// operator asking for the address by name is what earns the move, so it cannot depend on the probe
// finding an open port — with nothing listening there is no scan row to carry the fact, and before
// manual_scans existed the host silently stayed on the feed-only table.
func TestHandScanningAFeedOnlyHostMovesItEvenWithNoOpenPorts(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	scanner.ReportPath = filepath.Join(t.TempDir(), "report.json")
	t.Cleanup(func() { scanner.ReportPath = "" })
	logging.SetupLogger(io.Discard, 1, false)

	// Bound then closed, so the sweep dials a port nothing answers on.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target, err := netip.ParseAddrPort(listener.Addr().String())
	listener.Close()
	if err != nil {
		t.Fatal(err)
	}
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{
		Allow: []string{"127.0.0.0/8"}, CommonPorts: []int{int(target.Port())},
		MaxWorkers: 1, DialTimeoutMS: 200, TLSTimeoutMS: 200, JARMTimeoutMS: 200,
		FeedOnlyTargetsFile: "configured.json",
	}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "127.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	scope.FeedOnly = mustPrefixes(t, target.Addr().String())
	scope.FeedOnlyScannable = targetcfg.FeedOnlyHosts(scope)
	previousConfig, previousScope := targetcfg.Current.Config()
	previousFeeds := feeds.Current
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		feeds.Current = previousFeeds
	})
	targetcfg.Current.Set(cfg, scope)
	feeds.Current = &feeds.Cache{Index: feeds.BuildIndex([]feeds.Indicator{{
		Source: "cached", Value: target.Addr().String(), Tag: "known C2", FirstSeen: "2026-08-18T00:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false,
	}})}

	// It starts on the feed-only table: a feed names it and nothing has probed it.
	if hits := scanner.MatchFeedHits(ctx, scope, feeds.Current.Indicators()); len(hits) != 1 {
		t.Fatalf("feed hits = %d, want the one naming the feed-only target", len(hits))
	}
	if got, _, _ := scanner.Findings(ctx, scanner.FeedOnlyMatches); !slices.Equal(addressesOf(got), []string{target.Addr().String()}) {
		t.Fatalf("feed-only hosts before the scan = %v, want the target", addressesOf(got))
	}

	before := time.Now().Unix()
	scanner.SweepOnce(ctx, true, true, mustPrefixes(t, target.Addr().String()))

	complete, _, err := scanner.Findings(ctx, scanner.ActiveOpen)
	if err != nil {
		t.Fatal(err)
	}
	feedOnly, _, err := scanner.Findings(ctx, scanner.FeedOnlyMatches)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(complete); !slices.Equal(got, []string{target.Addr().String()}) {
		t.Fatalf("complete hosts = %v, want the hand-scanned target even with no open port", got)
	}
	if len(complete[0].Ports) != 0 || complete[0].FeedOnly {
		t.Fatalf("hand-scanned host = %+v, want no ports and no feed-only marker", complete[0])
	}
	// Origin and last-checked come from the port rows, which this scan never wrote. Without the
	// recorded request the row would claim Automatic origin for an address the sweep never
	// touches, and a last-checked lifted from the feed match.
	if !complete[0].Manual {
		t.Error("hand-scanned host reports Automatic origin, want Manual")
	}
	// The record the origin is read from. The manual pass re-runs the feed match too, so
	// CheckedAt lands on ~now either way — this asserts the row that actually carries the request.
	state, err := storage.CurrentHostState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Manual) != 1 || state.Manual[0].IP != target.Addr().String() ||
		state.Manual[0].ScannedAt < before {
		t.Fatalf("manual scan records = %+v, want one for the target stamped at or after %d",
			state.Manual, before)
	}
	// Its feed hit comes with it, so the reason it was worth scanning is on the row.
	if len(complete[0].Signals) != 1 || complete[0].Signals[0].Tag != "known C2" {
		t.Fatalf("feed hit missing from the scanned host: %+v", complete[0].Signals)
	}
	if got := addressesOf(feedOnly); len(got) != 0 {
		t.Fatalf("feed-only hosts after the scan = %v, want none", got)
	}
}

// Hand-scanning an address moves which table it appears on. It must not remove it from feed
// matching: the scheduled refresh works off the scope — the targets files narrowed by allow and
// Deny — and a manual scan changes none of those. So the address keeps collecting feed hits on
// every cycle, and they keep landing on the host table it moved to.
func TestHandScannedFeedOnlyHostKeepsMatchingFeeds(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	previousConfig, previousScope := targetcfg.Current.Config()
	previousFeeds := feeds.Current
	t.Cleanup(func() {
		targetcfg.Current.Set(previousConfig, previousScope)
		feeds.Current = previousFeeds
	})
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}, FeedOnlyTargetsFile: "configured.json"}}
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	scope.FeedOnly = mustPrefixes(t, "192.0.2.2")
	scope.FeedOnlyScannable = targetcfg.FeedOnlyHosts(scope)
	targetcfg.Current.Set(cfg, scope)
	feeds.Current = &feeds.Cache{Index: feeds.BuildIndex([]feeds.Indicator{
		{Source: "cached", Value: "192.0.2.2", Tag: "known C2", FirstSeen: "2026-08-18T00:00:00Z", Link: "", ConfidenceLevel: nil, Soft: false},
	})}

	// The address has been hand-scanned, so it lives on the host table from here on.
	if err := storage.SaveManualScans(ctx, []storage.ManualScan{{IP: "192.0.2.2", ScannedAt: 100}}); err != nil {
		t.Fatal(err)
	}

	// The scheduled cycle, run twice: the scope it consults is the live one, exactly as
	// matchTargetsAgainstFeeds does.
	if rows := scanner.MatchFeedHits(ctx, scope, feeds.Current.Indicators()); len(rows) != 1 {
		t.Fatalf("first refresh matched %d rows, want the hand-scanned feed-only address", len(rows))
	}
	if rows := scanner.MatchFeedHits(ctx, scope, feeds.Current.Indicators()); len(rows) != 1 {
		t.Fatalf("later refresh matched %d rows, want the address still matching", len(rows))
	}

	// The hit is stored against the address and its seen_at advances, so the match is genuinely
	// being re-confirmed rather than left frozen at whatever the first cycle wrote.
	state, err := storage.CurrentHostState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Matches) != 1 || state.Matches[0].IP != "192.0.2.2" {
		t.Fatalf("stored matches = %+v, want one for the hand-scanned address", state.Matches)
	}
	if state.Matches[0].SeenAt < 100 {
		t.Fatalf("seen_at = %d, want a fresh confirmation", state.Matches[0].SeenAt)
	}

	// And it shows on the host table, not the feed-only one.
	complete, _, err := scanner.Findings(ctx, scanner.ActiveOpen)
	if err != nil {
		t.Fatal(err)
	}
	feedOnly, _, err := scanner.Findings(ctx, scanner.FeedOnlyMatches)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(complete); !slices.Equal(got, []string{"192.0.2.2"}) {
		t.Fatalf("host table = %v, want the hand-scanned address", got)
	}
	if len(complete[0].Signals) != 1 || complete[0].Signals[0].Tag != "known C2" {
		t.Fatalf("feed signal missing from the hand-scanned host: %+v", complete[0].Signals)
	}
	if got := addressesOf(feedOnly); len(got) != 0 {
		t.Fatalf("feed-only table = %v, want none", got)
	}
}

// A scope with nothing in it makes every feed cycle report zero matches, which is what a quiet day
// looks like too. The warning is the only thing that tells the two apart in the log.
func TestFeedCycleWarnsWhenNothingCanMatch(t *testing.T) {
	ctx := context.Background()
	if err := storage.Open(ctx, filepath.Join(t.TempDir(), "matches.db")); err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	previousFeeds := feeds.Current
	feeds.Current = stubFeeds(t, http.StatusOK)
	previousCfg, previousScope := targetcfg.Current.Config()
	t.Cleanup(func() {
		feeds.Current = previousFeeds
		targetcfg.Current.Set(previousCfg, previousScope)
	})
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"192.0.2.0/24"}}}

	var out safeBuffer
	logging.SetupLogger(&out, 1, false)
	// Targets outside the allowlist: entries on the books, nothing a feed hit can land on.
	targetcfg.Current.Set(cfg, targetcfg.Scope{Targets: mustPrefixes(t, "198.51.100.0/24")})
	scanner.MatchTargetsAgainstFeeds(ctx)
	if !strings.Contains(out.String(), "no authorized targets") {
		t.Errorf("an empty scope logged %q", out.String())
	}

	out.Reset()
	scope, err := targetcfg.NewScope(cfg, mustPrefixes(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)
	scanner.MatchTargetsAgainstFeeds(ctx)
	if strings.Contains(out.String(), "no authorized targets") {
		t.Errorf("a populated scope logged %q", out.String())
	}
}
