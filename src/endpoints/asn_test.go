package endpoints

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"iocscanner/src/feeds"
	scanner "iocscanner/src/scan"
	targetcfg "iocscanner/src/targets"
)

type asnRoundTrip func(*http.Request) (*http.Response, error)

func (fn asnRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func isolateASNState(t *testing.T) {
	t.Helper()
	previousClient := targetcfg.ASNClient
	targetcfg.ASNClient = http.DefaultClient
	previousCache, previousPath, previousURL, previousFeeds := targetcfg.ASNPrefixes, targetcfg.ASNCachePath, targetcfg.RipeAnnouncedPrefixesURL, feeds.Current
	previousConfig, previousScope := targetcfg.Current.Config()
	targetcfg.ASNPrefixes = &targetcfg.ASNCache{Prefixes: map[uint32][]netip.Prefix{}}
	targetcfg.ASNCachePath = filepath.Join(t.TempDir(), "asn_prefixes.json")
	feeds.Current = &feeds.Cache{Client: http.DefaultClient, LastGood: map[string][]feeds.Indicator{}}
	t.Cleanup(func() {
		targetcfg.ASNClient = previousClient
		targetcfg.ASNPrefixes, targetcfg.ASNCachePath, targetcfg.RipeAnnouncedPrefixesURL, feeds.Current = previousCache, previousPath, previousURL, previousFeeds
		targetcfg.Current.Set(previousConfig, previousScope)
	})
}

func serveASN(t *testing.T, status int, prefixes ...string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if status < 300 {
			rows := make([]map[string]string, len(prefixes))
			for i, prefix := range prefixes {
				rows[i] = map[string]string{"prefix": prefix}
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"prefixes": rows}}) //nolint:errcheck
		}
	}))
	t.Cleanup(server.Close)
	targetcfg.RipeAnnouncedPrefixesURL = server.URL + "/?resource=AS"
	return server
}

func TestParseASN(t *testing.T) {
	for _, value := range []string{"AS13335", "as13335"} {
		if asn, ok := targetcfg.ParseASN(value); !ok || asn != 13335 {
			t.Errorf("parseASN(%q) = %d, %t", value, asn, ok)
		}
	}
	for _, value := range []string{"AS", "ASfoo", "13335", "AS4294967296"} {
		if _, ok := targetcfg.ParseASN(value); ok {
			t.Errorf("parseASN(%q) accepted", value)
		}
	}
}

func TestAnnouncedPrefixesDropsIPv6AndRejectsV6Only(t *testing.T) {
	isolateASNState(t)
	serveASN(t, http.StatusOK, "2001:db8::/32", "192.0.2.1/24")
	prefixes, err := targetcfg.AnnouncedPrefixes(context.Background(), 13335)
	if err != nil || len(prefixes) != 1 || prefixes[0].String() != "192.0.2.0/24" {
		t.Fatalf("prefixes = %v, err = %v", prefixes, err)
	}
	serveASN(t, http.StatusOK, "2001:db8::/32")
	if _, err := targetcfg.AnnouncedPrefixes(context.Background(), 13335); err == nil {
		t.Fatal("v6-only ASN accepted")
	}
}

func TestFailedRefreshKeepsCachedPrefixes(t *testing.T) {
	isolateASNState(t)
	serveASN(t, http.StatusOK, "2001:db8::/32")
	targetcfg.ASNPrefixes.Prefixes[13335] = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	targetcfg.Current.Set(targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"AS13335"}}}, targetcfg.Scope{})
	if targetcfg.RefreshASNs(context.Background()) {
		t.Fatal("failed refresh reported a change")
	}
	if prefixes, ok := targetcfg.ASNPrefixes.Lookup(13335); !ok || prefixes[0].String() != "192.0.2.0/24" {
		t.Fatalf("cached prefixes = %v, %t", prefixes, ok)
	}
}

func TestParsePrefixesExpandsCachedASN(t *testing.T) {
	isolateASNState(t)
	targetcfg.ASNPrefixes.Prefixes[13335] = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	prefixes, err := targetcfg.ParsePrefixes([]string{"AS13335", "192.0.2.8"})
	if err != nil || len(prefixes) != 1 || prefixes[0].String() != "192.0.2.0/24" {
		t.Fatalf("prefixes = %v, err = %v", prefixes, err)
	}
	if _, err := targetcfg.ParsePrefixes([]string{"AS64500"}); err == nil {
		t.Fatal("uncached ASN accepted")
	}
}

func TestRefreshQueriesEachReferencedASNOnce(t *testing.T) {
	isolateASNState(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{"data":{"prefixes":[{"prefix":"192.0.2.0/24"}]}}`)
	}))
	t.Cleanup(server.Close)
	targetcfg.RipeAnnouncedPrefixesURL = server.URL + "/?resource=AS"
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"AS13335"}, Deny: []string{"as13335"}}}
	targetcfg.Current.Set(cfg, targetcfg.Scope{TargetEntries: []string{"AS13335"}, FeedOnlyEntries: []string{"AS13335"}})
	targetcfg.RefreshASNs(context.Background())
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestRefreshDoesNotBlockOrEvictConcurrentSave(t *testing.T) {
	isolateASNState(t)
	started, release := make(chan struct{}), make(chan struct{})
	targetcfg.ASNClient = &http.Client{Transport: asnRoundTrip(func(*http.Request) (*http.Response, error) {
		close(started)
		<-release
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(
			`{"data":{"prefixes":[{"prefix":"192.0.2.0/24"}]}}`))}, nil
	})}
	targetcfg.ASNPrefixes.Prefixes[13335] = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	targetcfg.Current.Set(targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"AS13335"}}}, targetcfg.Scope{})
	done := make(chan struct{})
	go func() {
		targetcfg.RefreshASNs(context.Background())
		close(done)
	}()
	<-started
	saved := make(chan struct{})
	go func() {
		targetcfg.ChangeMu.Lock()
		targetcfg.ASNPrefixes.Mu.Lock()
		targetcfg.ASNPrefixes.Prefixes[64500] = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
		targetcfg.ASNPrefixes.Mu.Unlock()
		targetcfg.Current.Set(targetcfg.Config{Scan: targetcfg.ScanConfig{Allow: []string{"AS64500"}}}, targetcfg.Scope{})
		targetcfg.ChangeMu.Unlock()
		close(saved)
	}()
	select {
	case <-saved:
	case <-time.After(100 * time.Millisecond):
		close(release)
		<-done
		t.Fatal("refresh held configMu during its request")
	}
	close(release)
	<-done
	if _, ok := targetcfg.ASNPrefixes.Lookup(64500); !ok {
		t.Fatal("refresh evicted the ASN added by a concurrent save")
	}
	if _, ok := targetcfg.ASNPrefixes.Lookup(13335); ok {
		t.Fatal("refresh kept an ASN removed during its request")
	}
}

// A scope cannot be built with an ASN that has never been resolved, so the reload that would
// name a newly configured one fails on it. asnRefreshLoop resolves from the files first for
// exactly that reason; these run the same two steps in the same order.
func TestNewlyConfiguredASNsResolveWithoutRestart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, targetcfg.Config, string, string) targetcfg.Config
		check  func(targetcfg.Scope) bool
	}{
		{"allow", func(_ *testing.T, cfg targetcfg.Config, _, _ string) targetcfg.Config {
			cfg.Scan.Allow = []string{"AS13335"}
			return cfg
		},
			func(s targetcfg.Scope) bool { return len(s.Allow) == 1 && s.Scannable == 1 }},
		{"deny", func(_ *testing.T, cfg targetcfg.Config, _, _ string) targetcfg.Config {
			cfg.Scan.Deny = []string{"AS13335"}
			return cfg
		},
			func(s targetcfg.Scope) bool { return len(s.Deny) == 1 && s.Scannable == 1 }},
		{"targets", func(t *testing.T, cfg targetcfg.Config, targets, _ string) targetcfg.Config {
			if err := os.WriteFile(targets, []byte(`["AS13335"]`), 0o600); err != nil {
				t.Fatal(err)
			}
			return cfg
		}, func(s targetcfg.Scope) bool { return len(s.Targets) == 1 && s.TargetEntries[0] == "AS13335" }},
		{"feed-only targets", func(t *testing.T, cfg targetcfg.Config, _, feedOnly string) targetcfg.Config {
			cfg.Scan.FeedOnlyTargetsFile = feedOnly
			if err := os.WriteFile(feedOnly, []byte(`["AS13335"]`), 0o600); err != nil {
				t.Fatal(err)
			}
			return cfg
		}, func(s targetcfg.Scope) bool { return len(s.FeedOnly) == 1 && s.FeedOnlyEntries[0] == "AS13335" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateASNState(t)
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				fmt.Fprint(w, `{"data":{"prefixes":[{"prefix":"192.0.2.1/32"}]}}`)
			}))
			t.Cleanup(server.Close)
			targetcfg.RipeAnnouncedPrefixesURL = server.URL + "/?resource=AS"

			dir := t.TempDir()
			targets, feedOnly := filepath.Join(dir, "targets.json"), filepath.Join(dir, "feed-only.json")
			if err := os.WriteFile(targets, []byte(`["192.0.2.1","192.0.2.2"]`), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := targetcfg.LoadConfig(writeConfig(t, targets))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.toml")
			if err := targetcfg.SaveConfig(path, cfg); err != nil {
				t.Fatal(err)
			}
			var local targetcfg.Store
			if err := local.Load(path); err != nil {
				t.Fatal(err)
			}
			cfg = tc.change(t, cfg, targets, feedOnly)
			if err := targetcfg.SaveConfig(path, cfg); err != nil {
				t.Fatal(err)
			}
			// What asnRefreshLoop does on every cycle: resolve what the files name, then reload.
			fresh, err := targetcfg.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := targetcfg.ResolveStartupASNs(context.Background(), fresh, ""); err != nil {
				t.Fatal(err)
			}
			scanner.ReloadOnce(&local, path)
			_, scope := local.Config()
			if requests.Load() != 1 || !tc.check(scope) {
				t.Fatalf("requests = %d, scope = %+v", requests.Load(), scope)
			}
		})
	}
}

func TestFailedASNResolutionKeepsCacheAndScope(t *testing.T) {
	isolateASNState(t)
	serveASN(t, http.StatusBadGateway)
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(targets, []byte(`["192.0.2.1"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := targetcfg.LoadConfig(writeConfig(t, targets))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := targetcfg.SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	var local targetcfg.Store
	if err := local.Load(path); err != nil {
		t.Fatal(err)
	}
	beforeCfg, beforeScope := local.Config()
	cfg.Scan.Allow = []string{"AS13335"}
	if err := targetcfg.SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	fresh, err := targetcfg.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := targetcfg.ResolveStartupASNs(context.Background(), fresh, ""); err == nil {
		t.Fatal("an unreachable RIPEstat resolved anyway")
	}
	scanner.ReloadOnce(&local, path)
	afterCfg, afterScope := local.Config()
	if !reflect.DeepEqual(beforeCfg, afterCfg) || !reflect.DeepEqual(beforeScope, afterScope) {
		t.Fatal("failed ASN resolution replaced the last-good configuration")
	}
	if _, ok := targetcfg.ASNPrefixes.Lookup(13335); ok {
		t.Fatal("failed ASN resolution changed the cache")
	}
}

// The refresh installs the new prefixes before rebuilding the scope through them, so a failure
// after that point has to put the old ones back rather than leave memory ahead of the cache file.
func TestRefreshRollsBackPrefixesWhenTheCacheCannotBeSaved(t *testing.T) {
	isolateASNState(t)
	targetcfg.ASNPrefixes.Prefixes[13335] = mustPrefixes(t, "192.0.2.0/25")
	cfg := targetcfg.Config{Base: targetcfg.BaseConfig{RefreshSeconds: 1}, Scan: targetcfg.ScanConfig{
		Allow: []string{"192.0.2.0/24"}, TargetsFile: "targets.json", ScansPerDay: 1,
	}}
	scope, err := targetcfg.ScopeFromEntries(cfg, []string{"AS13335"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)

	// A regular file where the cache directory belongs, so MkdirAll fails and the save with it.
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	targetcfg.ASNCachePath = filepath.Join(blocked, "asn_prefixes.json")

	serveASN(t, http.StatusOK, "198.51.100.0/24")
	if targetcfg.RefreshASNs(context.Background()) {
		t.Fatal("a refresh that could not be saved reported a change")
	}
	prefixes, _ := targetcfg.ASNPrefixes.Lookup(13335)
	if len(prefixes) != 1 || prefixes[0].String() != "192.0.2.0/25" {
		t.Fatalf("cache = %v, want the prefixes from before the refresh", prefixes)
	}
	if _, current := targetcfg.Current.Config(); !reflect.DeepEqual(scope, current) {
		t.Fatalf("scope = %+v, want it untouched", current)
	}
}

func TestRefreshAtomicallyRebuildsScopeAndAllowsTemporaryZeroTargets(t *testing.T) {
	isolateASNState(t)
	targetcfg.ASNPrefixes.Prefixes[13335] = mustPrefixes(t, "192.0.2.0/25")
	cfg := targetcfg.Config{Base: targetcfg.BaseConfig{RefreshSeconds: 1}, Scan: targetcfg.ScanConfig{
		Allow: []string{"192.0.2.0/24"}, TargetsFile: "targets.json", ScansPerDay: 1,
	}}
	scope, err := targetcfg.ScopeFromEntries(cfg, []string{"AS13335"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	targetcfg.Current.Set(cfg, scope)

	serveASN(t, http.StatusOK, "192.0.2.128/25")
	if !targetcfg.RefreshASNs(context.Background()) {
		t.Fatal("changed prefixes were not reported")
	}
	_, scope = targetcfg.Current.Config()
	prefixes, _ := targetcfg.ASNPrefixes.Lookup(13335)
	stored, err := os.ReadFile(targetcfg.ASNCachePath)
	if err != nil {
		t.Fatal(err)
	}
	if prefixes[0].String() != "192.0.2.128/25" || scope.Targets[0] != prefixes[0] ||
		!strings.Contains(string(stored), "192.0.2.128/25") {
		t.Fatalf("cache = %v, scope = %v, persisted = %s", prefixes, scope.Targets, stored)
	}

	serveASN(t, http.StatusOK, "198.51.100.0/24")
	if !targetcfg.RefreshASNs(context.Background()) {
		t.Fatal("zero-target refresh was rejected")
	}
	if _, scope = targetcfg.Current.Config(); scope.Scannable != 0 {
		t.Fatalf("scannable = %d, want paused scope", scope.Scannable)
	}
	serveASN(t, http.StatusOK, "192.0.2.0/26")
	targetcfg.RefreshASNs(context.Background())
	if _, scope = targetcfg.Current.Config(); scope.Scannable != 64 {
		t.Fatalf("scannable = %d, want resumed scope", scope.Scannable)
	}
}

func TestResolveNewASNsUsesCache(t *testing.T) {
	isolateASNState(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{"data":{"prefixes":[{"prefix":"192.0.2.0/24"}]}}`)
	}))
	t.Cleanup(server.Close)
	targetcfg.RipeAnnouncedPrefixesURL = server.URL + "/?resource=AS"
	targetcfg.ASNPrefixes.Prefixes[13335] = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if err := targetcfg.ResolveNewASNs(context.Background(), []string{"AS13335"}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("cached ASN was fetched")
	}
}

func TestASNCacheRoundTripAndMissingFile(t *testing.T) {
	isolateASNState(t)
	if err := targetcfg.LoadASNCache(); err != nil {
		t.Fatalf("missing cache: %v", err)
	}
	targetcfg.ASNPrefixes.Prefixes[13335] = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if err := targetcfg.SaveASNPrefixes(targetcfg.ASNPrefixes.Prefixes); err != nil {
		t.Fatal(err)
	}
	targetcfg.ASNPrefixes.Prefixes = map[uint32][]netip.Prefix{}
	if err := targetcfg.LoadASNCache(); err != nil {
		t.Fatal(err)
	}
	if prefixes, ok := targetcfg.ASNPrefixes.Lookup(13335); !ok || prefixes[0].String() != "192.0.2.0/24" {
		t.Fatalf("round trip = %v, %t", prefixes, ok)
	}
}

func TestTargetFilePreservesASN(t *testing.T) {
	isolateASNState(t)
	targetcfg.ASNPrefixes.Prefixes[13335] = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	path := filepath.Join(t.TempDir(), "targets.json")
	if err := targetcfg.SaveTargets(path, []string{"AS13335"}); err != nil {
		t.Fatal(err)
	}
	entries, err := targetcfg.ReadTargetEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	prefixes, err := targetcfg.ParsePrefixes(entries)
	if err != nil || !reflect.DeepEqual(entries, []string{"AS13335"}) || len(prefixes) != 1 {
		t.Fatalf("entries = %v, prefixes = %v, err = %v", entries, prefixes, err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "AS13335") || strings.Contains(string(data), "192.0.2.0/24") {
		t.Fatalf("target file = %s", data)
	}
}

func TestTargetFileDeduplicatesCanonicalASNsButKeepsCoveredLiterals(t *testing.T) {
	isolateASNState(t)
	targetcfg.ASNPrefixes.Prefixes[13335] = mustPrefixes(t, "192.0.2.0/24")
	targetcfg.ASNPrefixes.Prefixes[64500] = mustPrefixes(t, "198.51.100.0/24")
	entries, err := targetcfg.ExpandEntries([]string{"AS13335", "as13335", "AS013335", "192.0.2.1", "AS64500"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"AS13335", "192.0.2.1/32", "AS64500"}
	if got := targetcfg.EntryValues(entries); !reflect.DeepEqual(got, want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
}

// EntryValues normalizes what the dashboard writes, but a hand-edited file never goes through it.
// The scope has to do its own deduplication or the Targets page shows one ASN three times.
func TestTargetFileOnDiskDeduplicatesRepeatedEntries(t *testing.T) {
	isolateASNState(t)
	targetcfg.ASNPrefixes.Prefixes[13335] = mustPrefixes(t, "192.0.2.0/25")
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.json")
	if err := os.WriteFile(targets,
		[]byte(`["AS13335","as13335","AS013335","192.0.2.5","192.0.2.5"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := targetcfg.LoadConfig(writeConfig(t, targets))
	if err != nil {
		t.Fatal(err)
	}
	scope, err := targetcfg.LoadScope(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The covered literal survives: only repeats go. Dropping it here would lose the covered_by
	// row the Targets page draws, which is entryValues' job on save and not this one.
	want := []string{"AS13335", "192.0.2.5/32"}
	if !reflect.DeepEqual(scope.TargetEntries, want) {
		t.Fatalf("entries = %v, want %v", scope.TargetEntries, want)
	}
	if scope.Scannable != 128 {
		t.Fatalf("scannable = %d, want 128", scope.Scannable)
	}
}

// scan.allow and scan.deny are hand-written lists, so they get the same treatment as the target
// files: a repeat is one entry, however it was spelled.
func TestAllowAndDenyDeduplicateRepeatedEntries(t *testing.T) {
	isolateASNState(t)
	targets := filepath.Join(t.TempDir(), "targets.json")
	if err := os.WriteFile(targets, []byte(`["192.0.2.1"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, targets,
		[2]string{`allow = ["192.0.2.0/24"]`,
			"allow = [\"192.0.2.0/24\", \"192.0.2.0/24\", \"AS13335\", \"as13335\", \"AS013335\"]\n" +
				"deny = [\"192.0.2.1\", \"192.0.2.1/32\"]"})
	cfg, err := targetcfg.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// The first spelling survives; nothing is rewritten behind the operator's back.
	if want := []string{"192.0.2.0/24", "AS13335"}; !reflect.DeepEqual(cfg.Scan.Allow, want) {
		t.Fatalf("allow = %v, want %v", cfg.Scan.Allow, want)
	}
	if want := []string{"192.0.2.1"}; !reflect.DeepEqual(cfg.Scan.Deny, want) {
		t.Fatalf("deny = %v, want %v", cfg.Scan.Deny, want)
	}
}

func TestOneShotASNResolutionIgnoresConfiguredTargetFiles(t *testing.T) {
	isolateASNState(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{"data":{"prefixes":[{"prefix":"192.0.2.0/24"}]}}`)
	}))
	t.Cleanup(server.Close)
	targetcfg.RipeAnnouncedPrefixesURL = server.URL + "/?resource=AS"
	dir := t.TempDir()
	malformed := filepath.Join(dir, "malformed.json")
	if err := os.WriteFile(malformed, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{
		Allow: []string{"192.0.2.0/24"}, TargetsFile: filepath.Join(dir, "missing.json"),
		FeedOnlyTargetsFile: malformed,
	}}
	if err := targetcfg.ResolveStartupASNs(context.Background(), cfg, "AS13335"); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want one ASN lookup", requests.Load())
	}
}

func TestTargetsBodyKeepsUnresolvedASNVisible(t *testing.T) {
	isolateASNState(t)
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	targetcfg.Current.Set(targetcfg.Config{Scan: targetcfg.ScanConfig{TargetsFile: "targets.json"}}, targetcfg.Scope{
		Targets:       []netip.Prefix{prefix},
		Allow:         []netip.Prefix{prefix},
		TargetEntries: []string{"AS64500", "192.0.2.0/24"},
	})
	rows, ok := targetsBody(false)["targets"].([]targetRow)
	if !ok || len(rows) != 2 {
		t.Fatalf("target rows = %#v", targetsBody(false)["targets"])
	}
	if rows[0].Value != "AS64500" || rows[0].Addresses != 0 || len(rows[0].Expansion) != 0 || rows[0].Status != "unresolved" {
		t.Fatalf("unresolved row = %+v", rows[0])
	}
}

func TestTargetsBodyShowsASNCoverageAndPrefixStatusesWithoutChangingFile(t *testing.T) {
	isolateASNState(t)
	targetcfg.ASNPrefixes.Prefixes[13335] = mustPrefixes(t, "192.0.2.0/24", "198.51.100.0/24")
	values := []string{"AS13335", "192.0.2.128/25", "198.51.100.0/23"}
	entries, err := targetcfg.ExpandEntries(values)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "targets.json")
	if err := targetcfg.SaveTargets(path, targetcfg.EntryValues(entries)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved []string
	if err := json.Unmarshal(before, &saved); err != nil || !reflect.DeepEqual(saved, values) {
		t.Fatalf("saved targets = %v, %v; want covered literal preserved", saved, err)
	}
	cfg := targetcfg.Config{Scan: targetcfg.ScanConfig{TargetsFile: path, Deny: []string{"198.51.100.0/24"}}}
	scope := targetcfg.Scope{
		TargetEntries: values,
		Targets:       mustPrefixes(t, "192.0.2.0/24", "198.51.100.0/23"),
		Allow:         mustPrefixes(t, "192.0.2.0/24", "198.51.100.0/23"),
		Deny:          mustPrefixes(t, "198.51.100.0/24"),
	}
	targetcfg.Current.Set(cfg, scope)

	rows := targetsBody(false)["targets"].([]targetRow)
	if rows[0].Status != "partially in scope" {
		t.Fatalf("ASN status = %q, want partially in scope", rows[0].Status)
	}
	if rows[1].Status != "covered" || rows[1].CoveredBy != "AS13335" {
		t.Fatalf("covered literal = %+v", rows[1])
	}
	if rows[2].Status == "covered" || rows[2].CoveredBy != "" {
		t.Fatalf("partly covered literal = %+v", rows[2])
	}
	wantStatuses := []string{"in scope", "denied"}
	if len(rows[0].Expansion) != len(wantStatuses) {
		t.Fatalf("ASN expansion = %+v", rows[0].Expansion)
	}
	for i, want := range wantStatuses {
		if rows[0].Expansion[i].Status != want {
			t.Errorf("prefix %s status = %q, want %q", rows[0].Expansion[i].Value, rows[0].Expansion[i].Status, want)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) || !strings.Contains(string(after), "192.0.2.128/25") {
		t.Fatalf("covered display changed targets file: %s", after)
	}
}

// Two subtractions narrow a feed-only entry and only one of them is a scope problem. The allow
// and deny lists decide how much of a target is authorized at all; the active targets file only
// decides which authorized addresses the sweep handles instead of feed matching. Conflating them
// is what makes an ordinary overlapping setup cry "partially in scope".
func TestFeedOnlyStatusSeparatesNarrowAllowFromActiveOverlap(t *testing.T) {
	announced := func(t *testing.T) []netip.Prefix {
		return mustPrefixes(t, "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
	}
	seed := func(t *testing.T, targets, allow []netip.Prefix) []targetRow {
		t.Helper()
		targetcfg.ASNPrefixes.Prefixes[13335] = announced(t)
		targetcfg.Current.Set(
			targetcfg.Config{Scan: targetcfg.ScanConfig{TargetsFile: "t.json", FeedOnlyTargetsFile: "f.json"}},
			targetcfg.Scope{Targets: targets, TargetEntries: []string{"targets"}, FeedOnly: announced(t),
				FeedOnlyEntries: []string{"AS13335"}, Allow: allow},
		)
		return targetsBody(true)["targets"].([]targetRow)
	}

	// An allow entry narrower than the announced prefix authorizes 4 of its 256 addresses. The row
	// carries 256 next to the status, so "in scope" would be a straight contradiction.
	t.Run("allow narrower than the prefix is partial", func(t *testing.T) {
		isolateASNState(t)
		rows := seed(t, mustPrefixes(t, "198.51.100.0/24"),
			mustPrefixes(t, "192.0.2.0/30", "198.51.100.0/24", "203.0.113.0/24"))
		if rows[0].Status != "partially in scope" {
			t.Fatalf("entry = %q, want partially in scope", rows[0].Status)
		}
		if got := rows[0].Expansion[0].Status; got != "partially in scope" {
			t.Errorf("192.0.2.0/24 = %q, want partially in scope", got)
		}
	})

	// Every announced prefix is authorized in full; the sweep simply handles half of one of them.
	// That is the documented precedence between the two files, so nothing here is partial.
	t.Run("active targets taking part of a prefix is not partial", func(t *testing.T) {
		isolateASNState(t)
		rows := seed(t, mustPrefixes(t, "192.0.2.0/25"), announced(t))
		if rows[0].Status != "in scope" {
			t.Fatalf("entry = %q, want in scope", rows[0].Status)
		}
		for _, prefix := range rows[0].Expansion {
			if prefix.Status != "in scope" {
				t.Errorf("%s = %q, want in scope", prefix.Value, prefix.Status)
			}
		}
	})

	// And a prefix the sweep covers outright still drops out of feed-only matching entirely.
	t.Run("active targets covering a prefix whole is actively scanned", func(t *testing.T) {
		isolateASNState(t)
		rows := seed(t, mustPrefixes(t, "192.0.2.0/24"), announced(t))
		if got := rows[0].Expansion[0].Status; got != "actively scanned" {
			t.Errorf("192.0.2.0/24 = %q, want actively scanned", got)
		}
	})
}

func TestSettingsASNAllowChangesScopeAndFetchFailuresAreNamed(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		isolateASNState(t)
		serveASN(t, http.StatusOK, "192.0.2.0/26")
		seedSettings(t)
		cfg, _ := getSettings(t)
		cfg.Scan.Allow = []string{"AS13335"}
		body, _ := json.Marshal(cfg)
		recorder := putSettings(t, string(body), "application/json")
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", recorder.Code, recorder.Body)
		}
		if _, scope := targetcfg.Current.Config(); scope.Scannable != 64 {
			t.Fatalf("scannable = %d, want 64", scope.Scannable)
		}
	})
	t.Run("failure", func(t *testing.T) {
		isolateASNState(t)
		serveASN(t, http.StatusBadGateway)
		seedSettings(t)
		cfg, _ := getSettings(t)
		cfg.Scan.Allow = []string{"AS13335"}
		body, _ := json.Marshal(cfg)
		recorder := putSettings(t, string(body), "application/json")
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "AS13335") {
			t.Fatalf("status = %d, body = %q", recorder.Code, recorder.Body.String())
		}
	})
}

func TestValidateConfigRequiresASNRefreshFloor(t *testing.T) {
	cfg, err := targetcfg.LoadConfig(writeConfig(t, "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []int{0, 14} {
		cfg.Scan.ASNRefreshMinutes = value
		if err := targetcfg.ValidateConfig(cfg); err == nil {
			t.Errorf("accepted %d minutes", value)
		}
	}
}
