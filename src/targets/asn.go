package targets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"iocscanner/src/httpclient"
	"iocscanner/src/parse"
)

// A bare number would be indistinguishable from a mistyped address.
var asnEntry = regexp.MustCompile(`(?i)^as([0-9]{1,10})$`)

// ASNClient uses the same timeout and default transport as upstream feed requests.
var ASNClient = &http.Client{Timeout: 30 * time.Second}

var RipeAnnouncedPrefixesURL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS"

var ASNCachePath = filepath.Join("db", "asn_prefixes.json")

type ASNCache struct {
	Mu       sync.RWMutex
	Prefixes map[uint32][]netip.Prefix
}

var ASNPrefixes = &ASNCache{Prefixes: map[uint32][]netip.Prefix{}}

func ParseASN(value string) (uint32, bool) {
	match := asnEntry.FindStringSubmatch(value)
	if match == nil {
		return 0, false
	}
	asn, err := strconv.ParseUint(match[1], 10, 32)
	return uint32(asn), err == nil
}

func (c *ASNCache) Lookup(asn uint32) ([]netip.Prefix, bool) {
	c.Mu.RLock()
	defer c.Mu.RUnlock()
	prefixes, ok := c.Prefixes[asn]
	return slices.Clone(prefixes), ok
}

func AnnouncedPrefixes(ctx context.Context, asn uint32) ([]netip.Prefix, error) {
	body, err := httpclient.Get(ctx, ASNClient, RipeAnnouncedPrefixesURL+strconv.FormatUint(uint64(asn), 10))
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var response struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := parse.JSON(io.LimitReader(body, 32<<20), &response); err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	for _, row := range response.Data.Prefixes {
		prefix, ok, err := parse.ParseIPv4Prefix(row.Prefix)
		if err != nil {
			return nil, err
		}
		if ok {
			prefixes = append(prefixes, prefix)
		}
	}
	prefixes = parse.DedupePrefixes(prefixes)
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("AS%d announces no IPv4 prefixes", asn)
	}
	return prefixes, nil
}

// referencedASNs is every ASN the live config and scope name. Only those: an ASN a scope cannot
// be built with is resolved by asnRefreshLoop before this runs.
func referencedASNs(cfg Config, s Scope) []uint32 {
	seen := map[uint32]bool{}
	var result []uint32
	for _, value := range slices.Concat(cfg.Scan.Allow, cfg.Scan.Deny, s.TargetEntries, s.FeedOnlyEntries) {
		if asn, ok := ParseASN(strings.TrimSpace(value)); ok && !seen[asn] {
			seen[asn] = true
			result = append(result, asn)
		}
	}
	return result
}

func RefreshASNs(ctx context.Context) bool {
	cfg, scope := Current.Config()
	ASNPrefixes.Mu.RLock()
	previous := cloneASNPrefixes(ASNPrefixes.Prefixes)
	ASNPrefixes.Mu.RUnlock()

	refreshed := make(map[uint32][]netip.Prefix)
	for _, asn := range referencedASNs(cfg, scope) {
		prefixes, err := AnnouncedPrefixes(ctx, asn)
		if err != nil {
			slog.Warn("ASN prefix refresh failed", "asn", fmt.Sprintf("AS%d", asn), "err", err)
			if cached, ok := previous[asn]; ok {
				refreshed[asn] = cached
			}
			continue
		}
		refreshed[asn] = prefixes
	}

	ChangeMu.Lock()
	defer ChangeMu.Unlock()
	cfg, scope = Current.Config()
	referenced := map[uint32]bool{}
	for _, asn := range referencedASNs(cfg, scope) {
		referenced[asn] = true
	}
	ASNPrefixes.Mu.RLock()
	current := cloneASNPrefixes(ASNPrefixes.Prefixes)
	ASNPrefixes.Mu.RUnlock()
	for asn := range refreshed {
		if !referenced[asn] {
			delete(refreshed, asn)
		}
	}
	for asn, prefixes := range current {
		_, existedBeforeRefresh := previous[asn]
		if _, fetched := refreshed[asn]; !fetched && (referenced[asn] || !existedBeforeRefresh) {
			refreshed[asn] = prefixes
		}
	}
	// Installed before the scope is rebuilt, so the rebuild resolves the new prefixes through the
	// ordinary lookup. Rolled back if the rebuild or the save fails, leaving the cache as it was.
	committed := false
	ASNPrefixes.Mu.Lock()
	ASNPrefixes.Prefixes = refreshed
	ASNPrefixes.Mu.Unlock()
	defer func() {
		if committed {
			return
		}
		ASNPrefixes.Mu.Lock()
		ASNPrefixes.Prefixes = current
		ASNPrefixes.Mu.Unlock()
	}()
	var nextScope Scope
	scopeChanged := false
	if len(scope.TargetEntries) != 0 {
		var err error
		// Empty is allowed: a refresh that leaves nothing in scope pauses scanning from the next
		// pass rather than keeping prefixes the ASN no longer announces.
		nextScope, err = ScopeFromEntries(cfg, scope.TargetEntries, scope.FeedOnlyEntries, true)
		if err != nil {
			slog.Warn("rebuilding scope after ASN refresh failed", "err", err)
			return false
		}
		scopeChanged = !reflect.DeepEqual(scope, nextScope)
	}
	if err := SaveASNPrefixes(refreshed); err != nil {
		slog.Warn("saving ASN prefix cache failed", "err", err)
		return false
	}
	committed = true
	if len(scope.TargetEntries) != 0 {
		Current.Set(cfg, nextScope)
	}
	return !reflect.DeepEqual(current, refreshed) || scopeChanged
}

func ASNRefreshLoop(ctx context.Context) {
	for {
		// Newly configured ASNs first. refreshASNs only revisits what the live config and scope
		// already name, and neither can name an ASN that blocks the scope's construction — so an
		// ASN hand-added to config.toml or a targets file would never resolve, and every reload
		// would fail on it until a restart. Read from the file for the same reason.
		if cfg, err := LoadConfig(Path); err == nil {
			if err := ResolveStartupASNs(ctx, cfg, ""); err != nil {
				slog.Warn("resolving newly configured ASNs failed", "err", err)
			}
		}
		if RefreshASNs(ctx) {
			slog.Info("asn prefixes refreshed")
		}
		cfg, _ := Current.Config()
		timer := time.NewTimer(time.Duration(cfg.Scan.ASNRefreshMinutes) * time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func cloneASNPrefixes(source map[uint32][]netip.Prefix) map[uint32][]netip.Prefix {
	copy := make(map[uint32][]netip.Prefix, len(source))
	for asn, prefixes := range source {
		copy[asn] = slices.Clone(prefixes)
	}
	return copy
}

func LoadASNCache() error {
	data, err := os.ReadFile(ASNCachePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var stored map[string][]string
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("invalid ASN prefix cache: %w", err)
	}
	loaded := make(map[uint32][]netip.Prefix, len(stored))
	for rawASN, values := range stored {
		asn64, err := strconv.ParseUint(rawASN, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid ASN prefix cache key %q", rawASN)
		}
		prefixes := make([]netip.Prefix, 0, len(values))
		for _, value := range values {
			prefix, err := parse.ParsePrefix(value)
			if err != nil {
				return fmt.Errorf("invalid ASN prefix cache entry %q", rawASN)
			}
			prefixes = append(prefixes, prefix)
		}
		prefixes = parse.DedupePrefixes(prefixes)
		if len(prefixes) == 0 {
			return fmt.Errorf("invalid ASN prefix cache entry %q", rawASN)
		}
		loaded[uint32(asn64)] = prefixes
	}
	ASNPrefixes.Mu.Lock()
	ASNPrefixes.Prefixes = loaded
	ASNPrefixes.Mu.Unlock()
	return nil
}

func SaveASNPrefixes(prefixes map[uint32][]netip.Prefix) error {
	stored := make(map[string][]string, len(prefixes))
	for asn, announced := range prefixes {
		values := make([]string, len(announced))
		for i, prefix := range announced {
			values[i] = prefix.String()
		}
		stored[strconv.FormatUint(uint64(asn), 10)] = values
	}
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ASNCachePath), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(ASNCachePath, append(data, '\n'))
}

func ResolveNewASNs(ctx context.Context, values []string) error {
	seen := map[uint32]bool{}
	resolved := map[uint32][]netip.Prefix{}
	for _, value := range values {
		asn, ok := ParseASN(strings.TrimSpace(value))
		if !ok || seen[asn] {
			continue
		}
		seen[asn] = true
		if _, ok := ASNPrefixes.Lookup(asn); ok {
			continue
		}
		prefixes, err := AnnouncedPrefixes(ctx, asn)
		if err != nil {
			return fmt.Errorf("AS%d: %w", asn, err)
		}
		resolved[asn] = prefixes
	}
	if len(resolved) == 0 {
		return nil
	}
	ChangeMu.Lock()
	defer ChangeMu.Unlock()
	ASNPrefixes.Mu.RLock()
	next := cloneASNPrefixes(ASNPrefixes.Prefixes)
	ASNPrefixes.Mu.RUnlock()
	for asn, prefixes := range resolved {
		if _, exists := next[asn]; !exists {
			next[asn] = prefixes
		}
	}
	if err := SaveASNPrefixes(next); err != nil {
		return err
	}
	ASNPrefixes.Mu.Lock()
	ASNPrefixes.Prefixes = next
	ASNPrefixes.Mu.Unlock()
	return nil
}

func ResolveStartupASNs(ctx context.Context, cfg Config, scan string) error {
	values := slices.Concat(cfg.Scan.Allow, cfg.Scan.Deny)
	if scan != "" {
		return ResolveNewASNs(ctx, append(values, scan))
	}
	targets, err := ReadTargetEntries(cfg.Scan.TargetsFile)
	if err != nil {
		return fmt.Errorf("targets file %s: %w", cfg.Scan.TargetsFile, err)
	}
	values = append(values, targets...)
	if cfg.Scan.FeedOnlyTargetsFile != "" {
		feedOnly, err := ReadTargetEntries(cfg.Scan.FeedOnlyTargetsFile)
		if err != nil {
			return fmt.Errorf("feed-only targets file %s: %w", cfg.Scan.FeedOnlyTargetsFile, err)
		}
		values = append(values, feedOnly...)
	}
	return ResolveNewASNs(ctx, values)
}
