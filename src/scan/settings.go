package scan

import (
	"context"
	"log/slog"
	"reflect"
	"slices"
	"time"

	storage "iocscanner/src/db"
	"iocscanner/src/feeds"
	"iocscanner/src/parse"
	targetcfg "iocscanner/src/targets"
)

// ApplyDomainIgnorelistChange re-indexes the feeds and refreshes everything derived from stored
// scans. db is nil before openDB and in the tests that never open one.
func ApplyDomainIgnorelistChange(ctx context.Context) error {
	feeds.Current.RebuildIndex()
	if storage.Handle == nil {
		return nil
	}
	return ApplyStoredResultChange(ctx)
}

// ReloadOnce re-reads the config and returns the refresh interval to run with. A reload that
// changed nothing stays silent. One that changed something logs the new scope, so an operator
// gets confirmation the edit landed instead of only hearing about failures.
func ReloadOnce(s *targetcfg.Store, path string) time.Duration {
	// Held across the read and the swap, so a dashboard write landing mid-reload cannot be
	// overwritten by the config this tick read before it.
	targetcfg.ChangeMu.Lock()
	defer targetcfg.ChangeMu.Unlock()
	before, beforeScope := s.Config()
	if err := s.Load(path); err != nil {
		slog.Error("config reload failed", "err", err) // keep the last good config
		return time.Duration(before.Base.RefreshSeconds) * time.Second
	}
	cfg, scope := s.Config()
	interval := time.Duration(cfg.Base.RefreshSeconds) * time.Second
	if reflect.DeepEqual(before, cfg) && reflect.DeepEqual(beforeScope, scope) {
		return interval
	}
	attrs := []any{"targets", parse.HostCount(scope.Targets), "allow", parse.HostCount(scope.Allow), "deny", parse.HostCount(scope.Deny)}
	if cfg.Scan.FeedOnlyTargetsFile != "" {
		attrs = append(attrs, "feed_only_targets", parse.HostCount(scope.FeedOnly))
	}
	if cfg.Base.RefreshSeconds != before.Base.RefreshSeconds {
		attrs = append(attrs, "interval", interval)
	}
	if !slices.Equal(cfg.Feeds.DomainIgnorelist, before.Feeds.DomainIgnorelist) {
		attrs = append(attrs, "ignored_domains", len(cfg.Feeds.DomainIgnorelist))
		if err := ApplyDomainIgnorelistChange(context.Background()); err != nil {
			slog.Error("applying domain ignorelist failed", "err", err)
		}
	}
	slog.Info("config reloaded", attrs...)
	return interval
}

// ReloadConfigLoop re-reads the config every refresh_seconds until ctx is cancelled, so edits
// to the allow/deny lists and the targets file take effect without a restart.
func ReloadConfigLoop(ctx context.Context, path string) {
	cfg, _ := targetcfg.Current.Config()
	interval := time.Duration(cfg.Base.RefreshSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		// A changed refresh_seconds applies without a restart too.
		if next := ReloadOnce(&targetcfg.Current, path); next != interval {
			interval = next
			ticker.Reset(interval)
		}
	}
}

// ApplyStoredResultChange refreshes state derived from stored scans after a local rule changes.
func ApplyStoredResultChange(ctx context.Context) error {
	if err := RetireStaleAcks(ctx); err != nil {
		return err
	}
	_, err := WriteReport(ctx, ReportPath)
	return err
}

// RematchFeeds re-checks the cached indicators against a scope that just changed. The feed refresh
// reads the scope at tick time, and a feed-only target has nothing else that would fill it in — no
// probe, no sweep — so without this a saved target matches nothing for up to a refresh interval
// even though the answer is already cached. No network: the index is the one already fetched.
//
// Persisted without alerting. Every hit here was already announced when its feed was fetched, and
// re-announcing the whole set on each save buries the new ones. Synchronous, so the response that
// follows already reflects the rows.
func RematchFeeds(ctx context.Context, scope targetcfg.Scope) {
	if storage.Handle == nil {
		return
	}
	persistFeedHits(ctx, FeedHitsInScope(scope, feeds.Current.Indicators(), time.Now().Unix()))
}
