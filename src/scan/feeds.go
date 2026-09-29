package scan

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	storage "iocscanner/src/db"
	"iocscanner/src/feeds"
	"iocscanner/src/logging"
	"iocscanner/src/parse"
	targetcfg "iocscanner/src/targets"
)

// MatchTargetsAgainstFeedsLoop re-runs the feed match every refreshInterval until cancelled.
func MatchTargetsAgainstFeedsLoop(ctx context.Context) {
	ticker := time.NewTicker(feeds.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		MatchTargetsAgainstFeeds(ctx)
	}
}

// MatchTargetsAgainstFeeds fetches every feed, rebuilds the lookup index the port scan reads,
// alerts on every authorized target found in a feed, and upserts those matches.
func MatchTargetsAgainstFeeds(ctx context.Context) {
	_, s := targetcfg.Current.Config()
	// A scope with nothing left in it makes the line below report zero matches, which reads exactly
	// like a quiet day. Warned every cycle rather than once: it is a state, not an event, and the
	// sweep's own pause notice does not cover feed matching.
	if s.Scannable == 0 && s.FeedOnlyScannable == 0 {
		slog.Warn("no authorized targets: feed matching can find nothing")
	}
	// Log before the network requests so their delay is visible.
	slog.Info("refreshing feeds")
	indicators := feeds.Current.Refresh(ctx)
	rows := MatchFeedHits(ctx, s, indicators)
	reachable, attempted := feeds.Current.Reachability()
	slog.Info("feeds refreshed", "feeds", fmt.Sprintf("%d/%d", reachable, attempted),
		"indicators", len(indicators), "matches", len(rows))
}

// MatchFeedHits checks one scope against the supplied feed snapshot, alerts on every hit, and
// persists them.
func MatchFeedHits(ctx context.Context, s targetcfg.Scope, indicators []feeds.Indicator) []storage.Match {
	rows := FeedHitsInScope(s, indicators, time.Now().Unix())
	// Alerted before the save, so a database failure can't swallow the hits.
	for _, row := range rows {
		// Always high. A feed naming the address is evidence, not a heuristic.
		args := []any{"ip", row.IP, "feed_only", row.FeedOnly, "band", "high", "source", row.Source, "tag", row.Tag, "indicator", row.Value}
		if row.FirstSeen != "" {
			args = append(args, feeds.FeedDateLabel(row.Source), row.FirstSeen)
		}
		logging.Alert("feed match", args...)
	}
	persistFeedHits(ctx, rows)
	return rows
}

// persistFeedHits stores a set of hits. Split from the alerting so a re-check against a scope that
// just changed can save what it finds without announcing hits the operator was already told about.
func persistFeedHits(ctx context.Context, rows []storage.Match) {
	storage.Enqueue(nil, rows)
	// Waited on rather than left queued. The caller reports this check as complete immediately,
	// so there is nothing to gain by batching it with anything else.
	storage.FlushWrites()
	// A hit landing on an acknowledged host invalidates its acknowledgement, and that row has to go
	// now rather than at the next sweep: a full pass can run for hours, and an indicator that drops
	// off the feed inside that window would leave the row to silently re-apply.
	if err := RetireStaleAcks(context.WithoutCancel(ctx)); err != nil {
		slog.Error("retiring stale acknowledgements failed", "err", err)
	}
}

// FeedHitsInScope returns one deduplicated row per feed hit on an authorized target IP.
func FeedHitsInScope(s targetcfg.Scope, indicators []feeds.Indicator, seenAt int64) []storage.Match {
	var rows []storage.Match
	for _, indicator := range indicators {
		// Only address and address:port indicators can match scan scope.
		addr, ok := parse.AddrOf(indicator.Value)
		if !ok {
			continue
		}
		feedOnly := s.ContainsFeedOnly(addr)
		if !s.Contains(addr) && !feedOnly {
			continue
		}
		rows = append(rows, storage.Match{
			IP:              addr.String(),
			Source:          indicator.Source,
			Value:           indicator.Value,
			Tag:             indicator.Tag,
			FirstSeen:       indicator.FirstSeen,
			ConfidenceLevel: indicator.ConfidenceLevel,
			SeenAt:          seenAt,
			FeedOnly:        feedOnly,
		})
	}
	// Sort and dedupe so the upsert batch is deterministic and the match count is honest. Feeds
	// do repeat an ip:port across refreshes.
	slices.SortStableFunc(rows, func(a, b storage.Match) int {
		return cmp.Or(cmp.Compare(a.IP, b.IP), cmp.Compare(a.Source, b.Source), cmp.Compare(a.Value, b.Value))
	})
	return slices.CompactFunc(rows, func(a, b storage.Match) bool {
		return a.IP == b.IP && a.Source == b.Source && a.Value == b.Value
	})
}
