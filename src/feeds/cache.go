package feeds

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"iocscanner/src/parse"
	targetcfg "iocscanner/src/targets"
)

// The upstream threat-feed endpoints. Variables so tests can point them at a stub server.
var (
	ThreatFoxURL        = "https://threatfox-api.abuse.ch/api/v1/"
	FeodoURL            = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
	SSLBLIPURL          = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"
	SSLBLCertURL        = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
	TweetFeedURL        = "https://api.tweetfeed.live/v1/week"
	PhishingArmyURL     = "https://phishing.army/download/phishing_army_blocklist.txt"
	URLHausURL          = "https://urlhaus.abuse.ch/downloads/json_recent"
	C2IntelURL          = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2swithURLwithIP.csv"
	ThreatViewC2URL     = "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt"
	ThreatViewDomainURL = "https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt"
	ThreatViewURL       = "https://threatview.io/Downloads/URL-High-Confidence-Feed.txt"
)

const RefreshInterval = 15 * time.Minute

const (
	PhishingArmySource = "phishing_army"
	URLHausSource      = "urlhaus"
	C2IntelSource      = "c2intel"
	ThreatViewSource   = "threatview"
)

// Indicator is a normalised feed entry and report reason. Value is its lookup key; FirstSeen is
// the feed's relevant RFC3339 date and empty for local certificate checks.
type Indicator struct {
	Source          string `json:"source"`
	Value           string `json:"value"`
	Tag             string `json:"tag"`
	FirstSeen       string `json:"first_seen,omitempty"`
	Link            string `json:"link,omitempty"`
	ConfidenceLevel *int   `json:"confidence_level,omitempty"`
	// Soft marks a heuristic: suggestive on its own, not evidence. A feed naming the address or
	// the certificate is never soft, which is why the zero value is the right default for one
	// rebuilt from a stored match. Off the wire, and so out of the acknowledgement signature: the
	// dashboard reads the band this produces, not the flag behind it.
	Soft bool `json:"-"`
}

// Current is the process's feed state. That is the index the port scan reads, plus the last
// good result of each feed. A pointer because feeds embeds a mutex and must never be copied.
var Current = &Cache{
	Client:   &http.Client{Timeout: 30 * time.Second},
	LastGood: map[string][]Indicator{},
}

// Cache fetches the threat feeds, retaining the last good result of each.
type Cache struct {
	Client *http.Client

	// mu guards every field below. index is read by the port-scan goroutine, so it is swapped
	// wholesale under the lock rather than mutated in place. lastGood has one writer today but
	// is locked anyway, so a second refresh caller cannot race it later on.
	mu       sync.RWMutex
	LastGood map[string][]Indicator
	// tried is the feeds attempted on the last refresh, in index order. A feed skipped for want
	// of a key is not on it, so its stale lastGood entry never re-enters the index.
	Tried []string
	Index map[string][]Indicator
	// reachable out of attempted on the last refresh. Kept here rather than returned from
	// fetchAllFeeds so a caller can ask how healthy the feeds are without refetching them.
	reachable, attempted int
}

// Reachability reports how many feeds answered on the last refresh, out of how many were tried.
// A feed skipped for want of a key is neither.
func (f *Cache) Reachability() (reachable, attempted int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.reachable, f.attempted
}

// Lookup returns feed entries indexed by an IP, domain, certificate SHA-1, or JARM hash.
func (f *Cache) Lookup(key string) []Indicator {
	// Never let an empty feed value match an empty probe field.
	if key == "" {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.Index[key]
}

// Counts returns how many distinct addresses each visible source's last good result
// holds. Taken under the lock: lastGood is rewritten by every refresh, and reading it from
// a dashboard handler without one is a data race.
func (f *Cache) Counts() map[string]int {
	// Read before the lock: feeds.mu must never be held across store.mu.
	cfg, _ := targetcfg.Current.Config()
	f.mu.RLock()
	defer f.mu.RUnlock()
	bySource := make(map[string]map[string]bool, len(f.LastGood))
	for name, indicators := range f.LastGood {
		source := name
		if strings.HasPrefix(name, "threatview_") {
			source = ThreatViewSource
		}
		if bySource[source] == nil {
			bySource[source] = map[string]bool{}
		}
		for _, indicator := range indicators {
			if IgnoredFeedValue(indicator.Value, cfg.Feeds.DomainIgnorelist) {
				continue
			}
			bySource[source][indicatorAddress(indicator.Value)] = true
		}
	}
	counts := make(map[string]int, len(bySource))
	for source, indicators := range bySource {
		counts[source] = len(indicators)
	}
	return counts
}

func RegistrableDomainSource(source string) bool {
	return source == PhishingArmySource || source == URLHausSource || source == C2IntelSource || source == ThreatViewSource
}

func C2IntelDomainMatchesIP(source, tag, ip string) bool {
	return source != C2IntelSource || !strings.HasPrefix(tag, "Domain — ") ||
		strings.HasSuffix(tag, " — IP "+ip)
}

// indicatorAddress drops the port from an ip:port indicator. Feeds list one address on several
// Ports; the analytics page counts matches per address, so its list size has to count the same way.
func indicatorAddress(value string) string {
	if addr, ok := parse.AddrOf(value); ok {
		return addr.String()
	}
	return value
}

// Indicators returns the current feed index as a flat snapshot, without fetching.
func (f *Cache) Indicators() []Indicator {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var indicators []Indicator
	for _, hits := range f.Index {
		indicators = append(indicators, hits...)
	}
	return indicators
}

// BuildIndex keys ip:port indicators by address and everything else by its value.
func BuildIndex(indicators []Indicator) map[string][]Indicator {
	set := make(map[string][]Indicator, len(indicators))
	for _, indicator := range indicators {
		key := indicatorAddress(indicator.Value)
		set[key] = append(set[key], indicator)
	}
	return set
}

// activeIndicators is every attempted feed's last good result with ignored domains removed.
// Caller holds f.mu.
func (f *Cache) activeIndicators(ignorelist []string) []Indicator {
	var all []Indicator
	for _, name := range f.Tried {
		all = append(all, f.LastGood[name]...)
	}
	return slices.DeleteFunc(all, func(indicator Indicator) bool {
		return IgnoredFeedValue(indicator.Value, ignorelist)
	})
}

// RebuildIndex re-applies the current domain ignorelist without refetching the feeds.
func (f *Cache) RebuildIndex() {
	// Read before the lock: feeds.mu must never be held across store.mu.
	cfg, _ := targetcfg.Current.Config()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Index = BuildIndex(f.activeIndicators(cfg.Feeds.DomainIgnorelist))
}

// Refresh fetches every feed once, rebuilds the lookup index, and returns all
// indicators. A feed that fails keeps its last good result, so a transient outage doesn't
// blank the list.
func (f *Cache) Refresh(ctx context.Context) []Indicator {
	sources := []struct {
		name  string
		fetch func(context.Context) ([]Indicator, error)
	}{
		{"threatfox", f.FetchThreatFox},
		{"feodo", f.FetchFeodo},
		{"sslbl", f.FetchSSLBL},
		{"sslbl_cert", f.FetchSSLBLCerts},
		{"tweetfeed", f.fetchTweetFeed},
		{PhishingArmySource, f.fetchPhishingArmy},
		{URLHausSource, f.fetchURLHaus},
		{C2IntelSource, f.fetchC2Intel},
		{"threatview_cobaltstrike", f.fetchThreatViewC2},
		{"threatview_domain", f.fetchThreatViewDomains},
		{"threatview_url", f.fetchThreatViewURLs},
	}
	cfg, _ := targetcfg.Current.Config()
	var reachable, attempted int

	// Fetch without the lock so network delays do not stall the sweep and dashboard.
	fetched := make(map[string][]Indicator, len(sources))
	// The feeds that were tried, in order. A skipped feed is not on it, so it contributes
	// nothing to the index even if it left a last good result behind from an earlier run.
	tried := make([]string, 0, len(sources))
	for _, source := range sources {
		// ThreatFox needs an auth key. Skip it rather than fail the whole refresh.
		if source.name == "threatfox" && cfg.Feeds.ThreatFoxAuthKey == "" {
			slog.Warn("skipping threatfox feed", "reason", "feeds.threatfox_auth_key is not set")
			continue
		}
		attempted++
		tried = append(tried, source.name)
		indicators, err := source.fetch(ctx)
		if err != nil {
			var partial *FeedValidation
			if !errors.As(err, &partial) {
				slog.Error("feed refresh failed", "feed", source.name, "err", err)
				continue
			}
			slog.Warn("feed refresh partially accepted", "feed", source.name,
				"skipped", partial.Skipped, "first_error", partial.first)
		}
		reachable++
		fetched[source.name] = indicators
	}

	// One write, at the end. A feed that failed is absent from fetched and keeps whatever
	// lastGood already held for it.
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, name := range tried {
		if indicators, ok := fetched[name]; ok {
			f.LastGood[name] = indicators
		}
	}
	f.Tried = tried
	all := f.activeIndicators(cfg.Feeds.DomainIgnorelist)
	f.Index = BuildIndex(all)
	f.reachable, f.attempted = reachable, attempted
	return all
}

// feedTimeLayouts are the UTC timestamp shapes published by the feeds.
var feedTimeLayouts = []string{"2006-01-02 15:04:05 UTC", "2006-01-02 15:04:05", "02 January 2006 03:04 PM UTC"}

// IgnoredFeedValue reports whether a feed value sits under an ignored registrable domain. The
// ignorelist is passed in rather than read here: callers loop over whole result sets, and a
// settings save landing mid-loop would otherwise filter later rows against a different list.
func IgnoredFeedValue(value string, ignorelist []string) bool {
	domain, ok := parse.RegistrableDomain(value)
	return ok && slices.Contains(ignorelist, domain)
}
