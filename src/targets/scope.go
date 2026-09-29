package targets

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"iocscanner/src/parse"
)

// Scope is the authorized address space. Targets, narrowed to allow, minus deny.
type Scope struct {
	Targets, FeedOnly, Allow, Deny []netip.Prefix
	TargetEntries, FeedOnlyEntries []string
	// scannable is what scannableHosts counts, held because that walk is one step per address
	// and the dashboard asks for the figure on every poll. Set by newScope, so it is filled in
	// on every scope that reaches the network.
	Scannable, FeedOnlyScannable int
}

// Contains reports whether addr is an authorized target.
func (s Scope) Contains(addr netip.Addr) bool {
	return addr.Is4() && parse.AnyContains(s.Targets, addr) && parse.AnyContains(s.Allow, addr) && !parse.AnyContains(s.Deny, addr)
}

// ContainsFeedOnly reports whether addr is authorized for direct feed matching but not scanning.
// Active wins when the two target files overlap.
func (s Scope) ContainsFeedOnly(addr netip.Addr) bool {
	return addr.Is4() && parse.AnyContains(s.FeedOnly, addr) && parse.AnyContains(s.Allow, addr) &&
		!parse.AnyContains(s.Deny, addr) && !s.Contains(addr)
}

// AuthorizedAddrs yields every authorized target address. An iterator rather than a slice, so a
// large target prefix isn't materialised just to be walked once.
func (s Scope) AuthorizedAddrs(yield func(netip.Addr) bool) {
	for _, prefix := range s.Targets {
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			if s.Contains(addr) && !yield(addr) {
				return
			}
		}
	}
}

// ScannableHosts counts the addresses a sweep would probe: the targets narrowed by allow and deny.
func ScannableHosts(s Scope) int {
	return s.countHosts(s.Targets, s.Deny)
}

// FeedOnlyHosts counts the addresses matched against the feeds but never probed. Active targets
// win where the two files overlap, so they are excluded alongside the denylist. The guard is what
// keeps an unconfigured deployment from building that exclusion list on every scope load.
func FeedOnlyHosts(s Scope) int {
	if len(s.FeedOnly) == 0 {
		return 0
	}
	return s.countHosts(s.FeedOnly, s.FeedOnlyExcluded())
}

// countHosts sums authorizedCount over a list of targets.
func (s Scope) countHosts(targets, excluded []netip.Prefix) int {
	total := 0
	for _, prefix := range targets {
		total += s.authorizedCount(prefix, excluded)
	}
	return total
}

// authorizedCount returns how many addresses of target survive the allowlist minus excluded.
// Prefix arithmetic rather than a walk, so a /0 costs a handful of comparisons instead of four
// billion address checks. Both lists are disjoint — parsePrefixes dedupes and so does the caller
// that concatenates them — so the intersections sum and subtract without overlapping each other.
func (s Scope) authorizedCount(target netip.Prefix, excluded []netip.Prefix) int {
	total := 0
	for _, allow := range s.Allow {
		allowed, ok := parse.Overlap(target, allow)
		if !ok {
			continue
		}
		left := 1 << (32 - allowed.Bits())
		for _, skip := range excluded {
			if covered, ok := parse.Overlap(allowed, skip); ok {
				left -= 1 << (32 - covered.Bits())
			}
		}
		total += max(left, 0)
	}
	return total
}

type TargetEntry struct {
	Value    string
	Prefixes []netip.Prefix
}

func ExpandEntries(values []string) ([]TargetEntry, error) {
	entries := make([]TargetEntry, 0, len(values))
	for _, value := range values {
		if asn, ok := ParseASN(strings.TrimSpace(value)); ok {
			prefixes, found := ASNPrefixes.Lookup(asn)
			if !found {
				return nil, fmt.Errorf("AS%d has not been resolved yet", asn)
			}
			entries = append(entries, TargetEntry{Value: fmt.Sprintf("AS%d", asn), Prefixes: prefixes})
			continue
		}
		prefix, err := parse.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		entries = append(entries, TargetEntry{Value: prefix.String(), Prefixes: []netip.Prefix{prefix}})
	}
	return entries, nil
}

func EntryValues(entries []TargetEntry) []string {
	values := make([]string, 0, len(entries))
	kept := map[string]bool{}
	seenASNs := map[uint32]bool{}
	var literals []netip.Prefix
	for _, entry := range entries {
		if _, ok := ParseASN(entry.Value); !ok {
			literals = append(literals, entry.Prefixes[0])
		}
	}
	for _, prefix := range parse.DedupePrefixes(literals) {
		kept[prefix.String()] = true
	}
	// ASN entries survive overlaps: their announcements can change independently of literals.
	for _, entry := range entries {
		if asn, ok := ParseASN(entry.Value); ok {
			if !seenASNs[asn] {
				values = append(values, entry.Value)
				seenASNs[asn] = true
			}
			continue
		}
		if kept[entry.Value] {
			values = append(values, entry.Value)
			delete(kept, entry.Value)
		}
	}
	return values
}

// DedupeEntries drops entries repeating one already listed, comparing canonical spellings so
// AS13335 and as13335 are one entry. The first spelling survives, and anything that will not parse
// is passed through untouched for the scope build to reject by name. Used on the config's
// Allow and deny lists; the target files go through canonicalEntries with the scope.
func DedupeEntries(values []string) []string {
	// Nil in, nil out: an absent deny list must not become an empty one.
	var kept []string
	seen := map[string]bool{}
	for _, value := range values {
		key := strings.TrimSpace(value)
		if asn, ok := ParseASN(key); ok {
			key = fmt.Sprintf("AS%d", asn)
		} else if prefix, err := parse.ParsePrefix(value); err == nil {
			key = prefix.String()
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, value)
	}
	return kept
}

// canonicalEntries returns the entry list with repeat spellings dropped, and the prefixes those
// entries cover. Both come from one expansion, so a file listing AS13335 twice — or as as13335 and
// AS013335 — is one entry and one target, the same way the prefixes have always deduplicated.
func canonicalEntries(values []string) ([]string, []netip.Prefix, error) {
	entries, err := ExpandEntries(values)
	if err != nil {
		return nil, nil, err
	}
	canonical := make([]string, 0, len(entries))
	seen := map[string]bool{}
	var prefixes []netip.Prefix
	for _, entry := range entries {
		if seen[entry.Value] {
			continue
		}
		seen[entry.Value] = true
		canonical = append(canonical, entry.Value)
		prefixes = append(prefixes, entry.Prefixes...)
	}
	return canonical, parse.DedupePrefixes(prefixes), nil
}

// ParsePrefixes turns IPv4 addresses, CIDRs and cached ASNs into masked, deduplicated prefixes.
func ParsePrefixes(values []string) ([]netip.Prefix, error) {
	entries, err := ExpandEntries(values)
	if err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	for _, entry := range entries {
		prefixes = append(prefixes, entry.Prefixes...)
	}
	return parse.DedupePrefixes(prefixes), nil
}

func ReadTargetEntries(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("failed to parse targets file: %w", err)
	}
	return values, nil
}

// LoadScope reads the active and optional feed-only target files and applies the shared guardrail.
func LoadScope(cfg Config) (Scope, error) {
	targetEntries, err := ReadTargetEntries(cfg.Scan.TargetsFile)
	if err != nil {
		return Scope{}, fmt.Errorf("targets file %s: %w", cfg.Scan.TargetsFile, err)
	}
	var feedOnlyEntries []string
	if cfg.Scan.FeedOnlyTargetsFile != "" {
		feedOnlyEntries, err = ReadTargetEntries(cfg.Scan.FeedOnlyTargetsFile)
		if err != nil {
			return Scope{}, fmt.Errorf("feed-only targets file %s: %w", cfg.Scan.FeedOnlyTargetsFile, err)
		}
	}
	return ScopeFromEntries(cfg, targetEntries, feedOnlyEntries, false)
}

// ScopeFromEntries builds a scope from already-read target entries. allowEmpty tolerates a scope
// where nothing survives allow and deny: an ASN refresh installs one so scanning pauses, where a
// reload or a -scan argument has to fail instead.
func ScopeFromEntries(cfg Config, targetEntries, feedOnlyEntries []string, allowEmpty bool) (Scope, error) {
	entries, targets, err := canonicalEntries(targetEntries)
	if err != nil {
		return Scope{}, fmt.Errorf("targets file %s: %w", cfg.Scan.TargetsFile, err)
	}
	if len(targets) == 0 {
		return Scope{}, fmt.Errorf("targets file %s contains no valid targets", cfg.Scan.TargetsFile)
	}
	s, err := newScopeWith(cfg, targets, allowEmpty)
	s.TargetEntries = entries
	if err != nil || cfg.Scan.FeedOnlyTargetsFile == "" {
		return s, err
	}
	s.FeedOnlyEntries, s.FeedOnly, err = canonicalEntries(feedOnlyEntries)
	if err != nil {
		return Scope{}, fmt.Errorf("feed-only targets file %s: %w", cfg.Scan.FeedOnlyTargetsFile, err)
	}
	s.FeedOnlyScannable = FeedOnlyHosts(s)
	return s, nil
}

// CheckFeedOnly refuses a feed-only list where nothing survives allow, deny and the active
// Targets. Saving one is a silent no-op otherwise: the file keeps the entries and no feed hit
// ever matches them. The dashboard's own edits go through this; a file already on disk does not,
// so a reload is never blocked by a list that merely matches nothing.
func CheckFeedOnly(s Scope) error {
	if len(s.FeedOnly) > 0 && s.FeedOnlyScannable == 0 {
		return errors.New("all feed-only targets are out of scope, denied, or already active targets")
	}
	return nil
}

// SaveTargets replaces the targets file with its normalized entries, preserving ASNs.
func SaveTargets(path string, entries []string) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'))
}

// Status describes what the scanner would do with one target: the allow and deny lists narrow the
// Targets file, so an entry can be listed and never probed. Answered per prefix rather than per
// address, since a target can cover millions of them.
func (s Scope) Status(target netip.Prefix) string {
	if !slices.ContainsFunc(s.Allow, target.Overlaps) {
		return "out of scope"
	}
	// Counted rather than tested for a single survivor. An allow entry narrower than the target
	// leaves most of it unscanned, and "in scope" sitting beside the target's full address count
	// is exactly where that goes unnoticed.
	authorized := s.authorizedCount(target, s.Deny)
	if authorized == 0 {
		return "denied"
	}
	if authorized < parse.HostCount([]netip.Prefix{target}) {
		return "partially in scope"
	}
	return "in scope"
}

// FeedOnlyStatus describes what feed matching does with one feed-only prefix. Active targets win
// where the two files overlap, so a prefix the sweep already covers is reported as scanned rather
// than as an in-scope feed-only entry that will never produce a row.
func (s Scope) FeedOnlyStatus(target netip.Prefix, excluded []netip.Prefix) string {
	status := s.Status(target)
	if status != "in scope" && status != "partially in scope" {
		return status
	}
	// Whether anything survives the active targets, never how much of it. The sweep taking part of
	// a feed-only prefix is the documented precedence between the two files, not a narrower scope.
	if s.authorizedCount(target, excluded) == 0 {
		return "actively scanned"
	}
	return status
}

func EntryStatus(s Scope, entry TargetEntry, excluded []netip.Prefix) string {
	status := "out of scope"
	inScope, partial := 0, 0
	for _, prefix := range entry.Prefixes {
		current := s.Status(prefix)
		if excluded != nil {
			current = s.FeedOnlyStatus(prefix, excluded)
		}
		if current == "in scope" {
			inScope++
			continue
		}
		if current == "partially in scope" {
			partial++
			continue
		}
		if current == "actively scanned" && status != "denied" {
			status = current
		}
		if current == "denied" {
			status = current
		}
	}
	if partial == 0 && inScope > 0 && inScope == len(entry.Prefixes) {
		return "in scope"
	}
	if inScope+partial > 0 {
		return "partially in scope"
	}
	return status
}

// FeedOnlyExcluded is what feed-only matching subtracts: the denylist plus the active targets.
func (s Scope) FeedOnlyExcluded() []netip.Prefix {
	return parse.DedupePrefixes(slices.Concat(s.Deny, s.Targets))
}

// HasAuthorizedAddr reports whether any part of target survives allow minus deny.
func (s Scope) HasAuthorizedAddr(target netip.Prefix) bool {
	return s.authorizedCount(target, s.Deny) > 0
}

// NewScope narrows targets by the config's allow/deny lists. It refuses to run unless at least one
// target survives both. The targets file and an on-demand -scan argument both come through here,
// so neither path can reach the network with the guardrail skipped.
func NewScope(cfg Config, targets []netip.Prefix) (Scope, error) {
	s, err := newScopeWith(cfg, targets, false)
	// The targets are the entries here: nothing named them by ASN. scopeFromEntries has the
	// original spellings and sets its own.
	for _, prefix := range targets {
		s.TargetEntries = append(s.TargetEntries, prefix.String())
	}
	return s, err
}

func newScopeWith(cfg Config, targets []netip.Prefix, allowEmpty bool) (Scope, error) {
	var err error
	s := Scope{Targets: targets}
	if s.Allow, err = ParsePrefixes(cfg.Scan.Allow); err != nil {
		return s, fmt.Errorf("invalid scan.allow entry: %w", err)
	}
	if s.Deny, err = ParsePrefixes(cfg.Scan.Deny); err != nil {
		return s, fmt.Errorf("invalid scan.deny entry: %w", err)
	}
	// Check with prefix arithmetic before scannableHosts walks the targets. A rejected /0 must not
	// cost four billion address checks just to prove that the denylist covers it.
	if !allowEmpty && !slices.ContainsFunc(s.Targets, s.HasAuthorizedAddr) {
		return s, errors.New("all targets are out of scope or denied")
	}
	s.Scannable = ScannableHosts(s)
	return s, nil
}

// NewManualScope rejects a partial scan instead of silently trimming it to the allow/deny lists.
// Ad-hoc targets may be absent from the targets file, but every address still has to be authorized.
// A feed-only address is allowed: the sweep leaves it alone, and asking for one by hand is how an
// operator gets ports and a certificate for it. The results land on the complete host table, which
// is the side project puts every hand-scanned address on — a sweep's own rows do not
// move a host, but asking for one by name does.
func NewManualScope(cfg Config, targets []netip.Prefix) (Scope, error) {
	s, err := NewScope(cfg, targets)
	if err != nil || s.Scannable != parse.HostCount(targets) {
		return Scope{}, errors.New("every target must be within scan.allow and outside scan.deny")
	}
	return s, nil
}
