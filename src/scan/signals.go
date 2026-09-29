package scan

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	storage "iocscanner/src/db"
	"iocscanner/src/feeds"
	"iocscanner/src/logging"
	"iocscanner/src/parse"
)

// ProbeSignals finds feed hits for a port's fingerprint, JARM hash, and certificate names.
func ProbeSignals(row storage.Scan) []feeds.Indicator {
	// Concat avoids writing into the index's own slices.
	hits := slices.Concat(feeds.Current.Lookup(row.Fingerprint), feeds.Current.Lookup(row.JARM),
		BlacklistIndicators(row.JARM))
	// Some C2 certificates put the domain only in the common name.
	for _, name := range append(strings.Split(row.DNSNames, ","), row.Subject) {
		name = parse.NormalizeName(name)
		for _, hit := range feeds.Current.Lookup(name) {
			if feeds.C2IntelDomainMatchesIP(hit.Source, hit.Tag, row.IP) {
				hits = append(hits, hit)
			}
		}
		if domain, ok := parse.RegistrableDomain(name); ok && domain != name {
			for _, hit := range feeds.Current.Lookup(domain) {
				if feeds.RegistrableDomainSource(hit.Source) && feeds.C2IntelDomainMatchesIP(hit.Source, hit.Tag, row.IP) {
					hits = append(hits, hit)
				}
			}
		}
	}
	return UniqueIndicators(hits)
}

func UniqueIndicators(signals []feeds.Indicator) []feeds.Indicator {
	unique := signals[:0]
	// ponytail: signal lists are tiny; use a map if a port can accumulate hundreds of hits.
	for _, signal := range signals {
		if !slices.ContainsFunc(unique, func(existing feeds.Indicator) bool { return sameIndicator(existing, signal) }) {
			unique = append(unique, signal)
		}
	}
	return unique
}

// sameIndicator compares two indicators by value. Indicator holds a pointer, so == on its own
// compares that pointer's identity rather than the score behind it.
func sameIndicator(a, b feeds.Indicator) bool {
	ac, bc := a.ConfidenceLevel, b.ConfidenceLevel
	a.ConfidenceLevel, b.ConfidenceLevel = nil, nil
	return a == b && (ac == bc || ac != nil && bc != nil && *ac == *bc)
}

// CertSignals runs the certificate checks over one probe result. The value carried is always the
// fingerprint. It identifies the certificate a signal fired on.
func CertSignals(row storage.Scan) []feeds.Indicator {
	// No fingerprint means no certificate was collected. That is an open port not speaking TLS,
	// whose zeroed date fields would otherwise read as a zero-length validity window.
	if row.Fingerprint == "" {
		return nil
	}
	var signals []feeds.Indicator
	if row.SelfSigned {
		signals = append(signals, feeds.Indicator{Soft: true, Source: "self_signed", Value: row.Fingerprint, Tag: "self-signed certificate", FirstSeen: "", Link: ""})
	}
	now := time.Now()
	if row.NotAfter < now.Unix() {
		signals = append(signals, feeds.Indicator{Soft: true, Source: "expired_cert", Value: row.Fingerprint, Tag: "expired certificate", FirstSeen: "", Link: ""})
	}
	if time.Unix(row.NotAfter, 0).After(time.Unix(row.NotBefore, 0).AddDate(10, 0, 0)) {
		signals = append(signals, feeds.Indicator{Soft: true, Source: "long_validity", Value: row.Fingerprint, Tag: "certificate validity exceeds 10 years", FirstSeen: "", Link: ""})
	}
	validity := row.NotAfter - row.NotBefore
	age := now.Unix() - row.NotBefore
	if row.DNSNames == "" && (validity < int64(shortValidity/time.Second) ||
		(age >= 0 && age < int64(freshlyIssued/time.Second))) {
		signals = append(signals, feeds.Indicator{Soft: true, Source: "cert_validity", Value: row.Fingerprint, Tag: "short-lived or freshly issued certificate on a bare IP", FirstSeen: "", Link: ""})
	}
	return signals
}

// Band ranks a host by the strongest signal that fired, so 400 flagged hosts have a triage order
// instead of 400 equal-weight lines. Each signal states its own weight, so a heuristic added later
// cannot be banded HIGH by being left off a list somewhere else.
func Band(why []feeds.Indicator) string {
	for _, hit := range why {
		if !hit.Soft {
			return "high"
		}
	}
	return "low"
}

// ProbeVerdict is what one probe result means: the signals that fired, the band they add up to,
// and the probe-derived hits to store. An empty band means nothing fired.
type ProbeVerdict struct {
	Band    string
	why     []feeds.Indicator
	Matches []storage.Match
}

// ClassifyProbe decides what one probe result means. It reads the feed index, the JARM list and
// the public-suffix list, owns nothing, and writes nothing — so a sweep can run max_workers of
// these at once, outside the lock that guards its tallies.
func ClassifyProbe(row storage.Scan) ProbeVerdict {
	probeHits := ProbeSignals(row)
	// Concat rather than append. indicatorsFor returns the map's own slice, which append could
	// write into.
	why := slices.Concat(feeds.Current.Lookup(row.IP), probeHits, CertSignals(row))
	if len(why) == 0 {
		return ProbeVerdict{}
	}
	matches := make([]storage.Match, 0, len(probeHits))
	for _, hit := range probeHits {
		matches = append(matches, storage.Match{IP: row.IP, Source: hit.Source, Value: hit.Value,
			Tag: hit.Tag, FirstSeen: hit.FirstSeen, ConfidenceLevel: hit.ConfidenceLevel, SeenAt: row.ScannedAt})
	}
	return ProbeVerdict{Band: Band(why), why: why, Matches: matches}
}

// AlertProbe announces one classified probe. Split from classifyProbe because this writes a line
// to stderr, and a sweep must not hold its lock across a slow terminal.
func AlertProbe(row storage.Scan, verdict ProbeVerdict) {
	why := verdict.why
	if len(why) == 0 {
		slog.Debug("open port", "ip", row.IP, "port", row.Port)
		return
	}
	// A feed listing several ports of one host repeats the same source and tag once per entry, and
	// the line names only those two. Collapse them to one reason carrying the earliest listing
	// date. The stamps are RFC3339 UTC, so the earliest is the smallest string.
	earliest := map[string]string{}
	var order []string
	for _, hit := range why {
		reason := fmt.Sprintf("%s (%s)", hit.Source, hit.Tag)
		stamp, seen := earliest[reason]
		if !seen {
			order = append(order, reason)
		}
		// Only a feed hit carries a stamp. A certificate check fired on this scan, not a record.
		if hit.FirstSeen != "" && (stamp == "" || hit.FirstSeen < stamp) {
			stamp = hit.FirstSeen
		}
		earliest[reason] = stamp
	}
	reasons := make([]string, 0, len(order))
	for _, reason := range order {
		if stamp := earliest[reason]; stamp != "" {
			source := reason[:strings.IndexByte(reason, ' ')]
			reason += " " + strings.ReplaceAll(feeds.FeedDateLabel(source), "_", " ") + " " + stamp
		}
		reasons = append(reasons, reason)
	}
	expires := ""
	if row.Fingerprint != "" || row.NotAfter != 0 {
		expires = time.Unix(row.NotAfter, 0).UTC().Format(time.DateOnly)
		if row.NotAfter < time.Now().Unix() {
			expires += " (expired)"
		}
	}
	// Empty certificate fields are dropped by the handler rather than logged blank.
	logging.Alert("suspicious host",
		"target", fmt.Sprintf("%s:%d", row.IP, row.Port),
		"band", verdict.Band,
		"reasons", strings.Join(reasons, ", "),
		"subject", row.Subject,
		"issuer", row.Issuer,
		"sans", row.DNSNames,
		"expires", expires,
		"sigalg", row.SignatureAlgorithm,
		"sha1", row.Fingerprint,
		"jarm", row.JARM)
}

const (
	// shortValidity is the window under which a certificate looks minted for one campaign
	// rather than issued for a service.
	shortValidity = 30 * 24 * time.Hour
	// freshlyIssued is how recently minted still counts as fresh.
	freshlyIssued = 7 * 24 * time.Hour
)

// BlacklistIndicators turns a stored JARM label into a scanner signal.
func BlacklistIndicators(hash string) []feeds.Indicator {
	if hash == "" {
		return nil
	}
	label, ok := storage.JARMBlacklist.Label(hash)
	if !ok {
		return nil
	}
	return []feeds.Indicator{{Source: storage.JARMBlacklistSource, Value: hash, Tag: label}}
}
