package scan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	storage "iocscanner/src/db"
	"iocscanner/src/feeds"
	"iocscanner/src/parse"
	targetcfg "iocscanner/src/targets"
)

// ReportPath is where the JSON report is written, empty for stdout. Assigned once from the
// -output flag before any goroutine starts.
var ReportPath string

// CLIScan is the -scan argument, empty in sweep mode. Assigned alongside reportPath.
var CLIScan string

// ReportHost is one flagged host.
type ReportHost struct {
	IP           string            `json:"ip"`
	OpenTLSPorts []int             `json:"open_tls_ports"`
	Signals      []feeds.Indicator `json:"signals"`
	Band         string            `json:"band"`
	CheckedAt    string            `json:"checked_at"`
}

// ReportSummary tallies hosts by what fired on them. It serves both the report's cumulative
// figures and the per-pass tally a sweep counts as it probes.
type ReportSummary struct {
	LiveTLSHosts int
	High, Low    int
	// Acked counts hosts an operator has dealt with. They leave High and Low, which is the point
	// of acknowledging one: the tallies are the queue, not a lifetime total.
	Acked int
}

// PortView is one open port and whatever fired on it. Empty signals on a port carrying a
// fingerprint means the certificate passed every check.
type PortView struct {
	storage.Scan
	Signals []feeds.Indicator `json:"signals"`
	Band    string            `json:"band"`
}

// HostView is one observed host, flagged or not. The report keeps only the flagged ones; the
// dashboard shows them all, which is where the host counts come from.
type HostView struct {
	IP    string     `json:"ip"`
	Ports []PortView `json:"ports"`
	// PortCount is how many ports the host actually has open. Ports is truncated on its way out
	// to the dashboard, so it is not always the length of that slice.
	PortCount int `json:"port_count"`
	// Signals is every signal on the host and its ports, deduped.
	Signals []feeds.Indicator `json:"signals"`
	// Band is "high" or "low", empty when nothing fired, "ack" once an operator has dealt with
	// the host and nothing has changed since.
	Band      string `json:"band"`
	CheckedAt int64  `json:"checked_at"`
	// Manual is the origin of the newest port result for this host.
	Manual bool `json:"manual"`
	// LiveTLS is set once any port completed a handshake.
	LiveTLS bool `json:"live_tls"`
	// FeedOnly is internal: it separates the two projections and marks the ack signature. Nothing
	// on the wire reads it.
	FeedOnly bool `json:"-"`
}

// AckSignature records the target state an operator acknowledged. Observation metadata is omitted
// so checking the same state again does not retire the acknowledgement.
func AckSignature(host HostView) string {
	// Only feed-only hosts carry the marker. An active host's signature is unchanged by the
	// feature existing, so acknowledgements stored before it was added still hold.
	var parts []string
	if host.FeedOnly {
		parts = append(parts, "feed_only=true")
	}
	for _, port := range host.Ports {
		port.ScannedAt, port.FullScannedAt, port.Manual = 0, 0, false
		port.Signals = stableIndicators(port.Signals)
		encoded, _ := json.Marshal(port)
		parts = append(parts, "port "+string(encoded))
	}
	for _, signal := range stableIndicators(host.Signals) {
		encoded, _ := json.Marshal(signal)
		parts = append(parts, "signal "+string(encoded))
	}
	slices.Sort(parts)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(parts, "\n"))))
}

func stableIndicators(signals []feeds.Indicator) []feeds.Indicator {
	stable := slices.Clone(signals)
	for i := range stable {
		stable[i].FirstSeen, stable[i].Link, stable[i].ConfidenceLevel = "", "", nil
	}
	slices.SortFunc(stable, func(a, b feeds.Indicator) int {
		return strings.Compare(a.Source+"\x00"+a.Value+"\x00"+a.Tag, b.Source+"\x00"+b.Value+"\x00"+b.Tag)
	})
	return stable
}

// ackHolds is the single ACK rule: the target state must be unchanged.
func ackHolds(host HostView, signature string) bool {
	return AckSignature(host) == signature
}

// Projection selects which view of the stored rows to build. These three are the whole set: the
// pair of booleans they replace had a fourth combination no caller could reach.
type Projection int

const (
	// activeOpen is the host table: currently open ports on addresses the sweep covers.
	ActiveOpen Projection = iota
	// activeHistory is the same addresses with every stored port, open or not. Analytics applies
	// its own window to them, so the live open/closed state must not filter them first.
	ActiveHistory
	// feedOnlyMatches is the feed-only table: matches on addresses matched but never probed.
	FeedOnlyMatches
)

// Findings re-runs the checks over every stored scan and feed match and returns one entry per
// host. Built from the stored rows, not from the pass that just ran, so it covers everything found
// so far and not only the ports of the last sweep.
func Findings(ctx context.Context, p Projection) ([]HostView, ReportSummary, error) {
	data, err := storage.CurrentHostState(ctx)
	if err != nil {
		return nil, ReportSummary{}, err
	}
	hosts, summary := Project(data, p)
	return hosts, summary, nil
}

func directFeedValue(ip, value string) bool {
	addr, ok := parse.AddrOf(value)
	return ok && addr.String() == ip
}

func scanCarriesValue(row storage.Scan, value string) bool {
	if value == row.Fingerprint || value == row.JARM {
		return value != ""
	}
	for _, raw := range append(strings.Split(row.DNSNames, ","), row.Subject) {
		name := parse.NormalizeName(raw)
		if value == name {
			return true
		}
		if domain, ok := parse.RegistrableDomain(name); ok && value == domain {
			return true
		}
	}
	return false
}

// Project builds one view of the stored rows. Nothing is on the feed-only side until something is
// listed there — a configured file, or a -scan -feed-only argument — so that projection is skipped
// entirely rather than run over an empty scope.
func Project(data storage.HostData, p Projection) ([]HostView, ReportSummary) {
	feedOnly := p == FeedOnlyMatches
	// Every projection but the analytics one shows the current surface. History keeps closed ports
	// and the feed hits that name something no longer live.
	openOnly := p != ActiveHistory
	var summary ReportSummary
	cfg, scope := targetcfg.Current.Config()
	if feedOnly && len(scope.FeedOnly) == 0 {
		return []HostView{}, ReportSummary{}
	}
	acks := make(map[string]string, len(data.Acks))
	for _, row := range data.Acks {
		acks[row.IP] = row.Signature
	}
	// Which side a host belongs to is the current scope's answer, with one deliberate exception:
	// an address an operator scanned by hand belongs on the host table whichever list it is on,
	// because that scan produced ports and a certificate and the feed-only table has no column to
	// show them.
	//
	// Only a hand-scan counts. The sweep's own rows get no vote: they are never deleted, so
	// counting those would pin an address demoted to the feed-only list on the host table for
	// good, however long ago it was swept. A hand-scan is the operator asking for this host by
	// name, which is the difference that earns the exception.
	manuallyProbed := make(map[string]bool, len(data.Manual)+len(data.Scans))
	observed := make(map[string]bool, len(data.Manual)+len(data.Scans))
	// Kept as a stamp as well as a flag: a hand-scan that found no open port is the only record
	// that the address was checked at all, so it has to supply the origin and the last-checked
	// time the port rows would otherwise carry.
	handScannedAt := make(map[string]int64, len(data.Manual))
	for _, row := range data.Manual {
		manuallyProbed[row.IP] = true
		observed[row.IP] = true
		handScannedAt[row.IP] = max(handScannedAt[row.IP], row.ScannedAt)
	}
	// Also from the scan rows themselves, which is where the fact lived before manual_scans
	// existed. A database written by an older build still moves its hand-scanned hosts.
	for _, row := range data.Scans {
		observed[row.IP] = true
		if row.Manual {
			manuallyProbed[row.IP] = true
		}
	}
	// Asked once per address rather than once per row: the loops below put the same question to
	// the same handful of addresses, and each answer walks the scope's prefix lists.
	side := map[string]bool{}
	isFeedOnly := func(ip string) bool {
		answer, asked := side[ip]
		if !asked {
			answer = !manuallyProbed[ip] && scope.ContainsFeedOnly(parse.AddrOrZero(ip))
			side[ip] = answer
		}
		return answer
	}
	// Grouped by host. A feed hit names the address, and would otherwise be counted once per
	// open port. The feed-only view is built from matches alone, so every scan row belongs to the
	// other side.
	byIP := map[string][]storage.Scan{}
	if !feedOnly {
		for _, row := range data.Scans {
			// Sweep results for an address since moved to the feed-only list are frozen history:
			// off the host table, since the host now lives on the other one, but still in the
			// historical projection, which applies its own window to them.
			if openOnly && (!row.IsOpen || isFeedOnly(row.IP)) {
				continue
			}
			byIP[row.IP] = append(byIP[row.IP], row)
		}
	}
	// One config read for the whole report, so every row is filtered against the same ignorelist.
	matchesByIP := map[string][]storage.Match{}
	for _, row := range data.Matches {
		if isFeedOnly(row.IP) != feedOnly ||
			(!feedOnly && openOnly && !scope.Contains(parse.AddrOrZero(row.IP)) && !observed[row.IP]) ||
			feeds.IgnoredFeedValue(row.Value, cfg.Feeds.DomainIgnorelist) {
			continue
		}
		matchesByIP[row.IP] = append(matchesByIP[row.IP], row)
	}
	order := make([]string, 0, len(byIP)+len(matchesByIP))
	for ip := range byIP {
		order = append(order, ip)
	}
	for ip := range matchesByIP {
		visible := !openOnly || slices.ContainsFunc(matchesByIP[ip], func(row storage.Match) bool {
			return directFeedValue(ip, row.Value)
		})
		if _, scanned := byIP[ip]; !scanned && visible {
			order = append(order, ip)
		}
	}
	slices.Sort(order)

	hosts := make([]HostView, 0, len(order))
	for _, ip := range order {
		host := HostView{IP: ip, Ports: make([]PortView, 0, len(byIP[ip])), FeedOnly: feedOnly}
		// A feed-only host's reasons are its stored matches. The live index belongs to the
		// addresses the scanner probes, and every ip here is on one side or the other: the two
		// loops above already sorted them by the same question.
		feedSignals := []feeds.Indicator{}
		if !feedOnly {
			feedSignals = slices.Clone(feeds.Current.Lookup(ip))
		}
		for _, match := range matchesByIP[ip] {
			if !feeds.C2IntelDomainMatchesIP(match.Source, match.Tag, ip) {
				continue
			}
			if openOnly && !directFeedValue(ip, match.Value) &&
				!slices.ContainsFunc(byIP[ip], func(row storage.Scan) bool { return scanCarriesValue(row, match.Value) }) {
				continue
			}
			duplicate := slices.IndexFunc(feedSignals, func(hit feeds.Indicator) bool {
				return hit.Source == match.Source && hit.Value == match.Value && hit.Tag == match.Tag
			})
			if duplicate >= 0 {
				if feedSignals[duplicate].ConfidenceLevel == nil {
					feedSignals[duplicate].ConfidenceLevel = match.ConfidenceLevel
				}
				continue
			}
			signal := feeds.Indicator{Source: match.Source, Value: match.Value, Tag: match.Tag,
				FirstSeen: match.FirstSeen, ConfidenceLevel: match.ConfidenceLevel}
			for _, current := range feeds.Current.Lookup(match.Value) {
				if current.Source == match.Source && current.Value == match.Value && current.Tag == match.Tag {
					signal.Link = current.Link
					break
				}
			}
			feedSignals = append(feedSignals, signal)
		}
		why := feedSignals
		for _, row := range byIP[ip] {
			if row.ScannedAt > host.CheckedAt {
				host.CheckedAt, host.Manual = row.ScannedAt, row.Manual
			}
			port := PortView{Scan: row}
			target := net.JoinHostPort(row.IP, strconv.Itoa(row.Port))
			for _, signal := range feedSignals {
				if signal.Value == target || openOnly && scanCarriesValue(row, signal.Value) {
					port.Signals = append(port.Signals, signal)
				}
			}
			// No fingerprint means the port answered but never completed a handshake. It is
			// still an open port, so it is still listed.
			if row.Fingerprint != "" {
				// Re-run the alert lookups against the current feed index.
				port.Signals = UniqueIndicators(slices.Concat(port.Signals, ProbeSignals(row), CertSignals(row)))
				host.LiveTLS = true
			}
			if len(port.Signals) > 0 {
				port.Band = Band(port.Signals)
			}
			why = slices.Concat(why, port.Signals)
			host.Ports = append(host.Ports, port)
		}
		// Origin and last-checked come from the port rows above, which a hand-scan that found
		// nothing never wrote — so without this such a host reports origin Automatic for an
		// address the sweep never touches, and a last-checked taken from a feed match. The same
		// gap covers a hand-scan that finds the last known port closed: closeScans leaves
		// scanned_at alone, and a closed row is filtered out of this projection anyway.
		//
		// At or after the newest port result, so a later sweep still supersedes the request.
		if at := handScannedAt[ip]; at > 0 && at >= host.CheckedAt {
			host.CheckedAt, host.Manual = at, true
		}
		for _, match := range matchesByIP[ip] {
			host.CheckedAt = max(host.CheckedAt, match.SeenAt)
		}
		host.PortCount = len(host.Ports)
		// Counted before anything is filtered. A host that completed a handshake is live whether
		// or not anything fired on it.
		if host.LiveTLS {
			summary.LiveTLSHosts++
		}
		// The same signal fires on every port of a host, so it arrives here many times over.
		// linear scan, the per-host signal list is a handful of entries.
		// Empty literal, not slices.Clone: why can be nil and host.Signals must serialise as [].
		host.Signals = UniqueIndicators(append([]feeds.Indicator{}, why...))
		if len(host.Signals) > 0 {
			host.Band = Band(why)
		}
		// A stale acknowledgement is ignored here and nothing more. This runs on every dashboard
		// poll, so it does not write; retireStaleAcks deletes the row from the loop that
		// invalidated it.
		if signature, acked := acks[host.IP]; acked && ackHolds(host, signature) {
			host.Band = "ack"
		}
		switch host.Band {
		case "high":
			summary.High++
		case "low":
			summary.Low++
		case "ack":
			summary.Acked++
		}
		hosts = append(hosts, host)
	}
	return hosts, summary
}

// RetireStaleAcks deletes the acknowledgements that no longer describe their host. Retired rather
// than merely ignored: left in place, one would re-apply the moment the host returned to the shape
// it was acknowledged in, and the operator would never see what happened in between.
//
// Called from the two loops that can invalidate one — a sweep finding the host changed, a feed
// refresh landing a new hit on it — and never from hostViews, which serves every dashboard poll
// and has no business writing.
//
// Those two callers run on their own goroutines and can overlap each other, and either can overlap
// an operator acknowledging a host. That is safe without a lock of its own: the read below decides
// what is stale, and retireAcks deletes by signature, so a row that changed between the two takes
// no part. Whichever pass runs second finds nothing left to do.
func RetireStaleAcks(ctx context.Context) error {
	data, err := storage.CurrentHostState(ctx)
	if err != nil {
		return err
	}
	hosts, _ := Project(data, ActiveOpen)
	feedOnly, _ := Project(data, FeedOnlyMatches)
	// A host is on one side or the other, never both: the projections split on the same question.
	byIP := make(map[string]HostView, len(hosts)+len(feedOnly))
	for _, host := range slices.Concat(hosts, feedOnly) {
		byIP[host.IP] = host
	}
	var stale []storage.Ack
	for _, ack := range data.Acks {
		if host, ok := byIP[ack.IP]; !ok || !ackHolds(host, ack.Signature) {
			stale = append(stale, ack)
		}
	}
	return storage.RetireAcks(ctx, stale)
}

// BuildReport returns one entry per host something fired on, the flagged subset of hostViews.
func BuildReport(ctx context.Context) ([]ReportHost, ReportSummary, error) {
	// One read for both halves of the report. They are two projections of the same rows.
	data, err := storage.CurrentHostState(ctx)
	if err != nil {
		return nil, ReportSummary{}, err
	}
	// A one-shot -scan answers for the address it was asked about. The stored rows are the whole
	// database, so without this every host an earlier sweep found is reported as this scan's
	// result. Filtered here and not in project, which also serves the dashboard and
	// retireStaleAcks — both of which need every stored host, and the latter deletes what it
	// cannot see.
	//
	// Cloned before filtering: these slices are the held state, shared with those readers.
	if CLIScan != "" {
		_, scan := targetcfg.Current.Config()
		// Either side: -feed-only puts the argument on the one the sweep never probes.
		outOfScope := func(ip string) bool {
			addr := parse.AddrOrZero(ip)
			return !scan.Contains(addr) && !scan.ContainsFeedOnly(addr)
		}
		data.Scans = slices.DeleteFunc(slices.Clone(data.Scans), func(row storage.Scan) bool {
			return outOfScope(row.IP)
		})
		data.Matches = slices.DeleteFunc(slices.Clone(data.Matches), func(row storage.Match) bool {
			return outOfScope(row.IP)
		})
	}
	hosts, summary := Project(data, ActiveOpen)
	feedOnly, feedSummary := Project(data, FeedOnlyMatches)
	hosts = append(hosts, feedOnly...)
	summary.High += feedSummary.High
	summary.Low += feedSummary.Low
	summary.Acked += feedSummary.Acked
	report := []ReportHost{}
	for _, host := range hosts {
		if host.Band == "" {
			continue
		}
		entry := ReportHost{IP: host.IP, OpenTLSPorts: []int{}, Signals: host.Signals, Band: host.Band,
			CheckedAt: time.Unix(host.CheckedAt, 0).UTC().Format(time.RFC3339)}
		for _, port := range host.Ports {
			if port.Fingerprint != "" {
				entry.OpenTLSPorts = append(entry.OpenTLSPorts, port.Port)
			}
		}
		report = append(report, entry)
	}
	return report, summary, nil
}

// WriteReport writes the report as JSON to path, or to stdout when path is empty. Logs go to
// stderr, so the two never mix. It returns the tally of what it wrote.
//
// An empty report is skipped on stdout but still written to a file. A file has one writer and one
// current value, so zero findings has to be recorded as []. Stdout is a stream shared by both
// sweeps, where a bare [] per pass is noise the report updated line already carries.
func WriteReport(ctx context.Context, path string) (ReportSummary, error) {
	report, summary, err := BuildReport(ctx)
	if err != nil {
		return summary, err
	}
	if path == "" && len(report) == 0 {
		return summary, nil
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return summary, err
	}
	data = append(data, '\n')
	if path == "" {
		_, err := os.Stdout.Write(data)
		return summary, err
	}
	// Written whole and renamed into place. Both sweeps write this same path, and a reader must
	// never catch a half-file.
	temp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return summary, err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return summary, err
	}
	if err := temp.Close(); err != nil {
		return summary, err
	}
	return summary, os.Rename(temp.Name(), path)
}
