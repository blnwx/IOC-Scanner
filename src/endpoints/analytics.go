package endpoints

import (
	"cmp"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	storage "iocscanner/src/db"
	"iocscanner/src/feeds"
	scanner "iocscanner/src/scan"
	targetcfg "iocscanner/src/targets"
)

// analyticsTop caps every ranked list on the page. A dozen rows is what a panel holds before it
// stops being read; the long tail says nothing a scroll would fix.
const analyticsTop = 12

// analyticsPeriods are the periods the page offers, in days. -1 is the latest completed full scan;
// zero days is everything stored.
var analyticsPeriods = map[string]int{"latest": -1, "1d": 1, "7d": 7, "30d": 30, "90d": 90, "all": 0}

// portCount is one port's tally: how many addresses full scans found listening on it and how
// those split by band. Configured is only meaningful in the coverage table and stays off the wire
// for the TLS rankings, which do not ask the question.
type portCount struct {
	Port       int  `json:"port"`
	Hosts      int  `json:"hosts"`
	High       int  `json:"high"`
	Low        int  `json:"low"`
	Configured bool `json:"configured,omitempty"`
}

type costView struct {
	Passes int `json:"passes"`
	// Targets is from the most recent full pass, not a mean.
	Targets int `json:"targets"`
}

// latencyView separates real deadline hits from fast protocol failures and reports exact
// successful timings. Legacy passes without exact samples are excluded from this one view.
//
// The quartiles are of the same successful samples the median comes from, so one stage feeds both
// its timeout card and its row in the spread panel. Complete carries no deadline of its own and so
// leaves the failure counts and the budget at zero.
type latencyView struct {
	Successes     int64 `json:"successes"`
	Failures      int64 `json:"failures"`
	Timeouts      int64 `json:"timeouts"`
	MedianUS      int64 `json:"median_us"`
	P90US         int64 `json:"p90_us"`
	AverageUS     int64 `json:"average_us"`
	MinUS         int64 `json:"min_us"`
	MaxUS         int64 `json:"max_us"`
	Q1US          int64 `json:"q1_us"`
	Q3US          int64 `json:"q3_us"`
	BudgetMS      int   `json:"budget_ms"`
	BudgetChanged bool  `json:"budget_changed"`
}

// coverageView measures the configured common scan against what a full scan actually finds: of
// every rated endpoint the full sweeps turned up, how many sit on a port common_ports already
// visits. The totals run over every observed port, not only the rows in the table.
//
// Rated endpoints only. A count of all open ports would be a count of whichever host answers on
// every port — one tarpit contributes tens of thousands of them and buries every real finding.
type coverageView struct {
	Ports          []portCount `json:"ports"`
	Flagged        int         `json:"flagged"`
	FlaggedCovered int         `json:"flagged_covered"`
}

// feedYield is one feed's return: what it lists, how many of your hosts it named, and how many of
// those no other source named. Local marks the operator's own list rather than an upstream feed.
type feedYield struct {
	Source     string `json:"source"`
	Indicators int    `json:"indicators"`
	Hosts      int    `json:"hosts"`
	Exclusive  int    `json:"exclusive"`
	Local      bool   `json:"local"`
}

// profileView gives each port ranking its own top twelve so a rare HIGH port cannot disappear
// behind high-volume clean TLS ports.
type profileView struct {
	TLSHigh    []portCount `json:"tls_high"`
	TLSLow     []portCount `json:"tls_low"`
	TLSFlagged []portCount `json:"tls_flagged"`
}

// scanTimeoutView is one completed full scan, reduced to the same timeout measurements the
// period view already shows. Keeping the pass metadata beside it makes mismatched comparisons
// visible without pretending that a target or worker change was caused by a timeout edit.
type scanTimeoutView struct {
	StartedAt  int64       `json:"started_at"`
	Source     string      `json:"source"`
	ElapsedMS  int64       `json:"elapsed_ms"`
	Targets    int         `json:"targets"`
	MaxWorkers int         `json:"max_workers"`
	Dial       latencyView `json:"dial"`
	TLS        latencyView `json:"tls"`
	JARM       latencyView `json:"jarm"`
	Complete   latencyView `json:"complete"`
}

type scanTimeoutComparison struct {
	Latest   scanTimeoutView `json:"latest"`
	Previous scanTimeoutView `json:"previous"`
}

type analyticsResponse struct {
	Period      string      `json:"period"`
	GeneratedAt int64       `json:"generated_at"`
	Cost        costView    `json:"cost"`
	Dial        latencyView `json:"dial"`
	TLS         latencyView `json:"tls"`
	JARM        latencyView `json:"jarm"`
	// Complete is one port's whole probe: the dial, the handshake and all ten JARM probes,
	// counted only where every stage finished.
	Complete latencyView  `json:"complete"`
	Coverage coverageView `json:"coverage"`
	Feeds    []feedYield  `json:"feeds"`
	Profile  profileView  `json:"profile"`
	// Comparison is independent of Period: the latest pair must remain available even when the
	// selected period contains only the newest scan.
	Comparison *scanTimeoutComparison `json:"comparison,omitempty"`
}

// periodCutoff resolves the period parameter to a name and a started_at floor. Anything unrecognised
// is the default window rather than an error: the control is a select, and a hand-typed URL
// should show a page.
func periodCutoff(period string, now time.Time) (string, int64) {
	days, ok := analyticsPeriods[period]
	if !ok {
		period, days = "30d", analyticsPeriods["30d"]
	}
	if days == 0 {
		return period, 0
	}
	if days < 0 {
		return period, now.Unix()
	}
	return period, now.AddDate(0, 0, -days).Unix()
}

func addSamples(totals *[]int64, encoded string) {
	if encoded == "" {
		return
	}
	values := make([]int64, 0, strings.Count(encoded, ",")+1)
	for _, field := range strings.Split(encoded, ",") {
		value, err := strconv.ParseInt(field, 10, 64)
		if err != nil {
			return
		}
		values = append(values, value)
	}
	*totals = append(*totals, values...)
}

func latencyQuantiles(view *latencyView, samples []int64) {
	view.Successes = int64(len(samples))
	if len(samples) == 0 {
		return
	}
	slices.Sort(samples)
	view.MinUS = samples[0]
	view.MaxUS = samples[len(samples)-1]
	middle := len(samples) / 2
	view.MedianUS = samples[middle]
	if len(samples)%2 == 0 {
		view.MedianUS = (samples[middle-1] + samples[middle]) / 2
	}
	view.P90US = samples[(9*len(samples)+9)/10-1]
	var total int64
	for _, sample := range samples {
		total += sample
	}
	view.AverageUS = total / int64(len(samples))
	view.Q1US = samples[(len(samples)+3)/4-1]
	view.Q3US = samples[(3*len(samples)+3)/4-1]
}

// passLatencies reduces any set of full passes to the four existing timing views. cfg supplies
// the displayed budgets: the live config for a period, or the pass's own config for one scan.
func passLatencies(passes []storage.ScanPass, cfg targetcfg.ScanConfig) (dial, tls, jarm, complete latencyView) {
	dial.BudgetMS, tls.BudgetMS, jarm.BudgetMS = cfg.DialTimeoutMS, cfg.TLSTimeoutMS, cfg.JARMTimeoutMS
	var dialSamples, tlsSamples, jarmSamples, completeSamples []int64
	for _, pass := range passes {
		if pass.TimingVersion >= 1 {
			addSamples(&tlsSamples, pass.TLSSamplesUS)
			addSamples(&jarmSamples, pass.JARMSamplesUS)
			tls.Timeouts += pass.TLSTimeouts
			jarm.Timeouts += pass.JARMTimeouts
			tls.Failures += pass.TLSFailures
			jarm.Failures += pass.JARMFailures
			tls.BudgetChanged = tls.BudgetChanged || pass.TLSTimeoutMS != cfg.TLSTimeoutMS
			jarm.BudgetChanged = jarm.BudgetChanged || pass.JARMTimeoutMS != cfg.JARMTimeoutMS
		}
		// The dial counts come from the same pass as the dial samples, so a pass stored before
		// exact dial timing contributes neither: an attempt total without its successes would
		// read as a stage that answers far less often than it does.
		if pass.TimingVersion >= 3 {
			addSamples(&dialSamples, pass.DialSamplesUS)
			addSamples(&completeSamples, pass.CompleteSamplesUS)
			dial.Timeouts += pass.Filtered
			dial.Failures += pass.Closed
			dial.BudgetChanged = dial.BudgetChanged || pass.DialTimeoutMS != cfg.DialTimeoutMS
		}
	}
	latencyQuantiles(&dial, dialSamples)
	latencyQuantiles(&tls, tlsSamples)
	latencyQuantiles(&jarm, jarmSamples)
	latencyQuantiles(&complete, completeSamples)
	return
}

func scanTimeoutViewFor(pass storage.ScanPass) scanTimeoutView {
	cfg := targetcfg.ScanConfig{DialTimeoutMS: pass.DialTimeoutMS, TLSTimeoutMS: pass.TLSTimeoutMS,
		JARMTimeoutMS: pass.JARMTimeoutMS}
	dial, tls, jarm, complete := passLatencies([]storage.ScanPass{pass}, cfg)
	return scanTimeoutView{StartedAt: pass.StartedAt, Source: pass.Source, ElapsedMS: pass.ElapsedMS,
		Targets: pass.Targets, MaxWorkers: pass.MaxWorkers,
		Dial: dial, TLS: tls, JARM: jarm, Complete: complete}
}

// handleAnalytics serves the performance and C2-characteristics page.
//
// No cache and no memo. It full-scans scans and matches, the same cost the host table already pays.
func handleAnalytics(w http.ResponseWriter, r *http.Request) {
	cfg, _ := targetcfg.Current.Config()
	period, cutoff := periodCutoff(r.URL.Query().Get("period"), time.Now())
	body := analyticsResponse{
		Period: period, GeneratedAt: time.Now().Unix(),
		// Never null: every panel renders an empty state off a zero-length list.
		Coverage: coverageView{Ports: []portCount{}},
		Feeds:    []feedYield{},
		Profile: profileView{TLSHigh: []portCount{}, TLSLow: []portCount{},
			TLSFlagged: []portCount{}},
	}

	var passes []storage.ScanPass
	var err error
	if period == "latest" {
		passes, err = storage.LoadLatestFullScanPasses(r.Context(), 1)
	} else {
		passes, err = storage.LoadFullScanPasses(r.Context(), cutoff)
	}
	if err != nil {
		analyticsFailed(w, "pass", err)
		return
	}
	if period == "latest" && len(passes) > 0 {
		// Scan rows are stamped as each port finishes, so the pass start includes its whole sweep.
		cutoff = passes[0].StartedAt
	}
	for _, pass := range passes {
		body.Cost.Passes++
		// Ordered by started_at, so the last one to land here is the most recent full scan.
		body.Cost.Targets = pass.Targets
	}
	body.Dial, body.TLS, body.JARM, body.Complete = passLatencies(passes, cfg.Scan)

	latest, err := storage.LoadLatestFullScanPasses(r.Context(), 2)
	if err != nil {
		analyticsFailed(w, "comparison pass", err)
		return
	}
	if len(latest) == 2 {
		body.Comparison = &scanTimeoutComparison{Latest: scanTimeoutViewFor(latest[0]),
			Previous: scanTimeoutViewFor(latest[1])}
	}
	// The historical host projection keeps analytics blind to the live open/closed state while
	// still re-banding stored ports against the current feed index.
	hosts, _, err := scanner.Findings(r.Context(), scanner.ActiveHistory)
	if err != nil {
		analyticsFailed(w, "host", err)
		return
	}
	ports := map[int]portCount{}
	tlsPorts := map[int]portCount{}
	jarmHosts := map[string]bool{}
	for _, host := range hosts {
		for _, port := range host.Ports {
			if port.FullScannedAt == 0 || port.FullScannedAt < cutoff {
				continue
			}
			if port.Fingerprint != "" {
				row := tlsPorts[port.Port]
				row.Port, row.Hosts = port.Port, row.Hosts+1
				if port.Band == "high" {
					row.High++
				} else if port.Band == "low" {
					row.Low++
				}
				tlsPorts[port.Port] = row
			}
			if slices.ContainsFunc(port.Signals, func(signal feeds.Indicator) bool {
				return signal.Source == storage.JARMBlacklistSource
			}) {
				jarmHosts[host.IP] = true
			}
			row := ports[port.Port]
			row.Port, row.Hosts = port.Port, row.Hosts+1
			if port.Band == "high" {
				row.High++
			} else if port.Band == "low" {
				row.Low++
			}
			ports[port.Port] = row
		}
	}
	body.Coverage.Ports = coveragePorts(ports, cfg.Scan.CommonPorts)
	for _, row := range ports {
		body.Coverage.Flagged += row.High + row.Low
		if slices.Contains(cfg.Scan.CommonPorts, row.Port) {
			body.Coverage.FlaggedCovered += row.High + row.Low
		}
	}
	body.Profile.TLSHigh = rankTLSPorts(tlsPorts, func(row portCount) int { return row.High })
	body.Profile.TLSLow = rankTLSPorts(tlsPorts, func(row portCount) int { return row.Low })
	body.Profile.TLSFlagged = rankTLSPorts(tlsPorts, func(row portCount) int { return row.High + row.Low })

	matches, err := storage.LoadFeedMatches(r.Context(), cutoff)
	if err != nil {
		analyticsFailed(w, "feed", err)
		return
	}
	yields := feedYields(matches, cfg.Feeds.DomainIgnorelist)
	if entries := storage.JARMBlacklist.Count(); entries > 0 || len(jarmHosts) > 0 {
		yields = append(yields, feedYield{Source: storage.JARMBlacklistSource, Indicators: entries,
			Hosts: len(jarmHosts), Local: true})
	}
	counts := feeds.Current.Counts()
	seen := make(map[string]bool, len(yields))
	for i, row := range yields {
		// jarm_blacklist reaches matches like a feed does, but it is the operator's own list and
		// has no upstream indicator count. Labelled local rather than reported as a feed with zero.
		yields[i].Local = row.Source == storage.JARMBlacklistSource
		if !yields[i].Local {
			yields[i].Indicators = counts[row.Source]
		}
		seen[row.Source] = true
	}
	// A feed with no matches is still a yield result — zero is what says it is not earning its place.
	for source, indicators := range counts {
		if !seen[source] {
			yields = append(yields, feedYield{Source: source, Indicators: indicators})
		}
	}
	slices.SortFunc(yields, func(a, b feedYield) int {
		if a.Hosts != b.Hosts {
			return b.Hosts - a.Hosts
		}
		return strings.Compare(a.Source, b.Source)
	})
	body.Feeds = yields

	writeJSON(w, body)
}

// feedYields reduces stored feed hits to one row per source: how many of your hosts it named, and
// how many of those no other source named. The ignorelist is passed in rather than read here, so
// every row is filtered against the same list even if a settings save lands mid-call.
func feedYields(matches []storage.Match, ignorelist []string) []feedYield {
	hostsBySource := map[string]map[string]struct{}{}
	sourcesByHost := map[string]map[string]struct{}{}
	for _, match := range matches {
		if feeds.IgnoredFeedValue(match.Value, ignorelist) {
			continue
		}
		if hostsBySource[match.Source] == nil {
			hostsBySource[match.Source] = map[string]struct{}{}
		}
		if sourcesByHost[match.IP] == nil {
			sourcesByHost[match.IP] = map[string]struct{}{}
		}
		hostsBySource[match.Source][match.IP] = struct{}{}
		sourcesByHost[match.IP][match.Source] = struct{}{}
	}
	rows := make([]feedYield, 0, len(hostsBySource))
	for source, hosts := range hostsBySource {
		row := feedYield{Source: source, Hosts: len(hosts)}
		for ip := range hosts {
			if len(sourcesByHost[ip]) == 1 {
				row.Exclusive++
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func analyticsFailed(w http.ResponseWriter, what string, err error) {
	slog.Error("dashboard analytics query failed", "query", what, "err", err)
	http.Error(w, "cannot read the scan database", http.StatusInternalServerError)
}

// coveragePorts keeps every configured port beside the strongest unconfigured replacements. A
// configured port nothing answers on gets an empty row rather than none — dead weight in the
// config is the other half of the question, and only a row can show it.
func coveragePorts(counts map[int]portCount, common []int) []portCount {
	rows := make([]portCount, 0, len(counts)+len(common))
	for _, row := range counts {
		row.Configured = slices.Contains(common, row.Port)
		rows = append(rows, row)
	}
	for _, port := range common {
		if _, seen := counts[port]; !seen {
			rows = append(rows, portCount{Port: port, Configured: true})
		}
	}
	slices.SortFunc(rows, func(a, b portCount) int {
		return cmp.Or(b.High-a.High, b.Low-a.Low, b.Hosts-a.Hosts, a.Port-b.Port)
	})
	kept := rows[:0]
	contenders := 0
	for _, row := range rows {
		if row.Configured || contenders < analyticsTop {
			kept = append(kept, row)
			if !row.Configured {
				contenders++
			}
		}
	}
	return kept
}

func rankTLSPorts(counts map[int]portCount, score func(portCount) int) []portCount {
	rows := make([]portCount, 0, len(counts))
	for _, row := range counts {
		if score(row) > 0 {
			rows = append(rows, row)
		}
	}
	slices.SortFunc(rows, func(a, b portCount) int {
		if score(a) != score(b) {
			return score(b) - score(a)
		}
		if a.Hosts != b.Hosts {
			return b.Hosts - a.Hosts
		}
		return a.Port - b.Port
	})
	return rows[:min(analyticsTop, len(rows))]
}
