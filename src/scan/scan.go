package scan

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	storage "iocscanner/src/db"
	"iocscanner/src/feeds"
	targetcfg "iocscanner/src/targets"
)

// ManualRequest is an operator's port choice and optional temporary targets. Nil targets means the
// configured scope. The prefixes are rechecked against the live allow/deny lists when the pass
// starts, so a guardrail edit made while the request waits still wins.
type ManualRequest struct {
	Common  bool
	Targets []netip.Prefix
}

// ManualSweep carries one operator request to its scan loop. A second request is refused while
// this one waits or runs.
var ManualSweep = make(chan ManualRequest, 1)

type SweepStatus struct {
	Running               bool
	Kind                  string // "common" or "full"
	TargetCount           int
	TotalPorts            int64
	StartedAt, FinishedAt int64
	Metrics               *PassMetrics
}

// SweepState is what the dashboard reads to describe both passes. Pass fields are written by
// SweepOnce; requested is written by the scan handler and cleared by the manual pass.
var SweepState struct {
	Mu                sync.Mutex
	Scheduled, Manual SweepStatus
	// requested stays set from acceptance through the end of the manual pass. The channel alone
	// cannot do that: receiving briefly empties it before sweepOnce marks the pass as running.
	Requested bool
}

// SweepLoop runs a pass every scans_per_day interval until cancelled. The interval is timed from
// the start of the pass, so a slow pass doesn't push the next one out. A pass that outlasts it
// starts again immediately. The full sweep normally does, it runs far longer than the interval.
//
// Manual scans are served by manualLoop, alongside this one, so neither disturbs the other.
func SweepLoop(ctx context.Context) {
	paused := false
	for {
		cfg, scope := targetcfg.Current.Config()
		if scope.Scannable == 0 {
			if !paused {
				slog.Warn("scheduled scanning paused: no authorized targets")
				paused = true
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(cfg.Base.RefreshSeconds) * time.Second):
			}
			continue
		}
		paused = false
		interval := 24 * time.Hour / time.Duration(cfg.Scan.ScansPerDay)
		started := time.Now()
		SavePass(ctx, SweepOnce(ctx, false, false, nil), "scheduled")
		select {
		case <-ctx.Done():
			return
		case <-time.After(max(0, interval-time.Since(started))):
		}
	}
}

// ManualLoop serves one operator scan at a time, on its own goroutine so it runs alongside the
// Scheduled sweep instead of stopping it. It holds the process context, so a scan outlives the
// request that asked for it and is still drained on shutdown.
func ManualLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-ManualSweep:
			SavePass(ctx, SweepOnce(ctx, request.Common, true, request.Targets), "manual")
		}
	}
}

// SweepPorts returns the configured common ports alone, or every port with the common ports first.
func SweepPorts(common bool, commonPorts []int) (string, []int) {
	if common {
		return "common", commonPorts
	}
	ports := make([]int, 0, 65535)
	ports = append(ports, commonPorts...)
	for port := 1; port <= 65535; port++ {
		if !slices.Contains(commonPorts, port) {
			ports = append(ports, port)
		}
	}
	return "full", ports
}

// SweepOnce probes every authorized target on the common ports (common), or on every port with the
// Common ports first. It then writes the report and summarises the pass. manual records whether an
// operator asked for it.
//
// It returns what the pass measured rather than storing it, so the caller can tag the row with the
// loop it came from and skip an interrupted pass. Nil means no pass ran at all.
func SweepOnce(ctx context.Context, common, manual bool, targets []netip.Prefix) *PassMetrics {
	cfg, s := targetcfg.Current.Config()
	if targets != nil {
		var err error
		s, err = targetcfg.NewManualScope(cfg, targets)
		if err != nil {
			slog.Warn("manual scan cancelled after scope changed", "err", err)
			SweepState.Mu.Lock()
			SweepState.Requested = false
			SweepState.Mu.Unlock()
			return nil
		}
	}
	addrs := slices.Collect(s.AuthorizedAddrs)
	// Built per pass, so an edit to common_ports applies on the next sweep.
	kind, ports := SweepPorts(common, cfg.Scan.CommonPorts)

	// took reads against the interval, which is timed from the same instant in sweepLoop.
	// Longer means the passes are running back to back.
	start := time.Now()
	SweepState.Mu.Lock()
	status := &SweepState.Scheduled
	if manual {
		status = &SweepState.Manual
	}
	status.Running = true
	status.Kind = kind
	status.TargetCount = len(addrs)
	status.TotalPorts = int64(len(addrs)) * int64(len(ports))
	status.Metrics = nil
	status.StartedAt = start.Unix()
	SweepState.Mu.Unlock()
	defer func() {
		SweepState.Mu.Lock()
		status.Running = false
		if manual {
			SweepState.Requested = false
		}
		status.FinishedAt = time.Now().Unix()
		SweepState.Mu.Unlock()
	}()
	slog.Info("sweep started", "kind", kind, "manual", manual, "targets", len(addrs),
		"ports", len(addrs)*len(ports))
	if manual {
		// Recorded before the probing, not after it. What moves a host onto the complete table is
		// the operator asking for it by name, and that is already true here — a pass that finds no
		// open port, or is interrupted, writes no scan row to carry the fact.
		probed := make([]storage.ManualScan, 0, len(addrs))
		for _, addr := range addrs {
			probed = append(probed, storage.ManualScan{IP: addr.String(), ScannedAt: start.Unix()})
		}
		// Not ctx. The request stands even if the pass it started is cancelled.
		if err := storage.SaveManualScans(context.WithoutCancel(ctx), probed); err != nil {
			slog.Error("recording the manual scan failed", "targets", len(probed), "err", err)
		}
		indicators := feeds.Current.Indicators()
		rows := MatchFeedHits(ctx, s, indicators)
		slog.Info("feed cache checked", "indicators", len(indicators), "matches", len(rows))
	}
	m := ProbePorts(ctx, addrs, ports, manual, status)
	// Recorded here rather than inside probePorts: these describe the pass, and probePorts is also
	// called on its own, without one around it.
	m.StartedAt, m.ElapsedMS = start.Unix(), time.Since(start).Milliseconds()
	m.targets, m.Ports, m.cfg = len(addrs), len(ports), cfg.Scan
	// sweep complete counts only what this pass probed; report updated carries the cumulative tally
	// over every scan stored so far.
	fields := []any{"kind", kind, "hosts", len(addrs), "open_ports", m.Open.Load(),
		"live_tls_hosts", m.Summary.LiveTLSHosts, "high", m.Summary.High, "low", m.Summary.Low,
		"took", time.Since(start).Round(time.Millisecond)}
	// A pass that could not dial has under-reported: the ports it failed on were never tested.
	// WARN so an incomplete pass is not read as a clean empty result.
	level := slog.LevelInfo
	if dialFails := m.untested.Load(); dialFails > 0 {
		level = slog.LevelWarn
		fields = append(fields, "dial_failures", dialFails, "err", errnoName(m.dialErr))
	}
	slog.Log(ctx, level, "sweep complete", fields...)
	// The acknowledgements this pass invalidated. It belongs here rather than in hostViews, which
	// every dashboard poll runs: a pass is what changes a host, so a pass is what retires them.
	if err := RetireStaleAcks(context.WithoutCancel(ctx)); err != nil {
		slog.Error("retiring stale acknowledgements failed", "err", err)
	}
	// Not ctx. An interrupt mid-pass would otherwise skip reporting what the pass found.
	summary, err := WriteReport(context.WithoutCancel(ctx), ReportPath)
	if err != nil {
		slog.Error("writing report failed", "err", err)
		return m
	}
	// Empty reportPath means stdout, and the handler drops the field rather than printing path="".
	slog.Info("report updated", "live_tls_hosts", summary.LiveTLSHosts, "high", summary.High,
		"low", summary.Low, "path", ReportPath)
	return m
}

// ProbePorts probes every port on every address, at most max_workers at a time, saving each
// Open port as it is found. It returns what the pass measured: the outcome of every dial, the
// worker-slot time each outcome cost, and a tally of this pass alone.
func ProbePorts(ctx context.Context, addrs []netip.Addr, ports []int, manual bool, status *SweepStatus) *PassMetrics {
	m := &PassMetrics{}
	if status != nil {
		SweepState.Mu.Lock()
		status.Metrics = m
		SweepState.Mu.Unlock()
	}
	full := len(ports) == 65535
	knownRows, err := storage.LoadOpenScans(ctx)
	if err != nil {
		slog.Error("loading open ports failed", "err", err)
		return m
	}
	known := make(map[string]map[int]bool)
	for _, row := range knownRows {
		if known[row.IP] == nil {
			known[row.IP] = map[int]bool{}
		}
		known[row.IP][row.Port] = true
	}
	var (
		// A host answering on nearly every port is a tarpit, or a middlebox on the path
		// answering the SYNs itself. Either way the pass is noise, not an attack surface.
		open = map[string]int{}
		// Both keyed by host, not by port. A host flagged on three ports counts once.
		tlsHosts = map[string]bool{}
		bands    = map[string]string{}
		closed   []storage.Scan
		mu       sync.Mutex
		wg       sync.WaitGroup
	)
	// Read after wg.Wait, so no lock.
	tally := func() *PassMetrics {
		storage.FlushWrites()
		if err := storage.CloseScans(context.WithoutCancel(ctx), closed); err != nil {
			slog.Error("closing scanned ports failed", "rows", len(closed), "err", err)
		}
		m.Summary = ReportSummary{LiveTLSHosts: len(tlsHosts)}
		for _, b := range bands {
			if b == "high" {
				m.Summary.High++
			} else {
				m.Summary.Low++
			}
		}
		return m
	}
	cfg, _ := targetcfg.Current.Config()
	timeouts := ScanTimeouts{
		Dial: time.Duration(cfg.Scan.DialTimeoutMS) * time.Millisecond,
		TLS:  time.Duration(cfg.Scan.TLSTimeoutMS) * time.Millisecond,
		// Per probe, and a fingerprint is ten of them in sequence inside one held slot.
		JARM: time.Duration(cfg.Scan.JARMTimeoutMS) * time.Millisecond,
	}
	// One slot per dial in flight. Sending blocks once max_workers are running, which is the
	// whole of the rate limiting. No pool, no job channel.
	// Sized once per pass. A max_workers change applies at the next sweep.
	//
	// Per pass, not per process: a manual scan running alongside the scheduled sweep gets its own
	// max_workers, so peak dials in flight is twice the setting while the two overlap. Share one
	// semaphore across both if that ever costs more than it saves.
	sem := make(chan struct{}, cfg.Scan.MaxWorkers)

	// Port-major, not address-major. Pointing every dial at one host at a time reads as an
	// attack and trips tarpits. A pass stopped halfway would also have covered half the hosts
	// and none of the rest.
	for _, port := range ports {
		for _, addr := range addrs {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Wait()
				return tally()
			}
			target := netip.AddrPortFrom(addr, uint16(port))
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				outcome := ProbePort(ctx, target, timeouts)
				m.Record(outcome)
				if outcome.Err != nil {
					// Recorded as untested above. Only the first error is kept here: once the
					// range is exhausted every dial fails the same way, and 16k copies say
					// nothing more.
					mu.Lock()
					first := m.dialErr == nil
					if first {
						m.dialErr = outcome.Err
					}
					mu.Unlock()
					if first {
						slog.Warn("dial failed on a local limit; ports are going untested, not reported closed",
							"target", target.String(), "err", errnoName(outcome.Err))
					}
					return
				}
				row := outcome.Row
				if row == nil {
					mu.Lock()
					if known[target.Addr().String()][int(target.Port())] {
						closed = append(closed, storage.Scan{IP: target.Addr().String(), Port: int(target.Port()),
							ScannedAt: time.Now().Unix()})
					}
					mu.Unlock()
					return
				}
				row.Manual = manual
				if full {
					row.FullScannedAt = row.ScannedAt
				}
				// Outside the lock. Classifying reads the feed index and the JARM list, walks the
				// certificate names through the public-suffix list, and is the same answer whoever
				// asks — none of which needs the pass's tallies held.
				verdict := ClassifyProbe(*row)
				mu.Lock()
				open[row.IP]++
				if row.Fingerprint != "" {
					tlsHosts[row.IP] = true
				}
				// Upgrade low to high, never the other way. The strongest signal on any
				// port of the host is the band the host gets.
				if verdict.Band != "" && bands[row.IP] != "high" {
					bands[row.IP] = verdict.Band
				}
				// Equality, not >=. It fires once, on the 1000th open port. >= would
				// re-log for every port after it, thousands of lines per tarpit.
				tarpit := open[row.IP] == 1000
				mu.Unlock()
				if tarpit {
					slog.Warn("host answers on nearly every port; results are not a real surface",
						"ip", row.IP)
				}
				// Announced as found, not at the end. A full pass runs for hours, so results have
				// to be visible while it is still running. Outside the lock: this writes a line to
				// stderr, and a slow terminal would otherwise hold every other probe behind it.
				AlertProbe(*row, verdict)
				// Queued, not written. Thousands of these goroutines run at once and SQLite
				// takes one writer, so writeLoop batches them instead.
				storage.Enqueue([]storage.Scan{*row}, verdict.Matches)
			}()
		}
	}
	wg.Wait()
	return tally()
}
