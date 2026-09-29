package scan

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	storage "iocscanner/src/db"
	targetcfg "iocscanner/src/targets"
)

// LatencySamples keeps exact successful timings for timeout decisions. TLS and JARM completions
// are sparse beside the port dials, so one small lock here is cheaper than another storage model.
type LatencySamples struct {
	mu     sync.Mutex
	Values []int64
}

func (s *LatencySamples) Add(took time.Duration) {
	s.mu.Lock()
	s.Values = append(s.Values, took.Microseconds())
	s.mu.Unlock()
}

func (s *LatencySamples) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	parts := make([]string, len(s.Values))
	for i, value := range s.Values {
		parts[i] = strconv.FormatInt(value, 10)
	}
	return strings.Join(parts, ",")
}

// PassMetrics is what one pass accumulates. The counters are atomic: probePort runs max_workers
// wide, and taking a mutex per dial would serialize the whole sweep behind it.
//
// The quantity recorded per outcome is worker-slot time, not dial time. probePorts releases its
// semaphore slot when probePort returns, so this is what a sweep actually spends on a port —
// dial, handshake, and all ten JARM probes — rather than the round trip of the SYN alone.
type PassMetrics struct {
	Completed                                atomic.Int64
	closed, filtered, Open, untested         atomic.Int64
	closedSlotMS, filteredSlotMS, openSlotMS atomic.Int64
	tlsTimeouts, jarmTimeouts                atomic.Int64
	tlsFailures, jarmFailures                atomic.Int64
	tlsSamples, jarmSamples                  LatencySamples
	// dialSamples is one entry per port that answered; completeSamples one per port that answered
	// and then finished both TLS and JARM, measured over the whole probe.
	DialSamples, CompleteSamples LatencySamples

	// Written by probePorts after its barrier, and by sweepOnce once the pass is over, so neither
	// needs a lock of its own.
	Summary        ReportSummary
	dialErr        error
	StartedAt      int64
	ElapsedMS      int64
	targets, Ports int
	cfg            targetcfg.ScanConfig
}

// Row renders the pass for storage. source names which loop ran it: hand-picked targets answer
// far more often than a swept range, so the outcome mix of the two must not be pooled.
func (m *PassMetrics) row(source string) storage.ScanPass {
	return storage.ScanPass{
		StartedAt: m.StartedAt, Source: source, ElapsedMS: m.ElapsedMS,
		Targets: m.targets, Ports: m.Ports,
		MaxWorkers: m.cfg.MaxWorkers, DialTimeoutMS: m.cfg.DialTimeoutMS,
		TLSTimeoutMS: m.cfg.TLSTimeoutMS, JARMTimeoutMS: m.cfg.JARMTimeoutMS,
		Closed: m.closed.Load(), Filtered: m.filtered.Load(), Open: m.Open.Load(),
		Untested:     m.untested.Load(),
		ClosedSlotMS: m.closedSlotMS.Load(), FilteredSlotMS: m.filteredSlotMS.Load(),
		OpenSlotMS:  m.openSlotMS.Load(),
		TLSTimeouts: m.tlsTimeouts.Load(), JARMTimeouts: m.jarmTimeouts.Load(),
		TimingVersion: 3, TLSSamplesUS: m.tlsSamples.String(), JARMSamplesUS: m.jarmSamples.String(),
		TLSFailures: m.tlsFailures.Load(), JARMFailures: m.jarmFailures.Load(),
		DialSamplesUS: m.DialSamples.String(), CompleteSamplesUS: m.CompleteSamples.String(),
	}
}

// SavePass stores a completed pass. Only a completed one: probePorts returns its partial tallies
// with no error when the context is cancelled, so without this check an interrupted sweep would
// be stored as a finished one and its short elapsed time would sit in the occupancy figure.
func SavePass(ctx context.Context, m *PassMetrics, source string) {
	if m == nil || ctx.Err() != nil {
		return
	}
	// Not ctx. It is still live here, but the write belongs to the pass that just ended.
	if err := storage.SaveScanPass(context.WithoutCancel(ctx), m.row(source)); err != nil {
		slog.Error("saving the scan pass failed", "source", source, "err", err)
	}
}

// Record folds one outcome into the pass. The only place these counters are written, so a new
// outcome is accounted for here rather than wherever it happened to be produced.
func (m *PassMetrics) Record(o probeOutcome) {
	m.Completed.Add(1)
	switch o.State {
	case probeUntested:
		m.untested.Add(1)
	case probeFiltered:
		m.filtered.Add(1)
		m.filteredSlotMS.Add(o.slot.Milliseconds())
	case ProbeClosed:
		m.closed.Add(1)
		m.closedSlotMS.Add(o.slot.Milliseconds())
	case probeOpen:
		m.Open.Add(1)
		m.openSlotMS.Add(o.slot.Milliseconds())
		m.DialSamples.Add(o.dial)
		if o.complete > 0 {
			m.CompleteSamples.Add(o.complete)
		}
	}
	m.tlsTimeouts.Add(o.tls.Timeouts)
	m.tlsFailures.Add(o.tls.failures)
	m.jarmTimeouts.Add(o.jarm.Timeouts)
	m.jarmFailures.Add(o.jarm.failures)
	for _, took := range o.tls.samples {
		m.tlsSamples.Add(took)
	}
	for _, took := range o.jarm.samples {
		m.jarmSamples.Add(took)
	}
}
