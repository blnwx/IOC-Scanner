package scan

import (
	"math"
	"net/netip"
)

// PassStatus describes one of the two independent scan loops. Queued is only used by the
// Manual loop, between accepting an operator request and starting its pass.
type PassStatus struct {
	Running     bool    `json:"running"`
	Queued      bool    `json:"queued"`
	Kind        string  `json:"kind"`
	TargetCount int     `json:"target_count"`
	Progress    float64 `json:"progress"`
	StartedAt   int64   `json:"started_at"`
	FinishedAt  int64   `json:"finished_at"`
}

type Status struct {
	Scheduled PassStatus `json:"scheduled"`
	Manual    PassStatus `json:"manual"`
}

func CurrentStatus() Status {
	SweepState.Mu.Lock()
	defer SweepState.Mu.Unlock()
	pass := func(status *SweepStatus, queued bool) PassStatus {
		var progress float64
		if status.Running && status.Metrics != nil && status.TotalPorts > 0 {
			progress = math.Round(float64(status.Metrics.Completed.Load())*1000/float64(status.TotalPorts)) / 10
		}
		return PassStatus{Running: status.Running, Queued: queued, Kind: status.Kind,
			TargetCount: status.TargetCount, Progress: progress, StartedAt: status.StartedAt,
			FinishedAt: status.FinishedAt}
	}
	return Status{
		Scheduled: pass(&SweepState.Scheduled, false),
		Manual:    pass(&SweepState.Manual, SweepState.Requested && !SweepState.Manual.Running),
	}
}

// QueueManual reserves the manual pass and queues an already-authorized target list.
func QueueManual(kind string, targets []netip.Prefix, targetCount int) bool {
	request := ManualRequest{Common: kind == "common", Targets: targets}
	// requested closes the gap between manualLoop receiving from the channel and sweepOnce marking
	// the pass as running, so two fast requests cannot both be accepted. It is cleared only once
	// that pass ends, which is why the send below cannot block: nothing is queued unless requested
	// is already set, and that case took the 409.
	SweepState.Mu.Lock()
	busy := SweepState.Requested || SweepState.Manual.Running
	if !busy {
		SweepState.Requested = true
		SweepState.Manual.Kind = kind
		SweepState.Manual.TargetCount = targetCount
	}
	SweepState.Mu.Unlock()
	if busy {
		return false
	}
	// Outside the lock. A send that ever did block must not take sweepState.mu down with it.
	ManualSweep <- request
	return true
}
