package db

import (
	"context"
	"log/slog"
	"time"
)

const (
	// flushInterval is how long a row can sit in the queue. It is the durability window: a
	// crash loses at most this much of a pass.
	flushInterval = 2 * time.Second
	// maxBatch caps rows per statement. SQLite has a ceiling on bound parameters, and a
	// tarpit host can produce thousands of rows between ticks.
	maxBatch = 500
)

// writeBatch is one handoff to the writer. A non-nil done asks it to flush what it holds and
// close the channel, which is how a caller waits for its own rows to land.
type writeBatch struct {
	scans   []Scan
	matches []Match
	done    chan struct{}
}

// writes is the queue every write goes through. SQLite takes one writer at a time and the probe
// fan-out is max_workers wide, so nothing writes directly; writeLoop owns the inserts.
var writes chan writeBatch

// Enqueue hands rows to the writer, blocking while the queue is full. That backpressure is the
// point: it holds the probe goroutines rather than piling unbounded rows in memory.
func Enqueue(scans []Scan, matches []Match) {
	if len(scans) == 0 && len(matches) == 0 {
		return
	}
	writes <- writeBatch{scans: scans, matches: matches}
}

// FlushWrites blocks until everything queued before the call is on disk. Callers that read back
// what they just wrote — the report at the end of a sweep — need it.
func FlushWrites() {
	done := make(chan struct{})
	writes <- writeBatch{done: done}
	<-done
}

// writeLoop is the only goroutine that writes. It batches whatever arrives between ticks into one
// upsert per table, so a pass finding thousands of open ports costs a few transactions rather than
// thousands of single-row ones. It runs for the life of the process.
func writeLoop(queue chan writeBatch) {
	tick := time.NewTicker(flushInterval)
	defer tick.Stop()
	var pending writeBatch
	flush := func() {
		// Not the probe's context. A row queued before an interrupt still has to be written.
		if err := SaveScans(context.Background(), pending.scans); err != nil {
			slog.Error("saving scans failed", "rows", len(pending.scans), "err", err)
		}
		sightings := make([]JARMSighting, 0, len(pending.scans))
		for _, row := range pending.scans {
			if row.JARM != "" {
				sightings = append(sightings, JARMSighting{Hash: row.JARM, IP: row.IP,
					Port: row.Port, FirstSeen: row.ScannedAt, LastSeen: row.ScannedAt})
			}
		}
		if err := SaveJARMSightings(context.Background(), sightings); err != nil {
			slog.Error("saving jarm sightings failed", "rows", len(sightings), "err", err)
		}
		// One host serving the same flagged certificate on several ports puts the same
		// (ip, source, value) in the batch more than once. No dedupe needed: SQLite applies an
		// upsert row by row within the statement, so the repeats resolve the same way they did
		// as separate statements. TestWriteLoopBatchesConcurrentEnqueues covers it.
		if err := SaveMatches(context.Background(), pending.matches); err != nil {
			slog.Error("saving matches failed", "rows", len(pending.matches), "err", err)
		}
		pending.scans, pending.matches = pending.scans[:0], pending.matches[:0]
	}
	for {
		select {
		case batch := <-queue:
			pending.scans = append(pending.scans, batch.scans...)
			pending.matches = append(pending.matches, batch.matches...)
			if batch.done != nil || len(pending.scans) >= maxBatch || len(pending.matches) >= maxBatch {
				flush()
			}
			if batch.done != nil {
				close(batch.done)
			}
		case <-tick.C:
			flush()
		}
	}
}
