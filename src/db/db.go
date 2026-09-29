package db

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	_ "modernc.org/sqlite"
)

// Handle is the process handle, assigned once by openDB before any goroutine starts.
var Handle *bun.DB

func Close() error {
	invalidateHostState()
	if Handle == nil {
		return nil
	}
	err := Handle.Close()
	Handle = nil
	return err
}

// writeMu serializes every write this process makes. SQLite takes one writer at a time and answers
// a second with SQLITE_BUSY; busy_timeout only turns that into a wait, and a wait that outlasts it
// still fails the write. Four goroutines write — writeLoop, the sweep, the feed refresh, and any
// dashboard request acknowledging a host — on four pooled connections, so without this the
// serialization is the database's to enforce under a deadline rather than this program's to
// guarantee.
//
// Writes only. Reads are deliberately left to run in parallel: that is what WAL is for, and the
// dashboard full-scans the scan table on every poll.
var writeMu sync.Mutex

// Open opens the SQLite store, creating it if needed, and installs it as the process handle.
func Open(ctx context.Context, path string) error {
	// A different file holds different rows, so nothing read from the last one survives the swap.
	invalidateHostState()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	// writeMu is what serializes this process's writes; busy_timeout is the backstop for a writer
	// this program does not own — a second copy of the scanner, or a sqlite3 shell against the same
	// file — making that write wait rather than fail. WAL lets writes overlap reads.
	//
	// Schema initialization is the one write not taken under writeMu. It runs before Open returns, and
	// therefore before there is a second goroutine to race.
	sqldb, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return err
	}
	handle := bun.NewDB(sqldb, sqlitedialect.New())
	if err := createSchema(ctx, handle); err != nil {
		handle.Close()
		return err
	}
	Handle = handle
	if err := refreshJARMBlacklist(ctx); err != nil {
		handle.Close()
		Handle = nil
		return err
	}
	writes = make(chan writeBatch, 1024)
	// Passed in rather than read from the global, so reopening the database leaves the old
	// writer on its own dead channel instead of racing the new handle.
	go writeLoop(writes)
	return nil
}
