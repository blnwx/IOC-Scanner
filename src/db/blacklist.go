package db

import (
	"context"
	"sync"
)

const JARMBlacklistSource = "jarm_blacklist"

// JARMBlacklist is independent of remote feeds and lifetime sightings. Reads happen on every
// stored scan shown by the dashboard, so writers swap the whole lookup after the database write.
var JARMBlacklist = &jarmBlacklistLookup{labels: map[string]string{}}

var jarmChangeMu sync.Mutex

type jarmBlacklistLookup struct {
	mu     sync.RWMutex
	labels map[string]string
}

func (b *jarmBlacklistLookup) Replace(rows []JARMBlacklistEntry) {
	labels := make(map[string]string, len(rows))
	for _, row := range rows {
		labels[row.Hash] = row.Label
	}
	b.mu.Lock()
	b.labels = labels
	b.mu.Unlock()
}

// Label looks up a stored JARM label.
func (b *jarmBlacklistLookup) Label(hash string) (string, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	label, ok := b.labels[hash]
	return label, ok
}

func (b *jarmBlacklistLookup) Contains(hash string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.labels[hash]
	return ok
}

func (b *jarmBlacklistLookup) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.labels)
}

func refreshJARMBlacklist(ctx context.Context) error {
	rows, err := JARMBlacklistEntries(ctx)
	if err != nil {
		return err
	}
	JARMBlacklist.Replace(rows)
	return nil
}

func SaveJARMBlacklist(ctx context.Context, rows []JARMBlacklistEntry) error {
	if len(rows) == 0 {
		return nil
	}
	jarmChangeMu.Lock()
	defer jarmChangeMu.Unlock()
	if err := upsertJARMBlacklist(ctx, rows); err != nil {
		return err
	}
	return refreshJARMBlacklist(ctx)
}

func DeleteJARMBlacklist(ctx context.Context, hash string) error {
	jarmChangeMu.Lock()
	defer jarmChangeMu.Unlock()
	if err := removeJARMBlacklist(ctx, hash); err != nil {
		return err
	}
	return refreshJARMBlacklist(ctx)
}
