package db

import (
	"context"
	"sync"
)

// HostState is the stored rows every projection is built from, held between reads. A dashboard
// poll, an acknowledgement and a report all ask the same four tables the same question, and only
// a write can change the answer — so the writes in queries.go drop this rather than the readers timing
// it out.
//
// The projection itself is deliberately not held. It reads the live feed index, the JARM list and
// the config, and re-running it is what keeps a feed refresh visible without a second thing to
// remember to invalidate.
var HostState struct {
	Mu     sync.Mutex
	Loaded bool
	data   HostData
}

// invalidateHostState drops the held rows. Called by every write that can change them.
func invalidateHostState() {
	HostState.Mu.Lock()
	HostState.Loaded, HostState.data = false, HostData{}
	HostState.Mu.Unlock()
}

// CurrentHostState returns the stored rows, reading them once per change. The lock is held across
// the query so concurrent readers collapse onto one read rather than each running their own.
func CurrentHostState(ctx context.Context) (HostData, error) {
	HostState.Mu.Lock()
	defer HostState.Mu.Unlock()
	if HostState.Loaded {
		return HostState.data, nil
	}
	data, err := LoadHostData(ctx)
	if err != nil {
		return HostData{}, err
	}
	HostState.data, HostState.Loaded = data, true
	return data, nil
}
