package db

import (
	"github.com/uptrace/bun"
)

// Match is one threat-feed hit against an authorized target IP.
type Match struct {
	bun.BaseModel `bun:"table:matches"`

	IP     string `bun:"ip,pk"`
	Source string `bun:"source,pk"`
	Value  string `bun:"value,pk"`
	Tag    string `bun:"tag,notnull"`
	// FirstSeen is the feed's relevant RFC3339 date: usually first seen, URLHaus last online, or
	// ThreatView detection time. SeenAt is when this scanner confirmed it, which expiry uses.
	FirstSeen string `bun:"first_seen"`
	// ConfidenceLevel is nullable because zero is a valid ThreatFox score.
	ConfidenceLevel *int  `bun:"confidence_level"`
	SeenAt          int64 `bun:"seen_at,notnull"`
	// FeedOnly marks a hit on an address matched against the feeds but never probed. Not stored:
	// it is a property of the current scope, re-derived wherever it is read.
	FeedOnly bool `bun:"-"`
}

// Scan is one open port found by either scan loop. The certificate fields stay empty when the port
// answers but does not speak TLS.
type Scan struct {
	bun.BaseModel `bun:"table:scans"`

	IP        string `bun:"ip,pk" json:"ip"`
	Port      int    `bun:"port,pk" json:"port"`
	IsOpen    bool   `bun:"is_open,notnull,default:true" json:"-"`
	ScannedAt int64  `bun:"scanned_at,notnull" json:"scanned_at"`
	// FullScannedAt is the latest full 1-65535 sweep that observed this endpoint. Common scans
	// may refresh the row, but cannot make a common-only result eligible for analytics.
	FullScannedAt      int64  `bun:"full_scanned_at,notnull,default:0" json:"full_scanned_at"`
	Manual             bool   `bun:"manual,notnull,default:false" json:"manual"`
	Subject            string `bun:"subject" json:"subject"`
	Issuer             string `bun:"issuer" json:"issuer"`
	DNSNames           string `bun:"dns_names" json:"dns_names"`
	NotBefore          int64  `bun:"not_before" json:"not_before"`
	NotAfter           int64  `bun:"not_after" json:"not_after"`
	SignatureAlgorithm string `bun:"signature_algorithm" json:"signature_algorithm"`
	// SerialNumber is decimal, not hex. The published C2 default-cert fingerprints are quoted
	// that way (Cobalt Strike's is 146473198).
	SerialNumber string `bun:"serial_number" json:"serial_number"`
	// SelfSigned is decided at probe time, while the parsed certificate is still in hand.
	SelfSigned bool `bun:"self_signed" json:"self_signed"`
	// Fingerprint is the leaf's hex SHA-1, the form SSLBL lists.
	Fingerprint string `bun:"fingerprint" json:"fingerprint"`
	// JARM fingerprints the TLS stack rather than the certificate. Empty when the port answered
	// no probe.
	JARM string `bun:"jarm" json:"jarm"`
}

// Ack records that an operator marked a host's current state as dealt with. A later state change
// retires it. AckedAt is only read as a yes/no today; it is a stamp because the time is the more
// useful thing to have kept.
type Ack struct {
	bun.BaseModel `bun:"table:acks"`

	IP        string `bun:"ip,pk"`
	AckedAt   int64  `bun:"acked_at,notnull"`
	Signature string `bun:"signature,notnull"`
}

// ManualScan records that an operator asked for one address by name. Kept apart from the scan
// rows because a hand-scan that finds no open port writes no row at all, and the request is what
// moves the host onto the complete table — not whatever the probe happened to find.
type ManualScan struct {
	bun.BaseModel `bun:"table:manual_scans"`

	IP        string `bun:"ip,pk"`
	ScannedAt int64  `bun:"scanned_at,notnull"`
}

// JARMSighting is one endpoint that has produced a hash over its lifetime.
type JARMSighting struct {
	bun.BaseModel `bun:"table:jarm_sightings"`

	Hash      string `bun:"hash,pk" json:"hash"`
	IP        string `bun:"ip,pk" json:"ip"`
	Port      int    `bun:"port,pk" json:"port"`
	FirstSeen int64  `bun:"first_seen,notnull" json:"first_seen"`
	LastSeen  int64  `bun:"last_seen,notnull" json:"last_seen"`
}

// JARMBlacklistEntry is one operator-curated JARM fingerprint.
type JARMBlacklistEntry struct {
	bun.BaseModel `bun:"table:jarm_blacklist"`

	Label string `bun:"label,notnull" json:"label"`
	Hash  string `bun:"hash,pk" json:"hash"`
}

// ScanPass is one completed pass. Manual and -scan passes are recorded too: the stored quantity
// is per-outcome cost, which is valid whatever the pass covered. Source separates them, because
// hand-picked targets answer far more often than a swept range and would skew the outcome mix.
type ScanPass struct {
	bun.BaseModel `bun:"table:scan_passes"`

	StartedAt int64  `bun:"started_at,pk"`
	Source    string `bun:"source,pk"` // "scheduled", "manual" or "cli"
	ElapsedMS int64  `bun:"elapsed_ms,notnull"`
	Targets   int    `bun:"targets,notnull"`
	Ports     int    `bun:"ports,notnull"`

	// The config in force, so analytics can detect a setting change inside its selected period.
	MaxWorkers                                 int `bun:",notnull"`
	DialTimeoutMS, TLSTimeoutMS, JARMTimeoutMS int `bun:",notnull"`

	// Outcome counts and the worker-slot time each consumed.
	Closed, Filtered, Open, Untested         int64 `bun:",notnull"`
	ClosedSlotMS, FilteredSlotMS, OpenSlotMS int64 `bun:",notnull"`

	// Legacy histogram fields remain in inserts because existing databases require these columns.
	TLSBuckets   string `bun:"tls_buckets,notnull"`
	TLSTimeouts  int64  `bun:"tls_timeouts,notnull"`
	JARMBuckets  string `bun:"jarm_buckets,notnull"`
	JARMTimeouts int64  `bun:"jarm_timeouts,notnull"`

	// Version 1 adds exact TLS/JARM samples; version 3 adds exact dial samples and the end-to-end
	// time of a port that completed all three stages. Version 2 stored connection-time histograms
	// no view reads any more; its passes are read as version 1.
	TimingVersion                    int    `bun:"timing_version,notnull,default:0"`
	TLSSamplesUS, JARMSamplesUS      string `bun:",notnull,default:''"`
	TLSFailures, JARMFailures        int64  `bun:",notnull,default:0"`
	DialSamplesUS, CompleteSamplesUS string `bun:",notnull,default:''"`
}

type HostData struct {
	Scans   []Scan
	Matches []Match
	Acks    []Ack
	// Manual is every address an operator has asked for by name, whether or not the scan that
	// followed found anything.
	Manual []ManualScan
}

type JARMRow struct {
	Hash        string `json:"hash"`
	Hosts       int    `json:"hosts"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
	Blacklisted bool   `json:"blacklisted"`
}
