package targets

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"iocscanner/src/parse"

	"github.com/BurntSushi/toml"
	"golang.org/x/net/publicsuffix"
)

// Config is the whole TOML config surface. The JSON tags are the dashboard's settings form, which
// reads and writes this same shape — every field but the auth key, which carries json:"-" so it
// can neither be read out of the running config nor set from a browser.
type Config struct {
	Base  BaseConfig  `toml:"config" json:"config"`
	Feeds FeedsConfig `toml:"feeds" json:"feeds"`
	Scan  ScanConfig  `toml:"scan" json:"scan"`
}

// BaseConfig holds the generic top-level settings.
type BaseConfig struct {
	// RefreshSeconds is how often the config and targets files are re-read.
	RefreshSeconds int `toml:"refresh_seconds" json:"refresh_seconds"`
	// RetainDays is accepted for compatibility with older config files but is no longer used.
	RetainDays int `toml:"retain_days" json:"retain_days"`
}

// FeedsConfig holds the upstream feed credentials.
type FeedsConfig struct {
	// ThreatFoxAuthKey may be empty. The ThreatFox feed is then skipped. It is never carried over
	// JSON: this server has no authentication, so the key stays in the file it was written in and
	// the settings endpoint keeps whatever is already loaded.
	ThreatFoxAuthKey string `toml:"threatfox_auth_key" json:"-"`
	// DomainIgnorelist removes feed indicators for these registrable domains or pseudo-domains.
	DomainIgnorelist []string `toml:"domain_ignorelist" json:"domain_ignorelist"`
}

// ScanConfig holds the allow/deny scope, the file of targets, and the active scan settings.
type ScanConfig struct {
	Allow               []string `toml:"allow" json:"allow"`
	Deny                []string `toml:"deny" json:"deny"`
	TargetsFile         string   `toml:"targets_file" json:"targets_file"`
	FeedOnlyTargetsFile string   `toml:"feed_only_targets_file" json:"feed_only_targets_file"`
	ASNRefreshMinutes   int      `toml:"asn_refresh_minutes" json:"asn_refresh_minutes"`
	// CommonPorts are tried first in a full sweep and can also be swept alone on request.
	CommonPorts []int `toml:"common_ports" json:"common_ports"`
	// ScansPerDay is how often each target is actively scanned. It sets the sweep interval,
	// timed from the start of a pass, so a long one restarts immediately.
	ScansPerDay int `toml:"scans_per_day" json:"scans_per_day"`
	// MaxWorkers caps the port dials in flight at once.
	MaxWorkers    int `toml:"max_workers" json:"max_workers"`
	DialTimeoutMS int `toml:"dial_timeout_ms" json:"dial_timeout_ms"`
	// TLSTimeoutMS budgets the handshake, which only runs on a port that already answered.
	// Separate from DialTimeoutMS because open ports are rare. A generous budget here collects
	// certificates from slow hosts without slowing the sweep, which is paid in dials.
	TLSTimeoutMS int `toml:"tls_timeout_ms" json:"tls_timeout_ms"`
	// JARMTimeoutMS budgets one JARM probe, and a fingerprint is ten probes run back to back.
	// A silent host therefore costs ten times this before the sweep moves on, which is why it
	// is set separately from TLSTimeoutMS rather than sharing that budget.
	JARMTimeoutMS int `toml:"jarm_timeout_ms" json:"jarm_timeout_ms"`
}

// LoadConfig decodes the TOML config file and validates every field.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	meta, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return cfg, err
	}
	// Reject unknown keys so a typo fails loudly instead of silently defaulting.
	if undecoded := meta.Undecoded(); len(undecoded) != 0 {
		return cfg, fmt.Errorf("unknown configuration key: %s", undecoded[0])
	}
	if cfg.Feeds.DomainIgnorelist, err = CanonicalDomainIgnorelist(cfg.Feeds.DomainIgnorelist); err != nil {
		return cfg, err
	}
	cfg.Scan.FeedOnlyTargetsFile = strings.TrimSpace(cfg.Scan.FeedOnlyTargetsFile)
	cfg.Scan.Allow, cfg.Scan.Deny = DedupeEntries(cfg.Scan.Allow), DedupeEntries(cfg.Scan.Deny)
	return cfg, ValidateConfig(cfg)
}

// ValidateConfig checks every field of a decoded config. Separate from loadConfig so a config
// arriving from the dashboard can be checked before it is written, rather than after.
func ValidateConfig(cfg Config) error {
	if len(cfg.Scan.Allow) == 0 {
		return errors.New("scan.allow must not be empty")
	}
	if cfg.Scan.TargetsFile == "" {
		return errors.New("scan.targets_file must not be empty")
	}
	// Sharing one file means the feed-only editor writes the active target list, and that editor
	// is allowed to save an empty one. The next reload would then find no targets at all.
	if cfg.Scan.FeedOnlyTargetsFile != "" && SameFile(cfg.Scan.FeedOnlyTargetsFile, cfg.Scan.TargetsFile) {
		return errors.New("scan.feed_only_targets_file must not be scan.targets_file")
	}
	if len(cfg.Scan.CommonPorts) == 0 {
		return errors.New("scan.common_ports must not be empty")
	}
	for i, port := range cfg.Scan.CommonPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("scan.common_ports entry %d is not a port", port)
		}
		if slices.Contains(cfg.Scan.CommonPorts[:i], port) {
			return fmt.Errorf("scan.common_ports contains duplicate port %d", port)
		}
	}
	// Every setting must be present in the file. An omitted key decodes to zero, so
	// rejecting zero is what makes a missing line fail loudly instead of picking a default.
	if cfg.Base.RefreshSeconds < 1 {
		return errors.New("config.refresh_seconds must be set to a positive number of seconds")
	}
	if durationOverflows(cfg.Base.RefreshSeconds, time.Second) {
		return errors.New("config.refresh_seconds is too large")
	}
	if cfg.Scan.ASNRefreshMinutes < 15 {
		return errors.New("scan.asn_refresh_minutes must be set to at least 15 minutes")
	}
	if durationOverflows(cfg.Scan.ASNRefreshMinutes, time.Minute) {
		return errors.New("scan.asn_refresh_minutes is too large")
	}
	// One scan a day at minimum, hourly at most. The interval is 24h/scans_per_day.
	if cfg.Scan.ScansPerDay < 1 || cfg.Scan.ScansPerDay > 24 {
		return errors.New("scan.scans_per_day must be set, between 1 and 24")
	}
	if cfg.Scan.MaxWorkers < 1 {
		return errors.New("scan.max_workers must be set to a positive number of workers")
	}
	if cfg.Scan.DialTimeoutMS < 1 {
		return errors.New("scan.dial_timeout_ms must be set to a positive number of milliseconds")
	}
	if durationOverflows(cfg.Scan.DialTimeoutMS, time.Millisecond) {
		return errors.New("scan.dial_timeout_ms is too large")
	}
	if cfg.Scan.TLSTimeoutMS < 1 {
		return errors.New("scan.tls_timeout_ms must be set to a positive number of milliseconds")
	}
	if durationOverflows(cfg.Scan.TLSTimeoutMS, time.Millisecond) {
		return errors.New("scan.tls_timeout_ms is too large")
	}
	if cfg.Scan.JARMTimeoutMS < 1 {
		return errors.New("scan.jarm_timeout_ms must be set to a positive number of milliseconds")
	}
	if durationOverflows(cfg.Scan.JARMTimeoutMS, time.Millisecond) {
		return errors.New("scan.jarm_timeout_ms is too large")
	}
	return nil
}

// ldhDomain is a strict letter-digit-hyphen domain of two or more labels: no leading or trailing
// hyphen on a label, no underscore, nothing empty.
var ldhDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// CanonicalDomainIgnorelist lowercases each entry, strips a leading "*." and trailing dot, and
// accepts ICANN registrable domains and two-label pseudo-domains. It rejects subdomains and bare
// public suffixes because registrableDomain reduces names to this level before matching.
func CanonicalDomainIgnorelist(values []string) ([]string, error) {
	domains := make([]string, len(values))
	for i, raw := range values {
		domain := parse.NormalizeName(raw)
		canonical, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if !ldhDomain.MatchString(domain) || len(domain) > 253 || err != nil || canonical != domain {
			return nil, fmt.Errorf("feeds.domain_ignorelist entry %d is not a registrable or pseudo-domain", i+1)
		}
		if slices.Contains(domains[:i], domain) {
			return nil, fmt.Errorf("feeds.domain_ignorelist contains duplicate domain %q", domain)
		}
		domains[i] = domain
	}
	return domains, nil
}

func durationOverflows(value int, unit time.Duration) bool {
	return int64(value) > int64(time.Duration(1<<63-1)/unit)
}

// Path is the file the config was loaded from, and the file the dashboard writes back to.
// Assigned once from the -config flag before any goroutine starts, like reportPath.
var Path string

// ChangeMu serializes the reload loop against a dashboard write. Without it a tick that read the
// old file can finish after the handler installed the new one and put the old config back, so a
// save appears to revert until the next tick.
var ChangeMu sync.Mutex

// SaveConfig replaces the config file with cfg. The comments in a hand-written config.toml are
// lost: the encoder emits values only, and config.example.toml is where the documented copy lives.
func SaveConfig(path string, cfg Config) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return err
	}
	return writeFileAtomic(path, buf.Bytes())
}

// writeFileAtomic replaces path with data, through a temporary file in the same directory renamed
// over the target. The reload loop reads either the old file or the new one and never a
// half-written one. 0600 throughout: the config carries the ThreatFox key, and the targets file
// names our own address space.
func writeFileAtomic(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	// Removed unless the rename below took it. Deferred now, so every failure path drops it.
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0o600); err != nil {
		temp.Close() //nolint:errcheck
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close() //nolint:errcheck
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

// Current is the live config and scope. Package-level because every loop reads it and nothing ever
// needs a second one. Config() is the only way in, and it holds the read lock.
var Current Store

// Store holds the live config and the scope derived from it, swapped wholesale on reload.
type Store struct {
	mu    sync.RWMutex
	Cfg   Config
	scope Scope
}

// Load re-reads the config and targets files and swaps them in. On failure the previous
// State is left untouched, so a half-saved edit doesn't blank the scope.
func (s *Store) Load(path string) error {
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	scope, err := LoadScope(cfg)
	if err != nil {
		return err
	}
	s.Set(cfg, scope)
	return nil
}

// Set installs a config and scope directly: the reload, the ASN refresh's rebuilt scope, and the
// on-demand run whose targets come from the command line rather than the targets file. A pass
// already running keeps the scope it started with, so what lands here applies from the next one.
func (s *Store) Set(cfg Config, scope Scope) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Cfg, s.scope = cfg, scope
}

// Config returns the current config and scope held in memory.
func (s *Store) Config() (Config, Scope) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Cfg, s.scope
}

// SameFile reports whether two config paths name one file. Resolved to absolute before comparing,
// so "targets.json" and an absolute spelling of the same path do not slip past as two files. A
// symlink pointing one at the other still reads as distinct; the files need not exist yet, so
// there is nothing to resolve them through.
func SameFile(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return absA == absB
}

// LoadTargets loads the config and the scope the run will probe. That is the -scan argument when
// one is given, otherwise the targets file. Either way the scope goes through newScope, so the
// allowlist guardrail runs before the process opens a connection.
//
// FeedOnly puts the -scan argument on the side the sweep never probes, so the run matches it
// against the feeds and dials nothing.
func LoadTargets(configPath, scan string, feedOnly bool) error {
	if scan == "" {
		if err := Current.Load(configPath); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		return nil
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	targets, err := ParsePrefixes([]string{scan})
	if err != nil {
		return fmt.Errorf("-scan: %w", err)
	}
	// Nothing is probed, so a scope with no active targets is the point rather than a fault: the
	// empty-target check is waived and checkFeedOnly is what rejects an unauthorized argument.
	if feedOnly {
		scope, err := newScopeWith(cfg, nil, true)
		if err != nil {
			return fmt.Errorf("-scan %s: %w", scan, err)
		}
		scope.FeedOnly = targets
		scope.FeedOnlyScannable = FeedOnlyHosts(scope)
		if err := CheckFeedOnly(scope); err != nil {
			return fmt.Errorf("-scan %s -feed-only: %w", scan, err)
		}
		Current.Set(cfg, scope)
		return nil
	}
	scope, err := NewScope(cfg, targets)
	if err != nil {
		return fmt.Errorf("-scan %s: %w", scan, err)
	}
	Current.Set(cfg, scope)
	return nil
}
