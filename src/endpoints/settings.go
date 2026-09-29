package endpoints

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"

	"iocscanner/src/parse"
	scanner "iocscanner/src/scan"
	targetcfg "iocscanner/src/targets"
)

// handleSettings serves the running config as the settings form reads it. The ThreatFox key is
// tagged json:"-", so it cannot appear here however this struct changes.
//
// It reports the live config rather than the file on disk: a failed reload keeps the last good one
// (see reloadOnce), so after a bad hand edit the two differ, and the running one is what an
// operator should be looking at and correcting.
func handleSettings(w http.ResponseWriter, _ *http.Request) {
	cfg, _ := targetcfg.Current.Config()
	writeJSON(w, map[string]any{"config": cfg, "threatfox_auth_key_set": cfg.Feeds.ThreatFoxAuthKey != ""})
}

// handleSaveSettings replaces the config file with what the settings form sent. It is a whole
// config, not a patch: the loader rejects every zero value, so a partial body fails naming the
// field it left out.
func handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		http.Error(w, "expected a JSON body", http.StatusUnsupportedMediaType)
		return
	}
	// Decode into a zero config so a missing field stays missing and validation rejects it. The
	// auth key is restored from the live config under configMu below; it never comes from JSON.
	var cfg targetcfg.Config
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	// The counterpart of loadConfig rejecting unknown TOML keys: a typoed field is an error, not
	// a silently dropped setting.
	decoder.DisallowUnknownFields()
	if err := parse.JSONDecoder(decoder, &cfg); err != nil {
		http.Error(w, "cannot read the settings: "+err.Error(), http.StatusBadRequest)
		return
	}
	domains, err := targetcfg.CanonicalDomainIgnorelist(cfg.Feeds.DomainIgnorelist)
	if err != nil {
		slog.Warn("settings rejected", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfg.Feeds.DomainIgnorelist = domains
	cfg.Scan.FeedOnlyTargetsFile = strings.TrimSpace(cfg.Scan.FeedOnlyTargetsFile)
	// Same normalization loadConfig applies to a hand-written file, so the form and the file agree.
	cfg.Scan.Allow, cfg.Scan.Deny = targetcfg.DedupeEntries(cfg.Scan.Allow), targetcfg.DedupeEntries(cfg.Scan.Deny)
	// Nothing reaches the disk until every check has passed. The loader's own messages name the
	// field, so they go to the operator as they are.
	if err := targetcfg.ValidateConfig(cfg); err != nil {
		slog.Warn("settings rejected", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := targetcfg.ResolveNewASNs(r.Context(), slices.Concat(cfg.Scan.Allow, cfg.Scan.Deny)); err != nil {
		slog.Warn("settings rejected", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Held across write and install, so a reload tick that read the old file cannot finish
	// afterwards and put it back. ASN resolution above performs no work under this lock.
	targetcfg.ChangeMu.Lock()
	defer targetcfg.ChangeMu.Unlock()
	live, _ := targetcfg.Current.Config()
	cfg.Feeds.ThreatFoxAuthKey = live.Feeds.ThreatFoxAuthKey
	// A new optional path starts as an empty target list so the Targets page can edit it. An
	// existing file is left alone, so a path already configured still fails loudly below if it
	// disappears or becomes invalid.
	if cfg.Scan.FeedOnlyTargetsFile != "" && cfg.Scan.FeedOnlyTargetsFile != live.Scan.FeedOnlyTargetsFile {
		if err = createEmptyTargets(cfg.Scan.FeedOnlyTargetsFile); err != nil {
			slog.Warn("settings rejected", "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	// scan.allow is the guardrail that keeps the scanner off address space that is not ours, and
	// this request can rewrite it. Building the scope proves the new lists still admit both files.
	scope, err := targetcfg.LoadScope(cfg)
	if err != nil {
		slog.Warn("settings rejected", "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := targetcfg.SaveConfig(targetcfg.Path, cfg); err != nil {
		slog.Error("writing the config failed", "path", targetcfg.Path, "err", err)
		http.Error(w, "cannot write the configuration file", http.StatusInternalServerError)
		return
	}
	// Install exactly what passed validation. Re-reading after the atomic replacement could fail on
	// an unrelated hand edit to the targets file and report failure after the config already changed.
	targetcfg.Current.Set(cfg, scope)
	if !slices.Equal(live.Feeds.DomainIgnorelist, cfg.Feeds.DomainIgnorelist) {
		if err := scanner.ApplyDomainIgnorelistChange(context.WithoutCancel(r.Context())); err != nil {
			slog.Error("applying domain ignorelist failed", "err", err)
			http.Error(w, "settings saved but results could not be refreshed", http.StatusInternalServerError)
			return
		}
	}
	scanner.RematchFeeds(context.WithoutCancel(r.Context()), scope)
	slog.Info("settings saved", "targets", parse.HostCount(scope.Targets), "allow", parse.HostCount(scope.Allow),
		"deny", parse.HostCount(scope.Deny))
	writeJSON(w, map[string]any{"config": cfg, "threatfox_auth_key_set": cfg.Feeds.ThreatFoxAuthKey != ""})
}

// prefixRow is one prefix an ASN entry expands to, shown indented under it.
type prefixRow struct {
	Value     string `json:"value"`
	Addresses int    `json:"addresses"`
	Status    string `json:"status"`
}

// targetRow is one entry of the targets file, with what the scanner would actually do with it.
type targetRow struct {
	Value     string      `json:"value"`
	Addresses int         `json:"addresses"`
	CoveredBy string      `json:"covered_by"`
	Expansion []prefixRow `json:"expansion"`
	// Status is "in scope", "partially in scope", "denied", "out of scope", "covered" or
	// "unresolved". The allow and deny lists narrow the targets file, so a target can be listed and
	// never probed — which is worth seeing before a sweep silently covers nothing.
	Status string `json:"status"`
}

// createEmptyTargets creates path holding an empty target list, leaving an existing file alone.
// Exclusive rather than stat-then-write: an operator writing the file by hand in between would
// otherwise have it replaced.
func createEmptyTargets(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("feed-only targets file %s: %w", path, err)
	}
	defer file.Close()
	_, err = file.WriteString("[]\n")
	return err
}

// feedOnlySelector reads the ?target selector for the two targets endpoints. Only the empty value
// and "feed-only" are accepted: a typo used to fall through to the active list, which on a save
// meant a feed-only edit silently overwrote the targets the scanner sweeps.
func feedOnlySelector(r *http.Request) (bool, bool) {
	switch r.URL.Query().Get("target") {
	case "":
		return false, true
	case "feed-only":
		return true, true
	}
	return false, false
}

// targetsBody describes the current target entries and their cached expansions.
func targetsBody(feedOnly bool) map[string]any {
	cfg, scope := targetcfg.Current.Config()
	values, scannable, targetFile := scope.TargetEntries, scope.Scannable, cfg.Scan.TargetsFile
	if feedOnly {
		values, scannable, targetFile = scope.FeedOnlyEntries, scope.FeedOnlyScannable, cfg.Scan.FeedOnlyTargetsFile
	}
	var excluded []netip.Prefix
	if feedOnly {
		excluded = scope.FeedOnlyExcluded()
	}
	entries := make([]targetcfg.TargetEntry, len(values))
	resolved := make([]bool, len(values))
	for i, value := range values {
		expanded, err := targetcfg.ExpandEntries([]string{value})
		if err != nil {
			continue
		}
		entries[i], resolved[i] = expanded[0], true
	}
	rows := make([]targetRow, len(values))
	for i, value := range values {
		rows[i] = targetRow{Value: value, Expansion: []prefixRow{}}
		if !resolved[i] {
			rows[i].Status = "unresolved"
			continue
		}
		entry := entries[i]
		rows[i].Value = entry.Value
		rows[i].Addresses = parse.HostCount(parse.DedupePrefixes(entry.Prefixes))
		rows[i].Status = targetcfg.EntryStatus(scope, entry, excluded)
		if _, isASN := targetcfg.ParseASN(entry.Value); isASN {
			for _, prefix := range entry.Prefixes {
				status := scope.Status(prefix)
				if excluded != nil {
					status = scope.FeedOnlyStatus(prefix, excluded)
				}
				rows[i].Expansion = append(rows[i].Expansion, prefixRow{
					Value: prefix.String(), Addresses: parse.HostCount([]netip.Prefix{prefix}), Status: status,
				})
			}
			continue
		}
		literal := entry.Prefixes[0]
		for j, candidate := range entries {
			if !resolved[j] {
				continue
			}
			if _, isASN := targetcfg.ParseASN(candidate.Value); !isASN {
				continue
			}
			for _, announced := range candidate.Prefixes {
				if shared, ok := parse.Overlap(announced, literal); ok && shared == literal {
					rows[i].Status, rows[i].CoveredBy = "covered", candidate.Value
					break
				}
			}
			if rows[i].CoveredBy != "" {
				break
			}
		}
	}
	return map[string]any{"targets": rows, "scannable": scannable, "targets_file": targetFile}
}

func handleTargets(w http.ResponseWriter, r *http.Request) {
	feedOnly, ok := feedOnlySelector(r)
	if !ok {
		http.Error(w, "unknown target selector", http.StatusBadRequest)
		return
	}
	writeJSON(w, targetsBody(feedOnly))
}

// handleSaveTargets replaces the targets file. This is the address space the scanner points at, so
// the list goes through the same parse and the same guardrail as the one loaded at startup, and
// nothing is written until both have passed.
func handleSaveTargets(w http.ResponseWriter, r *http.Request) {
	if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		http.Error(w, "expected a JSON body", http.StatusUnsupportedMediaType)
		return
	}
	var body struct {
		Targets []string `json:"targets"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := parse.JSONDecoder(decoder, &body); err != nil {
		http.Error(w, "cannot read the targets: "+err.Error(), http.StatusBadRequest)
		return
	}
	feedOnly, ok := feedOnlySelector(r)
	if !ok {
		http.Error(w, "unknown target selector", http.StatusBadRequest)
		return
	}
	if cfg, _ := targetcfg.Current.Config(); feedOnly && cfg.Scan.FeedOnlyTargetsFile == "" {
		http.Error(w, "configure scan.feed_only_targets_file before editing feed-only targets", http.StatusConflict)
		return
	}
	if err := targetcfg.ResolveNewASNs(r.Context(), body.Targets); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	targetcfg.ChangeMu.Lock()
	defer targetcfg.ChangeMu.Unlock()
	cfg, current := targetcfg.Current.Config()
	if feedOnly && cfg.Scan.FeedOnlyTargetsFile == "" {
		http.Error(w, "configure scan.feed_only_targets_file before editing feed-only targets", http.StatusConflict)
		return
	}
	entries, err := targetcfg.ExpandEntries(body.Targets)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	normalized := targetcfg.EntryValues(entries)
	targets, err := targetcfg.ParsePrefixes(normalized)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The scanner cannot run on an empty targets file, and loadScope says so at startup. Refusing
	// here means the dashboard cannot write the file that would stop the next reload.
	if !feedOnly && len(targets) == 0 {
		http.Error(w, "at least one target is required", http.StatusBadRequest)
		return
	}
	var scope targetcfg.Scope
	targetFile := cfg.Scan.TargetsFile
	if feedOnly {
		scope = current
		scope.FeedOnly = targets
		scope.FeedOnlyEntries = normalized
		targetFile = cfg.Scan.FeedOnlyTargetsFile
	} else if scope, err = targetcfg.NewScope(cfg, targets); err == nil {
		scope.TargetEntries = normalized
		scope.FeedOnly = current.FeedOnly
		scope.FeedOnlyEntries = current.FeedOnlyEntries
	}
	if err == nil {
		scope.FeedOnlyScannable = targetcfg.FeedOnlyHosts(scope)
		// Only the edit that would create a list matching nothing is refused. Widening the active
		// targets over the feed-only ones is a real thing to want, and the Targets page marks the
		// entries it swallowed rather than blocking the save.
		if feedOnly {
			err = targetcfg.CheckFeedOnly(scope)
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := targetcfg.SaveTargets(targetFile, normalized); err != nil {
		slog.Error("writing the targets file failed", "path", targetFile, "err", err)
		http.Error(w, "cannot write the targets file", http.StatusInternalServerError)
		return
	}
	targetcfg.Current.Set(cfg, scope)
	scanner.RematchFeeds(context.WithoutCancel(r.Context()), scope)
	if feedOnly {
		slog.Info("targets saved", "feed_only_targets", parse.HostCount(scope.FeedOnly), "feed_only_scannable", scope.FeedOnlyScannable)
	} else {
		slog.Info("targets saved", "targets", parse.HostCount(scope.Targets), "scannable", scope.Scannable)
	}
	writeJSON(w, targetsBody(feedOnly))
}
