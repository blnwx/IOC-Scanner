package endpoints

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"iocscanner/src/parse"
	scanner "iocscanner/src/scan"
	targetcfg "iocscanner/src/targets"
)

// handleScanStatus serves what the scanner is sweeping now.
func handleScanStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, scanner.CurrentStatus())
}

// handleScan asks for a sweep. It runs on its own loop, alongside the scheduled pass rather than
// in place of it. It stores nothing itself, but it redirects where the scanner points, so it
// carries the same content-type guard as handleAck.
func handleScan(w http.ResponseWriter, r *http.Request) {
	if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		http.Error(w, "expected a JSON body", http.StatusUnsupportedMediaType)
		return
	}
	var body struct {
		Kind    string `json:"kind"`
		Targets string `json:"targets"`
	}
	if err := parse.JSON(http.MaxBytesReader(w, r.Body, 1<<10), &body); err != nil {
		http.Error(w, "cannot read the request body", http.StatusBadRequest)
		return
	}
	if body.Kind != "common" && body.Kind != "full" {
		http.Error(w, `kind must be "common" or "full"`, http.StatusBadRequest)
		return
	}
	// Required. Sweeping the configured scope is what the schedule already does on its own cadence,
	// so the only thing this endpoint adds is pointing the scanner somewhere it does not.
	if strings.TrimSpace(body.Targets) == "" {
		http.Error(w, "at least one target is required", http.StatusBadRequest)
		return
	}
	values := strings.Split(body.Targets, ",")
	if err := targetcfg.ResolveNewASNs(r.Context(), values); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	targets, err := targetcfg.ParsePrefixes(values)
	cfg, _ := targetcfg.Current.Config()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Every address has to be inside scan.allow and outside scan.deny, with no silent trimming of
	// the part that is not.
	scope, err := targetcfg.NewManualScope(cfg, targets)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if !scanner.QueueManual(body.Kind, targets, scope.Scannable) {
		http.Error(w, "a scan is already running", http.StatusConflict)
		return
	}
	slog.Info("scan requested", "kind", body.Kind, "targets", scope.Scannable)
	// Accepted rather than OK: the pass starts on its own loop, not in this handler.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(scanner.CurrentStatus()); err != nil {
		slog.Error("dashboard response failed", "err", err)
	}
}
