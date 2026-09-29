package endpoints

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	storage "iocscanner/src/db"
	"iocscanner/src/parse"
	scanner "iocscanner/src/scan"
)

func normalizeJARMHash(raw string) (string, error) {
	hash := strings.ToLower(strings.TrimSpace(raw))
	if len(hash) != 62 {
		return "", errors.New("hash must be 62 hexadecimal characters")
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return "", errors.New("hash must be 62 hexadecimal characters")
	}
	if strings.Trim(hash, "0") == "" {
		return "", errors.New("all-zero JARM is not allowed")
	}
	return hash, nil
}

func normalizeJARMBlacklistEntries(rows []storage.JARMBlacklistEntry) ([]storage.JARMBlacklistEntry, error) {
	normalized := make([]storage.JARMBlacklistEntry, len(rows))
	seen := make(map[string]bool, len(rows))
	for i, row := range rows {
		row.Label = strings.TrimSpace(row.Label)
		if row.Label == "" {
			return nil, fmt.Errorf("item %d: label is required", i+1)
		}
		hash, err := normalizeJARMHash(row.Hash)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i+1, err)
		}
		if seen[hash] {
			return nil, fmt.Errorf("item %d: duplicate hash", i+1)
		}
		seen[hash] = true
		row.Hash = hash
		normalized[i] = row
	}
	return normalized, nil
}

func handleGetJARMBlacklist(w http.ResponseWriter, r *http.Request) {
	rows, err := storage.JARMBlacklistEntries(r.Context())
	if err != nil {
		slog.Error("dashboard JARM blacklist query failed", "err", err)
		http.Error(w, "cannot read the JARM blacklist", http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		w.Header().Set("Content-Disposition", `attachment; filename="jarm-blacklist.csv"`)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		writer := csv.NewWriter(w)
		if err := writer.Write([]string{"label", "hash"}); err == nil {
			for _, row := range rows {
				if err = writer.Write([]string{row.Label, row.Hash}); err != nil {
					break
				}
			}
		}
		writer.Flush()
		if err == nil {
			err = writer.Error()
		}
		if err != nil {
			slog.Error("dashboard JARM blacklist CSV failed", "err", err)
		}
		return
	}
	writeJSON(w, rows)
}

func handleSaveJARMBlacklist(w http.ResponseWriter, r *http.Request) {
	if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		http.Error(w, "expected a JSON body", http.StatusUnsupportedMediaType)
		return
	}
	var body *[]storage.JARMBlacklistEntry
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := parse.JSONDecoder(decoder, &body); err != nil || body == nil {
		http.Error(w, "cannot read the JARM blacklist", http.StatusBadRequest)
		return
	}
	rows, err := normalizeJARMBlacklistEntries(*body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := storage.SaveJARMBlacklist(r.Context(), rows); err != nil {
		slog.Error("saving JARM blacklist failed", "rows", len(rows), "err", err)
		http.Error(w, "cannot write the JARM blacklist", http.StatusInternalServerError)
		return
	}
	if len(rows) > 0 {
		if err := scanner.ApplyStoredResultChange(context.WithoutCancel(r.Context())); err != nil {
			slog.Error("applying JARM blacklist failed", "err", err)
			http.Error(w, "JARM blacklist saved but results could not be refreshed", http.StatusInternalServerError)
			return
		}
	}
	handleGetJARMBlacklist(w, r)
}

func handleDeleteJARMBlacklist(w http.ResponseWriter, r *http.Request) {
	if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		http.Error(w, "expected a JSON body", http.StatusUnsupportedMediaType)
		return
	}
	var body struct {
		Hash string `json:"hash"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10))
	decoder.DisallowUnknownFields()
	if err := parse.JSONDecoder(decoder, &body); err != nil {
		http.Error(w, "cannot read the JARM blacklist", http.StatusBadRequest)
		return
	}
	hash, err := normalizeJARMHash(body.Hash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := storage.DeleteJARMBlacklist(r.Context(), hash); err != nil {
		slog.Error("deleting JARM blacklist entry failed", "hash", hash, "err", err)
		http.Error(w, "cannot write the JARM blacklist", http.StatusInternalServerError)
		return
	}
	if err := scanner.ApplyStoredResultChange(context.WithoutCancel(r.Context())); err != nil {
		slog.Error("applying JARM blacklist deletion failed", "hash", hash, "err", err)
		http.Error(w, "JARM blacklist updated but results could not be refreshed", http.StatusInternalServerError)
		return
	}
	handleGetJARMBlacklist(w, r)
}
