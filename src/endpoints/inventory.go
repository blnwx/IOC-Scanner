package endpoints

import (
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	storage "iocscanner/src/db"
	"iocscanner/src/logging"
)

// handleLogs serves what the process has logged since it started, newest first.
func handleLogs(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	level := strings.ToUpper(strings.TrimSpace(query.Get("level")))
	needle := strings.ToLower(strings.TrimSpace(query.Get("q")))
	entries := slices.DeleteFunc(logging.LogRing.Recent(), func(entry logging.LogEntry) bool {
		if level != "" && entry.Level != level {
			return true
		}
		return needle != "" && !strings.Contains(strings.ToLower(entry.Msg+" "+entry.Attrs), needle)
	})
	writeJSON(w, entries)
}

// epochSeconds reads an optional timestamp bound off a query. Anything unparseable is no bound at
// all, so a hand-edited URL widens the table rather than emptying it.
func epochSeconds(raw string) int64 {
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds < 0 {
		return 0
	}
	return seconds
}

// handleDomains serves the names on every collected certificate, one row per endpoint. Unlike
// handleJARM the search cannot stay in SQL: the names shown are the merged, filtered set, and
// matching the raw columns would return rows whose only hit was a name certName then drops.
//
// Scan rows are retained, so this includes every name ever seen, like the host table, which is what
// the from/before bounds narrow to a day or a run of them.
func handleDomains(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	rows, err := domains(r.Context(), query.Get("q"), query.Get("sort"),
		epochSeconds(query.Get("from")), epochSeconds(query.Get("before")))
	if err != nil {
		slog.Error("dashboard domains query failed", "err", err)
		http.Error(w, "cannot read the scan database", http.StatusInternalServerError)
		return
	}
	writeJSON(w, rows)
}

// handleJARM serves lifetime hashes. Search stays in SQL and is always bound.
func handleJARM(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	sort, descending := sortOrder(query.Get("sort"), "hosts", "recent", "first", "hash")
	rows, err := storage.LoadJARMRows(r.Context(), sort, descending,
		strings.ToLower(strings.TrimSpace(query.Get("q"))))
	if err != nil {
		slog.Error("dashboard jarm query failed", "err", err)
		http.Error(w, "cannot read the JARM database", http.StatusInternalServerError)
		return
	}
	for i := range rows {
		rows[i].Blacklisted = storage.JARMBlacklist.Contains(rows[i].Hash)
	}
	writeJSON(w, rows)
}
