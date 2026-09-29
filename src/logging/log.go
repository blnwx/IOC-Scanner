package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LevelAlert sits above ERROR. A confirmed hit is never filtered out, whatever the handler's
// minimum level. Terminal output separately suppresses alerts in default mode or when writing a report file.
const LevelAlert = slog.Level(10)

// Alert logs a confirmed hit. That is an authorized target listed in a feed, or a scanned host
// whose address or certificate is listed.
func Alert(msg string, args ...any) {
	slog.Log(context.Background(), LevelAlert, msg, args...)
}

// SetupLogger controls terminal verbosity while retaining INFO and alerts for the dashboard.
// Verbosity 0 shows info, warnings and errors, 1 adds alerts, and 2 adds debug details.
// Findings stay in the dashboard but are omitted from the terminal in default mode or when a report file is used.
func SetupLogger(out io.Writer, verbosity int, outputFile bool) {
	min := slog.LevelInfo
	if verbosity >= 2 {
		min = slog.LevelDebug
	}
	slog.SetDefault(slog.New(&compactHandler{out: out, min: min, showAlerts: verbosity >= 1 && !outputFile}))
}

// compactHandler renders one line per record. Local timestamp, level as a bare tag, then the
// message, then key=value attrs. None of TextHandler's time=/level=/msg= clutter.
type compactHandler struct {
	mu         sync.Mutex
	out        io.Writer
	min        slog.Level
	showAlerts bool
}

func (h *compactHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.min
}

func (h *compactHandler) Handle(_ context.Context, record slog.Record) error {
	name := record.Level.String()
	if record.Level == LevelAlert {
		name = "ALERT"
	}
	attrs := make([]string, 0, record.NumAttrs())
	record.Attrs(func(attr slog.Attr) bool {
		// A detail that isn't there prints as nothing rather than as key="".
		if value := attr.Value.String(); value != "" {
			attrs = append(attrs, attr.Key+"="+quote(value))
		}
		return true
	})
	LogRing.add(LogEntry{At: record.Time.Unix(), Level: name, Msg: record.Message,
		Attrs: strings.Join(attrs, " ")})
	if record.Level < h.min || (record.Level == LevelAlert && !h.showAlerts) {
		return nil
	}
	line := fmt.Sprintf("%s  %-5s  %s", record.Time.Format(time.DateTime), name, record.Message)
	if len(attrs) > 0 {
		line += "  " + strings.Join(attrs, " ")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.out, line+"\n")
	return err
}

// LogEntry is one record kept for the dashboard's log panel.
type LogEntry struct {
	At    int64  `json:"at"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
	Attrs string `json:"attrs"`
}

// LogRing is the last few hundred records, for the dashboard to read back. Handle only runs for
// records that passed Enabled, so this holds INFO and above, or everything at debug verbosity.
//
// Held in memory, so the panel is empty after a restart. What survives one is whatever captured
// stderr — a redirect, or the supervisor running the process — and nothing if that is a terminal.
// An events table is what this wants if the history has to survive on its own.
var LogRing ring

// ring is a fixed-size circular buffer of log records. Its own lock: the handler's guards the
// output writer, and a reader must not wait on a slow terminal.
type ring struct {
	mu  sync.Mutex
	Buf [500]LogEntry
	// n is the total ever added, so n-len(buf) is where the surviving entries start.
	n int
}

func (r *ring) add(entry LogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Buf[r.n%len(r.Buf)] = entry
	r.n++
}

// Recent returns the held records, newest first.
func (r *ring) Recent() []LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	held := min(r.n, len(r.Buf))
	out := make([]LogEntry, 0, held)
	for i := 1; i <= held; i++ {
		out = append(out, r.Buf[(r.n-i)%len(r.Buf)])
	}
	return out
}

// The logger is never given persistent attributes or groups. Both stay pass-throughs.
func (h *compactHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *compactHandler) WithGroup(string) slog.Handler { return h }

// quote keeps the key=value output parseable when a value carries a space or a quote.
func quote(value string) string {
	if strings.ContainsAny(value, ` "`) {
		return strconv.Quote(value)
	}
	return value
}
