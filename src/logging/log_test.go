package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestTerminalVerbosityAndReportFile(t *testing.T) {
	previous := slog.Default()
	defer slog.SetDefault(previous)
	for _, level := range []int{0, 1, 2, 3} {
		for _, outputFile := range []bool{false, true} {
			var out bytes.Buffer
			SetupLogger(&out, level, outputFile)
			slog.Debug("debug detail")
			slog.Info("progress")
			slog.Warn("warning")
			slog.Error("failure")
			Alert("finding", "ip", "192.0.2.1")
			for message, want := range map[string]bool{
				"debug detail": level >= 2, "progress": true,
				"warning": true, "failure": true, "finding": level >= 1 && !outputFile,
			} {
				if got := strings.Contains(out.String(), message); got != want {
					t.Errorf("verbosity=%d outputFile=%t message=%q present=%t, want %t", level, outputFile, message, got, want)
				}
			}
			entries := LogRing.Recent()
			if entries[0].Msg != "finding" || entries[0].Attrs != "ip=192.0.2.1" || entries[3].Msg != "progress" {
				t.Fatalf("dashboard lost findings or progress: %v", entries[:4])
			}
		}
	}
}
