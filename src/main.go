package main

import (
	"cmp"
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	storage "iocscanner/src/db"
	"iocscanner/src/endpoints"
	"iocscanner/src/logging"
	"iocscanner/src/parse"
	scanner "iocscanner/src/scan"
	targetcfg "iocscanner/src/targets"
)

// dashboardFS embeds the React production build into the scanner binary.
//
//go:embed web
var dashboardFS embed.FS

// main runs the scanner and exits non-zero on error.
func main() {
	if err := runScanner(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// runScanner loads the config, opens the database, and runs every loop until the process is
// interrupted.
func runScanner() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	config := flag.String("config", "config.toml", "configuration file")
	verbosity := 0
	flag.BoolFunc("v", "increase terminal verbosity: -v for alerts, -v -v for debug", func(string) error {
		verbosity++
		return nil
	})
	flag.BoolFunc("vv", "enable debug terminal logging (same as -v -v)", func(string) error {
		verbosity = 2
		return nil
	})
	output := flag.String("output", "", "write the JSON report here instead of stdout")
	scan := flag.String("scan", "", "scan this IP, CIDR, or ASN once and exit, ignoring the target files")
	feedOnly := flag.Bool("feed-only", false, "with -scan: match the target against the feeds without probing it")
	listen := flag.String("listen", "", "serve the dashboard on this address, e.g. 127.0.0.1:8080")
	flag.Parse()
	scanner.ReportPath = *output
	targetcfg.Path = *config
	scanner.CLIScan = *scan
	logging.SetupLogger(os.Stderr, verbosity, *output != "")

	// Only -scan takes its scope from the command line. A long-running process gets its feed-only
	// list from the config file, where it can be edited without a restart.
	if *feedOnly && *scan == "" {
		return errors.New("-feed-only needs -scan; a scheduled run reads scan.feed_only_targets_file")
	}

	if err := targetcfg.LoadASNCache(); err != nil {
		slog.Warn("loading ASN prefix cache failed", "err", err)
	}
	if cfg, err := targetcfg.LoadConfig(targetcfg.Path); err == nil {
		if err := targetcfg.ResolveStartupASNs(ctx, cfg, *scan); err != nil {
			return fmt.Errorf("ASN resolution: %w", err)
		}
	}
	if err := targetcfg.LoadTargets(targetcfg.Path, *scan, *feedOnly); err != nil {
		return err
	}
	cfg, s := targetcfg.Current.Config()
	// More workers than the process has file descriptors for fails dials with EMFILE, which
	// looks the same as a closed port. Warn rather than report a silently empty surface.
	var files syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &files); err == nil && uint64(cfg.Scan.MaxWorkers) >= files.Cur {
		slog.Warn("a sweep may need more open files than allowed; raise ulimit -n",
			"max_workers", cfg.Scan.MaxWorkers, "open_files", files.Cur)
	}
	if err := storage.Open(ctx, filepath.Join("db", "matches.db")); err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer storage.Close()

	slog.Info("starting", "targets", parse.HostCount(s.Targets), "scannable", s.Scannable,
		"feed_only", s.FeedOnlyScannable, "allow", parse.HostCount(s.Allow), "deny", parse.HostCount(s.Deny))
	var running sync.WaitGroup
	// The dashboard is off unless asked for, and starts before the first feed pull: that pull
	// takes tens of seconds, and watching the log while it happens is half the point. A failure
	// to bind is logged, not fatal — the scan is the job, and it carries on without a way to
	// look at it. The on-demand mode below exits before a server would be useful, so it gets none.
	if *listen != "" && *scan == "" {
		assets, err := fs.Sub(dashboardFS, "web")
		if err != nil {
			return err
		}
		running.Add(1)
		go func() {
			defer running.Done()
			if err := endpoints.Serve(ctx, *listen, assets); err != nil {
				slog.Error("dashboard stopped", "addr", *listen, "err", err)
			}
		}()
	}
	// One match cycle up front, before the sweeps start. The first ports they probe then get
	// checked against the feeds like every later one.
	scanner.MatchTargetsAgainstFeeds(ctx)

	// On-demand mode. One full pass against the address given on the command line, then done.
	// No reload loop, no tickers, no repeat pass.
	if *scan != "" {
		// A feed-only scan is the feed match above and nothing else: no pass to run, and so no
		// sweep to write the report on the way out, which is why this mode writes it itself.
		if *feedOnly {
			if _, err := scanner.WriteReport(context.WithoutCancel(ctx), scanner.ReportPath); err != nil {
				return err
			}
		} else {
			scanner.SavePass(ctx, scanner.SweepOnce(ctx, false, false, nil), "cli")
		}

		// Not ctx. An interrupted run still gets a verdict for what it managed to scan.
		report, _, err := scanner.BuildReport(context.WithoutCancel(ctx))
		if err != nil {
			return err
		}
		slog.Info("scan complete", "targets", cmp.Or(s.Scannable, s.FeedOnlyScannable),
			"feed_only", *feedOnly, "findings", len(report), "report", cmp.Or(scanner.ReportPath, "stdout"))
		return nil
	}

	running.Add(5)
	go func() { defer running.Done(); scanner.ReloadConfigLoop(ctx, targetcfg.Path) }()
	go func() { defer running.Done(); targetcfg.ASNRefreshLoop(ctx) }()
	go func() { defer running.Done(); scanner.MatchTargetsAgainstFeedsLoop(ctx) }()
	go func() { defer running.Done(); scanner.SweepLoop(ctx) }()
	// Its own loop, so an operator's scan runs alongside the scheduled sweep instead of stopping it.
	go func() { defer running.Done(); scanner.ManualLoop(ctx) }()

	<-ctx.Done()
	slog.Info("shutting down")
	// A cancelled context fails the in-flight dials at once, so the loops stop promptly.
	running.Wait()
	slog.Info("stopped")
	return nil
}
