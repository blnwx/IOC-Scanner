package endpoints

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Serve runs the web UI until ctx is cancelled. It has no authentication and no TLS, so
// the address it is given should be a loopback one.
func Serve(ctx context.Context, addr string, assets fs.FS) error {
	// WriteTimeout covers the handler as well as the write, and a host query walks the whole
	// table, so it is generous rather than tight. IdleTimeout stops a kept-alive connection
	// holding a slot forever.
	srv := &http.Server{Handler: compressAPI(dashboardMux(assets)), ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	// Bound before anything is logged, so a taken port reports the failure and nothing else.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		// Not ctx, it is already cancelled. In-flight responses get a moment to finish.
		stopping, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		srv.Shutdown(stopping) //nolint:errcheck
	}()
	// The listener's address, not the one asked for, so a :0 port reports the one assigned.
	slog.Info("dashboard listening", "addr", listener.Addr())
	if err := srv.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// Serve returns as soon as Shutdown starts, with handlers still draining. Waiting for the
	// drain here is what keeps runScanner's deferred closeDB from landing underneath them.
	<-stopped
	return nil
}

// dashboardMux routes the dashboard.
func dashboardMux(assets fs.FS) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /", assetHeaders(dashboardFiles(assets)))
	mux.Handle("GET /api/", http.NotFoundHandler())
	mux.HandleFunc("GET /api/analytics", handleAnalytics)
	mux.HandleFunc("GET /api/domains", handleDomains)
	mux.HandleFunc("GET /api/hosts", handleHosts)
	mux.HandleFunc("GET /api/hosts/feed-only", handleFeedOnlyHosts)
	mux.HandleFunc("GET /api/jarm", handleJARM)
	mux.HandleFunc("GET /api/jarm-blacklist", handleGetJARMBlacklist)
	mux.HandleFunc("GET /api/logs", handleLogs)
	mux.HandleFunc("GET /api/scan", handleScanStatus)
	mux.HandleFunc("GET /api/settings", handleSettings)
	mux.HandleFunc("GET /api/targets", handleTargets)
	mux.HandleFunc("POST /api/ack", handleAck)
	mux.HandleFunc("POST /api/jarm-blacklist", handleSaveJARMBlacklist)
	mux.HandleFunc("POST /api/scan", handleScan)
	mux.HandleFunc("DELETE /api/jarm-blacklist", handleDeleteJARMBlacklist)
	mux.HandleFunc("PUT /api/settings", handleSaveSettings)
	mux.HandleFunc("PUT /api/targets", handleSaveTargets)
	return mux
}

// dashboardFiles serves built assets and falls back to the React entry point for page routes.
func dashboardFiles(assets fs.FS) http.Handler {
	files := http.FileServerFS(assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check decoded segments before cleaning so encoded traversal cannot become an asset alias.
		if slices.Contains(strings.Split(r.URL.Path, "/"), "..") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		info, err := fs.Stat(assets, name)
		isAsset := name == "assets" || strings.HasPrefix(name, "assets/")
		if name == "" || (errors.Is(err, fs.ErrNotExist) && !isAsset && path.Ext(name) == "") {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
			info, err = fs.Stat(assets, "index.html")
		}
		// Reject directories instead of letting FileServer list them.
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		// FileServer redirects index.html to its directory; do not cache that redirect forever.
		if isAsset && path.Base(name) != "index.html" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}

// assetHeaders stamps the security headers on the page and everything it loads.
//
// Fetches and form submissions stay same-origin, and markup cannot change the document base URL.
// Inline styles support Sonner's injected stylesheet and measured positions; scripts stay external.
func assetHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; base-uri 'none'; form-action 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// gzipResponseWriter sends the handler's bytes through gzip. Only Write is redirected: the
// header map and status code belong to the underlying writer as they always did.
type gzipResponseWriter struct {
	http.ResponseWriter
	gz *gzip.Writer
}

func (w gzipResponseWriter) Write(b []byte) (int, error) { return w.gz.Write(b) }

// compressAPI gzips the JSON API for clients that ask for it. The host table is around 19KB of
// very repetitive JSON — port records, signal objects, certificate fields — and compresses about
// fifteen times, which on a tunnelled or otherwise slow link is the bulk of the wait on every
// filter change and every poll. The query behind it answers in under a millisecond, so the bytes
// on the wire are the only thing worth shortening.
//
// The static assets are left alone. http.FileServerFS serves them through ServeContent, which
// honours Range requests, and compressing the body out from under that would break it for no
// gain: dashboardFiles already caches them immutable for a year, so they cost one transfer per
// build rather than one per filter change.
func compressAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		// Both headers have to be set before the handler writes anything. Vary keeps a cache from
		// handing a compressed body to a client that did not ask for one.
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		next.ServeHTTP(gzipResponseWriter{ResponseWriter: w, gz: gz}, r)
	})
}

// sortOrder reads a sort parameter against the keys a table offers. A "-" prefix reverses the
// listing. An unrecognised key is the empty key and takes no direction with it, so a stray prefix
// cannot flip a table's default order — the rule all three sortable tables want, spelled once.
func sortOrder(raw string, keys ...string) (string, bool) {
	key, descending := strings.CutPrefix(raw, "-")
	if !slices.Contains(keys, key) {
		return "", false
	}
	return key, descending
}

// ordering turns a direction into the sign applied to a comparator.
func ordering(descending bool) func(int) int {
	if descending {
		return func(comparison int) int { return -comparison }
	}
	return func(comparison int) int { return comparison }
}

// positive reads a query parameter that has to be a positive number, falling back when it is
// missing or junk. Every paging value is clamped rather than rejected: a bad URL should show the
// first page, not an error.
func positive(value string, fallback int) int {
	number, err := strconv.Atoi(value)
	if err != nil || number < 1 {
		return fallback
	}
	return number
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("dashboard response failed", "err", err)
	}
}
