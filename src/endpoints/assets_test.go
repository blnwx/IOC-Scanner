package endpoints

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func TestDashboardAssetBoundaries(t *testing.T) {
	assets := fstest.MapFS{
		"index.html":               {Data: []byte("<title>dashboard</title>")},
		"theme.js":                 {Data: []byte("theme")},
		"assets/index-abc123.js":   {Data: []byte("console.log('ok')")},
		"assets/nested/style.css":  {Data: []byte("body{}")},
		"assets/nested/index.html": {Data: []byte("nested")},
	}
	mux := dashboardMux(assets)
	for _, tc := range []struct {
		path      string
		status    int
		immutable bool
	}{
		{"/", 200, false},
		{"/hosts", 200, false},
		{"/theme.js", 200, false},
		{"/assets/index-abc123.js", 200, true},
		{"/assets/nested/style.css", 200, true},
		{"/assets", 404, false},
		{"/assets/", 404, false},
		{"/assets/nested/", 404, false},
		{"/assets/missing", 404, false},
		{"/assets/missing.js", 404, false},
		{"/assets/nested/index.html", 301, false},
		{"/assets/%2e%2e/theme.js", 404, false},
		{"/assets/%2e%2e/%2e%2e/config.toml", 404, false},
		{"/config.toml", 404, false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			wantCache := "no-store"
			if tc.immutable {
				wantCache = "public, max-age=31536000, immutable"
			}
			if got := w.Header().Get("Cache-Control"); got != wantCache {
				t.Errorf("Cache-Control = %q, want %q", got, wantCache)
			}
			policy := strings.Split(w.Header().Get("Content-Security-Policy"), "; ")
			for _, directive := range []string{"default-src 'none'", "base-uri 'none'", "form-action 'self'", "script-src 'self'", "frame-ancestors 'none'"} {
				if !slices.Contains(policy, directive) {
					t.Errorf("policy missing directive %q", directive)
				}
			}
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Error("missing nosniff")
			}
		})
	}

	// Preserve the file server's HEAD and byte-range support when applying cache policy.
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		r := httptest.NewRequest(method, "/assets/index-abc123.js", nil)
		r.Header.Set("Range", "bytes=0-6")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusPartialContent || w.Header().Get("Content-Range") != "bytes 0-6/17" {
			t.Errorf("%s range response = %d, %q", method, w.Code, w.Header().Get("Content-Range"))
		}
		wantBody := "console"
		if method == http.MethodHead {
			wantBody = ""
		}
		if w.Body.String() != wantBody {
			t.Errorf("%s body = %q, want %q", method, w.Body.String(), wantBody)
		}
	}
}
