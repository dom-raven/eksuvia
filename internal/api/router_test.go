package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRouterMatchesLiteralAndWildcardSegments(t *testing.T) {
	r := NewRouter()
	var got Params
	var hit string

	r.Handle(http.MethodGet, "/clusters", func(w http.ResponseWriter, _ *http.Request, p Params) {
		hit, got = "list", p
	})
	r.Handle(http.MethodGet, "/clusters/:name", func(w http.ResponseWriter, _ *http.Request, p Params) {
		hit, got = "describe", p
	})
	r.Handle(http.MethodGet, "/clusters/:name/node-groups/:nodegroup", func(w http.ResponseWriter, _ *http.Request, p Params) {
		hit, got = "nodegroup", p
	})

	tests := []struct {
		path      string
		wantHit   string
		wantParam map[string]string
	}{
		{"/clusters", "list", map[string]string{}},
		{"/clusters/demo", "describe", map[string]string{"name": "demo"}},
		{"/clusters/demo/node-groups/ng-1", "nodegroup", map[string]string{"name": "demo", "nodegroup": "ng-1"}},
	}

	for _, tt := range tests {
		hit, got = "", nil
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tt.path, nil))
		if hit != tt.wantHit {
			t.Errorf("%s matched %q, want %q", tt.path, hit, tt.wantHit)
		}
		for k, want := range tt.wantParam {
			if got[k] != want {
				t.Errorf("%s: param %q = %q, want %q", tt.path, k, got[k], want)
			}
		}
	}
}

func TestRouterUnescapesARNInPath(t *testing.T) {
	// EKS embeds a URL-encoded principal ARN as a single path segment. Getting
	// this wrong is the difference between access entries working and every
	// describe/delete returning 404.
	r := NewRouter()
	var principal string
	r.Handle(http.MethodGet, "/clusters/:name/access-entries/:principal",
		func(w http.ResponseWriter, _ *http.Request, p Params) { principal = p["principal"] })

	const arn = "arn:aws:iam::000000000000:role/Admin"
	path := "/clusters/demo/access-entries/" + url.PathEscape(arn)
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))

	if principal != arn {
		t.Errorf("principal = %q, want %q", principal, arn)
	}
}

func TestRouterFallsBackForUnknownPaths(t *testing.T) {
	r := NewRouter()
	proxied := false
	r.Handle(http.MethodGet, "/clusters", func(http.ResponseWriter, *http.Request, Params) {})
	r.Fallback(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxied = true }))

	// An unrelated AWS service path must reach the upstream emulator untouched.
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/some-other-service", nil))
	if !proxied {
		t.Error("unmatched path was not passed to the fallback proxy")
	}
}

func TestRouterReturnsMethodNotAllowedForKnownPath(t *testing.T) {
	// A known resource with the wrong verb must not be proxied to Floci, which
	// would answer with a confusing unrelated error.
	r := NewRouter()
	proxied := false
	r.Handle(http.MethodGet, "/clusters/:name", func(http.ResponseWriter, *http.Request, Params) {})
	r.Fallback(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxied = true }))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPatch, "/clusters/demo", nil))

	if proxied {
		t.Error("a known path with an unsupported method was proxied upstream")
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestRouterDoesNotMatchDifferentSegmentCounts(t *testing.T) {
	r := NewRouter()
	matched := false
	r.Handle(http.MethodGet, "/clusters/:name", func(http.ResponseWriter, *http.Request, Params) { matched = true })
	r.Fallback(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/clusters/a/b/c", nil))
	if matched {
		t.Error("a three-segment path matched a two-segment route")
	}
}
