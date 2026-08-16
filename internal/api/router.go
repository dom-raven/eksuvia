package api

import (
	"net/http"
	"net/url"
	"strings"
)

// Params holds path variables captured by a route.
type Params map[string]string

// HandlerFunc is a route handler with captured path parameters.
type HandlerFunc func(http.ResponseWriter, *http.Request, Params)

type route struct {
	method   string
	segments []string // literal, or ":name" for a wildcard
	handler  HandlerFunc
}

// Router matches EKS-style REST paths.
//
// net/http's pattern matching is not used here because several EKS paths embed
// a URL-encoded ARN as a single segment
// (/clusters/x/access-entries/arn%3Aaws%3Aiam%3A%3A...). Matching on the
// escaped path and unescaping only after a segment has been captured avoids any
// ambiguity about when %2F becomes a separator.
type Router struct {
	routes   []route
	fallback http.Handler
}

// NewRouter returns an empty router.
func NewRouter() *Router { return &Router{} }

// Handle registers a handler. The pattern is a slash-separated path where a
// segment beginning with ':' captures a parameter.
func (rt *Router) Handle(method, pattern string, h HandlerFunc) {
	rt.routes = append(rt.routes, route{
		method:   method,
		segments: splitPath(pattern),
		handler:  h,
	})
}

// Fallback sets the handler used when no route matches. eksuvia points this at
// the Floci proxy, so every AWS API it does not implement itself still works.
func (rt *Router) Fallback(h http.Handler) { rt.fallback = h }

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	segments := splitPath(r.URL.EscapedPath())

	// Tracks whether a path matched under a different method, so an unmatched
	// request can be reported as 405 rather than silently proxied.
	pathMatched := false

	for i := range rt.routes {
		params, ok := rt.routes[i].match(segments)
		if !ok {
			continue
		}
		if rt.routes[i].method != r.Method {
			pathMatched = true
			continue
		}
		rt.routes[i].handler(w, r, params)
		return
	}

	if pathMatched {
		writeError(w, http.StatusMethodNotAllowed, "ClientException", "method not allowed for this resource")
		return
	}
	if rt.fallback != nil {
		rt.fallback.ServeHTTP(w, r)
		return
	}
	writeError(w, http.StatusNotFound, "ResourceNotFoundException", "no such resource")
}

func (rt route) match(segments []string) (Params, bool) {
	if len(segments) != len(rt.segments) {
		return nil, false
	}
	var params Params
	for i, want := range rt.segments {
		if strings.HasPrefix(want, ":") {
			// Unescape only the captured value. A malformed escape is treated as
			// a literal so the caller sees a clean 404 rather than a 500.
			value, err := url.PathUnescape(segments[i])
			if err != nil {
				value = segments[i]
			}
			if params == nil {
				params = make(Params, len(rt.segments))
			}
			params[want[1:]] = value
			continue
		}
		if segments[i] != want {
			return nil, false
		}
	}
	if params == nil {
		params = Params{}
	}
	return params, true
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}
