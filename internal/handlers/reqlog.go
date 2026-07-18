package handlers

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"

	"github.com/go-chi/chi/v5/middleware"
)

// redactedQueryKeys lists query parameter names whose VALUES must never
// reach the request log. Today that's just the BLE events WebSocket bearer
// token: the RN client can't attach an Authorization header to a WS
// upgrade, so the bearer travels as ?token=<bearer> instead (see
// EventsBLE's doc comment in tesla_session.go and its mount point outside
// BLEBearerRequired in router.go). Transport is fine — wss encrypts the
// query end-to-end — but chi's stock middleware.Logger logs r.RequestURI
// verbatim, which would write the live bearer token to the Pi's own
// stdout/journal on every connection.
var redactedQueryKeys = []string{"token"}

// RedactingLogFormatter wraps chi's DefaultLogFormatter, redacting the
// values of any redactedQueryKeys in the request's query string before
// handing off to the default formatter. The logged essentials — method,
// path (with query redacted), protocol, remote/real IP, then status, bytes
// written, and duration on completion — match chi's stock Logger output;
// only sensitive values differ (replaced with "REDACTED", key preserved).
type RedactingLogFormatter struct {
	inner *middleware.DefaultLogFormatter
}

// NewRedactingLogFormatter builds the root request logger formatter used by
// NewRouterWithFS in place of middleware.Logger. It logs to stdout with the
// same timestamp flags and color behavior as chi's default logger.
func NewRedactingLogFormatter() *RedactingLogFormatter {
	color := runtime.GOOS != "windows"
	return &RedactingLogFormatter{
		inner: &middleware.DefaultLogFormatter{
			Logger:  log.New(os.Stdout, "", log.LstdFlags),
			NoColor: !color,
		},
	}
}

// NewLogEntry implements middleware.LogFormatter. It rewrites r.RequestURI
// to redact sensitive query parameter values (if any), then delegates to
// the wrapped DefaultLogFormatter so the rest of the request line — and the
// Write(status, bytes, ...) call on completion — behaves exactly like
// chi's stock logger.
func (f *RedactingLogFormatter) NewLogEntry(r *http.Request) middleware.LogEntry {
	if redacted := redactRequestURI(r.RequestURI); redacted != r.RequestURI {
		clone := r.Clone(r.Context())
		clone.RequestURI = redacted
		r = clone
	}
	return f.inner.NewLogEntry(r)
}

// redactRequestURI parses raw (a request-URI, e.g. "/path?a=1&token=xyz")
// and replaces the value of any key in redactedQueryKeys with "REDACTED",
// preserving the path and every other query parameter. It uses net/url to
// parse and rewrite the query rather than a regex, so it can't accidentally
// redact — or miss — a param embedded oddly in the string. If raw has no
// query string, isn't parseable, or has nothing to redact, it is returned
// unchanged.
func redactRequestURI(raw string) string {
	if raw == "" {
		return raw
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return raw
	}
	if parsed.RawQuery == "" {
		return raw
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return raw
	}

	changed := false
	for _, key := range redactedQueryKeys {
		if _, present := values[key]; present {
			values.Set(key, "REDACTED")
			changed = true
		}
	}
	if !changed {
		return raw
	}

	parsed.RawQuery = values.Encode()
	return parsed.String()
}
