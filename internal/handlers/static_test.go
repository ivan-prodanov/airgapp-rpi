package handlers

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/web"
)

// Fonts and images never change between builds of the same name, so the
// browser keeps them; CSS and JS revalidate cheaply by content hash. Without
// this every page switch re-downloaded the fonts and the menu re-flowed.
func TestStaticCaching(t *testing.T) {
	staticFS, _ := fs.Sub(web.Content, "static")
	h := http.StripPrefix("/static/", StaticHandler(staticFS))
	get := func(path, inm string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if inm != "" {
			req.Header.Set("If-None-Match", inm)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	font := get("/static/fonts/martian-mono.woff2", "")
	if font.Code != 200 || !strings.Contains(font.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("font: %d Cache-Control %q", font.Code, font.Header().Get("Cache-Control"))
	}
	css := get("/static/css/gap.css", "")
	etag := css.Header().Get("ETag")
	if css.Code != 200 || etag == "" || css.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("css: %d ETag %q Cache-Control %q", css.Code, etag, css.Header().Get("Cache-Control"))
	}
	if again := get("/static/css/gap.css", etag); again.Code != http.StatusNotModified {
		t.Fatalf("css revalidation: %d, want 304", again.Code)
	}
	if missing := get("/static/css/nope.css", ""); missing.Code != http.StatusNotFound {
		t.Fatalf("missing file: %d", missing.Code)
	}
}

// The menu's own font is preloaded with the body font, so the first paint of
// every page already uses it.
func TestLayoutPreloadsMenuFont(t *testing.T) {
	body, _ := renderPage(NewRenderer(web.Content), "devices.html", "devices")
	if !strings.Contains(body, `<link rel="preload" href="/static/fonts/martian-mono.woff2" as="font" type="font/woff2" crossorigin>`) {
		t.Error("layout doesn't preload Martian Mono")
	}
}
