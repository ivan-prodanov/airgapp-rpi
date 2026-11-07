package handlers

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/web"
)

// testPages is every page template that renders inside the layout, with the
// page key its handler passes (which drives the active nav link).
var testPages = []struct{ file, key string }{
	{"dashboard.html", "dashboard"},
	{"devices.html", "devices"},
	{"traffic.html", "traffic"},
	{"stats.html", "stats"},
	{"filters.html", "filters"},
	{"firewall.html", "firewall"},
	{"bandwidth.html", "bandwidth"},
	{"settings.html", "settings"},
	{"remote-access.html", "remote-access"},
}

// renderPage renders one page through the real embedded templates, the way
// the page handlers do.
func renderPage(r *Renderer, file, key string) (body string, status int) {
	rec := httptest.NewRecorder()
	r.RenderPage(rec, file, map[string]string{"page": key})
	return rec.Body.String(), rec.Code
}

func TestRenderPageConcurrent(t *testing.T) {
	r := NewRenderer(web.Content)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(p struct{ file, key string }) {
			defer wg.Done()
			if _, code := renderPage(r, p.file, p.key); code != 200 {
				t.Errorf("%s: status %d", p.file, code)
			}
		}(testPages[i%len(testPages)])
	}
	wg.Wait()
}

func TestRenderEveryPage(t *testing.T) {
	r := NewRenderer(web.Content)
	for _, p := range testPages {
		body, code := renderPage(r, p.file, p.key)
		if code != 200 || !strings.Contains(body, "<title>") {
			t.Errorf("%s: status %d, has title %v", p.file, code, strings.Contains(body, "<title>"))
		}
	}
}
