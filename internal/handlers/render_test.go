package handlers

import (
	"net/http/httptest"
	"regexp"
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

// The Gap stylesheet loads after app.css (so its tokens win), fonts are
// self-hosted, and the product name in the title is "Airgapp".
func TestLayoutStylesheets(t *testing.T) {
	body, _ := renderPage(NewRenderer(web.Content), "devices.html", "devices")
	app, gap := strings.Index(body, `href="/static/css/app.css"`), strings.Index(body, `href="/static/css/gap.css"`)
	if app < 0 || gap < 0 || gap < app {
		t.Errorf("want app.css then gap.css, got app.css at %d, gap.css at %d", app, gap)
	}
	for _, want := range []string{
		`<link rel="preload" href="/static/fonts/saira.woff2" as="font" type="font/woff2" crossorigin>`,
		`<title>Devices — Airgapp</title>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("layout lacks %s", want)
		}
	}
	if strings.Contains(body, "fonts.googleapis.com") {
		t.Error("layout still requests Google Fonts")
	}
}

// The Gap top bar: five links in a fixed order, the current one marked active
// (System covers Settings and Remote access until they merge); pages outside
// the nav mark nothing. The old sidebar is gone.
func TestLayoutNav(t *testing.T) {
	active := map[string]string{
		"dashboard": "Dashboard", "devices": "Devices", "traffic": "Traffic", "filters": "Filters",
		"settings": "System", "remote-access": "System",
		"firewall": "", "stats": "", "bandwidth": "",
	}
	activeRe := regexp.MustCompile(`aria-current="page">([A-Za-z]+)<`)
	r := NewRenderer(web.Content)
	for _, p := range testPages {
		body, _ := renderPage(r, p.file, p.key)
		start, end := strings.Index(body, `<nav class="topnav"`), strings.Index(body, `</nav>`)
		if start < 0 || end < start {
			t.Errorf("%s: no top nav", p.key)
			continue
		}
		nav := body[start:end]
		if n := strings.Count(nav, `class="navlink`); n != 5 {
			t.Errorf("%s: %d nav links, want 5", p.key, n)
		}
		last := -1
		for _, label := range []string{">Dashboard<", ">Devices<", ">Traffic<", ">Filters<", ">System<"} {
			i := strings.Index(nav, label)
			if i < 0 || i < last {
				t.Errorf("%s: %s missing or out of order", p.key, label)
			}
			last = i
		}
		for _, href := range []string{`href="/"`, `href="/devices"`, `href="/traffic"`, `href="/filters"`, `href="/settings"`} {
			if !strings.Contains(nav, href) {
				t.Errorf("%s: nav lacks %s", p.key, href)
			}
		}
		got := ""
		if m := activeRe.FindAllStringSubmatch(nav, -1); len(m) == 1 {
			got = m[0][1]
		} else if len(m) > 1 {
			got = "several"
		}
		if got != active[p.key] {
			t.Errorf("%s: active link %q, want %q", p.key, got, active[p.key])
		}
		for _, gone := range []string{"shellApp(", `class="rail`, "head-bar"} {
			if strings.Contains(body, gone) {
				t.Errorf("%s: old sidebar markup %q still present", p.key, gone)
			}
		}
	}
}

// The sidebar footer (sign out) and its Remote access link are gone; until the
// System page lands, Settings carries both.
func TestSettingsInterimLinks(t *testing.T) {
	body, _ := renderPage(NewRenderer(web.Content), "settings.html", "settings")
	for _, want := range []string{`href="/remote-access"`, `onclick="logout()"`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks %s", want)
		}
	}
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
