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

// The login page uses the Gap theme and drops the old placeholder copy.
func TestLoginPage(t *testing.T) {
	rec := httptest.NewRecorder()
	NewRenderer(web.Content).RenderLogin(rec, nil)
	body := rec.Body.String()
	// method="post": submitted before Alpine binds @submit.prevent (slow load, password
	// manager autofill+submit), a GET would put the password in the URL and the request log.
	for _, want := range []string{"/static/css/gap.css", "<title>Sign in — Airgapp</title>", ">Sign in</button>", `method="post"`} {
		if !strings.Contains(body, want) {
			t.Errorf("login page lacks %s", want)
		}
	}
	for _, gone := range []string{"fonts.googleapis.com", "netfilterd-01", "Guardian", "Operator", "192.168.4.1"} {
		if strings.Contains(body, gone) {
			t.Errorf("login page still contains %q", gone)
		}
	}
}

// The Gap dashboard: headline, gate with lane slots, readouts — and none of the
// cards the redesign dropped (hero, stat cards, car lock, WAN probe, switch).
func TestDashboardPage(t *testing.T) {
	body, _ := renderPage(NewRenderer(web.Content), "dashboard.html", "dashboard")
	for _, want := range []string{`class="dash"`, `class="hstmt"`, `class="gate"`, `class="lanes"`, "This sweep"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %s", want)
		}
	}
	if n := strings.Count(body, `class="hostrow`); n != 7 {
		t.Errorf("%d host rows, want 7 lane slots", n)
	}
	for _, gone := range []string{"Guardian", "Probe WAN", "stat-card", "lock_", "segbtn"} {
		if strings.Contains(body, gone) {
			t.Errorf("dashboard still contains %q", gone)
		}
	}
}

// The dashboard runs edge to edge; other pages keep the content padding.
func TestLayoutBleed(t *testing.T) {
	r := NewRenderer(web.Content)
	dash, _ := renderPage(r, "dashboard.html", "dashboard")
	devs, _ := renderPage(r, "devices.html", "devices")
	if !strings.Contains(dash, `<main class="content content-bleed">`) {
		t.Error("dashboard main is not content-bleed")
	}
	if !strings.Contains(devs, `<main class="content">`) {
		t.Error("devices main should be plain content")
	}
}

// The Gap devices page: the Tesla's card, the colour key and the roster — no
// lease table and no client-side Tesla regex any more.
func TestDevicesPage(t *testing.T) {
	body, _ := renderPage(NewRenderer(web.Content), "devices.html", "devices")
	for _, want := range []string{`class="specimen`, `class="legend"`, `class="roster"`, "Other devices", `name="pol-tesla"`, "Open the Tesla"} {
		if !strings.Contains(body, want) {
			t.Errorf("devices page lacks %s", want)
		}
	}
	for _, gone := range []string{"<table", "Lease table", "/tesla/i"} {
		if strings.Contains(body, gone) {
			t.Errorf("devices page still contains %q", gone)
		}
	}
}

// The Gap filters page: groups, search, one switch per filter, the new-filter
// dialog — no filter cards, no "why is it needed", no per-domain switches.
func TestFiltersPage(t *testing.T) {
	body, _ := renderPage(NewRenderer(web.Content), "filters.html", "filters")
	for _, want := range []string{`class="flist"`, "Find a domain or filter", "New filter", `class="ndlg"`, "A filter is a named list of domains."} {
		if !strings.Contains(body, want) {
			t.Errorf("filters page lacks %s", want)
		}
	}
	for _, gone := range []string{"filter-card", "Why is it needed", "description is required"} {
		if strings.Contains(body, gone) {
			t.Errorf("filters page still contains %q", gone)
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
