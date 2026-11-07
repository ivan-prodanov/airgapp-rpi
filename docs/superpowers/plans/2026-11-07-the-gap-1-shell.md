# The Gap, slice 1 (shell & theme): implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every page renders inside the new Gap shell: a top bar with five links, self-hosted Saira and Martian Mono, and the Gap palette and motion tokens. Pages not yet ported are bridged onto the new palette, and no function is lost.

**Architecture:**
- A new stylesheet, `web/static/css/gap.css`, loads after `app.css`. It carries the Gap tokens, fonts, base styles, shell, motion and toast.
- It also points the old `app.css` tokens at Gap values, so pages not yet ported pick up the palette. This bridge is removed in slice 6.
- `layout.html` replaces the sidebar rail with the top bar, and the document becomes the scroller.
- Go tests render the real embedded templates to pin the shell.

**Tech Stack:** Go `html/template` and chi; Alpine.js 3.15.11 (vendored); plain CSS. There is no build step and no JavaScript test runner.

**Spec:** `docs/superpowers/specs/2026-11-07-the-gap-redesign.md`. The mockups are at `.claude/design/the-gap/*.dc.html` in the main checkout, which git ignores. Lift CSS from them.

## Global Constraints
- **No new dependencies.**
  - No new JavaScript libraries and no build step.
  - No CDN requests: no Google Fonts `<link>` anywhere.
- **This repository is public.** Code, tests, fixtures and docs must not contain production hostnames, device names, tokens or VINs. Preview mocks use `example` names.
- **Copy:**
  - Write "Airgapp", never "Airgapp app".
  - The `<title>` suffix is ` — Airgapp`.
  - Remove the words "Guardian", "netfilterd-01" and "Operator" from the shell and the login page.
- **Templates and handlers:**
  - Page templates keep defining `title`, `content` and `scripts`.
  - Handlers keep passing `map[string]string{"page": key}`.
- **Values to use exactly as the spec gives them:**
  - Tokens: Type and colour, and Motion.
  - Breakpoints: 520px (top bar static below this), 380px (smaller link type) and 860px (compact layout), plus `pointer:coarse` for tap targets.
- **Commits:** commit locally after each task and never push. End every commit message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus
1. **Narrow screens:** at 320px with a classic 15px scrollbar, all five links are visible and the page doesn't scroll sideways. This is checked in Task 8, step 3.
2. **Pages outside the nav:** firewall, stats and bandwidth render with no active link. Settings and remote-access mark System as active. This is pinned in Task 4, `TestLayoutNav`.
3. **Login errors:** a wrong password shows an inline error without reloading the page, and a lockout shows the server's "try again in …" text. This is checked in Task 7, step 4, through the preview mock from Task 6.
4. **Fonts missing or blocked:** text renders in the fallback stack with `font-display:swap`, so text is never invisible. This is pinned in Task 2, `TestGapCSSDeclaresFonts`.
5. **First renders at the same time:** two pages rendered concurrently for the first time must not race the template cache. This is pinned in Task 1, `TestRenderPageConcurrent`, under `-race`.

---

### Task 1: Thread-safe renderer and render-test helper

**Files:**
- Modify: `internal/handlers/render.go:12-38`
- Create: `internal/handlers/render_test.go`

**Interfaces:**
- Produces (test-only, in `render_test.go`):
  - `var testPages = []struct{ file, key string }{…}`, holding all nine pages: dashboard, devices, traffic, stats, filters, firewall, bandwidth, settings, remote-access.
  - `func renderPage(r *Renderer, file, key string) (body string, status int)`, which uses `httptest.NewRecorder` and `map[string]string{"page": key}`.
  - Later tasks' tests use both.

- [ ] **Step 1: Write the failing tests**

```go
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
```

- [ ] **Step 2: Run the tests and confirm the concurrency test fails**

  Run: `go test -race ./internal/handlers -run 'TestRender' -count=1`

  Expected: FAIL with `WARNING: DATA RACE` or `concurrent map writes` from `RenderPage`.
- [ ] **Step 3: Guard `Renderer.cache` with a `sync.RWMutex` field `mu`**

  Read under `RLock`, and parse and store under `Lock`, re-checking the map once the lock is held. Nothing else in `RenderPage` changes.
- [ ] **Step 4: Run the tests and confirm they pass**

  Run: `go test -race ./internal/handlers -run 'TestRender' -count=1`

  Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `fix(web): guard the template cache; render every page in tests`.

### Task 2: Self-hosted fonts

**Files:**
- Modify: `Makefile`. Add a `fonts` target and include it in `assets`.
- Create:
  - `web/static/fonts/saira.woff2`
  - `web/static/fonts/martian-mono.woff2`
  - `web/static/fonts/OFL-Saira.txt`
  - `web/static/fonts/OFL-MartianMono.txt`
- Create: `web/static/css/gap.css`, containing only the two `@font-face` rules at this point.
- Create: `web/embed_test.go`

**Interfaces:**
- Produces:
  - `/static/fonts/saira.woff2`: variable font, weights 300–700, latin subset.
  - `/static/fonts/martian-mono.woff2`: variable font, weights 400–600, latin subset.
  - The font-family names `'Saira'` and `'Martian Mono'`.

- [ ] **Step 1: Write the failing tests in `web/embed_test.go` (package `web`)**
  - `TestFontsEmbedded`:
    - Both `.woff2` files read from `Content` must be at least 10,000 bytes and start with `wOF2`.
    - Both `OFL-*.txt` files must contain `SIL OPEN FONT LICENSE`.
  - `TestGapCSSDeclaresFonts`: `static/css/gap.css` must contain each of these strings:
    - `font-family:'Saira'`
    - `url(/static/fonts/saira.woff2) format('woff2')`
    - `font-weight:300 700`
    - `font-family:'Martian Mono'`
    - `url(/static/fonts/martian-mono.woff2) format('woff2')`
    - `font-weight:400 600`
    - `font-display:swap`
- [ ] **Step 2: Run the tests and confirm they fail**

  Run: `go test ./web -count=1`

  Expected: FAIL (file does not exist).
- [ ] **Step 3: Add the `fonts` Makefile target**
  - Fetch `https://fonts.googleapis.com/css2?family=Saira:wght@300..700&family=Martian+Mono:wght@400..600&display=swap` with a desktop Chrome User-Agent.
  - From each family's `/* latin */` block, take the woff2 URL and download it to the file named above.
  - Fetch `https://raw.githubusercontent.com/google/fonts/main/ofl/saira/OFL.txt` and `…/ofl/martianmono/OFL.txt` into the two licence files.
  - Run `make fonts` and commit the downloaded files, the same way `alpine.min.js` is vendored.
- [ ] **Step 4: Write the two `@font-face` rules at the top of `gap.css`**

  Use the exact strings from Step 1, with no spaces after the colons.
- [ ] **Step 5: Run the tests and confirm they pass**

  Run: `go test ./web -count=1`

  Expected: `ok`. Also check that `file web/static/fonts/*.woff2` reports `Web Open Font Format (Version 2)`.
- [ ] **Step 6: Commit**

  Message: `feat(web): self-host Saira and Martian Mono for the Gap theme`.

### Task 3: Gap tokens, base styles and motion, with the old tokens bridged

**Files:**
- Modify: `web/static/css/gap.css`
- Modify: `web/templates/layout.html:7-11`
- Modify: `web/static/css/app.css:63-75`. Remove `overflow: hidden;` and `height: 100%;` from `html, body`.
- Test: `internal/handlers/render_test.go`

**Interfaces:**
- Produces, used by later slices:
  - The CSS custom properties from the spec: colour tokens plus `--t-*`, `--rise-*` and `--ease-*`.
  - `@keyframes rise`.
  - Attribute hooks `[data-rise]`, `[data-rise="1"]`, `[data-rise="2"]` and `[data-rise="3"]` for the page-arrival sequence.

- [ ] **Step 1: Write the failing test `TestLayoutStylesheets`**

  Render `devices.html` and assert that the body:
  - contains `href="/static/css/app.css"` before `href="/static/css/gap.css"`;
  - contains `<link rel="preload" href="/static/fonts/saira.woff2" as="font" type="font/woff2" crossorigin>`;
  - doesn't contain `fonts.googleapis.com`;
  - contains `<title>Devices — Airgapp</title>`. Only the layout suffix changes here; the page's own title block already says "Devices".
- [ ] **Step 2: Run the test and confirm it fails**

  Run: `go test ./internal/handlers -run TestLayoutStylesheets -count=1`

  Expected: FAIL.
- [ ] **Step 3: Update the layout `<head>`**
  - Delete the three Google Fonts lines.
  - Add the font preload for `saira.woff2` and the `gap.css` link after `app.css`.
  - Change the title suffix to ` — Airgapp`.
- [ ] **Step 4: Fill in `gap.css` after the `@font-face` rules**
  - **Tokens:** one block with selector `:root,[data-theme="dark"]`. That is the same selector `app.css` uses, so this later stylesheet wins. Put every spec token in it, then the bridge:
    - `--bg:var(--bg0)`
    - `--bg-elev:#0C111B`
    - `--bg-elev-2:#121A28`
    - `--bg-inset:#05070D`
    - `--line-bright:var(--line2)`
    - `--line-strong:var(--faint)`
    - `--fg:var(--txt)`
    - `--fg-dim:var(--dim)`
    - `--fg-mute:var(--faint)`
    - `--fg-faint:#4A5568`
    - `--accent:var(--txt)`
    - `--danger-faint:rgba(255,90,60,.12)`
    - `--warn:var(--watch)`
    - `--warn-faint:rgba(245,181,68,.12)`
    - `--ok:var(--safe)`
    - `--ok-faint:rgba(74,222,128,.14)`

    `--line` and `--danger` need no bridge entry, because they share names with the old tokens.
  - **Base:**
    - `body` takes the mockup's body rule verbatim: `background:var(--bg0)`, `color:var(--txt)`, `font-family:'Saira','Helvetica Neue',sans-serif`, the two-layer `background-image` from the spec, `background-attachment:fixed` and `min-height:100vh`.
    - `code,.mono,.tnum` get `font-family:'Martian Mono',ui-monospace,monospace`.
  - **Motion:**
    - `@keyframes rise{from{opacity:0;transform:translateY(12px)}}`
    - `[data-rise]{animation:rise var(--t-rise) var(--ease-rise) backwards}`
    - `[data-rise="1"]`, `"2"` and `"3"` set `animation-delay:var(--rise-1)`, `--rise-2` and `--rise-3`.
    - The reduced-motion block, verbatim: `@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-delay:0s!important;animation-iteration-count:1!important;transition-duration:.01ms!important;transition-delay:0s!important}}`
- [ ] **Step 5: Run the tests and confirm they pass**

  Run: `go test ./internal/handlers ./web -count=1`

  Expected: `ok`.
- [ ] **Step 6: Commit**

  Message: `feat(web): Gap tokens, base type and motion; bridge app.css tokens`.

### Task 4: The top bar replaces the sidebar

**Files:**
- Modify: `web/templates/layout.html:14-111` and `:117-145`. Delete the `shellApp` script.
- Modify: `web/static/css/app.css`. Delete these rules:
  - `.app`
  - every `.rail*` rule and `@keyframes ag-pulse`
  - `.main`
  - every `.head-bar*` rule
  - `.content` (line 176)
  - `.head-bar-burger` and `.nav-scrim` (lines 580-581)
  - inside `@media (max-width: 900px)`: the `.app`, `.rail`, `.nav-open …`, `.nav-scrim`, `.head-bar*` and `.content` rules

  Keep `.brand-logo`, which the login page uses.
- Modify: `web/static/css/gap.css`, to add the shell section.
- Test: `internal/handlers/render_test.go`

**Interfaces:**
- Produces the markup that later slices style against:

```html
<header class="topbar">
  <a class="brand" href="/" aria-label="Airgapp dashboard"><span class="brand-logo" aria-hidden="true"></span></a>
  <nav class="topnav" aria-label="Primary">
    <a class="navlink active" href="/devices" aria-current="page">Devices</a>  <!-- one per link; active only on the current one -->
  </nav>
</header>
<main class="content">{{template "content" .}}</main>
```

  The five links are, in order: Dashboard `/`, Devices `/devices`, Traffic `/traffic`, Filters `/filters`, System `/settings`.

  **Active link:**
  - Use `{{if eq .page "…"}} active{{end}}` inside `class`, plus a matching `{{if}} aria-current="page"{{end}}` after `href`.
  - System is active when `.page` is `settings`, `remote-access` or `system`.

- [ ] **Step 1: Write the failing test `TestLayoutNav`**

  Table-driven over `testPages`. For each page, take the slice of `body` between `<nav class="topnav"` and `</nav>`, then assert:
  - It has exactly 5 occurrences of `class="navlink`.
  - The labels `>Dashboard<`, `>Devices<`, `>Traffic<`, `>Filters<` and `>System<` appear in that order.
  - It has the hrefs `/`, `/devices`, `/traffic`, `/filters` and `/settings`.
  - The active label matches the regexp `aria-current="page">([A-Za-z]+)<` and equals:

    | Page key | Active label |
    |---|---|
    | dashboard | `Dashboard` |
    | devices | `Devices` |
    | traffic | `Traffic` |
    | filters | `Filters` |
    | settings, remote-access | `System` |
    | firewall, stats, bandwidth | none (no match) |

  Also assert that `body` doesn't contain `shellApp(`, `class="rail` or `head-bar`.
- [ ] **Step 2: Run the test and confirm it fails**

  Run: `go test ./internal/handlers -run TestLayoutNav -count=1`

  Expected: FAIL.
- [ ] **Step 3: Replace the `.app` rail and the main wrapper with the markup above**
  - `#toast-container` stays after `</main>`.
  - Keep the Alpine and `app.js` script tags. The global `logout()` in `app.js` stays.
- [ ] **Step 4: Add the shell CSS to `gap.css`**
  - Lift `.topbar`, `.brand-logo`, `.topnav`, `.navlink`, `.navlink:hover` and `.navlink.active` from the mockup, with their `@media(pointer:coarse)`, `@media(max-width:519px)` and `@media(max-width:379px)` blocks.
  - Change the mask URL to `/static/img/airgapp-logo.png` and the size to 78×32.
  - Add `.brand{display:flex;flex:none}`.
  - Set `.content{padding:clamp(22px,3vw,40px) clamp(20px,3vw,44px) 60px}`, and `.content{padding-top:20px}` inside the 519px block.
- [ ] **Step 5: Delete the dead `app.css` shell rules listed under Files**
- [ ] **Step 6: Run the tests and confirm they pass**

  Run: `go test ./internal/handlers ./web -count=1`

  Expected: `ok`.
- [ ] **Step 7: Commit**

  Message: `feat(web): Gap top bar replaces the sidebar; the page is the scroller`.

### Task 5: Toast with Undo and an exit animation

**Files:**
- Modify: `web/static/js/app.js:35-49`
- Modify: `web/static/css/app.css`. Delete the old toast section at lines 546-560.
- Modify: `web/static/css/gap.css`
- Modify: `web/templates/layout.html`. Make it `<div id="toast-container" role="status" aria-live="polite"></div>`.

**Interfaces:**
- Produces `notify(msg: string, type = 'info', opts = {})`, where:
  - `opts.undo` is an optional function;
  - `opts.ms` is optional and defaults to `7000` with `undo`, `4000` without.

  It stays backward compatible with every existing `notify(msg, type)` call.

- [ ] **Step 1: Rewrite `notify` to this behaviour**
  - Only one `.toast` element exists in `#toast-container` at a time. A new call removes the current toast immediately.
  - The element has classes `toast toast-<type>` and contains `<span class="toast-t">` with the text, set via `textContent`.
  - With `opts.undo`, it also contains `<button type="button">Undo</button>`. Clicking it calls `opts.undo()` and dismisses the toast.
  - After `ms`, or on Undo, the toast gets class `out` and is removed 150ms later.
- [ ] **Step 2: Add the toast CSS to `gap.css`**
  - Lift `.toast`, `.toast button`, `@keyframes toastin` and `@keyframes toastout` from the mockup verbatim.
  - Add `.toast.out{animation:toastout var(--t-exit) var(--ease-exit) both}`.
  - Add the accents `.toast-error{box-shadow:inset 3px 0 0 var(--danger),0 14px 34px rgba(0,0,0,.55)}` and `.toast-success{box-shadow:inset 3px 0 0 var(--safe),0 14px 34px rgba(0,0,0,.55)}`.
  - Add `@media(pointer:coarse){.toast button{min-height:44px}}`.
- [ ] **Step 3: Delete the old toast section from `app.css`**
- [ ] **Step 4: Verify in the preview**

  `go run ./cmd/preview` already serves `/devices`. In the browser console on `/devices`:
  1. Run `notify('Saved','success')`. Expected: one toast at the bottom centre, with a green left bar, gone after about 4s.
  2. Run `notify('Tesla → Blocked','info',{undo:()=>console.log('undone')})`. Expected: an Undo button. Clicking it logs `undone` and the toast fades out.
  3. Call `notify('a');notify('b')` back to back. Expected: exactly one `.toast`, reading "b".
- [ ] **Step 5: Commit**

  Message: `feat(web): Gap toast — one at a time, optional Undo, animated exit`.

### Task 6: Interim System entry, sign-out, and the preview

**Files:**
- Modify: `web/templates/settings.html`. In the page head, add `<a class="btn" href="/remote-access">Remote access</a>` and `<button class="btn" type="button" onclick="logout()">Sign out</button>`.
- Modify: `cmd/preview/main.go`:
  - Add `remote-access` to the page list (`:206`).
  - Serve `GET /login`.
  - Mock `POST /api/login`:
    - password `wrong` → 401 `{"error":"invalid credentials"}`
    - password `locked` → 429 `{"error":"too many failed attempts; try again in 1m59s"}`
    - anything else → 200 `{}`
  - Mock `POST /api/logout` → 204.
  - Mock `GET /api/remote/status` → `{"installed":true,"daemon_active":true,"authenticated":true,"backend_state":"Running","tailnet_hostname":"airgapp-preview","tailnet_ipv4":"100.64.0.1","ble_funnel":true,"ble_funnel_url":"https://airgapp-preview.example.ts.net/api/ble"}`.
  - Mock `GET /api/tesla/tokens` → `{"tokens":[]}`.
- Test: `internal/handlers/render_test.go`

- [ ] **Step 1: Write the failing test `TestSettingsInterimLinks`**

  The rendered `settings.html` must contain `href="/remote-access"` and `onclick="logout()"`.
- [ ] **Step 2: Run the test and confirm it fails**

  Run: `go test ./internal/handlers -run TestSettingsInterimLinks -count=1`

  Expected: FAIL.
- [ ] **Step 3: Add the two controls to `settings.html`, and the routes and mocks to the preview**
- [ ] **Step 4: Run the test and the preview smoke check**

  Run: `go test ./internal/handlers -count=1`. Expected: `ok`.

  Then run `go run ./cmd/preview &` and request each of `/`, `/devices`, `/traffic`, `/filters`, `/settings`, `/remote-access`, `/login`, `/static/css/gap.css` and `/static/fonts/saira.woff2` with `curl -s -o /dev/null -w '%{http_code}\n'`. Expected: `200` for all nine.
- [ ] **Step 5: Commit**

  Message: `feat(web): interim Remote access and Sign out on Settings; preview covers the shell`.

### Task 7: Login page

**Files:**
- Modify: `web/templates/login.html`
- Modify: `web/static/css/gap.css`. Add a login section.
- Test: `internal/handlers/render_test.go`

**Interfaces:**
- Consumes the Gap tokens and fonts (Tasks 2–3) and `#toast-container` (Task 5).

- [ ] **Step 1: Write the failing test `TestLoginPage`**

  Render with `NewRenderer(web.Content).RenderLogin` into a recorder. Assert that the body:
  - contains `/static/css/gap.css`, `<title>Sign in — Airgapp</title>` and `>Sign in</button>`;
  - contains none of `fonts.googleapis.com`, `netfilterd-01`, `Guardian`, `Operator` or `192.168.4.1`.
- [ ] **Step 2: Run the test and confirm it fails**

  Run: `go test ./internal/handlers -run TestLoginPage -count=1`

  Expected: FAIL.
- [ ] **Step 3: Rewrite the markup and the login script**
  - **Head:** same as the layout's — the `app.css` and `gap.css` links, the font preload, no Google Fonts.
  - **Body:** a centred card with the wordmark, "Username" and "Password" fields, and a `Sign in` button. There is no footer.
  - **Script:** call `fetch('/api/login', …)` directly, not `api.post`, so a 401 doesn't redirect. Then:

    | Response | Inline error |
    |---|---|
    | 2xx | none; go to `/` |
    | 401 | `Wrong username or password.` |
    | 429 | the server's `error` text, first letter capitalised |
    | anything else | the server's `error`, or `Couldn't sign in. Try again.` |

  - Style the page in `gap.css` with Gap tokens: Martian Mono labels and the Saira 600 button.
- [ ] **Step 4: Run the test, then check the behaviour in the preview**

  Run: `go test ./internal/handlers -run TestLoginPage -count=1`. Expected: `ok`.

  Then, with Task 6's preview mock running:
  - Password `wrong` shows "Wrong username or password." and the URL stays `/login` with no reload.
  - Password `locked` shows "Too many failed attempts; try again in 1m59s".
  - Any other password lands on `/`.
- [ ] **Step 5: Commit**

  Message: `feat(web): Gap login — inline errors, lockout message, no reload on 401`.

### Task 8: Verify the whole slice

- [ ] **Step 1: Run the full Go checks**

  Run: `gofmt -l . && go vet ./... && go test -race ./... -count=1`

  Expected: `gofmt` prints nothing, `go vet` prints nothing, and every package reports `ok`.
- [ ] **Step 2: Walk through the pages in the preview**

  At 1440px, open each of the nine pages. Expected:
  - The top bar shows on every page and the correct link is active, as in `TestLayoutNav`.
  - Pages not yet ported render in the Gap palette and fonts, with no unstyled flashes or overlapping elements.
- [ ] **Step 3: Check the narrow widths**

  At 720, 519, 390 and 320px, on `/traffic` and `/settings`:
  - `document.documentElement.scrollWidth <= innerWidth`.
  - At 520px and wider, `getComputedStyle(document.querySelector('.topbar')).position === 'sticky'`; below 520px it is `static`.
  - All five `.navlink` elements are fully visible. For each one, its bounding rect lies within `0..innerWidth`.
- [ ] **Step 4: Check reduced motion**

  With `prefers-reduced-motion: reduce` emulated, `document.getAnimations().length === 0` one second after load, on every page.
- [ ] **Step 5: Commit any fixes, then summarise the slice for review**

  The summary covers what changed, screenshots at 1440 and 390, and any spec deviations.
