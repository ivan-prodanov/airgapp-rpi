# The Gap, slice 2 (Dashboard): implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `/` becomes the Gap Dashboard. A headline follows the Tesla's policy, the gate shows the Tesla's 7 most recent hosts (cut or crossed, safe or danger) from real traffic, and the 24-hour readouts count its events. The old hero, stat cards, car-lock card and WAN probe are gone.

**Architecture:**
- **Server:**
  - A handler picks the Tesla from the device list.
  - Two new `TrafficLogService` queries return its recent distinct hosts and its 24-hour class counts. Rows are matched by MAC, or by IP, because DNS and SNI rows carry only the IP.
  - `GET /api/dashboard` is reshaped to just what the page needs.
- **Page:**
  - Alpine drives the text and readouts.
  - The 7 SVG lanes are built once with `createElementNS`, because Alpine's `x-for` can't render inside `<svg>`. They're updated in place on each sweep.
- **Preview:** it gets a matching mock that rotates hosts, so the sweep can be seen.

**Tech Stack:** Go (chi, `database/sql` on SQLite), `html/template`, Alpine.js 3, plain CSS in `gap.css`.

**Spec:** `docs/superpowers/specs/2026-11-07-the-gap-redesign.md`, section "Dashboard `/`". It is binding, including the decisions recorded there on 2026-11-07. The mockup is `.claude/design/the-gap/Main.dc.html` in the main checkout. Lift CSS and the lane geometry from it.

## Global Constraints
- Everything in the slice-1 plan's Global Constraints still holds:
  - no new dependencies or CDNs;
  - the repository is public, so no production names, hosts or MACs;
  - "Airgapp", never "Airgapp app";
  - commit locally, never push;
  - the `Co-Authored-By` line on every commit.
- **The page has no regime switch and no pause button.** The headline is display-only.
- **Lane geometry, exactly as in the mockup:**
  - viewBox `0 0 1000 700`, gate at x=600, slot `y=(i+0.5)*100`.
  - A crossing lane is `M200,350 C 360,350 440,y 600,y L1000,y`, width 1.7.
  - A cut lane is `M200,350 C 360,350 440,y 600,y`, width 1.5, with a red × from (590,y−10) to (610,y+10), mirrored.
  - The end dot of a crossing lane is at (988,y), r=5.
  - Delays: lane `i*0.07s`, mark `i*0.07+0.5s`, host row `i*0.05s`.
  - Colours: safe `#4ADE80`, danger `#FF5A3C`.
- **Sweep timing:** poll every 3200ms, only while `document.visibilityState === 'visible'`.
  - When the host ids change: set `notrans` and hide, swap the data after 330ms, drop `notrans` at +40ms, show at +90ms.
  - The counter tween runs 760ms with ease-out cubic `1-(1-p)^3`. Under reduced motion it jumps.
- **Rise sequence:** headline `data-rise`, work `data-rise="1"`, readouts `data-rise="2"`.
- **Counting:** Blocked is `blocked` plus `sinkholed`; allowed is `allowed` plus `resolved`; `logged` is never counted. The window is 24h.

## Review Focus
1. **No Tesla on the network** (a fresh install): the headline reads "No Tesla yet", no lanes are drawn, readouts are 0, and there are no errors. Pinned by `TestDashboardAPI_NoTesla` (Task 3) and dash-check scenario "none" (Task 6).
2. **A Tesla with no traffic in the last 24h** (asleep): no lanes, readouts 0, and no sweep loop when nothing changes. Pinned by `TestRecentHosts_Window` (Task 2) and dash-check "quiet" (Task 6).
3. **Fewer than 7 distinct hosts:** only those lanes are drawn, and the host rows stay aligned to their lane slots. Pinned by dash-check "few" (Task 6).
4. **Long host names at 320px:** they end in an ellipsis and the page doesn't scroll sideways. Pinned by dash-check at 320 (Task 6).
5. **Hidden tab:** polling stops while hidden and resumes once visible, without piling up overlapping sweeps or tween timers. Pinned by dash-check "hidden" (Task 6).

---

### Task 1: Pick the Tesla on the server

**Files:**
- Modify: `internal/handlers/dashboard.go`
- Create: `internal/handlers/dashboard_test.go`

**Interfaces:**
- Produces `func pickTesla(devs []models.Device) *models.Device`:
  - returns `nil` when no device matches;
  - otherwise returns a pointer to a copy.

- [ ] **Step 1: Write the failing test `TestPickTesla`**

  Table-driven, with example names only. Expected results:

  | Case | Devices | Expected |
  |---|---|---|
  | No match | `{Alias:"Laptop"}`, `{Hostname:"phone"}` | `nil` |
  | Alias match | `{Alias:"Model Y (garage)", Hostname:"tesla_y"}` vs `{Alias:"tv"}` | the Model Y |
  | Case-insensitive | `{Alias:"TESLA"}` | matches |
  | Hostname-only match | `{Hostname:"Tesla-Model-3"}` | matches |
  | Two matches, different online state | offline one with newer `LastSeen`, online one with older `LastSeen` | the online one |
  | Two matches, both online | different `LastSeen` | the newer `LastSeen` |
- [ ] **Step 2: Run it and confirm it fails**

  Run: `go test ./internal/handlers -run TestPickTesla -count=1`

  Expected: FAIL (`undefined: pickTesla`).
- [ ] **Step 3: Implement `pickTesla`**

  Match with case-insensitive `strings.Contains(strings.ToLower(alias+" "+hostname), "tesla")`. Prefer online, then the latest `LastSeen`.
- [ ] **Step 4: Run it and confirm it passes**

  Run: `go test ./internal/handlers -run TestPickTesla -count=1`

  Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `feat(dashboard): pick the Tesla on the server`.

### Task 2: The Tesla's recent hosts and 24-hour counts

**Files:**
- Modify: `internal/services/trafficlog.go`
- Create: `internal/services/trafficlog_dashboard_test.go`

**Interfaces:**
- Produces:
  - `type HostVerdict struct { ID int64 \`json:"id"\`; Domain string \`json:"domain"\`; Crossed bool \`json:"crossed"\`; Safe bool \`json:"safe"\` }`
  - `func (s *TrafficLogService) IsAllowListed(domain string) bool`, the exported form of `dnsResolvable`.
  - `func (s *TrafficLogService) RecentHosts(mac, ip string, since time.Time, limit int) ([]HostVerdict, error)`
  - `func (s *TrafficLogService) ClassCountsSince(mac, ip string, since time.Time) (blocked, allowed int)`
- **Which rows belong to the device:** `LOWER(client_mac)=LOWER(mac)` when `mac` is not empty, OR `client_ip=ip` when `ip` is not empty. If both are empty, nothing matches.
- **`RecentHosts`:**
  - Considers rows with `timestamp >= since`, a non-empty `domain`, and an action in (`allowed`,`resolved`,`blocked`,`sinkholed`).
  - Orders them `id DESC` and scans at most 500 rows.
  - The first row per domain wins.
  - It stops at `limit` domains and returns them newest first.
  - `Crossed` is `action IN (allowed,resolved)`. `Safe` is `IsAllowListed(domain)`.

- [ ] **Step 1: Write the failing tests**

  The tests use `memDB(t)` and `NewTrafficLogService(db)`, and insert `query_log` rows directly with explicit UTC timestamps. The Tesla is MAC `aa:bb:cc:00:00:01` and IP `192.168.4.42`; another device is `aa:bb:cc:00:00:02` at `.43`.
  - **`TestRecentHosts_DistinctNewestFirst`:**
    - Rows, in insert order:
      - `a.example` blocked
      - `b.example` resolved (DNS row: empty MAC, IP .42)
      - `a.example` allowed
      - the other device's `c.example` allowed
      - a Tesla row with an empty domain
      - a Tesla row `d.example` with action `logged`
    - Want exactly `[a.example crossed=true, b.example crossed=true]`, in that order.
  - **`TestRecentHosts_Limit`:** 9 distinct Tesla domains; want 7, the newest.
  - **`TestRecentHosts_Window`:** one Tesla row 25h old and `since` = 24h ago; want empty with no error.
  - **`TestRecentHosts_Safe`:**
    - Enable the filter named `Connectivity` and add domain `ok.example` to it, enabled, through SQL. Then call `RefreshAllowCache()`.
    - Want `ok.example` with Safe=true and `bad.example` with Safe=false.
    - Also want a protected host, `x.ap.tesla.services`, with Safe=false.
  - **`TestClassCountsSince`:**
    - Tesla rows: blocked ×2, sinkholed ×3, allowed ×1, resolved ×4, logged ×5, plus 1 blocked row 25h old.
    - The other device: blocked ×7.
    - Want `blocked=5, allowed=5`.
- [ ] **Step 2: Run them and confirm they fail**

  Run: `go test ./internal/services -run 'TestRecentHosts|TestClassCountsSince' -count=1`

  Expected: FAIL (undefined methods).
- [ ] **Step 3: Implement the type and the three methods**

  Put them in `trafficlog.go`, beside `CountByActionSince`.
- [ ] **Step 4: Run them and confirm they pass**

  Run: `go test ./internal/services -run 'TestRecentHosts|TestClassCountsSince' -count=1`

  Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `feat(traffic): a device's recent distinct hosts and 24 h verdict counts`.

### Task 3: Reshape `GET /api/dashboard`

**Files:**
- Modify: `internal/handlers/dashboard.go`. Delete `compactAge`, the lock, stat and system fields, and their imports.
- Test: `internal/handlers/dashboard_test.go`

**Interfaces:**
- Consumes `pickTesla` (Task 1), plus `RecentHosts` and `ClassCountsSince` (Task 2).
- Produces this JSON:
  - `{"tesla": {"status": "blocked|filtered|open", "online": bool} | null, "hosts": [HostVerdict], "blocked_24h": int, "allowed_24h": int}`
  - `hosts` is never `null`; use `[]`.
  - The window is `time.Now().Add(-24*time.Hour)` and the limit is 7.

- [ ] **Step 1: Write the failing tests**

  Build real services on a `database.Open` temp DB, the same way `newTestTokenService` does in `tesla_session_test.go`. The handler needs only `svc.Network` and `svc.TrafficLog`, so construct those two services into a `&services.Services{…}`. Insert devices and `query_log` rows through SQL.
  - **`TestDashboardAPI_NoTesla`:** devices table without a Tesla. Want 200 and the body `{"tesla":null,"hosts":[],"blocked_24h":0,"allowed_24h":0}`, compared as JSON.
  - **`TestDashboardAPI_Tesla`:**
    - A filtered, online Tesla with 2 hosts.
    - Want `tesla.status=="filtered"`, `tesla.online==true` and `len(hosts)==2`, with counts matching the inserted rows.
    - Also assert that the body has none of these keys: `lock_state`, `devices_online`, `system`.
- [ ] **Step 2: Run them and confirm they fail**

  Run: `go test ./internal/handlers -run TestDashboardAPI -count=1`

  Expected: FAIL.
- [ ] **Step 3: Rewrite `API`**
  - Use `ListDevices` → `pickTesla`.
  - If a Tesla is found, call `RecentHosts(t.MACAddress, t.IPAddress, since, 7)` and `ClassCountsSince(...)`.
  - Respond with `JSON(w, 200, …)`.
- [ ] **Step 4: Run them and confirm they pass**

  Run: `go test ./internal/handlers -count=1 && go vet ./internal/handlers`

  Expected: `ok`, and no vet output.
- [ ] **Step 5: Commit**

  Message: `feat(dashboard): /api/dashboard serves the Tesla, its recent hosts and 24 h counts`.

### Task 4: Preview mock for the new API

**Files:**
- Modify: `cmd/preview/main.go`, the `/api/dashboard` handler.

**Interfaces:**
- Produces the Task 3 JSON shape:
  - **`tesla`** comes from the first mock device matching `/tesla/i`. Its `status` follows `PUT /api/devices/{mac}/status`.
  - **Scenario switch:** `?scenario=none|quiet|few` returns, respectively, no Tesla, a Tesla with no hosts, and a Tesla with 3 hosts. These are for the browser check.
  - **Default `hosts`:** 7 of a fixed example list of about 14 Tesla-style hostnames already present in the repo's mocks, with about 4 safe and the rest danger. The pick rotates with `time.Now().UnixMilli()/3200` so the page sweeps. Ids are derived from the window.
  - **`crossed`:** for filtered, `crossed = safe`; for open, `true`; for blocked, `false`.
  - **Counts** grow with time from 48,280 blocked and 9,044 allowed.

- [ ] **Step 1: Implement the handler**
- [ ] **Step 2: Verify it**

  Run: `go vet ./cmd/preview`, then start the preview on `-addr :8091` and fetch the API:
  - `curl -s localhost:8091/api/dashboard` returns 7 hosts with a status.
  - `?scenario=none` returns `"tesla":null`.

  Change the Tesla's status through `PUT /api/devices/{mac}/status` and confirm that `crossed` follows it.
- [ ] **Step 3: Commit**

  Message: `feat(preview): dashboard mock with rotating hosts and test scenarios`.

### Task 5: The Dashboard page

**Files:**
- Modify: `web/templates/layout.html`. Make it `<main class="content{{if eq .page "dashboard"}} content-bleed{{end}}">`.
- Rewrite: `web/templates/dashboard.html`
- Modify: `web/static/css/gap.css`. Add a Dashboard section, plus `body{display:flex;flex-direction:column}`, `.content{flex:1 0 auto}` and `.content-bleed{padding:0;display:flex;flex-direction:column}`.
- Test: `internal/handlers/render_test.go`

**Interfaces:**
- Consumes the Task 3 JSON.
- Produces this markup, which Task 6's browser check targets:
  - `h1.hstmt` holds `span.pre` and `span.word`, and carries `data-rise`.
  - `.work[data-rise="1"]` contains:
    - `.stage`, holding `.gatelabel` ("Airgapp") and `.stage-inner`;
    - `.stage-inner`, holding `.car` (`.car.off` when the Tesla is offline) and `svg.viz.scene` with `g.gate` and `g.lanes`;
    - `aside.panel > .hostlist`, holding 7 `.hostrow` slots, each with `.hdot`, `.hname` and `.hsub2`.
  - `.readouts[data-rise="2"]` holds three readouts:
    - `Blocked · 24 h` (`.ro-v.danger`)
    - `Allow-listed · 24 h` (`.ro-v.safe`)
    - `This sweep` (`n<span class="slash">/</span>k`)
  - The Alpine root is `x-data="dashApp()"` on `.dash`.

- [ ] **Step 1: Write the failing tests**
  - **`TestDashboardPage`:** render `dashboard.html`. It must:
    - contain `class="dash"`, `class="hstmt"`, `class="gate"`, `class="lanes"` and `This sweep`;
    - contain exactly 7 `class="hostrow`;
    - not contain `Guardian`, `Probe WAN`, `stat-card`, `lock_` or `segbtn`.
  - **`TestLayoutBleed`:**
    - `/` (dashboard) has `<main class="content content-bleed">`.
    - devices has `<main class="content">`.
- [ ] **Step 2: Run them and confirm they fail**

  Run: `go test ./internal/handlers -run 'TestDashboardPage|TestLayoutBleed' -count=1`

  Expected: FAIL.
- [ ] **Step 3: Write the markup, the CSS and `dashApp()`**
  - **CSS:** lift from `Main.dc.html`:
    - `.herohead`, `.hstmt`, `.work`, `.stage` (and its grid `::before`), `.gatelabel`, `.stage-inner`, `.viz`, `.gate` (`gatein`, `gateglow`), `.scene .ln`, `.scene .mark`, `.notrans`, `.car`, `.panel`, `.hostlist`, `.hostrow`, `.hdot`, `.hname`, `.hsub2`, `.readouts`, `.ro-l`, `.ro-v`, and the `@media(max-width:640px)` block.
    - `.screen` becomes `.dash{flex:1;display:flex;flex-direction:column;position:relative;overflow:hidden;…}`, keeping its background.
    - Leave out the switch, pause, seal and gatecode rules.
    - Add `.car.off{opacity:.55}` and `.hostrow.empty .hdot{visibility:hidden}`.
  - **`dashApp()`:**
    - Fetch `/api/dashboard` plus `location.search` immediately, then every 3200ms while the tab is visible. Forwarding the query string lets the preview's `?scenario=` reach its mock; the real API ignores unknown parameters.
    - Listen for `visibilitychange` to stop and restart polling.
    - Store `hostsKey = hosts.map(h=>h.id).join(',')` and sweep only when it changes. A sweep already in flight is cancelled by clearing its timers.
    - The headline comes from the spec's table.
    - Counters tween with one interval handle, which is cleared before each new tween.
    - `buildLanes()` runs once on `init` and creates 7 `<g>` elements under `g.lanes`. Each holds `path.ln[pathLength=1]`, `g.mark.cut` with 2 lines, and `circle.mark.cross`.
    - `paint()` sets `d`, stroke, width, dashoffset, the marks' display and opacity, and the transition-delays, using the constraint values.
    - Lanes beyond `hosts.length` are hidden.
    - Host rows show `name`, `Safe`/`Danger` and the dot class. Rows past the end get `.empty`.
- [ ] **Step 4: Run them and confirm they pass**

  Run: `go test ./internal/handlers ./web -count=1`

  Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `feat(dashboard): the Gap dashboard — headline, gate of the Tesla's hosts, 24 h readouts`.

### Task 6: Browser verification

**Files:**
- Create `dash-check.mjs` in the plan workspace (git-ignored). It drives the preview on `:8091` with headless Chrome, like slice 1's checks.

- [ ] **Step 1: Write the check, then run it against `HEAD~` (the old dashboard) and confirm it fails**

  The check covers:
  - **default:**
    - The headline is "ELON IS GATED", read from `textContent` after `text-transform`, so compare case-insensitively.
    - 7 lanes are visible.
    - Each red lane under filtered is cut (`.mark.cut` shown) and each green lane crosses.
    - Host-row names equal the API's domains, in order.
    - The readouts show the API counts after the tween settles.
  - **regime:** `PUT` the Tesla's status to `open`. Within 4s the headline is "ELON IS IN" and every lane crosses. Then set it to `blocked`: "TESLA IS BLOCKED" and every lane is cut.
  - **sweep:** across two 3.2s windows the host ids change, and lanes animate. Some `.ln` has a running transition on `stroke-dashoffset`.
  - **none / quiet / few** (Review Focus 1–3), using `?scenario=`. The page must forward its own query string to the API, so `/?scenario=none` reaches `/api/dashboard?scenario=none`.
  - **320px** (Review Focus 4): no sideways scroll, and the longest `.hname` ends in an ellipsis (`scrollWidth > clientWidth`).
  - **hidden** (Review Focus 5): override `document.visibilityState` to `'hidden'` with `Object.defineProperty` and dispatch `visibilitychange`. Wait 7s and count `/api/dashboard` requests through `Network.requestWillBeSent`; expect 0. Then restore it to `'visible'`, dispatch the event again, and expect at least 1 request within 4s.
  - **reduced motion:** no running animations or transitions after load, and counters show their final values at once.
  - **errors:** no page errors.
- [ ] **Step 2: Run it against HEAD and confirm it passes, then rerun slice 1's `shell-check.mjs`, `toast-check.mjs` and `login-check.mjs`**

  Expected: all PASS.
- [ ] **Step 3: Run the full suite**

  Run: `go vet ./... && go test -race ./... -count=1`

  Expected: every package reports `ok`.
- [ ] **Step 4: Take screenshots at 1440 and 390, in each of the three regimes, and commit any fixes**
