# The Gap, slice 5: Traffic — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Traffic page with the Gap ledger: a live tail fed by one request per tick, with outcome/protocol/search filters, the Muted dialog, and an Allow dialog that adds to a real filter.

**Architecture:** A new `GET /api/traffic/feed` returns events newer than the last id the page has seen, each already carrying what the row needs: the device name, the Allowed/Blocked class, whether it is always blocked (locked Allow), the filter that lists it and the mute pattern that covers it. The page keeps at most 80 rows, buffers new ones while someone is reading (scrolled away, paused, or a row open on a phone), and slides them in with FLIP at the live edge. Mute and Allow reuse the existing mute and filter endpoints.

**Tech Stack:** Go (chi, database/sql on SQLite), html/template, Alpine.js 3.15.11, plain CSS (`web/static/css/gap.css`).

**Spec:** `docs/superpowers/specs/2026-11-07-the-gap-redesign.md` (Traffic, Motion, Components, Copy rules, Backend changes → Traffic). Mockup: `.claude/design/the-gap/Traffic.dc.html` in the main checkout (git-ignored; holds prod-like data, never copy its device names or IPs into the repo).

## Global Constraints

- Product name is "Airgapp", never "Airgapp app". Banned: "Severed", "PROTECTED", "Guardian", "netfilterd-01", "Operator".
- Row labels are **Allowed** (`allowed`, `resolved`) and **Blocked** (`blocked`, `sinkholed`). Finer detail goes in the fold.
- The repo is public: preview mocks use generic names (Tesla, Phone, Laptop, Speaker), `192.168.4.x` clients and public domains only.
- Phones (860px and below): compact two-line rows, the page is the scroller, touch targets at least 44px.
- Motion: FLIP slide 520ms `cubic-bezier(.22,.8,.24,1)`, transform only; new-row flash `--t-flash`; under `prefers-reduced-motion: reduce` FLIP is skipped. Dialogs and toasts as in slices 1–4 (`dialog.ndlg`, `notify()`).
- Shared controls are scoped under `.wrap`; page CSS that could clash is scoped under `.pg-traffic`.
- Polling: only while the tab is visible, one request in flight, every 2 s.

## Review Focus

1. **A burst while held:** more than 80 new events arrive while the view is held. The buffer keeps the newest 80, the pill reads "80+ new", and releasing shows the newest 80 rows. Pinned by traffic-check `burst` (Task 6).
2. **Changing a filter while held or paused:** the buffer is dropped and the rows reload from the server for the new filter; no row from the old filter survives. Pinned by traffic-check `filter-while-held` (Task 6).
3. **Old DNS rows stored as `query`** (before 1 Nov 2026 on the Pi): they show a verdict worked out from today's allow-list, like the old page did. Pinned by `TestTrafficFeed_EntryContext/legacy_query` (Task 1).
4. **Rows with no domain** (firewall drops by IP, about 1 in 8 rows on the Pi): the domain column shows the destination IP and the row offers neither Allow nor Mute. Pinned by `TestTrafficFeed_EntryContext/no_domain` (Task 1) and traffic-check `no-domain` (Task 6).
5. **A tab that was hidden for a long time:** polling stopped while hidden; on return one request catches up from `last_id`, capped at 200 rows, newest first. Pinned by `TestTrafficFeed_AfterID` (cap) (Task 1).

---

### Task 1: The feed endpoint

**Files:**
- Modify: `internal/services/protected.go` (export `IsAlwaysBlocked`)
- Modify: `internal/services/trafficlog.go` (`Feed`, `Verdict`, `MutedBy`, `SourceMAC`; `AddMuted` copy)
- Modify: `internal/services/filter.go` (`CoverIndex`)
- Create: `internal/handlers/traffic.go`, `internal/handlers/traffic_test.go`
- Modify: `internal/handlers/router.go` (route)

**Interfaces:**
- Produces:
  - `services.IsAlwaysBlocked(domain string) bool` (the existing `isProtectedDenied`).
  - `type services.FeedFilter struct { After int64; Outcome, Proto, Query string; Limit int }`
  - `func (s *TrafficLogService) Feed(f FeedFilter) (entries []TrafficEntry, lastID int64, err error)` — `lastID` is `MAX(id)` of the whole log (0 when empty); entries have `id <= lastID`, and `id > After` when `After > 0`; newest first; `Limit` defaults to 80 and is capped at 200. Outcome `allowed` = `allowed`+`resolved`, `blocked` = `blocked`+`sinkholed`, anything else = all. Proto compares upper-cased. Query uses the same FTS/LIKE rule as `QueryPaginated` (extract it as `searchClause(q string) (string, []any)` and use it in both).
  - `func (s *TrafficLogService) Verdict(e TrafficEntry) string` — `e.Action`, except a legacy `query` row: `sinkholed` if always blocked, `resolved` if `dnsResolvable`, else `sinkholed`.
  - `func (s *TrafficLogService) MutedBy(domain string) string` — the mute pattern covering the domain (exact or suffix), or "".
  - `func SourceMAC(raw string) string` — upper-case MAC from a 6-octet value or octets 7–12 of a 14-octet nflog header; "" otherwise.
  - `var ErrBadMuteDomain = errors.New("Enter a domain like apple.com.")`, returned by `AddMuted` for a bad domain.
  - `type services.FilterCover struct { ID int64 \`json:"id"\`; Name string \`json:"name"\`; Enabled bool \`json:"enabled"\` }`
  - `func (s *FilterService) CoverIndex() (func(domain string) *FilterCover, error)` — one query over all filter domains; the matcher returns the filter listing the domain (exact or suffix), preferring an enabled one, then the lowest id; nil when none.
  - `GET /api/traffic/feed?after=&outcome=&proto=&q=&limit=` → `{"entries":[…],"last_id":N,"muted":N}`; each entry: `id, time, client, client_ip, domain, dst_ip, port, proto, action, class, locked, cover, muted_by`.
    - `action` = `Verdict(e)`; `class` = `allowed` / `blocked` / `""` from it.
    - `locked` = class blocked, domain set and `IsAlwaysBlocked(domain)`.
    - `cover` = `CoverIndex()(domain)` when the domain is set and not locked, else null.
    - `client` = the device's name (alias, else hostname, else "Unknown device") matched by `SourceMAC(client_mac)`, else by IP; with no device, the IP.
    - `muted` = number of mute patterns.

- [ ] **Step 1: Write the failing tests** in `internal/handlers/traffic_test.go`, on a real test DB (reuse the filters test setup; insert `query_log` rows with SQL):
  - `TestTrafficFeed_AfterID`: 3 rows → GET returns them newest first and `last_id` = third id; `?after=<last_id>` → `[]`; insert one more → `?after=<old last_id>` returns just it. Insert 250 rows → `?after=0&limit=999` returns 200.
  - `TestTrafficFeed_Outcome`: rows allowed/resolved/blocked/sinkholed → `outcome=allowed` returns exactly allowed+resolved, `outcome=blocked` exactly blocked+sinkholed; `proto=tls` returns only TLS rows; `q=examp` matches `cdn.example.com`.
  - `TestTrafficFeed_EntryContext` subtests: `cover_prefers_enabled` (two filters list `example.com`, only the second on → cover is the second); `locked` (blocked `hermes-prd.ap.tesla.services` → locked, cover null); `muted_by` (mute `apple.com` → a `push.apple.com` row says `apple.com`); `legacy_query` (a `query` row for a domain in an enabled filter → action `resolved`, class `allowed`; for an unlisted domain → `sinkholed`); `client_by_mac` (14-octet header whose octets 7–12 are a device's MAC → its alias); `client_by_ip`; `unknown_client` (client == IP); `no_domain` (blocked UDP row with no domain → domain "", locked false, cover null).
  - `TestAddMuted_BadDomain` (services): `AddMuted("not a domain!")` returns `ErrBadMuteDomain`.

- [ ] **Step 2: Run them to see them fail**
  Run: `go test ./internal/handlers -run TestTrafficFeed -count=1; go test ./internal/services -run TestAddMuted_BadDomain -count=1`
  Expected: FAIL (handler, `Feed` and `ErrBadMuteDomain` undefined).

- [ ] **Step 3: Implement** the Interfaces above. Route `r.Get("/traffic/feed", trafH.Feed)` inside the authenticated `/api` group, next to `/filters`.

- [ ] **Step 4: Run the tests and the suite**
  Run: `go test ./internal/handlers ./internal/services -count=1 && go vet ./...`
  Expected: PASS.

- [ ] **Step 5: Commit** `feat(traffic): one feed request per tick, with each row's verdict, filter, mute and device`

### Task 2: Preview mock for the feed

**Files:** Modify `cmd/preview/main.go`.

**Interfaces:**
- Consumes: Task 1's JSON shape; `services.IsAlwaysBlocked`, `services.NormalizeDomain`.
- Produces: `GET /api/traffic/feed` with the same params and shape, generated from a deterministic event pool (generic clients, public domains, a few always-blocked Tesla hosts, some rows with no domain); events accrue with time since the preview started (about 1–3 per 2 s). Cover and muted_by are computed from the preview's own filters and mutes. `GET/POST /api/system/traffic/muted`, `DELETE /api/system/traffic/muted/{id}` backed by an in-memory list (bad domain → 400 `ErrBadMuteDomain`). Scenarios via the page URL (`location.search` is forwarded by the page): `quiet` (no new events), `burst` (100 new events per tick), `slow` (1.5 s delay), `error` (500).

- [ ] **Step 1:** Implement; `gofmt -l cmd/preview` empty; `go build ./cmd/preview`.
- [ ] **Step 2:** `curl -s 'localhost:8091/api/traffic/feed?limit=3'` shows 3 entries with every field; a second call with `after=<last_id>` after 2 s returns only newer ids.
- [ ] **Step 3: Commit** `feat(preview): traffic feed and mute mocks`

### Task 3: The ledger page

**Files:** Rewrite `web/templates/traffic.html`; add a Traffic section to `web/static/css/gap.css`; test in `internal/handlers/render_test.go`.

**Interfaces:**
- Consumes: `/api/traffic/feed`; `notify()`; shared `.wrap` controls.
- Produces: `trafficApp()` with `rows` (≤80), `pending` (≤80), `lastId`, `live`, `held`, `openId`, `outcome`, `proto`, `query`; `matchesRow` is server-side, so the client never re-filters.

Behaviour (from the mockup, `Traffic.dc.html`):
- Head: eyebrow "Raw event stream" (the mockup's "Surveillance ·" prefix is dropped as UI chrome), h1 "Traffic", sub as in the mockup.
- Toolbar: Live/Paused button (`aria-pressed`), outcome radios All · Allowed · Blocked (`name="outcome"`, pill style, dots), protocol pill over a native select (All protocols, DNS, TLS, TCP, UDP), search (`id="q"`, placeholder "Search domain · client · IP", "Search" on phones; applies 300 ms after typing stops), Muted button with count.
- Ledger: desktop grid with the mockup's columns (Time, Client, Domain, Port, Proto, Verdict, actions), its own scroller `height:clamp(360px,56vh,560px)`, `overflow-anchor:none`, sticky header. The domain splits into head and registrable tail so the tail stays visible. A row with no domain shows the destination IP in the domain column.
- Live edge: desktop = scroller `scrollTop <= 24`; phones = an IntersectionObserver sentinel with top `rootMargin` of minus the top bar's height when the bar is sticky. Held = paused, or away from the edge, or a row open on a phone. While held, new rows go to `pending` (newest 80); the pill "↑ N new" (or "80+ new") returns to live. Leaving held releases the buffer.
- FLIP on commit, as the mockup's `componentDidUpdate` (measure in `$nextTick`): body slides from minus the new rows' height, plus a flash on the new rows; skipped under reduced motion.
- Changing outcome, protocol or search: drop rows and pending, scroll to the top, reload (`after` absent). A poll whose filter is stale is discarded.
- Phones: compact rows (domain line; verdict, client, time line; chevron), tap toggles the fold (client, destination, port · proto, verdict text), actions in the fold.
- Verdict text in the fold: allowed "Passed the gate", resolved "Resolved by DNS", blocked "Dropped at the gate", sinkholed "Sinkholed by DNS".
- Empty: "No traffic matches this filter." Feed failure: keep rows, one toast per failure streak, not per poll.

- [ ] **Step 1: Write the failing test** `TestTrafficPage`: wants `class="ledger"`, `class="toolbar"`, `name="outcome"`, `id="q"`, `class="led-edge"`, "No traffic matches this filter."; gone: `<table`, `protectedDeny`, `/api/system/traffic?`, `confirmClear`.
- [ ] **Step 2:** Run `go test ./internal/handlers -run TestTrafficPage -count=1`. Expected: FAIL.
- [ ] **Step 3:** Implement the page and CSS (rows, fold, toolbar, pill, phone layout, rise sequence `phead` / `toolbar` / `ledger`).
- [ ] **Step 4:** Run the handlers tests; rebuild the preview and look at 1440 and 390 (screenshots in the plan workspace).
- [ ] **Step 5: Commit** `feat(traffic): the Gap ledger — live tail, hold and FLIP, filters`

### Task 4: Muting

**Files:** `web/templates/traffic.html`, `web/static/css/gap.css`.

**Interfaces:** Consumes `GET/POST /api/system/traffic/muted`, `DELETE /api/system/traffic/muted/{id}`; produces the Muted dialog and row Mute.

- Row **Mute** (unmuted rows with a domain): POST, toast "Muted `<d>`. New events are dropped." with Undo (DELETE). Rows already shown whose domain the pattern covers turn muted at once: dimmed, Mute replaced by a "Muted" tag (fold: "Muted by `<pattern>`").
- **Muted dialog** (`dialog.ndlg`, `aria-labelledby`): help text from the mockup; a field + Mute (disabled while empty); status line (`role=status`) for "Muted `<d>` and every *.`<d>`.", "`<d>` is already muted." (checked against the list), and server errors as they come (`ErrBadMuteDomain`); the list sorted as the server returns it, each with "and subdomains · since `<d Mon>`" or "covered by `<pattern>`", and Unmute → status "Unmuted `<p>`." with Undo (re-POST). "Nothing muted yet." when empty. The toolbar count updates from the feed's `muted` and after each change.

- [ ] **Step 1:** Extend `TestTrafficPage` with `aria-labelledby="mdlg-h"` and "Nothing muted yet."; run; FAIL.
- [ ] **Step 2:** Implement; run; PASS.
- [ ] **Step 3: Commit** `feat(traffic): mute from a row or the Muted dialog, with Undo`

### Task 5: Allowing

**Files:** `web/templates/traffic.html`, `web/static/css/gap.css`.

**Interfaces:** Consumes `GET /api/filters?domains=1`, `POST /api/filters`, `PUT /api/filters/{id}/enabled`, `POST /api/filters/{id}/domains`, `DELETE /api/filters/{id}/domains/{did}`, `DELETE /api/filters/{id}`; the row's `cover` and `locked`.

- Blocked rows with a domain, not locked and not covered: **Allow** opens the dialog. Locked rows: Allow stays visible, `aria-disabled="true"`, focusable, dashed with a lock icon; activating it toasts "`<d>` is always blocked. It can't be allowed." Covered rows show a tag: "Allowed · `<filter>`" or "Pending · `<filter>` is off".
- **Dialog** (`dialog.ndlg.adlg`, "Allow a domain"): editable domain; filter radios (`name="allow-target"`) with System-group filters first, an "off" mark on filters that are off, then "+ New filter"; the pre-selected option is the suggested filter (a filter listing the same registrable domain, the last two labels) and otherwise none, never the first in the list; "New filter name" when "+ New filter" is picked; optional note; status line; Cancel / Allow.
- **Confirm:** client-side only what the server can't say: empty pick → "Pick a filter, or create a new one."; new-filter name rules and duplicates (same copy as the Filters page); a domain an enabled filter already covers → "`<d>` is already allowed by `<filter>`.". Then: for a new filter POST it, POST the domain, then PUT enabled true (created ON); otherwise POST the domain. Server errors (bad domain, always blocked, too broad, duplicate) show in the status line as they come; a new filter created before a failed domain POST is deleted again.
- **After:** the dialog closes; rows covered by the new domain update their tag at once; toast with Undo: on "Created `<f>` and allowed `<d>`. New connections pass." / "Allowed `<d>` in `<f>`. New connections pass."; off "Added `<d>` to `<f>`. It applies once `<f>` is on." Undo deletes the domain (and the created filter) and restores the tags.
- The dialog keeps its content while it fades out (as the Filters dialog).

- [ ] **Step 1:** Extend `TestTrafficPage` with `aria-labelledby="adlg-h"`, `name="allow-target"`, "+ New filter"; run; FAIL.
- [ ] **Step 2:** Implement; run; PASS.
- [ ] **Step 3: Commit** `feat(traffic): Allow adds to a real filter — suggested filter, new filter on, locked Allow`

### Task 6: Browser check

**Files:** Create `traffic-check.mjs` in the plan workspace (copied to the session's gap-port-checks afterwards). Update `toast-check.mjs`, which used the old Traffic Muted dialog to prove toasts sit above old dialogs: point it at an old dialog that still exists (Settings or Remote access) or drop that case if none remains.

Real clicks and typing (`Input.dispatchMouseEvent` at uncovered points, `Input.insertText`), fresh preview per run. Cases:
- **load:** rows newest first, columns, a locked row, a covered row tag, a no-domain row (`no-domain`: IP in the domain column, no Allow or Mute).
- **live:** new rows arrive and the top row changes within 5 s; FLIP animation runs on the body.
- **hold:** scroll the ledger down 200px → rows stop changing, pill appears with a count; click the pill → back to top, pill gone, rows include the buffered ids.
- **burst** (`?scenario=burst`, held): pill reads "80+ new"; after release the ledger has 80 rows, the newest id on top.
- **pause:** Live → Paused stops changes; Live resumes.
- **filter-while-held:** held with a pending count, pick Blocked → pill gone, every row Blocked; proto TLS → every row TLS; search a domain substring → every row contains it.
- **mute:** row Mute → toast, row tag "Muted", count +1; Undo → count back. Dialog: empty disables Mute; bad domain error text; add → status + list; duplicate → "already muted"; Unmute → status with Undo → back in the list.
- **allow:** on an uncovered blocked row the dialog opens with the suggested filter checked (a row whose registrable domain a filter lists) or none; empty pick error; new filter dup-name error; allow into an enabled filter → toast "Allowed … New connections pass.", row tag "Allowed · <f>"; Undo → tag gone. Into an off filter → "Pending · <f> is off". New filter → API shows it enabled with the domain. Locked Allow → toast "… is always blocked. It can't be allowed.", no dialog.
- **phones 390 and 320:** no sideways scroll; rows are two lines; tap opens the fold and holds the view; dialogs are bottom sheets; touch targets ≥ 44px; the pill sits below the top bar.
- **reduced motion:** no running animations after load and after new rows (FLIP skipped).
- **no page errors.**

- [ ] **Step 1:** Write the check; run it against the Task 2 commit (old page): FAIL.
- [ ] **Step 2:** Run it against HEAD: PASS. Rerun every check in gap-port-checks, `go vet ./...`, `go test -race ./... -count=1`.
- [ ] **Step 3:** Commit any fixes, each with the failing case first.
