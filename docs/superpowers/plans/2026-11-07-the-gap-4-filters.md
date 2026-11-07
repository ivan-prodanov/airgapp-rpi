# The Gap, slice 4 (Filters): implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `/filters` becomes the Gap Filters page, backed by a simpler model:
- one switch per filter (no per-domain switch);
- an optional note on each domain;
- real 7-day hit counts;
- changes that take effect at once;
- the merged "Navigation" filter;
- Car Apps split into Connectivity and Spotify.

**Architecture:**
- **Data:** migrations v27–v29 turn on every domain that's off and drop the `enabled` column (user decision), merge Nav and Maps into Navigation, and split Car Apps.
- **Code:** everything that read `fd.enabled` now reads only `f.enabled`.
- **Domain rules:** `CreateDomain` takes an optional note, rejects duplicates, and speaks the mockup's copy.
- **Effect at once:** filter and domain handlers apply the firewall and DNS, and refresh the allow and SNI caches, so changes take effect immediately.
- **One request:** `GET /api/filters/?domains=1` returns filters with their domains and 7-day hits, so the page needs a single request.
- **Page:** Alpine `filtersApp()`, CSS lifted from the mockup.

**Tech Stack:** Go (chi, SQLite migrations as positional strings), `html/template`, Alpine.js 3, `gap.css`.

**Spec:** `docs/superpowers/specs/2026-11-07-the-gap-redesign.md`, sections "Filters `/filters`", "Backend changes, by slice → Filters" and "Decisions" (3: domains that are off get turned on). The mockup is `.claude/design/the-gap/Filters.dc.html` in the main checkout. It is the source for copy and behaviour (`addDomain`, `toggleFilter`, `removeDomain`, `createFilter`, `renderVals`).

## Global Constraints
- The slice-1 constraints still hold:
  - the repository is public, so preview data uses seed domains and invented hit counts;
  - "Airgapp", never "Airgapp app";
  - commit locally;
  - the `Co-Authored-By` line on every commit.
- **Migrations:** v27, v28 and v29, appended to `migrations` in `internal/database/migrations.go`. Never edit an earlier migration. They key on filter **names**, so keep `'Connectivity'`, which the git-ignored `local_seed.go` uses.
- **Copy, verbatim from the mockup:**
  - Groups: "Car system" ("What the Tesla needs to drive, navigate and stay online.") and "Apps & streaming" ("Turn on what you want to use in the car.")
  - Row summary: "N domains · N ports · N hits this week" / "no hits this week" / "empty"
  - Switch label: "On" / "Off"
  - Sections: "Ports" and "Domains"; "N of M match"; "No domains yet. Add the first one below."
  - Add-domain placeholders: "Domain, e.g. cdn.example.com" and "Note (optional)"
  - Add results:
    - "Added d. Filtered devices can reach it now."
    - "Added d. It applies once F is on."
  - Errors:
    - "Enter a domain like cdn.example.com."
    - "d is always blocked. It can't be allowed."
    - "d is too broad: it would also allow always-blocked Tesla domains. Add the exact subdomain instead."
    - "d is already in F."
  - Toasts:
    - "F on. Filtered devices can now reach its N domains." / "F off. Its N domains no longer apply." (with Undo; "N ports" when the filter has no domains)
    - "Removed d from F." (with Undo)
    - "Created F. Add domains, then turn it on."
    - "F deleted."
  - Built-in note: "Built-in: you can edit its domains, but it can't be deleted."
  - Delete confirm: "Delete F? Filtered devices lose every domain it carried."
  - New-filter dialog: "New filter", "A filter is a named list of domains. It starts off: add domains, then turn it on.", "Name"; errors "Give the filter a name." / "Use letters, numbers, spaces and _ - + ' / only, starting with a letter or number." / "There's already a filter called F."
  - Search: placeholder "Find a domain or filter". No match: "Nothing matches “q”, so Filtered devices can't reach it." / "q is always blocked. No filter can allow it."
- **Hits:** `allowed` plus `resolved` rows over the last 7 days, attributed to a filter domain when the host equals it or ends with `"." + domain`. Domains are sorted most-hit first. Numbers are exact (`toLocaleString('en-US')`).
- **Search** matches filter names and domains only.

## Review Focus
1. **A domain that was off, in a filter that's on:** after the migration it is reachable, as the user decided. Pinned by `TestMigrateV27_DomainsTurnOn` (Task 1).
2. **Spotify deleted on an install:** v29 recreates it, as a user filter, to carry TCP 4070. Pinned by `TestMigrateV29_CarAppsSplit/spotify_deleted` (Task 2).
3. **Turning a filter on or off:** DNS, the SNI proxy and the traffic classifier see it at once, not after up to 30 s. Pinned by `TestSetEnabledTakesEffectNow` (Task 4).
4. **Deleting a user filter that owns a port** (Spotify, TCP 4070): the firewall is re-applied, so the port closes. Pinned by `TestDeleteFilterReappliesFirewall` (Task 4).
5. **A domain pasted as a URL** (`https://cdn.example.com/path`): it is accepted as `cdn.example.com`, as the mockup's `normalizeDomain` does. Pinned by `TestCreateDomain_Normalises` (Task 3).

---

### Task 1: One switch per filter

**Files:**
- `internal/database/migrations.go`: add v27.
- `internal/database/migrations_test.go`: add a `migrateTo(t, db, n)` helper and `TestMigrateV27_DomainsTurnOn`. Update the tests that assert disabled rows.
- `internal/models/filter.go`: remove `FilterDomain.Enabled`.
- `internal/services/filter.go`:
  - remove `SetDomainEnabled` and `AllEnabledDomains` (it has no callers);
  - `UpdateDomain(id int64, description string) error`;
  - `CreateDomain` stops inserting `enabled`.
- `internal/services/dns.go`, `sniproxy.go`, `trafficlog.go`: drop `fd.enabled = 1` from the predicates.
- `internal/handlers/filters.go` and `router.go`: remove `PUT /api/filters/domains/{domainID}/enabled` and `SetDomainEnabled`. `UpdateDomain` takes `{description}`.
- `web/templates/traffic.html`, an interim edit until slice 5: its allow state treats a domain as live when its filter is on (`f.enabled`), not `f.enabled && d.enabled`.
- Tests: `internal/services/dns_test.go` (replace `TestAllowedDomainsExcludesDisabled`) and `internal/services/filter_test.go`.

**Interfaces:**
- v27 SQL: `UPDATE filter_domains SET enabled = 1; ALTER TABLE filter_domains DROP COLUMN enabled;`
- Test-only: `func migrateTo(t *testing.T, db *sql.DB, n int)` applies `migrations[:n]` and records `schema_version`, exactly as `Migrate` does.

- [ ] **Step 1: Write the failing tests**
  - **`TestMigrateV27_DomainsTurnOn`:**
    - `migrateTo(26)`, then insert a domain with `enabled=0` into YouTube, then `Migrate`.
    - The domain row exists, and `PRAGMA table_info(filter_domains)` has no `enabled` column.
  - **`TestAllowedDomainsFollowFilter`** (in place of the disabled-domain test): a domain is in the DNS allow list exactly when its filter is enabled.
- [ ] **Step 2: Run them and confirm they fail**

  Run: `go test ./internal/database ./internal/services -run 'TestMigrateV27|TestAllowedDomainsFollowFilter' -count=1`

  Expected: FAIL.
- [ ] **Step 3: Implement v27 and the code changes**

  Run `grep -rn 'enabled = 1 AND\|fd.enabled\|d.enabled\|SetDomainEnabled\|AllEnabledDomains' internal web cmd` and confirm it finds nothing that's still needed.
- [ ] **Step 4: Run the tests**

  Run: `go vet ./... && go test ./... -count=1`

  Expected: every package reports `ok`. Update any existing test that asserted disabled rows to the new rule.
- [ ] **Step 5: Commit**

  Message: `feat(filters): one switch per filter — domains apply when their filter is on (v27)`.

### Task 2: Navigation, and the Car Apps split

**Files:**
- `internal/database/migrations.go`: add v28 and v29.
- `internal/database/migrations_test.go`: update `TestMigrateSeedsSystemFilters` (Navigation instead of Nav and Maps) and `TestMigrateV23SeedsLiveState` (it checks the v23 state through `migrateTo(23)`). Add new tests.
- `internal/services/firewall_test.go`: `TestGenerateConfig_CarAppsPorts` becomes a ports-follow-filters test.
- Hardcoded copy: `filters.html` (rewritten in Task 7), and the "Tesla AP/Nav" text in `traffic.html`, `cmd/preview/main.go` and `docs`. Fix the code ones.

**Interfaces:**
- **v28:**
  - Rename `Nav` to `Navigation`.
  - Move Maps' domains in with `INSERT OR IGNORE … SELECT`, along with any UDP/TCP ports.
  - Set Navigation's `enabled` to Nav's OR Maps', so nothing that was reachable is cut off.
  - Delete Maps. Its domains go by cascade.
- **v29:**
  - Upsert `Spotify` (`is_system=0`, `grp=''`, `enabled` unchanged when it exists, 0 when created), the way v22 handles Grok.
  - Move UDP 443, UDP 19302 and TCP 5228 to Connectivity, and TCP 4070 to Spotify, with `INSERT OR IGNORE` and their descriptions.
  - Delete Car Apps (ports cascade).
  - Target filters keep their own enabled state. A port now opens exactly when its filter is on.

- [ ] **Step 1: Write the failing tests**
  - **`TestMigrateV28_NavigationMerge`:**
    - Default: `Navigation` has `grp='System'`, `is_system=1` and the 12 domains (the union of Nav and Maps). There are no `Nav` or `Maps` rows.
    - Sub-test "only Maps on": with Nav disabled and Maps enabled at v27, Navigation ends up enabled.
  - **`TestMigrateV29_CarAppsSplit`:**
    - Default: Connectivity has UDP 443, UDP 19302 and TCP 5228; Spotify has TCP 4070; there are no `Car Apps` rows.
    - Sub-test "spotify_deleted": delete Spotify at v28. After `Migrate` it exists as a user filter with TCP 4070 and is disabled.
- [ ] **Step 2: Run them and confirm they fail**

  Run: `go test ./internal/database -run 'TestMigrateV28|TestMigrateV29' -count=1`

  Expected: FAIL.
- [ ] **Step 3: Implement v28 and v29, and update the affected tests and copy**
- [ ] **Step 4: Run the tests**

  Run: `go vet ./... && go test ./... -count=1`

  Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `feat(filters): merge Nav and Maps into Navigation; split Car Apps into Connectivity and Spotify (v28, v29)`.

### Task 3: Domain rules — optional note, duplicates, the design's copy

**Files:**
- `internal/services/filter.go`: `CreateDomain` and `UpdateDomain`; remove `ErrDescRequired`.
- `internal/services/validate.go`: `NormalizeDomain` also strips a scheme, a path, a port and a trailing dot, as the mockup does.
- `internal/services/filter_test.go`

**Interfaces:**
- `CreateDomain(filterID int64, d models.FilterDomain) (int64, error)`:
  - The description (note) is optional.
  - The errors read, verbatim:
    - invalid: "Enter a domain like cdn.example.com."
    - always blocked: "%s is always blocked. It can't be allowed."
    - too broad: "%s is too broad: it would also allow always-blocked Tesla domains. Add the exact subdomain instead."
    - already present: "%s is already in %s." (the filter's name). This is now an error, no longer an upsert.

- [ ] **Step 1: Write the failing tests**
  - **`TestCreateDomain_NoteOptional`:** an empty description succeeds.
  - **`TestCreateDomain_Normalises`:** `https://CDN.Example.com:443/path?q` is stored as `cdn.example.com`.
  - **`TestCreateDomain_Messages`:** each of the four error texts, exactly.
- [ ] **Step 2: Run them and confirm they fail**

  Run: `go test ./internal/services -run TestCreateDomain -count=1`

  Expected: FAIL.
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run the tests**

  Run: `go test ./internal/services ./internal/handlers -count=1`

  Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `feat(filters): optional domain note; clear rejections; pasted URLs accepted`.

### Task 4: Changes take effect at once

**Files:**
- `internal/handlers/filters.go`: add `trafficLog *services.TrafficLogService` and `sni *services.SNIProxyService` to `FiltersHandler`, and set them in `NewFiltersHandler`.
- `internal/handlers/filters_test.go`: create it.

**Interfaces:**
- Add `func (h *FiltersHandler) applyChange() error`, which runs:
  - `firewall.Apply()`
  - `dns.Apply()`
  - `trafficLog.RefreshAllowCache()`
  - `sni.RefreshCache()`

  Any handler that changes what is reachable calls it: `SetEnabled`, `Delete`, `CreateDomain`, `DeleteDomain`. On error, respond 500 with "saved but failed to apply: …".

- [ ] **Step 1: Write the failing tests**

  These use real services on a temp DB with `executor.New(true)` (DryRun).
  - **`TestSetEnabledTakesEffectNow`:**
    - Insert domain `ok.example` into a disabled filter.
    - PUT `/api/filters/{id}/enabled {"enabled":true}`.
    - `trafficLog.IsAllowListed("ok.example")` is true immediately, with no ticker.
  - **`TestDeleteFilterReappliesFirewall`:**
    - A user filter owns TCP 4070.
    - DELETE it.
    - The executor's `Recorded()` contains an `nft` command issued after the delete.
- [ ] **Step 2: Run them and confirm they fail**

  Run: `go test ./internal/handlers -run 'TestSetEnabledTakesEffectNow|TestDeleteFilterReappliesFirewall' -count=1`

  Expected: FAIL.
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run the tests**

  Run: `go test ./internal/handlers -count=1`

  Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `fix(filters): filter and domain changes apply now — firewall, DNS, allow and SNI caches`.

### Task 5: Filters with domains and 7-day hits in one request

**Files:**
- `internal/services/trafficlog.go`: add `AllowedByHostSince`. Bound the scan by row id, like `RecentHosts`.
- `internal/handlers/filters.go`: `List` honours `?domains=1`. A 30 s cache for the hit map sits behind a mutex.
- Tests: `internal/services/trafficlog_dashboard_test.go` and `internal/handlers/filters_test.go`.

**Interfaces:**
- `func (s *TrafficLogService) AllowedByHostSince(since time.Time) (map[string]int, error)`: lower-cased host → count of `allowed` plus `resolved` rows.
- **`GET /api/filters/?domains=1`:** each filter carries `"domains": [{id, domain, description, hits}]`, sorted by hits descending, then by domain.
  - A domain's hits are the sum over hosts `h` where `h == d || strings.HasSuffix(h, "."+d)`.
  - Without the parameter, the response is unchanged.

- [ ] **Step 1: Write the failing tests**
  - **`TestAllowedByHostSince`:** counts by host; `blocked`/`sinkholed`/`logged` rows don't count, and neither do rows older than 7 d.
  - **`TestListFiltersWithDomains`:** `googlevideo.com` collects the hosts `r1.googlevideo.com` and `googlevideo.com`. `notgooglevideo.com` doesn't count toward it. The order is by hits.
- [ ] **Step 2: Run them and confirm they fail**

  Run: `go test ./internal/services ./internal/handlers -run 'TestAllowedByHostSince|TestListFiltersWithDomains' -count=1`

  Expected: FAIL.
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run the tests**

  Same command. Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `feat(filters): filters with their domains and 7-day hits in one request`.

### Task 6: Preview mocks

**Files:**
- `cmd/preview/main.go`

**Interfaces:**
- **Seed data:** 13 filters taken from the migration seeds (Navigation, Time, Grok and Connectivity, with their ports, in `System`; the apps in `""`). The domains come from the seeds and the hits are invented.
- **The real API's shape and rules:**
  - `GET /api/filters/?domains=1`
  - `PUT /api/filters/{id}/enabled`
  - `POST /api/filters` with a name only; the same name rule and duplicate check; created off.
  - `DELETE /api/filters/{id}` returns 409 for built-ins.
  - `POST /api/filters/{id}/domains`, with the Task 3 rules and messages, including the always-blocked list from `services/protected.go`.
  - `DELETE /api/filters/domains/{id}`
- **Undo:** the mock accepts a POST of a previously removed domain back into its filter.

- [ ] **Step 1: Implement**
- [ ] **Step 2: Verify it**

  Run `go vet ./cmd/preview`, then curl each endpoint, including the four error texts.
- [ ] **Step 3: Commit**

  Message: `feat(preview): filters mock with the real API's shape and rules`.

### Task 7: The Filters page

**Files:**
- Rewrite: `web/templates/filters.html`
- Modify: `web/static/css/gap.css`, adding a "Filters" section lifted from `Filters.dc.html`. Scope `.btnp`, `.btnq` and `.search` under `.wrap` if they collide with `app.css`.
- Test: `internal/handlers/render_test.go`

**Interfaces:**
- **Markup hooks:**
  - `.wrap`, then `p.eyebrow` "Allow-lists · for Filtered devices"
  - `.phead` with `h1.h1` "Filters" and `button.btnp` "New filter"
  - `.search input[type=search]`
  - `.flist`, containing `.ghead` (h2 and p) and `.frow`
- **Each `.frow`** has:
  - `.f-id` (`.fname-t`, `.fsub`)
  - `label.f-sw` (`.swl`, a switch)
  - `button.f-chev`
  - `.f-fold` (`.fsec` "Ports" `ul.plist`; `.fsec` "Domains" `ul.dlist li` with `.dm-t b`, `.dm-hits`, `button.dm-x`)
  - `.dadd` (two `.finput` and `button.btnq` "Add")
  - `.fstatus`
  - `.ffoot` (`.fnote` or "Delete filter" and `.d-confirm`)
- **`dialog.ndlg`**, the native modal. Gap dialog styles with `@starting-style` and `@supports (overlay:auto)` exits go in `gap.css`.
- **Behaviour:** as in the mockup's methods, against the real API.
  - Load once with `?domains=1`, then refresh hits every 30 s while the tab is visible.
  - Toggling a filter applies at once and offers Undo.
  - Removing a domain offers Undo (the domain is re-added with its note).

- [ ] **Step 1: Write the failing test `TestFiltersPage`**

  The page:
  - contains `class="flist"`, `Find a domain or filter`, `New filter`, `class="ndlg"` and `A filter is a named list of domains.`;
  - doesn't contain `filter-card`, `Why is it needed` or `description is required`.
- [ ] **Step 2: Run it and confirm it fails**

  Run: `go test ./internal/handlers -run TestFiltersPage -count=1`

  Expected: FAIL.
- [ ] **Step 3: Implement**
- [ ] **Step 4: Run the tests**

  Run: `go test ./internal/handlers ./web -count=1`

  Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `feat(filters): the Gap filters page — groups, one switch per filter, domains with hits`.

### Task 8: Browser verification

- [ ] **Step 1: Write `filters-check.mjs`**

  Put it in the plan workspace. Use real clicks and typing, and run it RED against the Task 6 commit. It covers:
  - **load:** the groups, row summaries, and a domain sorted by hits.
  - **toggle:** On, then Off, with Undo; the API agrees.
  - **add:**
    - a pasted URL is normalised;
    - the four error texts;
    - success copy for a filter that's on and one that's off.
  - **remove:** with Undo, which restores the domain.
  - **new filter:**
    - empty name gives an error;
    - a duplicate gives an error;
    - creating one leaves it off and open, with the toast.
  - **delete:** a user filter, after confirming. A built-in shows the note and no Delete.
  - **search:**
    - by a domain substring, which opens the matching rows with "N of M match";
    - no match;
    - an always-blocked domain.
  - **phones, 390 and 320:** no sideways scroll; the dialog is a bottom sheet; tap targets are at least 44 px.
  - **dialog exit:** it fades out in about 150 ms and keeps its name while leaving.
  - **reduced motion**, and **no page errors**.
- [ ] **Step 2: Run it and the earlier slices' checks against HEAD**

  Expected: all PASS. Then run `go vet ./... && go test -race ./... -count=1`.
- [ ] **Step 3: Take screenshots at 1440 and 390, and commit any fixes**
