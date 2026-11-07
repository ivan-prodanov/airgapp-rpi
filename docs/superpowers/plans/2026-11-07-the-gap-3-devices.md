# The Gap, slice 3 (Devices): implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `/devices` becomes the Gap Devices page:
- the Tesla's card, with its policy control and how many of its requests were blocked this hour;
- a one-line colour key;
- a roster of the other devices as rows that open to show details, logging, rename and forget.

It is backed by a partial device update, a device list that marks the Tesla, and a small activity feed for the row blips.

**Architecture:**
- **Server:**
  - `PUT /api/devices/{mac}` becomes a partial update. The fields are optional, and history is wiped only when logging turns *off*.
  - `GET /api/devices` adds `tesla:true` and `blocked_1h` to the Tesla's entry, using slice 2's `pickTesla` and `ClassCountsSince`.
  - New: `GET /api/devices/activity` lists the MACs with traffic in the last 5 s.
- **Page:** Alpine `devicesApp()`. Shared Gap controls (`.btn`, `.finput`, `.flabel`, `.field`, `.sw`, `.empty`) go in `gap.css`, scoped under `.wrap` so they don't collide with `app.css`'s `.btn` on pages not yet ported.
- **Preview:** mirrors all of the above.

**Tech Stack:** Go (chi, SQLite), `html/template`, Alpine.js 3, `gap.css`.

**Spec:** `docs/superpowers/specs/2026-11-07-the-gap-redesign.md`, sections "Devices `/devices`" and "Backend changes, by slice → Devices". The mockup is `.claude/design/the-gap/Devices.dc.html` in the main checkout. Lift its CSS and copy, and follow its `renderVals()` for the rules on names, sub-lines and confirmations.

## Global Constraints
- The slice-1 constraints still hold:
  - no new dependencies or CDNs;
  - the repository is public, so tests and mocks use example names and MACs only;
  - "Airgapp", never "Airgapp app";
  - commit locally;
  - the `Co-Authored-By` line on every commit.
- **Copy, verbatim from the mockup:**
  - "On the network · **N online** of M"
  - "N blocked this hour" or "Nothing blocked · everything passes"
  - "Other devices"
  - Legend: "**Blocked** no internet", "**Filtered** approved sites only", "**Open** full internet"
  - "Open the Tesla? Everything it sends will pass the gate, and data that leaves can't be recalled." with buttons Cancel / "Open the Tesla"
  - "Stop logging X and wipe its history from Traffic? Firewall rules keep applying." with buttons Cancel / "Stop and wipe"
  - "Forget X? Its traffic history is wiped. If it reconnects, it comes back as Blocked." with buttons Cancel / "Forget device"
  - Toasts: "X → Blocked/Filtered/Open" (with Undo), "Traffic logging resumed", "Logging off, history wiped", "X forgotten"
  - Empty roster: "No other devices yet. Connect something to the hotspot and it'll appear here as Blocked."
- **Names:** alias → hostname → "Unknown device".
- **Sub-line:**
  - a new device: "joined `<first seen>`";
  - a device with both an alias and a hostname: the hostname;
  - a device with no hostname: "unrecognised".
- **A new device** was first seen less than 24 h ago.
- **Roster order:** new devices, then online, then offline; then by name. The order is set when the list first loads. Later refreshes update rows in place, put newly seen devices at the top, and drop forgotten ones.
- **Times:**
  - under 1 min: "just now"
  - under 60 min: "N min ago"
  - under 24 h: "N h ago"
  - otherwise "12 Mar" (`en-GB` short day and month)
- **Policy changes** apply at once and show an Undo toast. The Tesla's Open asks first, inline. Logging off asks first, because it wipes history. Forget asks first and has no Undo.

## Review Focus
1. **Renaming a device whose logging is off:** logging stays off and history is not wiped again. Pinned by `TestUpdateDevice_RenameKeepsLogging` (Task 1).
2. **A failed policy request** (the API returns an error): the row reverts to its previous policy, and the error toast replaces the Undo toast. Pinned by devices-check "fail" (Task 6), with a preview mock that fails on `?fail=status`.
3. **No Tesla on the network:** the Tesla card shows "No Tesla yet. It'll appear here when it joins the Airgapp Wi-Fi." and the roster lists every device. Pinned by `TestListDevices_MarksTesla` with no Tesla (Task 2) and devices-check "notesla" (Task 6).
4. **Open on a phone:** the policy pill-select works, rows open with 44px targets, and nothing scrolls sideways. Pinned by devices-check at 390/320 (Task 6).
5. **Typing a name and leaving the field:** the rename is saved once, and survives a reload. Pinned by devices-check "rename" (Task 6).

---

### Task 1: Partial device update

**Files:**
- Modify: `internal/handlers/devices.go` (`Update`)
- Modify: `internal/services/network.go`. Add `SetAlias` and `SetIgnoreTrafficLog`. Keep `UpdateDevice` only if something else still calls it; otherwise delete it.
- Create: `internal/handlers/devices_test.go`

**Interfaces:**
- Produces:
  - `func (s *NetworkService) SetAlias(mac, alias string) error`
  - `func (s *NetworkService) SetIgnoreTrafficLog(mac string, ignore bool) (changed bool, err error)`
- **`PUT /api/devices/{mac}` body:** `{"alias"?: string, "ignore_traffic_log"?: bool}`.
  - An empty body, or neither field, returns 400 `{"error":"nothing to update"}`.
  - History is wiped (`WipeForDevice`) only when `ignore_traffic_log` changes from false to true.

- [ ] **Step 1: Write the failing tests**

  Use a real DB through `database.Open` on `t.TempDir()`, and a `DevicesHandler{network, trafficLog, audit}` built from `services.NewNetworkService`, `services.NewTrafficLogService` and `services.NewAuditService`. The firewall and DNS services are not used by `Update`. Route the request through a chi router so `{mac}` resolves.
  - **`TestUpdateDevice_RenameKeepsLogging`:**
    - A device with `ignore_traffic_log=1` and 2 `query_log` rows for its MAC.
    - PUT `{"alias":"Car"}`.
    - Expect alias `Car`, the flag still 1, and the 2 rows still present.
  - **`TestUpdateDevice_LogOffWipesOnce`:**
    - A device with alias `TV`, flag 0, and 3 rows.
    - PUT `{"ignore_traffic_log":true}`.
    - Expect alias `TV`, the flag 1, and 0 rows.
  - **`TestUpdateDevice_Empty`:** PUT `{}` returns 400.
- [ ] **Step 2: Run them and confirm they fail**

  Run: `go test ./internal/handlers -run TestUpdateDevice -count=1`

  Expected: FAIL. Today the alias is overwritten with an empty string, the flag is reset, and `{}` returns 200.
- [ ] **Step 3: Implement**

  Decode into `struct{ Alias *string; IgnoreTrafficLog *bool }` with the same JSON tags. Apply only the fields that are present. Audit them as `device.rename` and `device.logging`.
- [ ] **Step 4: Run them and confirm they pass**

  Run: `go test ./internal/handlers ./internal/services -count=1`

  Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `fix(devices): partial update — renaming keeps logging; wipe only when logging turns off`.

### Task 2: The device list marks the Tesla

**Files:**
- Modify: `internal/handlers/devices.go` (`List`)
- Test: `internal/handlers/devices_test.go`

**Interfaces:**
- Consumes `pickTesla` and `TrafficLogService.ClassCountsSince` from slice 2.
- Produces this `GET /api/devices` element: the existing `models.Device` fields, plus `"tesla": true` and `"blocked_1h": N` on the Tesla only. Use an embedding struct `deviceView{models.Device; Tesla bool \`json:"tesla,omitempty"\`; Blocked1h *int \`json:"blocked_1h,omitempty"\`}`. The response stays a JSON array, so existing readers are unaffected.

- [ ] **Step 1: Write the failing test `TestListDevices_MarksTesla`**
  - **With a Tesla:** the Tesla has 3 blocked and 2 sinkholed rows in the last hour, plus 1 blocked row 2 h old. A laptop is also present.
    - The Tesla's element has `tesla==true` and `blocked_1h==5`.
    - The laptop's element has neither key.
  - **Without a Tesla:** a second sub-test with only the laptop. No element has `tesla`.
- [ ] **Step 2: Run it and confirm it fails**

  Run: `go test ./internal/handlers -run TestListDevices -count=1`

  Expected: FAIL.
- [ ] **Step 3: Implement it in `List`**
- [ ] **Step 4: Run it and confirm it passes**

  Run: `go test ./internal/handlers -count=1`

  Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `feat(devices): the device list marks the Tesla and counts its blocks this hour`.

### Task 3: Activity feed for the row blips

**Files:**
- Modify: `internal/services/trafficlog.go`. Add `ActiveSince`.
- Modify: `internal/handlers/devices.go`, with an `Activity` handler.
- Modify: `internal/handlers/router.go`. Add `r.Get("/activity", devH.Activity)` in the `/api/devices` route.
- Tests: `internal/services/trafficlog_dashboard_test.go` (append) and `internal/handlers/devices_test.go`.

**Interfaces:**
- Produces:
  - `func (s *TrafficLogService) ActiveSince(since time.Time) (macs, ips map[string]bool, err error)`. MACs are lower-cased.
  - `GET /api/devices/activity` → `{"active": ["AA:BB:…", …]}`: the uppercase MACs of devices with any `query_log` row in the last 5 s, matched by MAC, or by the device's current IP.

- [ ] **Step 1: Write the failing tests**
  - **`TestActiveSince`:**
    - Rows 2 s ago: one by MAC A, one by IP only for B.
    - One row 30 s ago for C.
    - `ActiveSince(now−5s)` contains A's MAC and B's IP, and not C's.
  - **`TestDeviceActivity`:** the handler returns `{"active":[A,B]}` in any order, for devices A and B in the table.
- [ ] **Step 2: Run them and confirm they fail**

  Run: `go test ./internal/services ./internal/handlers -run 'TestActiveSince|TestDeviceActivity' -count=1`

  Expected: FAIL.
- [ ] **Step 3: Implement**

  The query is `SELECT DISTINCT LOWER(client_mac), client_ip FROM query_log WHERE timestamp >= ?`. The handler maps devices onto that result.
- [ ] **Step 4: Run them and confirm they pass**

  Same command. Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `feat(devices): which devices had traffic in the last few seconds`.

### Task 4: Preview mocks

**Files:**
- Modify: `cmd/preview/main.go`.

**Interfaces:**
- **`GET /api/devices`:** add `tesla:true` and `blocked_1h` (growing over time, and 0 once the Tesla is open) to the first `/tesla/i` device.
  - Give the devices example `first_seen` and `last_seen` timestamps, with one device first seen 10 min ago so it shows as new.
  - One device is offline.
  - `?scenario=notesla` leaves the Tesla out.
- **`PUT /api/devices/{mac}`:** partial semantics, as in Task 1.
- **`PUT /api/devices/{mac}/status`:** returns 500 `{"error":"could not apply the firewall"}` when the page's URL had `?fail=status`.
  - The mock can't see the page's URL, so the page forwards `location.search` to its API calls, the same as the dashboard does.
- **`GET /api/devices/activity`:** returns 1–2 random online MACs per call.

- [ ] **Step 1: Implement**
- [ ] **Step 2: Verify it**

  Run `go vet ./cmd/preview`, then curl each endpoint on a preview at `:8091`:
  - Partial PUT keeps the other field.
  - `?fail=status` returns 500.
- [ ] **Step 3: Commit**

  Message: `feat(preview): devices mock — Tesla mark, activity, partial update, failure scenario`.

### Task 5: The Devices page

**Files:**
- Rewrite: `web/templates/devices.html`
- Modify: `web/static/css/gap.css`. Add a "Controls" section and a "Devices" section.
- Test: `internal/handlers/render_test.go`

**Interfaces:**
- **Markup hooks** for Task 6:
  - `.wrap > .phead` contains `.eyebrow` and `h1.h1`.
  - `section.specimen.s-<policy>` contains `.spec-meta`, `.spec-live`, `.reg` (3 radios, `name="pol-tesla"`), `label.polpill > select`, and an optional `.d-confirm`.
  - `.rhead h2` "Other devices".
  - `ul.legend` has 3 items.
  - `ul.roster > li.drow.s-<policy>` per device, with:
    - `.d-id`: `.dname-t`, `.newtag`, `.dpres`, `.dsub`
    - `.d-pol`: `.reg` and `.polpill`
    - `button.d-chev[aria-expanded]`
    - `.d-fold`: `dl.d-facts`, a log switch `input[role=switch]`, a rename `input.finput`, `button.d-forget`, and an optional `.d-confirm`
  - `p.empty` when there are no other devices.
- **Behaviour (`devicesApp()`):**
  - Load and poll every 10 s, in place. Poll `/api/devices/activity` every 3 s, and give each MAC it returns `.active` on its row for 700 ms. Both polls run only while the tab is visible, and both forward `location.search`.
  - Policy changes and Undo call `PUT …/status`. On failure, revert the row, and `notify` shows the error.
  - The log switch, rename (`change` event) and forget follow the global constraints.
- **CSS:**
  - Lift from `Devices.dc.html`.
  - Scope the controls under `.wrap`: `.wrap .btn` resets `app.css`'s `.btn` (`display:inline-flex`, `gap:0`, `border-radius:8px`, `background:transparent`, `padding:0 14px`, `text-transform:uppercase`, …).
  - `.wrap` here is `max-width:1080px` only. `.content` already provides the padding.
  - Rise sequence: `.phead` `data-rise`, `.specimen` `data-rise="1"`, and the rhead, legend and roster `data-rise="2"`.

- [ ] **Step 1: Write the failing test `TestDevicesPage`**

  The rendered page:
  - contains `class="specimen`, `class="legend"`, `class="roster"`, `Other devices`, `name="pol-tesla"` and `Open the Tesla`;
  - does not contain `<table`, `Lease table` or `/tesla/i`.
- [ ] **Step 2: Run it and confirm it fails**

  Run: `go test ./internal/handlers -run TestDevicesPage -count=1`

  Expected: FAIL.
- [ ] **Step 3: Write the markup, the CSS and `devicesApp()`**
- [ ] **Step 4: Run it and confirm it passes**

  Run: `go test ./internal/handlers ./web -count=1`

  Expected: `ok`.
- [ ] **Step 5: Commit**

  Message: `feat(devices): the Gap devices page — Tesla card, colour key, roster with folds`.

### Task 6: Browser verification

**Files:**
- Create `devices-check.mjs` in the plan workspace.

- [ ] **Step 1: Write the check and run it against the previous page**

  Build the previous page from the Task 4 commit in a temporary worktree and confirm the check fails. All clicks are real mouse events, and all typing is `Input.insertText`. The check covers:
  - **load:**
    - The eyebrow counts.
    - The Tesla card shows its MAC at 1440 and hides it at 390, and shows the blocked-this-hour line.
    - The roster order is new, then online, then offline.
  - **policy:**
    - Click Filtered on a Blocked row. The row's class becomes `s-filtered`, the toast reads "X → Filtered", and the mock reports the new status through GET.
    - Click Undo. The row is back to `s-blocked` and the mock is back too.
  - **tesla:**
    - Click Open. The inline confirm appears and the policy is unchanged.
    - Click Cancel. Nothing changes.
    - Click Open, then "Open the Tesla". The policy is open and the live line reads "Nothing blocked · everything passes".
    - Restore the Tesla to filtered.
  - **log:**
    - Open a row and click the switch. The confirm appears. Click "Stop and wipe". The toast reads "Logging off, history wiped", and the mock has the flag set and the alias unchanged.
    - Turn the switch back on. The toast reads "Traffic logging resumed".
  - **rename:** type a new name and press Tab. Reload. The name persists, and the mock saw one PUT with an `alias` key only.
  - **forget:** confirm Forget. The row is gone and the toast reads "X forgotten".
  - **fail:** load with `?fail=status` and change a policy. The row reverts, and an error toast shows.
  - **notesla:** load with `?scenario=notesla`. The Tesla placeholder shows, and the roster lists every device.
  - **blip:** within 7 s, some row gets `.active`.
  - **phones, 390 and 320:**
    - The policy pill-select changes a row's policy, through `form_input` or by setting `.value` and dispatching `change`.
    - The chevrons are at least 44 px under `pointer:coarse` emulation.
    - Nothing scrolls sideways.
  - **reduced motion:** no running animations.
  - **errors:** no page errors.
- [ ] **Step 2: Run it against HEAD and confirm it passes, then rerun slice 1's and slice 2's checks**

  The slice-1 checks are in the session scratchpad `gap-port-checks/`; slice 2's check is in its plan workspace.
- [ ] **Step 3: Run the full suite**

  Run: `go vet ./... && go test -race ./... -count=1`

  Expected: every package reports `ok`.
- [ ] **Step 4: Take screenshots at 1440 and 390, and commit any fixes**
