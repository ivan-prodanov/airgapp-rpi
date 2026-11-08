# The Gap, slice 6: System and cleanup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One System page (`/system`) for the appliance — vitals, hotspot, access, maintenance — with the backend fixes it needs, and the console without the Firewall, Stats and Bandwidth pages, their APIs, the old pages and `app.css`.

**Architecture:** Settings get validated before they are saved and applied synchronously, so the page can say what went wrong. DNS and the firewall read the upstream resolvers from the settings table. A vitals endpoint reads `/proc`, `/sys` and `statfs` through an injectable root so it is testable. The System page is one Alpine component in the Gap style; `app.css` and its bridge go once nothing references them.

**Tech Stack:** Go (chi, SQLite), html/template, Alpine.js 3.15.11, plain CSS, vendored `qrcode.min.js`.

**Spec:** `docs/superpowers/specs/2026-11-07-the-gap-redesign.md` (System, Backend changes → System, Found while mapping, Decisions 1, 4, 5, 6). Mockup: `.claude/design/the-gap/System.dc.html` in the main checkout (git-ignored; prod data — never copy its hostnames, IPs, SSID or user names).

## Global Constraints

- "Airgapp", never "Airgapp app". Public repo: generic names in mocks (`airgapp-preview.example.ts.net`, "Phone", SSID "Airgapp").
- Decisions: Sign out is the last row of System → Access. Enrolment stays `airgapp://enrol`. A password change ends every session, including the current one. Firewall/Stats/Bandwidth: pages and APIs removed (`/api/firewall/rules*`, `/api/bandwidth/limits*`, `/api/system/stats/*`); services and stored rules/limits stay.
- Hotspot: 2.4 GHz channels 1/6/11, 5 GHz 36/40/44/48. SSID at most 32 bytes. WPA password 8–63 characters. Retention 7, 30 or 90 days. DNS upstreams: one or more valid IPv4 addresses.
- Secrets never leave the server: `GET /api/settings` reports whether a hotspot password is set, never the password.
- Destructive actions confirm inline in the row (sign out of Tailscale, remove user, reboot). Toasts via `notify()`.
- Phones: rows bleed to the edges, 44px targets, dialogs as bottom sheets. Reduced motion as elsewhere.

## Review Focus

1. **A hotspot change that fails to apply** (hostapd won't restart): the page says so instead of "Hotspot restarted", and the saved values are what the page shows. Pinned by `TestUpdateSettings_ApplyErrorReturned` (Task 1).
2. **An SSID with emoji** past 32 bytes but under 32 characters is refused with the byte count. Pinned by `TestValidateSettings` (Task 1) and system-check (Task 7).
3. **Removing the last DNS resolver** is refused; a bad address never reaches dnsmasq. Pinned by `TestValidateSettings` and `TestDNSUpstreamFromSettings` (Tasks 1–2).
4. **Changing the password from a second browser** signs out the first one too. Pinned by `TestChangePassword_EndsAllSessions` (Task 4).
5. **Old audit rows holding a VIN** never reach the page, before or after the scrub migration. Pinned by `TestMigrateV30_ScrubsVINs` and `TestAuditRecent_ScrubsVINs` (Task 4).

---

### Task 1: Settings validated, applied, and the password kept server-side

**Files:** `internal/services/validate.go`, `internal/services/hotspot.go`, `internal/handlers/settings.go`, tests in `internal/services/validate_test.go`, `internal/services/hotspot_test.go`, `internal/handlers/settings_test.go` (new).

**Interfaces:**
- Produces:
  - `services.SettingKeys = []string{"ap_ssid","ap_password","ap_channel","ap_country","dns_upstream","log_retention_days"}` — the one list.
  - `func services.ValidateSettings(in map[string]string) error` — unknown key → `unknown setting "<k>"`; `ap_ssid` empty → "Give the network a name."; over 32 bytes → "Too long: N of 32 bytes. Emoji count as 4 each."; `ap_password` (when present and non-empty) outside 8–63 → "The password needs 8 to 63 characters."; `ap_channel` not in {1,6,11,36,40,44,48} → "Pick a channel the hotspot supports."; `ap_country` not two letters → "Use a two-letter country code."; `dns_upstream` empty → "Keep at least one resolver.", any entry not IPv4 → "<x> isn't an IPv4 address like 9.9.9.9."; `log_retention_days` not 7/30/90 → "Keep traffic for 7, 30 or 90 days.". Errors are `*SettingError{Key, Msg}` so the page can mark the field.
  - `PUT /api/settings`: validate everything first (400 `{error, key}`), then save in one transaction, then apply synchronously: hotspot keys → `Hotspot.Apply()`; `dns_upstream` → `DNS.Apply()` then `Firewall.Apply()`; an apply error → 500 `{error: "Saved, but the hotspot didn't restart: <err>"}` (or the DNS equivalent). An empty `ap_password` means unchanged and is not saved.
  - `GET /api/settings` → every setting except `ap_password`, plus `"ap_password_set": "true"|"false"`.
  - `hostapd.conf` is written `0600`.
- [ ] Step 1: failing tests — `TestValidateSettings` (table of the cases above, incl. "🌶️🔥" ×5 SSID = 40 bytes), `TestHotspotConfMode0600` (DryRun writer into a temp path: make the conf path a `HotspotService` field), `TestUpdateSettings_RejectsBeforeSaving` (bad channel + good SSID → 400, SSID unchanged in DB), `TestUpdateSettings_ApplyErrorReturned` (Hotspot apply fails → 500 with the message), `TestGetSettings_HidesPassword`.
- [ ] Step 2: run → FAIL. Step 3: implement. Step 4: `go test ./internal/... -count=1` → PASS.
- [ ] Step 5: commit `fix(settings): validate before saving, apply and report errors, keep the hotspot password server-side`

### Task 2: DNS upstreams from settings

**Files:** `internal/services/dns.go`, `internal/services/firewall.go`, tests.

**Interfaces:**
- Produces: `func upstreamsFrom(db *sql.DB, fallback string) []string` (services package) — the `dns_upstream` setting when it holds at least one valid IPv4, else `splitUpstreams(fallback)`; invalid entries dropped. `DNSService` and `FirewallService` use it instead of `cfg.DNSUpstream` (server lines, Open-device DHCP option 6, Open DNAT target).
- [ ] Step 1: failing tests `TestDNSUpstreamFromSettings` (setting "9.9.9.9,149.112.112.112" → generated config has `server=/<allowed domain>/9.9.9.9` and `dhcp-option=tag:open,6,9.9.9.9,149.112.112.112`), `TestDNSUpstreamFallsBack` (setting "not-an-ip" → config's `cfg.DNSUpstream`), `TestFirewallOpenDNATUsesSettingsUpstream`.
- [ ] Step 2–4: FAIL → implement → PASS.
- [ ] Step 5: commit `fix(dns): the DNS upstream setting is what DNS and the firewall use`

### Task 3: Vitals

**Files:** `internal/services/system.go`, `internal/handlers/system.go`, router, tests.

**Interfaces:**
- Produces: `type Vitals struct { UptimeS int64; TempC *float64; Load1 float64; MemUsed, MemTotal, DiskUsed, DiskTotal, WanRx, WanTx uint64; WanIf, WanIP, LanIP, Model, OS string }` (JSON snake_case); `func (s *SystemService) Vitals() Vitals` reading `<root>/proc/uptime`, `/proc/loadavg`, `/proc/meminfo` (used = MemTotal − MemAvailable), `/sys/class/thermal/thermal_zone0/temp` (milli-°C; nil when absent), `/sys/class/net/<wan>/statistics/{rx,tx}_bytes`, `/proc/device-tree/model` (NUL-trimmed), `/etc/os-release` PRETTY_NAME, and `statfs("/")`. `SystemService.root` defaults to "/" (tests point it at a temp tree; statfs uses the temp dir).
  - `GET /api/system/vitals`.
- [ ] Step 1: failing `TestVitals` on a fake tree (uptime "622.40 …" → 622; temp "32600" → 32.6; meminfo → used/total bytes; rx/tx; model; PRETTY_NAME) and `TestVitals_NoThermal` (temp nil).
- [ ] Step 2–4: FAIL → implement → PASS. Step 5: commit `feat(system): vitals — uptime, temperature, load, memory, storage, WAN counters`

### Task 4: Access and audit fixes

**Files:** `internal/services/auth.go`, `internal/handlers/settings.go` (password), `internal/handlers/auth.go`, `internal/services/remote.go`, `internal/handlers/remote.go`, `cmd/netfilterd/main.go`, `internal/handlers/router.go`, `internal/services/audit.go`, `internal/handlers/tesla.go`, `internal/handlers/tesla_session.go`, `internal/database/migrations.go`, tests.

**Interfaces:**
- `func (s *AuthService) EndAllSessions() error`; `PUT /api/settings/password` ends every session and clears the caller's cookie; responds `{"signed_out": true}`.
- Funnel always on: after a successful `Up`, and at boot when authenticated, `EnableBLEFunnel` runs (non-fatal, logged). `POST /api/remote/funnel/ble/disable` is removed.
- `POST /api/remote/install` is outside the 30 s timeout group, with its own 120 s context.
- Audit: VINs never written — `tesla.set_vin` details become "<user> set the VIN"; `tesla.ble_session_open` drops " (vin=…)"; `AuditService.Recent` scrubs any 17-character VIN-shaped token (`[A-HJ-NPR-Z0-9]{17}`) to "the VIN" when reading. Migration **v30** rewrites existing `tesla.set_vin` and `tesla.ble_session_open` rows the same way.
  - `GET /api/system/audit` → `{"entries":[…14 newest], "total": N, "since": "<oldest timestamp>"}`.
- [ ] Step 1: failing tests `TestChangePassword_EndsAllSessions` (two sessions → both invalid after the change; response clears the cookie), `TestAuditRecent_ScrubsVINs`, `TestMigrateV30_ScrubsVINs` (rows at v29 with a VIN → none after), `TestAuditLog_TotalAndSince`, `TestRemoteUp_EnablesFunnel` (fake runner records `tailscale funnel --bg --set-path=/api/ble …` after up; reuse remote_test's runner), `TestFunnelDisableRouteGone`.
- [ ] Step 2–4: FAIL → implement → PASS. Step 5: commit `fix(access): password change ends sessions, Funnel always on, VINs never reach the audit log`

### Task 5: Remove Firewall, Stats, Bandwidth; /system replaces Settings and Remote access

**Files:** `internal/handlers/router.go`, delete `internal/handlers/firewall.go` and `internal/handlers/bandwidth.go` page/API handlers (services stay), `internal/handlers/system.go` (stats handlers), delete `web/templates/{firewall,stats,bandwidth}.html`, `cmd/preview/main.go`, `internal/handlers/render_test.go`.

**Interfaces:**
- `GET /system` renders `system.html` (a stub in this task, the page in Task 6); `/settings` and `/remote-access` → 301 to `/system`; `/firewall`, `/stats`, `/bandwidth` → 404; their APIs → 404. `/netfilter-ca.crt` stays (devices may fetch it); the page has no CA row.
- Nav: System → `/system`.
- [ ] Step 1: failing `TestRemovedRoutes` (router built with a test `Services`; each API and page path → 404; `/settings`, `/remote-access` → 301 `/system`), `TestLayoutNav` updated to `href="/system"` with `system` active; `testPages` drops the removed templates and adds `system.html`.
- [ ] Step 2–4: FAIL → implement → PASS. Step 5: commit `feat(console): /system replaces Settings and Remote access; Firewall, Stats and Bandwidth pages and APIs removed`

### Task 6: The System page

**Files:** `web/templates/system.html`, `web/static/css/gap.css`, `cmd/preview/main.go` (mocks: vitals with growing counters, settings incl. `ap_country`/`log_retention_days`/`ap_password_set`, validation via `services.ValidateSettings`, remote status/up/logout/install, tesla tokens list/issue/delete with plain tokens, audit `{entries,total,since}`, reboot), `internal/handlers/render_test.go`.

Behaviour (mockup `System.dc.html`, plus the decisions):
- Eyebrow "The appliance", h1 "System". **Vitals** (polled every 2 s while visible): Uptime (live dot; "Rebooting" while rebooting), Processor °C + "load x.xx" ("—" without a sensor), Memory used + "of N GB", Storage used + "of N GB", Internet ↓/↑ as rates from successive counters ("↓ 12 KB/s"), with the WAN interface. Machine line: model · OS · internet <wan ip> · hotspot <lan ip>.
- **Hotspot**: Wi-Fi network (name, password "Unchanged" with Show, band radios, channel radios per band, country hint, Apply → server status or error on the field), DNS upstream (chips, remove, add with IPv4 check, toast with Undo — each change PUTs the whole list), Traffic history (7/30/90 radios, toast with Undo).
- **Access**: Tailscale (connected: facts Dashboard `https://<tailnet_hostname>:10000` with Copy, Tailnet IP; Sign out confirm; signed out: auth key field + Sign in; not installed: Install), Airgapp access (always-on locked switch; summary by Tailscale state), Users (list with Show QR / Set up on phones, Remove with inline confirm; add → opens the QR), Dashboard password (one field with Show; ≥ 8; afterwards go to `/login`), **Sign out** (last row; button).
- **QR dialog**: `airgapp://enrol?api=<ble_funnel_url>&token=<plain>&nickname=<name>`; white modules on `--brand`, the Airgapp icon in the middle; "Scan with a phone that has Airgapp installed"; on a phone "Open in Airgapp" + "Show QR instead"; "Sign in to Tailscale first." when there's no Funnel URL. Named by `aria-label`, no title, no ×; Escape/backdrop close.
- **Maintenance**: Recent activity ("N events since D Mon"; newest 14), Reboot (confirm inline; "Rebooting…").
- [ ] Step 1: failing `TestSystemPage` (wants `class="vitals"`, "Wi-Fi network", "DNS upstream", "Traffic history", "Tailscale", "Airgapp access", "Users", "Dashboard password", "Sign out", "Recent activity", "Reboot the Pi", `class="qdlg"`, `/static/js/qrcode.min.js`; gone: "netfilter-ca", "Certificate").
- [ ] Step 2–4: FAIL → implement → PASS; screenshots 1440 and 390.
- [ ] Step 5: commit `feat(system): the Gap System page`

### Task 7: app.css goes; browser check

**Files:** delete `web/static/css/app.css`, `web/static/css/pico.min.css` (and the Makefile `assets` line for it), `web/templates/settings.html`, `web/templates/remote-access.html`; `web/templates/layout.html`, `web/templates/login.html`, `web/static/css/gap.css` (drop the bridge; add the base rules the pages relied on: `*{box-sizing:border-box}`, `html,body{margin:0;padding:0}`, body line-height 1.5, `::selection`, the login logo mask), `internal/handlers/render_test.go`; `system-check.mjs` in the plan workspace.

- [ ] Step 1: failing `TestLayoutStylesheets` → only `gap.css`, no `app.css`; `TestLoginPage` → no `app.css`.
- [ ] Step 2: implement; every earlier browser check still passes (fix-checks F1 retired: no old dialogs remain).
- [ ] Step 3: `system-check.mjs` (real clicks and typing), RED against the Task 5 commit, GREEN at HEAD: vitals render and the uptime ticks; Wi-Fi: emoji SSID over 32 bytes → byte-count error on the field, short password error, a good change → status; DNS: bad address, duplicate, add with Undo, can't remove the last; retention change with Undo; Tailscale sign-out confirm and cancel; Users: add opens the QR dialog (QR svg present, scan note), Remove confirm → gone; password < 8 error, a good one → `/login`; Sign out → `/login`; activity count; Reboot confirm → "Rebooting…"; phones 390/320: no sideways scroll, rows bleed, 44px targets, QR dialog is a bottom sheet; reduced motion; no page errors.
- [ ] Step 4: commit `chore(css): drop app.css and the bridge; the console is all Gap`
