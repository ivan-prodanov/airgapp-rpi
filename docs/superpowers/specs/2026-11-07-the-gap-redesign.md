# The Gap — Airgapp console redesign

**Status:** design approved 2026-11-07 (mockup version 42).

**Mockups:** these exist in two places. Neither is in this repository.
- The private Claude artifact "The Gap".
- A local copy at `.claude/design/the-gap/{Main,Devices,Traffic,Filters,System}.dc.html` in the main checkout. Git ignores it on purpose: the mockups are seeded with production data (device names, the tailnet hostname, real hit counts), and this repository is public.

The `.dc.html` files are written for a React-like design runtime. `{{holes}}`, `<sc-for>`, `<sc-if>` and `renderVals()` are that runtime's syntax. Read the files for CSS, markup structure and behaviour, and lift CSS rules from them. The port itself uses Go `html/template` and Alpine.js.

## Concept

The UI *is* the airgap:
- A gate stands between the car and the internet.
- Every request the Tesla makes either crosses the gate or is cut.
- Each page is a view of that gate: what is connected (Devices), what crossed or was cut (Traffic), what may cross (Filters), and the machine that holds the gate (System).

## Global

### Navigation
- **Top bar:** the Airgapp wordmark, then five links in this order:

  | Link | Path |
  |---|---|
  | Dashboard | `/` |
  | Devices | `/devices` |
  | Traffic | `/traffic` |
  | Filters | `/filters` |
  | System | `/system` |

  The sidebar rail, its status box and the mobile burger drawer are removed.
- **Pages outside the nav:** Firewall, Stats and Bandwidth are not linked. Their routes keep working by URL until decided otherwise (see Open decisions).
- **System:** Settings and Remote access merge into System (slice 6). Until then the System link goes to `/settings` and is active on the `settings` and `remote-access` pages.
- **The page scrolls, not an inner pane.** The top bar is sticky from 520px wide upward: `position:sticky; top:0; z-index:10; background:rgba(7,10,18,.82); backdrop-filter:blur(8px)`.
- **Narrow layouts:**
  - Below 520px the bar is static and the links take their own row: `justify-content:space-between`, 10px type, letter-spacing .06em, gap 4px, no scrolling.
  - Below 380px the links shrink to 9.5px with letter-spacing .03em.
  - On coarse pointers, link padding is 14px top and 12px bottom, which gives 44px tap targets.
  - All five links must fit at 320px, even with a 15px classic scrollbar.
- **Fixed elements clear the bar.** Anything fixed to the top of the viewport has to sit below the sticky bar. Measure the bar's height while it is sticky; Traffic's "↑ N new" pill is the existing case.

### Type and colour
- **Type:** Saira 300–700 for UI text and Martian Mono 400–600 for labels, data and nav. Both are self-hosted woff2 files; the page makes no font CDN requests.
- **Tokens:**
  - `--bg0:#070A12`
  - `--line:rgba(132,164,205,.14)`
  - `--line2:rgba(132,164,205,.26)`
  - `--panel:rgba(12,17,27,.55)`
  - `--gate:#AFC7D4`
  - `--txt:#EAF0F7`
  - `--dim:#93A1B5`
  - `--faint:#7A879C`
  - `--safe:#4ADE80`
  - `--danger:#FF5A3C`
  - `--watch:#F5B544`
  - `--brand:#e02434`, used only for the enrol QR field and the "Open in Airgapp" button.
- **Body background:** `radial-gradient(130% 70% at 50% 0%, rgba(44,76,108,.16), rgba(7,10,18,0) 60%), linear-gradient(180deg,#080B14,#06080F)`.
- **Contrast:** text must be at least 4.5:1 against `--bg0`. Every token above passes.

### Motion

**Tokens:**
- Durations:
  - `--t-fast:120ms`
  - `--t-panel:200ms`
  - `--t-exit:150ms`
  - `--t-blip:700ms`
  - `--t-flash:1.2s`
  - `--t-live:2s`
  - `--t-rise:400ms`
- Step delays: `--rise-1:60ms`, `--rise-2:120ms`, `--rise-3:180ms`.
- Easings:
  - `--ease-std:cubic-bezier(.2,0,.38,.9)`
  - `--ease-enter:cubic-bezier(0,0,.38,.9)`
  - `--ease-exit:cubic-bezier(.2,0,1,.9)`
  - `--ease-rise:cubic-bezier(0,0,.3,1)`

**Rules:**
1. **The frame is still.** The top bar never animates.
2. **Pages arrive top to bottom.**
   - Keyframes `rise`: from `opacity:0; transform:translateY(12px)` to the element's natural state, over `--t-rise` with `--ease-rise`.
   - Fill mode `backwards` only. Nothing may linger, because a leftover transform or stacking context breaks sticky and fixed children.
   - Steps start at 0, 60, 120 and 180ms: title, then lead block, then list. The Dashboard's steps are headline, regime, gate, readouts.
   - Lists rise too.
3. **Controls, panels, dialogs and toasts.**
   - Controls transition in `--t-fast` with `--ease-std`. Folds and chevrons use `--t-panel`.
   - Dialogs and toasts enter in `--t-panel` with `--ease-enter` and leave in `--t-exit` with `--ease-exit`.
   - They keep showing their content while leaving.
   - Dialog exits apply only under `@supports (overlay:auto)`. Elsewhere dialogs close instantly.
4. **Data motion.**
   - The live dot pulses every `--t-live` with a 6px green ring.
   - Activity blips last `--t-blip`, and new-row highlights last `--t-flash`.
   - Traffic's row slide uses FLIP: 520ms, `cubic-bezier(.22,.8,.24,1)`, transform only.
   - Blocked counts and dots do not pulse, because blocking is normal.
5. **`prefers-reduced-motion: reduce`:** every animation and transition runs for .01ms with zero delay and one iteration. JavaScript tweens (counters) jump straight to their value, and FLIP is skipped.

### Components
- **Lists are rows, not cards.**
  - Each row has a coloured left bar (inset box-shadow) and opens a fold when tapped.
  - The fold animates `grid-template-rows` from `0fr` to `1fr`, and the content keeps `visibility:hidden` until the fold opens.
  - A chevron rotates with the fold.
- **Switch:** a native checkbox with `role="switch"`.
- **Small exclusive choices:** native radios styled as pills. Where a phone row is too tight, use a pill over a native `<select>` (device policy is the case).
- **Dialogs:**
  - Native `<dialog>` opened with `showModal()`: centred on desktop, a bottom sheet at 860px and below.
  - Always named with `aria-labelledby` or `aria-label`.
  - Escape and a backdrop click close them.
- **Toast:** bottom centre, one at a time, `role=status`. Undo is optional; a toast with Undo stays 7s, a plain toast 4s.
- **Destructive actions:** confirm inline, in the row's fold, instead of with `confirm()`.
- **Phones (860px and below):** compact two-line rows, and the page is the scroller.
- **Touch targets:** at least 44px on coarse pointers.

### Copy rules
- **Product name:** always "Airgapp", never "Airgapp app".
- **Outcomes:**
  - The labels are **Allowed** and **Blocked**.
  - Allowed covers `allowed` and `resolved`; Blocked covers `blocked` and `sinkholed`.
  - `logged` appears only under All.
- **Banned wording:** "Severed", a "PROTECTED" label, "Guardian", "netfilterd-01" and "Operator".

## Pages

### Dashboard `/`
- **Headline** (Martian Mono, uppercase), keyed by the Tesla's regime:
  - Blocked: "Tesla is Blocked".
  - Filtered: "Elon is Gated", with "Gated" in `--safe`.
  - Open: "Elon is In", with "In" in `--danger`.
- **Gate:** a vertical gate. The latest seven Tesla requests fan out from the car node to the gate. Blocked requests are cut with a red ×, and allowed requests cross in green. The fan refreshes about every 3.2s from real events.
- **Counters:** Blocked and Allow-listed, with an odometer roll over 760ms. Sinkholed counts as blocked.
- **Controls:** a pause button for the stream.
- **Readouts:** a row along the bottom.

### Devices `/devices`
- **Tesla card:**
  - Name, online status and IP. The MAC appears on desktop only.
  - "N blocked this hour".
  - The policy control: radios on desktop, a pill over a select on phones. The Tesla has the same control as any other device; there is no lock.
- **Colour key:** one line.
- **Device rows:**
  - Each row shows name and status, policy, and a chevron.
  - The fold holds the network facts, first and last seen, a Log switch, Rename and Forget.
  - Turning Log off wipes history, so it asks first.
  - Forget asks first, then shows a toast with Undo where the action can be undone.
- **Names:** the alias, else the hostname, else "Unknown device".
- **New devices** start Blocked.

### Traffic `/traffic`
- **The ledger is a live tail with the newest row on top.**
  - At the live edge, new rows slide in with FLIP.
  - More than 24px away from the edge, the view holds still, buffers new rows and shows an "↑ N new" pill.
  - The scroller uses `overflow-anchor:none`.
  - On phones the page is the scroller. An IntersectionObserver sentinel detects leaving the live edge, with its top `rootMargin` set to minus the sticky bar's height.
- **Filters:** outcome radios All · Allowed · Blocked, with protocol as a secondary select.
- **Rows** say Allowed or Blocked. Finer detail goes in the fold.
- **Muted domains:** a dialog to add a domain, list them, and remove one with Undo.
  - Muting is a suffix match.
  - Rows already logged stay, marked "Muted by `<pattern>`".
- **Allow dialog:**
  - An editable domain.
  - A pick-list of filters. Filters that are off are marked as off, and the likely filter is suggested from the registrable domain.
  - "+ New filter", created ON.
  - An optional note.
  - Afterwards the row reads "Allowed · `<filter>`" or "Pending · `<filter>` is off".
- **Always-blocked domains:**
  - Allow stays visible but locked: `aria-disabled`, still focusable, dashed with a lock icon.
  - Tapping it shows the toast "`<domain>` is always blocked. It can't be allowed."
  - The always-blocked list comes from the server, not from a JavaScript copy.

### Filters `/filters`
- **Groups:**
  - "Car system": Navigation, Time, Grok, Connectivity.
  - "Apps & streaming": YouTube, Netflix, Twitch, Spotify, Max, Hulu, F1, TikTok, Prime.
- **Domains:** there is no per-domain switch; a domain applies exactly when its filter is on. The domain note is optional.
- **Filter names:** filters have no description, and the new-filter dialog asks only for a name.
- **Section headings:** "Ports" and "Domains". Ports are read-only. Built-in filters can't be deleted.
- **Hits:** allowed events per domain over the last 7 days, most-used first, exact numbers. Zero shows "no hits".
- **Search** matches filter names and domains only.
- **Rejected domains:** always-blocked domains and too-broad parents are refused with the existing server messages.

### System `/system`
- **Vitals:** uptime, °C and load, memory, storage, and WAN ↓/↑ as rates.
- **Hotspot**
  - **Wi-Fi network:** SSID, password, and band. 2.4 GHz offers channels 1/6/11 and 5 GHz offers 36/40/44/48.
  - **DNS upstream:** shown as chips. You can add and remove them, and each must be a valid IPv4 address.
  - **Traffic history:** 7, 30 or 90 days.
- **Access**
  - **Tailscale:** status, sign in with an auth key, and sign out (asks first).
  - **Airgapp access:** the Funnel for `/api/ble`. It is always on, shown as a disabled switch, and no public URL is displayed.
  - **Users:**
    - Adding a user opens their QR immediately. Each user has Show QR and Remove (asks first).
    - The QR dialog is just the QR and "Scan with a phone that has Airgapp installed", with no title and no ×.
    - On phones it offers "Open in Airgapp" (the `airgapp://enrol` link) plus "Show QR instead".
  - **Dashboard password:** one field with Show.
  - **Sign out:** the last row (see Open decisions).
- **Maintenance:** Recent activity (the audit log, with VINs stripped) and Reboot the Pi (asks first).
- **Removed:** there is no HTTPS certificate row.

## Backend changes, by slice

**Devices**
- `PUT /api/devices/{mac}` currently overwrites both `alias` and `ignore_traffic_log`, so a rename turns logging back on. It must become a partial update.
- Add a per-device "blocked this hour" count.

**Filters**
- **Drop per-domain `enabled`.** Today the condition `fd.enabled = 1 AND f.enabled = 1` appears in `dns.go`, `sniproxy.go`, `trafficlog.go` and `filter.go`.
- **Make the domain description optional.** Remove `ErrDescRequired` from `CreateDomain` and `UpdateDomain`.
- **Add a 7-day hits endpoint.** Group `query_log` by host, then assign each host to filter suffixes in Go.
- **Data migrations:**
  - Nav and Maps merge into one filter, "Navigation".
  - Car Apps splits up. UDP 443, TCP 5228 and UDP 19302 move to Connectivity; TCP 4070 moves to Spotify, which must be upserted because it is a user filter. Then delete Car Apps.
  - Migrations are positional and key on filter **names**. The latest is v26, so new ones start at v27.
- **Deleting a filter must re-apply the firewall too.** Ports can now belong to user filters.
- **Refresh caches on change.** Refresh the SNI and allow caches when a filter or domain changes, not only on the 30s ticker.

**Traffic**
- Expose the always-blocked list, or an `allowable` flag per entry.
- Collapse the polling into one request per tick: today each tick sends 4+N requests. Use events since the last seen id.
- Allow defaults to the suggested filter, never to the first filter in the list (today that is the ports-only Car Apps).

**System**
- **Vitals endpoint:** numeric uptime, temperature from `/sys/class/thermal`, load, memory used, storage via statfs, and WAN byte counters for rates.
- **Hotspot settings:**
  - Validate before saving, including the real channel sets.
  - Return errors from applying the settings to the caller.
  - Write `hostapd.conf` as 0600.
  - Use one key list, including `ap_country`.
- **DNS upstream:** the DB value must actually be used by DNS and the firewall. Today nothing reads it.
- **Retention:** accept only 7, 30 or 90.
- **Funnel:** always on. Enable it after Tailscale `Up` and at boot, and remove the disable route.
- **Audit log:** strip VINs from details. Today the `tesla.set_vin` and `tesla.ble_session_open` entries contain them. Scrub when reading, and run a one-off scrub of existing rows.
- **Routes:**
  - `/system` replaces `/settings` and `/remote-access`, and the old routes redirect.
  - Remove the CA row. Decide separately what happens to the `/netfilter-ca.crt` route.

## Slices
Each slice ships on its own. Pages not yet ported keep their current markup inside the new shell, with the Gap palette bridged onto the old `app.css` tokens.

1. Shell & theme
2. Dashboard
3. Devices
4. Filters, with data migrations from v27
5. Traffic
6. System, which also deletes the bridge and the remaining `app.css` shell rules

## Found while mapping
These are outside the design. Each is fixed in the slice that owns the code.
- **Template cache race:** the render cache map has no lock, so two first renders can race.
- **Login 401 reloads the page:** `api.request` redirects every 401 to `/login`, so a wrong password reloads the page. The lockout message is also lost.
- **Remote access runs `init()` twice.** That doubles the 10s poll.
- **The 30s request timeout cuts off Tailscale install,** which needs 90s.
- **Stats "+Allow" goes nowhere.** It links to `/traffic?q=…`, but nothing reads the query.
- **`pico.min.css` is vendored but never linked.**
- **Admin password change** doesn't check the current password and doesn't end existing sessions.

## Open decisions
1. **Sign-out:** proposed as the last row of System → Access. Until slice 6 it is a button on the Settings page.
2. **Dashboard regime control:** show the Tesla's policy switch as in the mockup, or a read-only regime? An earlier note said the switch was a demo control.
3. **Disabled filter domains:** what happens to rows that are currently disabled when the per-domain flag goes away, enable them or delete them?
4. **Firewall, Stats, Bandwidth:** keep them reachable by URL, or remove them.
5. **Enrolment link:** a universal link, so it falls back when Airgapp isn't installed.
