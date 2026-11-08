package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
)

var migrations = []string{
	// v1: core schema
	`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac_address TEXT NOT NULL UNIQUE,
		ip_address TEXT DEFAULT '',
		hostname TEXT DEFAULT '',
		alias TEXT DEFAULT '',
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		is_blocked INTEGER DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS firewall_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		description TEXT DEFAULT '',
		direction TEXT NOT NULL CHECK(direction IN ('inbound','outbound','forward')),
		protocol TEXT CHECK(protocol IN ('tcp','udp','icmp','all')),
		source_ip TEXT DEFAULT '',
		dest_ip TEXT DEFAULT '',
		dest_port TEXT DEFAULT '',
		action TEXT NOT NULL CHECK(action IN ('drop','reject','accept')),
		device_mac TEXT DEFAULT '',
		enabled INTEGER DEFAULT 1,
		priority INTEGER DEFAULT 100,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS dns_blocklist (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		category TEXT DEFAULT 'custom',
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS bandwidth_limits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_mac TEXT NOT NULL UNIQUE,
		download_kbps INTEGER DEFAULT 0,
		upload_kbps INTEGER DEFAULT 0,
		enabled INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		action TEXT NOT NULL,
		details TEXT DEFAULT '',
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- No universal hotspot password: setup writes the chosen (or generated) one.
	INSERT OR IGNORE INTO settings (key, value) VALUES
		('ap_ssid', 'Airgapp'),
		('ap_password', ''),
		('ap_channel', '6'),
		('dns_upstream', '1.1.1.1,8.8.8.8');`,

	// v2: query log table for persistent traffic history
	`CREATE TABLE IF NOT EXISTS query_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		client_ip TEXT DEFAULT '',
		domain TEXT DEFAULT '',
		dst_ip TEXT DEFAULT '',
		dst_port TEXT DEFAULT '',
		protocol TEXT DEFAULT '',
		action TEXT DEFAULT 'query',
		client_mac TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_query_log_domain ON query_log(domain);
	CREATE INDEX IF NOT EXISTS idx_query_log_client ON query_log(client_ip);`,

	// v3: kv store for journalctl cursors and other state
	`CREATE TABLE IF NOT EXISTS kv_store (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	INSERT OR IGNORE INTO settings (key, value) VALUES
		('log_retention_days', '30');`,

	// v4: dynamic allow list via dnsmasq nftset integration
	`CREATE TABLE IF NOT EXISTS allowed_domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		description TEXT DEFAULT '',
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,

	// v5: explicit block list — domains that can never be allow-listed,
	// DNS-sinkholed to 0.0.0.0 so they fail to resolve even if the firewall
	// is bypassed. Seeded with Tesla firmware/diagnostic endpoints to prevent
	// accidental allow-list inclusion via the traffic monitor.
	`CREATE TABLE IF NOT EXISTS blocked_domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		match_type TEXT NOT NULL DEFAULT 'suffix' CHECK(match_type IN ('exact','suffix')),
		reason TEXT DEFAULT '',
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	INSERT OR IGNORE INTO blocked_domains (domain, match_type, reason) VALUES
		('ota.vn.tesla.services',       'exact',  'Tesla firmware update channel'),
		('ota.cn.tesla.services',       'exact',  'Tesla firmware update channel (China)'),
		('firmware.vn.tesla.services',  'suffix', 'Tesla firmware metadata'),
		('software-update.tesla.com',   'suffix', 'Tesla update orchestration'),
		('dl.tesla.com',                'exact',  'Tesla firmware blob CDN'),
		('tesla-cdn.com',               'suffix', 'Tesla asset and firmware CDN'),
		('tesla-cdn.net',               'suffix', 'Tesla asset and firmware CDN'),
		('diag.vn.tesla.services',      'exact',  'Tesla remote diagnostics'),
		('remote-diagnostics.tesla.com','suffix', 'Tesla remote service access');`,

	// v6: per-policy allow-listing — replaces the single global allow list with
	// named policies that can be assigned to specific devices. Each policy has
	// its own mode ('permissive' falls back to the global default chain on a
	// miss; 'strict' drops on a miss) and its own set of allowed domains that
	// populate a dedicated nftables IP set.
	//
	// Default policy ships as STRICT with an EMPTY allow list. Unassigned
	// devices fall back to Default, so new devices joining the hotspot are
	// blocked by default until explicitly authorised in the UI. This is a
	// deliberate departure from v1's "permissive global list" model — security
	// posture first.
	//
	// Existing v1 allowed_domains entries are intentionally NOT migrated (per
	// user decision during v2 design). Users who want to restore them can
	// re-add from the v1 DB snapshot kept at /var/lib/netfilterd/netfilter.db.
	//
	// Tesla policy is strict with exactly one entry (connman.vn.tesla.services)
	// — the connection-manager endpoint that keeps the car online without
	// exposing OTA/diagnostic channels.
	//
	// Per-entry resolution metadata (resolved_ips, last_resolved_at, hit_count)
	// is populated by the re-resolve cron so the UI can answer "is this rule
	// actually working?" — addresses the main v1 UX complaint.
	`CREATE TABLE IF NOT EXISTS policies (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT NOT NULL UNIQUE,
		mode        TEXT NOT NULL DEFAULT 'permissive' CHECK(mode IN ('permissive','strict')),
		description TEXT DEFAULT '',
		is_default  INTEGER DEFAULT 0,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_default ON policies(is_default) WHERE is_default = 1;

	CREATE TABLE IF NOT EXISTS policy_allowed_domains (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		policy_id         INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
		domain            TEXT NOT NULL,
		description       TEXT DEFAULT '',
		enabled           INTEGER DEFAULT 1,
		resolved_ips      TEXT DEFAULT '',
		last_resolved_at  DATETIME,
		hit_count         INTEGER DEFAULT 0,
		created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(policy_id, domain)
	);

	CREATE INDEX IF NOT EXISTS idx_policy_domains_policy ON policy_allowed_domains(policy_id);

	CREATE TABLE IF NOT EXISTS device_policies (
		device_mac   TEXT PRIMARY KEY,
		policy_id    INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
		assigned_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	INSERT OR IGNORE INTO policies (name, mode, description, is_default) VALUES
		('Default', 'strict', 'Fallback policy for devices with no explicit assignment. Strict + empty by default — unassigned devices are blocked until you authorise them.', 1),
		('Tesla',   'strict', 'Tesla vehicle policy: connman keeps the car online; everything else blocked including OTA, diagnostics, and CDN.', 0);

	INSERT OR IGNORE INTO policy_allowed_domains (policy_id, domain, description)
	SELECT id, 'connman.vn.tesla.services', 'Tesla connection-manager; keeps car online without exposing OTA.'
	FROM policies WHERE name='Tesla';

	DROP TABLE allowed_domains;`,

	// v7: traffic monitor split — tag each query_log row with the source
	// stream (dns|forward) and, for forward rows, the policy name that
	// produced the verdict. The UI reads `source` to split DNS events
	// from firewall events into separate tabs so users stop confusing
	// dnsmasq query logs with actual packet drops/accepts.
	`ALTER TABLE query_log ADD COLUMN source TEXT DEFAULT 'forward';
	ALTER TABLE query_log ADD COLUMN policy TEXT DEFAULT '';
	UPDATE query_log SET source='dns' WHERE action='query';
	CREATE INDEX IF NOT EXISTS idx_query_log_source ON query_log(source);`,

	// v8: wipe device_policies rows with URL-encoded MACs that a
	// prior handler bug (no PathUnescape on the {mac} path param)
	// inserted as literal "aa%3abb%3a..." strings. Those strings
	// ended up verbatim in the generated nftables ruleset and broke
	// the Apply() call with "unexpected string, expecting colon".
	`DELETE FROM device_policies WHERE instr(device_mac, '%') > 0;`,

	// v9: add 'open' as a valid policy mode. An open-mode policy's
	// chain is a single `accept` rule — the hard block-list and the
	// DoH/DoT chokepoint still apply (they run before the per-MAC
	// vmap dispatch), but everything else is unconditionally allowed.
	// Required for trusted devices (owner phone, laptop, TV) where
	// curating a hostname allow list is impractical.
	//
	// SQLite can't ALTER a CHECK constraint in place — rebuild the
	// table and copy rows. FK references from device_policies use
	// the plain id so the drop+rename is safe (PRAGMA foreign_keys
	// defaults off in this build).
	`CREATE TABLE policies_new (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT NOT NULL UNIQUE,
		mode        TEXT NOT NULL DEFAULT 'permissive' CHECK(mode IN ('permissive','strict','open')),
		description TEXT DEFAULT '',
		is_default  INTEGER DEFAULT 0,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	INSERT INTO policies_new (id, name, mode, description, is_default, created_at)
	SELECT id, name, mode, description, is_default, created_at FROM policies;

	DROP TABLE policies;
	ALTER TABLE policies_new RENAME TO policies;

	CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_default ON policies(is_default) WHERE is_default = 1;

	INSERT OR IGNORE INTO policies (name, mode, description, is_default) VALUES
		('Open', 'open', 'Trusted devices — no allow-list filtering. Hard block-list + DoH/DoT chokepoint still apply.', 0);`,

	// v10: Tesla MCU3 Preset B block-list + Tesla-policy allow list expansion.
	//
	// Derived from a per-endpoint impact analysis of Tesla Model 3 MCU3
	// firmware 2026.8.6 (fw_dump/TESLA_DOMAINS_BLOCKLIST.md in the sibling
	// fsd/ project). Preset B = "no config changes / FSD retention": Tesla
	// can no longer push firmware, rotate features, downgrade tier, or
	// VIN-ban; all surveillance/telemetry/upload pipes die; nav, maps,
	// Supercharger, account auth, and music services still work. Mobile
	// app loses live features (live status, remote lock) because those
	// ride the Hermes channel we're killing.
	//
	// The blocked entries go into blocked_domains (DNS-sinkholed globally,
	// pre-empting any policy allow list). The Tesla policy allow list also
	// grows so the car doesn't just hit connman in isolation — it can
	// resolve go.tesla.services (nav), auth.tesla.com (OAuth),
	// managed-charging (Supercharger billing + music tokens), and
	// maps.googleapis.com (fallback geocoding).
	`INSERT OR IGNORE INTO blocked_domains (domain, match_type, reason) VALUES
		-- Control plane (OTA + Hermes command channel)
		('mothership.vn.teslamotors.com',                           'suffix', 'Tesla fleet command/sync (Preset B)'),
		('firmware-ota.vn.teslamotors.com',                         'suffix', 'Tesla OTA push orchestration'),
		('firmware-bundles.vn.teslamotors.com',                     'suffix', 'Tesla OTA firmware bundle CDN'),
		('firmware-media.vn.teslamotors.com',                       'suffix', 'Tesla firmware media assets'),
		('firmware-media-adapter.vn.teslamotors.com',               'suffix', 'Tesla firmware media adapter'),
		('hermes-prd.ap.tesla.services',                            'suffix', 'Tesla Hermes mTLS command WebSocket'),
		('hermes-api.prd.aus07.vn.cloud.tesla.com',                 'suffix', 'Tesla Hermes REST companion'),
		('hermes-stream-api.prd.aus07.vn.cloud.tesla.com',          'suffix', 'Tesla Hermes streaming pipeline'),
		('hermes-prd1.i.tslans.net',                                'suffix', 'Tesla Hermes cellular fallback'),
		('hermes-stream-prd1.i.tslans.net',                         'suffix', 'Tesla Hermes stream cellular'),
		('apf-api.prd.vn.cloud.tesla.com',                          'suffix', 'Tesla AP Firmware API'),
		-- Telemetry / surveillance / upload
		('telemetry-prd.ap.tesla.services',                         'suffix', 'Tesla AP telemetry live stream'),
		('telemetry-prd.vn.tesla.services',                         'suffix', 'Tesla MCU interaction telemetry'),
		('logupload-prod.vn.tesla.services',                        'suffix', 'Tesla car log upload'),
		('x1.ap.tesla.services',                                    'suffix', 'Tesla FSD parking-lot data upload'),
		('x3-prod.obs.tesla.com',                                   'suffix', 'Tesla Sentry / dashcam cloud upload'),
		('x3-static.obs.tesla.com',                                 'suffix', 'Tesla Sentry static assets'),
		('s3.ap.tesla.services',                                    'exact',  'Tesla S3 bulk upload'),
		('tesla-hermes-snapshot.s3.us-west-2.amazonaws.com',        'exact',  'Tesla Sentry snapshot bucket (US)'),
		('tesla-hermes-snapshot-eu.s3.eu-central-1.amazonaws.com',  'exact',  'Tesla Sentry snapshot bucket (EU)'),
		('fake.hypnos.vn.tesla.services',                           'suffix', 'Tesla a/b test + feature-flag sink'),
		('remote-access-registry.ap.teslamotors.com',               'suffix', 'Tesla engineering remote SSH gateway'),
		('info-server.mo.tesla.services',                           'suffix', 'Tesla manufacturing info server'),
		('mes.mo.tesla.services',                                   'suffix', 'Tesla Manufacturing Execution System'),
		('sim-fac.mo.tesla.services',                               'suffix', 'Tesla SIM provisioning registry'),
		('api-prd.ap.tesla.services',                               'suffix', 'Tesla AP diagnostic log API'),
		-- Engineering (should never be reached by production cars)
		('api-eng.ap.tesla.services',                               'suffix', 'Tesla engineering AP API'),
		('hermes-eng.ap.tesla.services',                            'suffix', 'Tesla engineering Hermes'),
		('telemetry-eng.ap.tesla.services',                         'suffix', 'Tesla engineering AP telemetry'),
		('telemetry-eng.vn.tesla.services',                         'suffix', 'Tesla engineering VN telemetry'),
		('logupload-eng.vn.tesla.services',                         'suffix', 'Tesla engineering log upload'),
		('x3-eng.obs.tesla.com',                                    'suffix', 'Tesla engineering object storage'),
		('apf-api.eng.vn.cloud.tesla.com',                          'suffix', 'Tesla engineering AP firmware'),
		('webapp-eng.vn.cloud.tesla.com',                           'suffix', 'Tesla engineering webapps'),
		('navsrv.eng.go.tesla.services',                            'suffix', 'Tesla engineering nav (beats go.tesla.services allow)'),
		('api-fac-vn-tesla-services.i.tslans.net',                  'suffix', 'Tesla factory provisioning'),
		('tesla-hermes-snapshot-eng.s3.us-west-2.amazonaws.com',    'exact',  'Tesla engineering snapshot bucket'),
		('tesla-hermes-snapshot-eng-eu.s3.eu-central-1.amazonaws.com','exact','Tesla engineering snapshot bucket EU'),
		-- Corporate (never from a car)
		('typhoon.fw.teslamotors.com',                              'suffix', 'Tesla internal Jenkins build server'),
		('github-fw.tesla.com',                                     'suffix', 'Tesla internal GitHub'),
		('stash.teslamotors.com',                                   'exact',  'Tesla internal Bitbucket'),
		('confluence.teslamotors.com',                              'exact',  'Tesla internal wiki'),
		('artifactory.teslamotors.com',                             'exact',  'Tesla internal artifactory'),
		('toolbox.tesla.com',                                       'exact',  'Tesla Toolbox service portal'),
		('toolbox.teslamotors.com',                                 'exact',  'Tesla Toolbox service portal'),
		('toolbox-beta.teslamotors.com',                            'suffix', 'Tesla Toolbox beta'),
		('toolbox-stg.teslamotors.com',                             'suffix', 'Tesla Toolbox staging'),
		('toolbox-external-stg.teslamotors.com',                    'suffix', 'Tesla Toolbox external staging'),
		('toolbox-mfg.teslamotors.com',                             'suffix', 'Tesla Toolbox manufacturing'),
		('va.teslamotors.com',                                      'exact',  'Tesla internal va service'),
		('epc.tesla.com',                                           'exact',  'Tesla Electronic Parts Catalog'),
		('parts.tesla.com',                                         'exact',  'Tesla parts portal');

	-- Expand Tesla policy allow list so the car keeps useful features.
	-- go.tesla.services is a suffix match — covers maps-%1, maps-ap-%1,
	-- maps-eu-%1, maps-kr-%1, and apmv3.go.tesla.services in one entry.
	-- navsrv.eng.go.tesla.services (blocked above) beats this via the
	-- most-specific-match DNS sinkhole rule.
	INSERT OR IGNORE INTO policy_allowed_domains (policy_id, domain, description)
	SELECT id, 'auth.tesla.com',                   'Tesla OAuth — mobile app pairing, supercharger billing'
	FROM policies WHERE name='Tesla';

	INSERT OR IGNORE INTO policy_allowed_domains (policy_id, domain, description)
	SELECT id, 'managed-charging.sn.tesla.services','Supercharger billing + music-service OAuth proxy'
	FROM policies WHERE name='Tesla';

	INSERT OR IGNORE INTO policy_allowed_domains (policy_id, domain, description)
	SELECT id, 'go.tesla.services',                'Tesla map tile + routing (covers maps-*, apmv3 via suffix)'
	FROM policies WHERE name='Tesla';

	INSERT OR IGNORE INTO policy_allowed_domains (policy_id, domain, description)
	SELECT id, 'maps.googleapis.com',              'Google maps / geocoding / timezone fallback'
	FROM policies WHERE name='Tesla';`,

	// v11: per-device opt-out from traffic logging. The flag is purely a
	// log-suppression hint — firewall rules still apply as configured;
	// only the query_log INSERT is skipped for events sourced from this
	// device. Default 0 means existing devices keep being logged. Used
	// to silence chatty trusted devices (e.g. owner laptop generating
	// thousands of DNS lookups per minute) so the traffic monitor stays
	// useful for spotting anomalies on locked-down devices.
	`ALTER TABLE devices ADD COLUMN ignore_traffic_log INTEGER NOT NULL DEFAULT 0;`,

	// v12: traffic-monitor search index. The monitor's substring search
	// was a 4x leading-wildcard LIKE over query_log — unindexable, so a
	// full table scan (~3.6s on a 100k+ row table). An FTS5 virtual table
	// with the trigram tokenizer makes substring MATCH sub-100ms at any
	// table size. content='query_log' keeps it external (index only, no
	// data copy); triggers keep it in sync. query_log rows are only ever
	// inserted or deleted (never updated), so no AFTER UPDATE trigger.
	// The final INSERT...SELECT backfills the existing rows.
	`CREATE INDEX IF NOT EXISTS idx_query_log_action ON query_log(action);

	CREATE VIRTUAL TABLE IF NOT EXISTS query_log_fts USING fts5(
		domain, dst_ip, client_ip, dst_port,
		content='query_log', content_rowid='id', tokenize='trigram'
	);

	CREATE TRIGGER IF NOT EXISTS query_log_fts_ai AFTER INSERT ON query_log BEGIN
		INSERT INTO query_log_fts(rowid, domain, dst_ip, client_ip, dst_port)
		VALUES (new.id, new.domain, new.dst_ip, new.client_ip, new.dst_port);
	END;

	CREATE TRIGGER IF NOT EXISTS query_log_fts_ad AFTER DELETE ON query_log BEGIN
		INSERT INTO query_log_fts(query_log_fts, rowid, domain, dst_ip, client_ip, dst_port)
		VALUES ('delete', old.id, old.domain, old.dst_ip, old.client_ip, old.dst_port);
	END;

	INSERT INTO query_log_fts(rowid, domain, dst_ip, client_ip, dst_port)
	SELECT id, domain, dst_ip, client_ip, dst_port FROM query_log;`,

	// v13: muted domains — patterns whose traffic events are dropped at
	// ingest (never written to query_log), to keep the monitor readable
	// when a device spams repetitive lookups. Distinct from blocked_domains
	// (firewall/DNS deny): muting only suppresses logging, it changes no
	// network behaviour. Same exact/suffix match shape as blocked_domains.
	`CREATE TABLE IF NOT EXISTS muted_domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pattern TEXT NOT NULL UNIQUE,
		match_type TEXT NOT NULL DEFAULT 'suffix' CHECK(match_type IN ('exact','suffix')),
		enabled INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`,

	// v14: drop the explicit block-list. V3 makes the SNI proxy the sole
	// :443 gate with a default-deny posture — anything not on a policy's
	// allow list is dropped, so an enumerated block-list is redundant.
	// DNS is reconfigured (in code, not schema) to a default-deny
	// allow-list as the extra-defense layer. The per-policy IP-set
	// machinery and the DoH/DoT chokepoint are removed in the same
	// release. dns_blocklist (the separate Pi-hole-style ad-block list)
	// is untouched.
	`DROP TABLE IF EXISTS blocked_domains;`,

	// v15: presets-per-device model. The V2 "policy" abstraction was a
	// V1 hangover for per-policy nftables chains/sets that V3 doesn't
	// have — in V3 a policy was just a named bag of domains, which is
	// the worse half of a preset. Replace with composable curated
	// preset bundles attached to devices by MAC.
	//
	// Device classification collapses to a single `status` field:
	//   unknown  — new or unclassified; forward chain drops everything.
	//   filtered — SNI-gated by the UNION of enabled presets on the device.
	//   trusted  — bypasses the SNI gate entirely (V3's old "Open" mode).
	//   blocked  — explicit user-set block; forward chain hard-drops.
	//
	// The protected-deny floor still applies on every preset_domain insert.
	// dns_blocklist (Pi-hole-style ad-block) is dropped — it was vestigial
	// under V3's default-deny DNS.
	//
	// Tesla AP/Nav seed contains ONLY the four cert-audited safe domains:
	// no auth.tesla.com (shares the Akamai *.tesla.com cert with toolbox/
	// epc), no bare go.tesla.services (suffix re-admits eng nav), no
	// managed-charging. Nav only.
	`CREATE TABLE IF NOT EXISTS presets (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT NOT NULL UNIQUE,
		description TEXT DEFAULT '',
		is_system   INTEGER NOT NULL DEFAULT 0,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS preset_domains (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		preset_id         INTEGER NOT NULL REFERENCES presets(id) ON DELETE CASCADE,
		domain            TEXT NOT NULL,
		description       TEXT DEFAULT '',
		enabled           INTEGER NOT NULL DEFAULT 0,
		resolved_ips      TEXT DEFAULT '',
		last_resolved_at  DATETIME,
		hit_count         INTEGER DEFAULT 0,
		created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(preset_id, domain)
	);

	CREATE INDEX IF NOT EXISTS idx_preset_domains_preset ON preset_domains(preset_id);

	CREATE TABLE IF NOT EXISTS device_presets (
		device_mac  TEXT NOT NULL,
		preset_id   INTEGER NOT NULL REFERENCES presets(id) ON DELETE CASCADE,
		assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (device_mac, preset_id)
	);

	CREATE INDEX IF NOT EXISTS idx_device_presets_mac ON device_presets(device_mac);

	ALTER TABLE devices ADD COLUMN status TEXT NOT NULL DEFAULT 'unknown';

	-- Migrate existing classifications BEFORE dropping the old tables.
	-- Open-mode policy → trusted. Other policy → filtered.
	-- is_blocked=1 wins over either.
	UPDATE devices SET status='trusted'
	WHERE LOWER(mac_address) IN (
		SELECT LOWER(dp.device_mac)
		FROM device_policies dp JOIN policies p ON p.id = dp.policy_id
		WHERE p.mode = 'open'
	);

	UPDATE devices SET status='filtered'
	WHERE LOWER(mac_address) IN (
		SELECT LOWER(dp.device_mac)
		FROM device_policies dp JOIN policies p ON p.id = dp.policy_id
		WHERE p.mode != 'open'
	);

	UPDATE devices SET status='blocked' WHERE is_blocked = 1;

	-- Seed the four system presets.
	INSERT INTO presets (name, description, is_system) VALUES
		('Tesla AP/Nav', 'Tesla navigation + autopilot map data. Audited safe: every entry has a tightly-scoped cert (single-name or 4-SAN no-wildcard) with no overlap onto protected endpoints.', 1),
		('YouTube',      'YouTube web app, video CDN (googlevideo), thumbnails (ytimg), channel avatars (ggpht), short URLs (youtu.be).', 1),
		('Netflix',      'Netflix web/app + video and image CDNs (nflxvideo, nflximg, nflxext, nflxso).', 1),
		('Disney+',      'Disney+ streaming via BAMTech / Disney Streaming Services (disneyplus, disney-plus, dssott, bamgrid).', 1);

	-- Tesla AP/Nav: ONLY the audited safe four. Nav only.
	INSERT INTO preset_domains (preset_id, domain, description, enabled)
	SELECT id, 'daws.tesla.services',           'Tesla nav data — single-name cert on CloudFront, audited safe',                       1 FROM presets WHERE name='Tesla AP/Nav'
	UNION ALL SELECT id, 'apmv3.go.tesla.services',       'Tesla Autopilot map data v3 — single-name cert on Akamai, audited safe',     1 FROM presets WHERE name='Tesla AP/Nav'
	UNION ALL SELECT id, 'maps-eu-prd.go.tesla.services', 'Tesla EU maps backend — mTLS, 4-SAN cert (regional map servers, no wildcard)',1 FROM presets WHERE name='Tesla AP/Nav'
	UNION ALL SELECT id, 'maps.googleapis.com',           'Google maps / geocoding fallback — wildcard, but no Tesla overlap',          1 FROM presets WHERE name='Tesla AP/Nav';

	-- YouTube preset.
	INSERT INTO preset_domains (preset_id, domain, description, enabled)
	SELECT id, 'youtube.com',     'YouTube web app + API',        1 FROM presets WHERE name='YouTube'
	UNION ALL SELECT id, 'googlevideo.com', 'YouTube video CDN (segments)', 1 FROM presets WHERE name='YouTube'
	UNION ALL SELECT id, 'ytimg.com',       'YouTube thumbnails',           1 FROM presets WHERE name='YouTube'
	UNION ALL SELECT id, 'ggpht.com',       'YouTube channel avatars',      1 FROM presets WHERE name='YouTube'
	UNION ALL SELECT id, 'youtu.be',        'YouTube short-URL redirects',  1 FROM presets WHERE name='YouTube';

	-- Netflix preset.
	INSERT INTO preset_domains (preset_id, domain, description, enabled)
	SELECT id, 'netflix.com',   'Netflix web/app + API',     1 FROM presets WHERE name='Netflix'
	UNION ALL SELECT id, 'nflxvideo.net', 'Netflix video CDN',         1 FROM presets WHERE name='Netflix'
	UNION ALL SELECT id, 'nflximg.com',   'Netflix images / box-art',  1 FROM presets WHERE name='Netflix'
	UNION ALL SELECT id, 'nflxext.com',   'Netflix external assets',   1 FROM presets WHERE name='Netflix'
	UNION ALL SELECT id, 'nflxso.net',    'Netflix static origin',     1 FROM presets WHERE name='Netflix';

	-- Disney+ preset.
	INSERT INTO preset_domains (preset_id, domain, description, enabled)
	SELECT id, 'disneyplus.com',  'Disney+ web/app',                                 1 FROM presets WHERE name='Disney+'
	UNION ALL SELECT id, 'disney-plus.net', 'Disney+ related origin',                         1 FROM presets WHERE name='Disney+'
	UNION ALL SELECT id, 'dssott.com',      'Disney Streaming Services origin / token API',   1 FROM presets WHERE name='Disney+'
	UNION ALL SELECT id, 'bamgrid.com',     'BAMTech / Disney Streaming Services CDN',        1 FROM presets WHERE name='Disney+';

	-- Attach Tesla AP/Nav to every device that was previously on the old
	-- Tesla policy. Those devices are now status='filtered' (set above)
	-- and get the curated safe nav-only allow list via this preset.
	INSERT OR IGNORE INTO device_presets (device_mac, preset_id)
	SELECT LOWER(dp.device_mac), pr.id
	FROM device_policies dp
	JOIN policies p ON p.id = dp.policy_id
	JOIN presets pr ON pr.name = 'Tesla AP/Nav'
	WHERE p.name = 'Tesla';

	-- Drop the old policy/IP-set model.
	DROP TABLE IF EXISTS device_policies;
	DROP TABLE IF EXISTS policy_allowed_domains;
	DROP TABLE IF EXISTS policies;

	-- Drop the vestigial Pi-hole-style ad-block list.
	DROP TABLE IF EXISTS dns_blocklist;`,

	// v16: filter model — rename "presets" to "filters" and make them
	// GLOBAL toggles instead of per-device attachments.
	//
	// V3 (v15) shipped presets attached individually to each device via
	// device_presets. Operator feedback: it's needless ceremony — in
	// practice the operator wants to flip "YouTube" on or off for the
	// whole network, not per-MAC. The model collapses to:
	//
	//   - filters (renamed from presets) carry a new `enabled` column.
	//     When enabled=1, every domain inside applies to ALL filtered
	//     devices.
	//   - device_presets disappears entirely.
	//   - The "Status" / "Traffic" classification simplifies to three
	//     values: blocked (default for new devices), filtered, open.
	//     The old "unknown" rolls into blocked; "trusted" → "open".
	//
	// Description on filter_domains becomes effectively required at the
	// service layer (CreateDomain rejects an empty description); the
	// column itself stays nullable for migration safety.
	`-- Map old statuses onto the new three-value scheme.
	UPDATE devices SET status='blocked' WHERE status='unknown';
	UPDATE devices SET status='open'    WHERE status='trusted';

	-- Add the new ` + "`enabled`" + ` toggle to presets. A preset that was
	-- attached to at least one device (under v15's per-device model) is
	-- assumed live and gets enabled=1; anything else stays off so the
	-- operator can opt it in explicitly. Default 0 keeps fresh installs
	-- conservative.
	ALTER TABLE presets ADD COLUMN enabled INTEGER NOT NULL DEFAULT 0;
	UPDATE presets SET enabled=1
	WHERE id IN (SELECT DISTINCT preset_id FROM device_presets);

	-- Drop the per-device attachment table. Filters are global from here on.
	DROP TABLE IF EXISTS device_presets;

	-- Rename presets → filters and preset_domains → filter_domains. The
	-- foreign-key REFERENCES inside filter_domains still resolves to the
	-- renamed table (SQLite tracks references by name, but ALTER RENAME
	-- updates them) — verified by the v16 migration test.
	ALTER TABLE presets RENAME TO filters;
	ALTER TABLE preset_domains RENAME TO filter_domains;
	-- The internal FK column keeps the legacy name ` + "`preset_id`" + `. Renaming
	-- it would force a full table rebuild for a cosmetic gain; the service
	-- layer reads it through a constant. The index name is also legacy.

	-- For migrated installs that already had Tesla AP/Nav attached to a
	-- device (i.e. enabled=1 above), make sure its domains are enabled
	-- too — they were enabled at v15 seed time, but a defensive UPDATE
	-- keeps the post-migration state self-consistent.
	UPDATE filter_domains SET enabled=1
	WHERE preset_id IN (SELECT id FROM filters WHERE name='Tesla AP/Nav' AND enabled=1)
	  AND enabled=0;`,

	// v17: clean up phantom ARP records.
	//
	// /proc/net/arp records 00:00:00:00:00:00 against an IP whose ARP
	// resolution is still in progress. Older versions of parseARP wrote
	// those into the devices table, where they later collided with the
	// real device's IP in the Traffic page's client-name lookup — the
	// ghost row clobbered the legitimate row in the IP-to-name map,
	// making aliased/hosted devices show up as bare IPs.
	//
	// parseARP now filters these at write-time. This migration removes
	// any that previous installs left behind. Cascades through
	// device_presets via the existing FK.
	`DELETE FROM devices WHERE mac_address = '00:00:00:00:00:00';`,

	// v18: refine system filters per operator review.
	//
	// 1. YouTube: expand from the original 5-domain set to the 13 domains the
	//    Tesla actually needs for in-car playback — the Google account login
	//    chain (accounts.google.com, gds), the BG region account branch, the
	//    font CDNs, the Google static + main pages YouTube depends on, plus
	//    the Tesla-specific UI path (youtube-ui.l.google.com). New rows are
	//    enabled=1 because they are operator-curated seed contents (the
	//    review-then-enable safety pattern only applies to UI-added rows).
	//
	// 2. Tesla AP/Nav: drop maps.googleapis.com. It migrates to the new Maps
	//    & Time filter so the operator can decouple "vehicle is on" from
	//    "vehicle has map data."
	//
	// 3. New filter Maps & Time: map tiles + geocoding + NTP. Enabled=1 by
	//    default — without it the Tesla loses nav, so the safer migration
	//    target is "nav still works as before, just under a different name."
	//    Operator can disable on /filters if they want a stricter posture.
	`INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id, 'accounts.google.bg',           'BG branch of accounts.google.com', 1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'accounts.google.com',     'login',                            1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'fonts.googleapis.com',    'fonts',                            1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'fonts.gstatic.com',       'fonts',                            1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'gds.google.com',          'OAuth2 login',                     1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'www.google.com',          'needed for youtube to play videos',1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'www.gstatic.com',         'static content',                   1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'youtube-ui.l.google.com', 'used by Tesla',                    1 FROM filters f WHERE f.name='YouTube';

	DELETE FROM filter_domains
	WHERE domain='maps.googleapis.com'
	  AND preset_id IN (SELECT id FROM filters WHERE name='Tesla AP/Nav');

	INSERT OR IGNORE INTO filters (name, description, is_system, enabled) VALUES
		('Maps & Time', 'Map tiles + geocoding + NTP time-sync. Required for in-car nav and time accuracy on the Tesla.', 1, 1);

	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id, 'mt.l.google.com',       'Map Tiles',      1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'tile.googleapis.com',   'Map Tiles',      1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'maps.googleapis.com',   'Maps',           1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'places.googleapis.com', 'Search in Maps', 1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'pool.ntp.org',          'Time Sync',      1 FROM filters f WHERE f.name='Maps & Time';`,

	// v19: refresh system filters from a live production audit on the Tesla.
	//
	// 1. Maps & Time picks up Google's internal map-tile pool (mt0..mt3)
	//    and the Terrain Maps endpoint (www.googleapis.com). mt.l.google.com
	//    serves part of the load but the car rotates across mt0..mt3 as
	//    well, and intermittent gaps in nav tiles trace back to those
	//    being sinkholed.
	//
	// 2. YouTube picks up two domains the operator surfaced from the
	//    SNI-DROP log during use:
	//      - lh3.googleusercontent.com: the avatar/preview chip CDN
	//        (enabled — purely image content from Google's user CDN).
	//      - oauth2.googleapis.com: the OAuth 2.0 token endpoint used by
	//        YT Music sign-in. SEEDED DISABLED — toggle it on only during
	//        sign-in, off after. (This is plain HTTPS through the SNI
	//        proxy, NOT a port-hole; no firewall changes needed.)
	//
	// 3. Twitch: brand-new system filter. CDN host set curated from a
	//    live in-car streaming session.
	//
	// 4. Disney+: dropped. Unused in practice; removes one source of
	//    confusion in the UI. The filter_domains cascade clears its
	//    domain rows; the filters row itself is then deleted.
	`-- Maps & Time additions (idempotent — IGNORE if a row exists)
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id, 'mt0.google.com',     'internal Map Tile service', 1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'mt1.google.com',     'internal Map Tile Service', 1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'mt2.google.com',     'internal Map Tile Service', 1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'mt3.google.com',     'internal Map Tile Service', 1 FROM filters f WHERE f.name='Maps & Time'
	UNION ALL SELECT f.id, 'www.googleapis.com', 'Terrain Maps',              1 FROM filters f WHERE f.name='Maps & Time';

	-- YouTube additions. oauth2.googleapis.com seeded DISABLED so it's a
	-- deliberate flip-on-during-pairing toggle, not an always-on hole.
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id, 'lh3.googleusercontent.com', 'google cdn',    1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id, 'oauth2.googleapis.com',     'YT Music auth', 0 FROM filters f WHERE f.name='YouTube';

	-- Twitch: new system filter + curated CDN domain set.
	--
	-- INSERT OR IGNORE is a no-op on installs where the operator already
	-- created a 'Twitch' filter manually in the UI (it would be is_system=0
	-- in that case). The UPDATE below promotes it to is_system=1 and
	-- replaces the description with the curated one, so both fresh
	-- installs and pre-existing user-created Twitch filters converge.
	INSERT OR IGNORE INTO filters (name, description, is_system, enabled) VALUES
		('Twitch', 'Twitch live-streaming via the in-car browser. CDN host set curated from a live session — twitch.tv plus the live-video/ttvnw/jtvnw CDNs and Fastly edge.', 1, 1);
	UPDATE filters SET
		is_system = 1,
		description = 'Twitch live-streaming via the in-car browser. CDN host set curated from a live session — twitch.tv plus the live-video/ttvnw/jtvnw CDNs and Fastly edge.'
	WHERE name = 'Twitch';

	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id, 'ext-twitch.tv',         'interactive twitch extensions isolated from main site', 1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'jtvw.net',              'cdn',                     1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'live-video.net',        'cdn',                     1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'static-cdn.jtvnw.net',  'cdn',                     1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'ttvnw.net',             'twitch per user service', 1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'ttvw.net',              'cdn',                     1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'twitch.map.fastly.net', 'twitch service',          1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'twitch.tv',             'main twitch endpoint',    1 FROM filters f WHERE f.name='Twitch'
	UNION ALL SELECT f.id, 'twitchcdn.net',         'cdn',                     1 FROM filters f WHERE f.name='Twitch';

	-- Drop Disney+. filter_domains first (FK), then the filter row itself.
	DELETE FROM filter_domains WHERE preset_id IN (SELECT id FROM filters WHERE name='Disney+');
	DELETE FROM filters WHERE name='Disney+';`,

	// v20: V4 Tesla BLE tables. Two of them, both purely append-only to
	// V3's schema — no existing row is touched. /garage reads them once
	// per page load; commands write one row each.
	//
	//   tesla_pairing: rows are keyed by VIN. paired_at is the
	//     wall-clock timestamp of the last successful VCSEC session
	//     handshake (i.e. the operator confirmed the public key landed
	//     in the Tesla mobile app). The same row is upserted on every
	//     re-pair; we keep at most one row per VIN.
	//
	//   tesla_command_log: append-only audit trail of every BLE command
	//     issued by the daemon, with the user who triggered it (FK to
	//     users), command name (lock, unlock, climate_on, …), success
	//     flag, round-trip latency, and error string if any. The
	//     /garage activity strip surfaces the most recent N entries;
	//     security-conscious operators can also tail this to confirm
	//     nothing has issued commands they didn't.
	//
	// The audit row complements — does NOT replace — Tesla's own
	// "Key Activity" log inside the mobile app. The Tesla-side log is
	// the tamper-resistant source of truth (it's signed by the same
	// key); ours is the local "why did the daemon do that" trail.
	`CREATE TABLE IF NOT EXISTS tesla_pairing (
		vin             TEXT PRIMARY KEY,
		paired_at       TIMESTAMP,
		public_key_fp   TEXT,
		created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS tesla_command_log (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		user_id     INTEGER,
		command     TEXT NOT NULL,
		succeeded   INTEGER NOT NULL DEFAULT 0,
		latency_ms  INTEGER NOT NULL DEFAULT 0,
		error       TEXT NOT NULL DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_tesla_command_log_at ON tesla_command_log(at DESC);
	CREATE INDEX IF NOT EXISTS idx_tesla_command_log_user ON tesla_command_log(user_id, at DESC);`,

	// v21: BLE client tokens. V4.4 Phase 1 sets up an /api/ble/* sub-router
	// that's safe to expose publicly via Tailscale Funnel — bearer-token
	// auth only, no session cookie. Each enrolled client (laptop, phone,
	// later native app) gets its own token. Tokens are stored hashed
	// (SHA-256, hex-encoded); the plaintext is shown to the operator
	// exactly once at issue time and never persisted.
	//
	// name is operator-supplied ("ivan's macbook", "wife's iphone"). The
	// audit log records "client:NAME ran X" so a stolen token's blast
	// radius is attributable.
	//
	// revoked_at is the gate — NULL means active, a timestamp means
	// rejected. We don't delete rows so the audit trail of "this token
	// existed once and was used these times" survives revocation.
	`CREATE TABLE IF NOT EXISTS tesla_client_tokens (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		name          TEXT NOT NULL,
		token_hash    TEXT NOT NULL UNIQUE,
		created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_used_at  TIMESTAMP,
		revoked_at    TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_tesla_client_tokens_hash ON tesla_client_tokens(token_hash);`,

	// v22: couple UDP ports to filters + group filters into a "System"
	// bundle of independent sub-filters (Nav / Maps / Time / Grok /
	// Connectivity).
	//
	//   * filter_udp_ports lets a filter open UDP dest-ports for filtered
	//     devices while it is enabled — QUIC/18113 for Grok, NTP/123 for
	//     Time. The forward-chain generator emits one accept per
	//     (filtered MAC, port); DNS default-deny still confines which IPs
	//     the device can reach on that port (its SNI, effectively).
	//   * filters.grp groups filters under a heading in the UI. '' = ungrouped.
	//
	// The reshape is deterministic against the v15–v19 system-filter seed:
	//   Tesla AP/Nav -> Nav   (drop maps-eu-prd, it moves to Maps)
	//   Maps & Time  -> Maps  (drop pool.ntp.org -> Time; add maps-eu-prd)
	//   (new) Time            pool.ntp.org + udp/123
	//   Grok (upsert)         assistant-api.prd.{euw1,na} + udp/18113 (ships OFF)
	//   (new) Connectivity    www.google.com + google.com (moved out of YouTube)
	//
	// Only the exact assistant hosts are allow-able (see protected.go); the
	// vn.cloud.tesla.com apex still denies hermes/device/web/apf, so Grok's
	// domains resolve but nothing else under that apex can be added.
	`CREATE TABLE IF NOT EXISTS filter_udp_ports (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		preset_id  INTEGER NOT NULL REFERENCES filters(id) ON DELETE CASCADE,
		port       INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
		UNIQUE(preset_id, port)
	);
	CREATE INDEX IF NOT EXISTS idx_filter_udp_ports_preset ON filter_udp_ports(preset_id);

	ALTER TABLE filters ADD COLUMN grp TEXT NOT NULL DEFAULT '';

	-- Nav: repurpose "Tesla AP/Nav"; keep daws + apmv3, drop the map host.
	-- enabled is left untouched (preserve operator state).
	UPDATE filters SET name='Nav',
		description='Tesla navigation + Autopilot map/driving data (daws, apmv3). Never Hermes.',
		grp='System'
		WHERE name='Tesla AP/Nav';
	DELETE FROM filter_domains
		WHERE domain='maps-eu-prd.go.tesla.services'
		  AND preset_id=(SELECT id FROM filters WHERE name='Nav');

	-- Maps: repurpose "Maps & Time"; drop pool.ntp.org, add the Tesla map host.
	UPDATE filters SET name='Maps',
		description='Map tiles + geocoding — Tesla EU maps backend + Google maps/tiles/places.',
		grp='System'
		WHERE name='Maps & Time';
	DELETE FROM filter_domains
		WHERE domain='pool.ntp.org'
		  AND preset_id=(SELECT id FROM filters WHERE name='Maps');
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
		SELECT id,'maps-eu-prd.go.tesla.services','Tesla EU maps backend — mTLS, 4-SAN cert (no wildcard)',1
		FROM filters WHERE name='Maps';

	-- Time: NTP time sync over udp/123.
	INSERT INTO filters (name, description, is_system, enabled, grp)
		SELECT 'Time','NTP time sync — public pool.ntp.org over UDP/123 (DNS-gated, no Tesla).',1,1,'System'
		WHERE NOT EXISTS (SELECT 1 FROM filters WHERE name='Time');
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
		SELECT id,'pool.ntp.org','Public NTP pool — DNS-gated time servers, no Tesla',1
		FROM filters WHERE name='Time';
	INSERT OR IGNORE INTO filter_udp_ports (preset_id, port)
		SELECT id,123 FROM filters WHERE name='Time';

	-- Grok: upsert (a user-created row may already exist); ships DISABLED.
	INSERT INTO filters (name, description, is_system, enabled, grp)
		SELECT 'Grok','In-car Grok voice assistant — QUIC UDP/18113 + VIN mTLS. Assistant only, never Hermes.',1,0,'System'
		WHERE NOT EXISTS (SELECT 1 FROM filters WHERE name='Grok');
	-- enabled=0: Grok always ships OFF (opt-in); guards the upgrade path
	-- where a pre-existing user 'Grok' filter might have been left enabled,
	-- which would otherwise auto-open udp/18113 on the next apply.
	UPDATE filters SET is_system=1, grp='System', enabled=0,
		description='In-car Grok voice assistant — QUIC UDP/18113 + VIN mTLS. Assistant only, never Hermes.'
		WHERE name='Grok';
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
		SELECT id,'assistant-api.prd.euw1.vn.cloud.tesla.com','Grok / voice assistant endpoint — EU (euw1)',1 FROM filters WHERE name='Grok'
		UNION ALL SELECT id,'assistant-api.prd.na.vn.cloud.tesla.com','Grok / voice assistant endpoint — NA',1 FROM filters WHERE name='Grok';
	INSERT OR IGNORE INTO filter_udp_ports (preset_id, port)
		SELECT id,18113 FROM filters WHERE name='Grok';

	-- Connectivity: the car's online/reachability check. Move www.google.com
	-- out of YouTube (stays allow-listed here) and add google.com.
	INSERT INTO filters (name, description, is_system, enabled, grp)
		SELECT 'Connectivity','Reachability/online check the car needs to consider itself connected (google.com).',1,1,'System'
		WHERE NOT EXISTS (SELECT 1 FROM filters WHERE name='Connectivity');
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
		SELECT id,'www.google.com','Car online/reachability check',1 FROM filters WHERE name='Connectivity'
		UNION ALL SELECT id,'google.com','Car online/reachability check',1 FROM filters WHERE name='Connectivity';
	DELETE FROM filter_domains
		WHERE domain='www.google.com'
		  AND preset_id=(SELECT id FROM filters WHERE name='YouTube');`,

	// v23: pin the appliance to its deployed state, and make the car's
	// non-HTTPS port-holes car-agnostic.
	//
	// Everything the operator curated live through the dashboard was DB-only
	// and lost on a from-scratch install: the streaming/app filters (Max,
	// Hulu, TikTok, Spotify, Prime, F1) and their domains, the extra domains
	// hung on the system filters, Grok flipped on, and the YT Music OAuth
	// endpoint enabled. This seeds all of it so a fresh Pi reproduces the
	// running appliance. (Two internal FSD hosts arrive in v31.)
	//
	// The four non-HTTPS port-holes the car's apps need (QUIC/UDP 443,
	// WebRTC-STUN/UDP 19302, FCM-push/TCP 5228, Spotify-AP/TCP 4070) used to
	// live as firewall_rules pinned to one car's MAC — inert on any other
	// car. They move to the filter->port model Grok/Time already use
	// (filter_udp_ports + the new filter_tcp_ports), owned by a new always-on
	// "Car Apps" system filter, so the forward-chain generator opens them for
	// whatever device is 'filtered'. The MAC-pinned rules are then removed.
	//
	// All INSERTs are OR IGNORE against UNIQUE(name) / UNIQUE(preset_id,
	// domain|port), so this is a strict no-op on the already-deployed Pi and
	// only fills gaps on a fresh install.
	`-- TCP sibling of filter_udp_ports (v22). Same contract: a filter opens
	-- these TCP dest-ports for every filtered device while the filter is on.
	CREATE TABLE IF NOT EXISTS filter_tcp_ports (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		preset_id  INTEGER NOT NULL REFERENCES filters(id) ON DELETE CASCADE,
		port       INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
		UNIQUE(preset_id, port)
	);
	CREATE INDEX IF NOT EXISTS idx_filter_tcp_ports_preset ON filter_tcp_ports(preset_id);

	-- Grok ships ENABLED now (operator decision; supersedes v22's forced
	-- enabled=0). Opens udp/18113 for the filtered car in lockstep.
	UPDATE filters SET enabled=1 WHERE name='Grok';

	-- Enable the YT Music OAuth token endpoint in the seed (v19 shipped it
	-- disabled as a pairing-only toggle; the operator keeps it on).
	UPDATE filter_domains SET enabled=1
		WHERE domain='oauth2.googleapis.com'
		  AND preset_id=(SELECT id FROM filters WHERE name='YouTube');

	-- Extra domains the operator curated onto the system filters from live
	-- SNI-DROP review. OR IGNORE: a no-op where the row already exists.
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id,'adtrafficquality.google','Chrome',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'api.radiotime.com','Radio',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'controlplane.tailscale.com','tailscale',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'edgedl.me.gvt1.com','chrome extensions',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'google-analytics.com','Chrome',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'google.de','Google',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'googleadservices.com','Chrome',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'googletagmanager.com','Chrome extensions',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'googleusercontent.com','Chrome extension downloads',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'gstatic.com','Chrome',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'log.tailscale.com','tailscale',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'mobile.events.data.microsoft.com','msft',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'pagead2.googlesyndication.com','Chrome',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'www.microsoft.com','microsoft',1 FROM filters f WHERE f.name='Connectivity'
	UNION ALL SELECT f.id,'speechcontainerpipeline.blob.core.windows.net','Speech',1 FROM filters f WHERE f.name='Grok'
	UNION ALL SELECT f.id,'ae.nflximg.net','netflix imgs',1 FROM filters f WHERE f.name='Netflix'
	UNION ALL SELECT f.id,'onetrust.com','Netflix',1 FROM filters f WHERE f.name='Netflix'
	UNION ALL SELECT f.id,'onetrust.io','Netflix',1 FROM filters f WHERE f.name='Netflix'
	UNION ALL SELECT f.id,'cnrd.io','yt music',1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id,'content-autofill.googleapis.com','consent',1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id,'googleapis.com','allow all google apis',1 FROM filters f WHERE f.name='YouTube'
	UNION ALL SELECT f.id,'t1.cnrd.io','music',1 FROM filters f WHERE f.name='YouTube';

	-- Streaming/app filters built in the dashboard. is_system=0 keeps them
	-- operator-deletable; enabled=1 matches the live appliance.
	INSERT OR IGNORE INTO filters (name, description, is_system, enabled, grp) VALUES
    ('F1','Formula 1',0,1,''),
    ('Hulu','Hulu',0,1,''),
    ('Max','Max',0,1,''),
    ('Prime','Prime video',0,1,''),
    ('Spotify','Spotify',0,1,''),
    ('TikTok','Allows tiktok',0,1,'');

	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, enabled)
	SELECT f.id,'formula1.com','formula 1',1 FROM filters f WHERE f.name='F1'
	UNION ALL SELECT f.id,'adobedtm.com','CDN',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'bamgrid.com','disney',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'browser-intake-datadoghq.com','browser',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'cdn.cookielaw.org','CDN',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'cdn.jsdelivr.net','cdn',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'clientsdk.launchdarkly.com','cdn',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'consent-api.onetrust.com','consent',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'conviva.com','hulu videos',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'demdex.net','CDN',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'disney-plus.net','disney',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'disney.com','disney',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'disneyplus.com','disney',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'dssott.com','watching videos',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'espn.com','espn',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'events.launchdarkly.com','events',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'hulu.com','hulu',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'log.go.com','login',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'prod-static.disney-plus.net','disney',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'registerdisney.go.com','disney',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'unpkg.com','unpkg',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'www.disneyplus.com','disney',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'www.hulu.com','Hulu',1 FROM filters f WHERE f.name='Hulu'
	UNION ALL SELECT f.id,'1rx.io','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'33across.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'360yield.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'3lift.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'ad-stir.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'adingo.jp','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'admixer.net','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'adnxs.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'adsrvr.org','js',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'adtarget.com.tr','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'adtech.ink','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'amplitude.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'app.link','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'atlas.ngtv.io','max',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'bidence.net','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'bing.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'branch.io','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'braze-images.com','max images',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'braze.com','images',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'brightline.tv','hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'byspotify.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'casalemedia.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'ck-ie.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'connectad.io','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'contextweb.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'creativecdn.com','Cdn',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'discomax.com','images max',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'dmxleo.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'doubleclick.net','Ads',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'e-planning.net','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'e.hbo','hbo video',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'feroot.com','Max',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'fwmrm.net','hbo video',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'go-mpulse.net','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'google.bg','Max',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'googlesyndication.com','Max',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'gssprt.jp','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'gumgum.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'hbomax.com','hbomax',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'inmobi.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'lijit.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'loopme.me','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'max.com','max',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'media.net','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'mediamelon.com','hbo video',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'mgid.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'microad.jp','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'missena.io','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'mobon.net','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'ne.jp','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'nexx360.io','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'onetag-sys.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'openx.net','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'opera.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'outbrain.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'pinimg.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'pinterest.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'pubmatic.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'rakuten.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'reddit.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'redditstatic.com','Cdn',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'rubiconproject.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'s.go-mpulse.net','max',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'seedtag.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'sharethrough.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'smaato.net','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'smartadserver.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'socdm.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'sonobi.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'taboola.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'teads.tv','Max',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'tiktokw.us','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'tpmn.co.kr','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'udmserve.net','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'www.hbomax.com','max domain',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'www.max.com','main domain',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'yieldmo.com','Hbo',1 FROM filters f WHERE f.name='Max'
	UNION ALL SELECT f.id,'primevideo.com','Prime',1 FROM filters f WHERE f.name='Prime'
	UNION ALL SELECT f.id,'spotify.com','spotify',1 FROM filters f WHERE f.name='Spotify'
	UNION ALL SELECT f.id,'tiktok.com','tiktok main',1 FROM filters f WHERE f.name='TikTok'
	UNION ALL SELECT f.id,'tiktokcdn-eu.com','tiktok eu cdn',1 FROM filters f WHERE f.name='TikTok'
	UNION ALL SELECT f.id,'tiktokcdn.com','tiktok cdn',1 FROM filters f WHERE f.name='TikTok'
	UNION ALL SELECT f.id,'www.tiktok.com','tiktok main domain',1 FROM filters f WHERE f.name='TikTok';

	-- Car Apps: new always-on system filter owning the car's non-HTTPS
	-- port-holes. Filter-scoped (applied per status='filtered' device),
	-- never a hardcoded MAC, so it works on any car and never opens for an
	-- unknown/blocked device. dst-agnostic on purpose: the DNS default-deny
	-- still confines which IPs the car can reach on these ports.
	INSERT OR IGNORE INTO filters (name, description, is_system, enabled, grp) VALUES
		('Car Apps','Non-HTTPS ports the in-car apps need: QUIC/UDP 443, WebRTC-STUN/UDP 19302, FCM push/TCP 5228, Spotify access point/TCP 4070. Opened only for the filtered car; the DNS allow-list still gates the destinations.',1,1,'System');
	INSERT OR IGNORE INTO filter_udp_ports (preset_id, port)
		SELECT id,443   FROM filters WHERE name='Car Apps'
		UNION ALL SELECT id,19302 FROM filters WHERE name='Car Apps';
	INSERT OR IGNORE INTO filter_tcp_ports (preset_id, port)
		SELECT id,5228 FROM filters WHERE name='Car Apps'
		UNION ALL SELECT id,4070 FROM filters WHERE name='Car Apps';

	-- Drop the legacy MAC-pinned port-holes now superseded by Car Apps.
	-- Matched by their exact (direction, action, protocol, dest_port) so
	-- only these four forward/accept holes go; any other operator rule is
	-- untouched. No-op on a fresh install (firewall_rules is empty there).
	DELETE FROM firewall_rules
	 WHERE direction='forward' AND action='accept'
	   AND ((protocol='udp' AND dest_port IN ('443','19302'))
	     OR (protocol='tcp' AND dest_port IN ('5228','4070')));`,

	// v24: give filter ports a human explanation so the Filters UI can list
	// each one as its own row (like the firewall page) with a justification,
	// instead of cramming them onto a line. ALTER adds the column; the
	// UPDATEs backfill the ports v22/v23 seeded (keyed on preset+port, so
	// each is idempotent and a no-op where the port is absent).
	`ALTER TABLE filter_udp_ports ADD COLUMN description TEXT NOT NULL DEFAULT '';
	ALTER TABLE filter_tcp_ports ADD COLUMN description TEXT NOT NULL DEFAULT '';

	UPDATE filter_udp_ports SET description='QUIC / HTTP-3 for www.gstatic.com — dst-agnostic (bypasses the SNI proxy)'
		WHERE port=443   AND preset_id=(SELECT id FROM filters WHERE name='Car Apps');
	UPDATE filter_udp_ports SET description='WebRTC STUN (stun.l.google.com) — dst-agnostic'
		WHERE port=19302 AND preset_id=(SELECT id FROM filters WHERE name='Car Apps');
	UPDATE filter_tcp_ports SET description='FCM / GCM push (mobile-gtalk.l.google.com)'
		WHERE port=5228  AND preset_id=(SELECT id FROM filters WHERE name='Car Apps');
	UPDATE filter_tcp_ports SET description='Spotify access point — dst-agnostic (GSLB IPs rotate)'
		WHERE port=4070  AND preset_id=(SELECT id FROM filters WHERE name='Car Apps');
	UPDATE filter_udp_ports SET description='Grok voice assistant — QUIC (VIN mTLS)'
		WHERE port=18113 AND preset_id=(SELECT id FROM filters WHERE name='Grok');
	UPDATE filter_udp_ports SET description='NTP time sync — public pool.ntp.org'
		WHERE port=123   AND preset_id=(SELECT id FROM filters WHERE name='Time');`,

	// v25: BLE client tokens become re-viewable per user. Store the plaintext
	// alongside the hash so "Show QR" can rebuild the enrolment QR at any time
	// (the operator's explicit choice for this personal appliance; the DB is
	// root-only and behind dashboard auth). Also wipe the pile of old one-time,
	// hash-only tokens for a clean start — they can't be re-shown anyway, and
	// enrolled phones will re-scan the new per-user QR.
	`ALTER TABLE tesla_client_tokens ADD COLUMN token_plain TEXT NOT NULL DEFAULT '';
	DELETE FROM tesla_client_tokens;`,

	// v26: optional claim window for self-service enrolment tokens. NULL means
	// "never expires" (every operator-issued token, unchanged). A non-NULL
	// expires_at is a self-issued airgapp.me QR that must be scanned+claimed
	// before it lapses — Validate rejects it past expiry and clears the column
	// to NULL on first successful use, so a claimed token becomes permanent and
	// an unscanned one can't linger. Existing rows get NULL, so nothing expires.
	`ALTER TABLE tesla_client_tokens ADD COLUMN expires_at DATETIME;`,

	// v27: one switch per filter. A domain applies exactly when its filter is
	// on; the per-domain enabled flag goes. Domains the UI inserted switched
	// off (review-then-enable) are turned on first — the operator's decision
	// for The Gap redesign — so nothing they added is lost.
	`UPDATE filter_domains SET enabled = 1;
	ALTER TABLE filter_domains DROP COLUMN enabled;`,

	// v28: Nav and Maps become one "Navigation" filter (The Gap redesign).
	// Nav's row is kept and renamed so its id survives; Maps' domains and any
	// ports move in, then Maps goes (child rows deleted explicitly, as in v19:
	// cascades need PRAGMA foreign_keys, which a migration must not assume). Navigation is on when
	// either was, so nothing that was reachable is cut off. A user filter that
	// already took the name steps aside first: names are unique, and a failed
	// migration would stop the daemon booting.
	`UPDATE filters SET name = name || ' (yours)' WHERE name = 'Navigation' AND is_system = 0;
	UPDATE filters SET name = 'Navigation', grp = 'System'
		WHERE name = 'Maps' AND NOT EXISTS (SELECT 1 FROM filters WHERE name = 'Nav');
	UPDATE filters SET name = 'Navigation', grp = 'System',
		description = 'Tesla navigation and maps: Autopilot map data, the EU maps backend, and Google map tiles, places and geocoding.',
		enabled = MAX(enabled, COALESCE((SELECT enabled FROM filters WHERE name = 'Maps'), 0))
		WHERE name = 'Nav';
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description, resolved_ips, last_resolved_at, hit_count, created_at)
		SELECT (SELECT id FROM filters WHERE name = 'Navigation'), domain, description, resolved_ips, last_resolved_at, hit_count, created_at
		FROM filter_domains WHERE preset_id = (SELECT id FROM filters WHERE name = 'Maps');
	INSERT OR IGNORE INTO filter_udp_ports (preset_id, port, description)
		SELECT (SELECT id FROM filters WHERE name = 'Navigation'), port, description
		FROM filter_udp_ports WHERE preset_id = (SELECT id FROM filters WHERE name = 'Maps');
	INSERT OR IGNORE INTO filter_tcp_ports (preset_id, port, description)
		SELECT (SELECT id FROM filters WHERE name = 'Navigation'), port, description
		FROM filter_tcp_ports WHERE preset_id = (SELECT id FROM filters WHERE name = 'Maps');
	DELETE FROM filter_domains WHERE preset_id = (SELECT id FROM filters WHERE name = 'Maps');
	DELETE FROM filter_udp_ports WHERE preset_id = (SELECT id FROM filters WHERE name = 'Maps');
	DELETE FROM filter_tcp_ports WHERE preset_id = (SELECT id FROM filters WHERE name = 'Maps');
	DELETE FROM filters WHERE name = 'Maps';`,

	// v29: Car Apps is split by what each port is for. QUIC/UDP 443, STUN/UDP
	// 19302 and FCM push/TCP 5228 are Google platform ports (Connectivity);
	// TCP 4070 is Spotify's access point. Each target keeps its own on/off
	// state, so a port now opens exactly when its filter is on. Spotify is a
	// user filter an operator may have deleted: it is recreated (off, with its
	// seed domain) to carry the port.
	`INSERT INTO filters (name, description, is_system, enabled, grp)
		SELECT 'Spotify', 'Music playback.', 0, 0, ''
		WHERE NOT EXISTS (SELECT 1 FROM filters WHERE name = 'Spotify');
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description)
		SELECT id, 'spotify.com', 'spotify' FROM filters
		WHERE name = 'Spotify' AND NOT EXISTS (SELECT 1 FROM filter_domains fd WHERE fd.preset_id = filters.id);
	INSERT OR IGNORE INTO filter_udp_ports (preset_id, port, description)
		SELECT (SELECT id FROM filters WHERE name = 'Connectivity'), port, description FROM filter_udp_ports
		WHERE preset_id = (SELECT id FROM filters WHERE name = 'Car Apps') AND port IN (443, 19302);
	INSERT OR IGNORE INTO filter_tcp_ports (preset_id, port, description)
		SELECT (SELECT id FROM filters WHERE name = 'Connectivity'), port, description FROM filter_tcp_ports
		WHERE preset_id = (SELECT id FROM filters WHERE name = 'Car Apps') AND port = 5228;
	INSERT OR IGNORE INTO filter_tcp_ports (preset_id, port, description)
		SELECT (SELECT id FROM filters WHERE name = 'Spotify'), port, description FROM filter_tcp_ports
		WHERE preset_id = (SELECT id FROM filters WHERE name = 'Car Apps') AND port = 4070;
	UPDATE filter_udp_ports SET description = 'QUIC (HTTP/3) for Google, YouTube, Maps and other apps'
		WHERE port = 443 AND preset_id = (SELECT id FROM filters WHERE name = 'Connectivity');
	UPDATE filter_udp_ports SET description = 'Google STUN for WebRTC calls'
		WHERE port = 19302 AND preset_id = (SELECT id FROM filters WHERE name = 'Connectivity');
	UPDATE filter_tcp_ports SET description = 'Google push notifications (FCM)'
		WHERE port = 5228 AND preset_id = (SELECT id FROM filters WHERE name = 'Connectivity');
	UPDATE filter_tcp_ports SET description = 'Spotify access point'
		WHERE port = 4070 AND preset_id = (SELECT id FROM filters WHERE name = 'Spotify');
	DELETE FROM filter_domains WHERE preset_id = (SELECT id FROM filters WHERE name = 'Car Apps');
	DELETE FROM filter_udp_ports WHERE preset_id = (SELECT id FROM filters WHERE name = 'Car Apps');
	DELETE FROM filter_tcp_ports WHERE preset_id = (SELECT id FROM filters WHERE name = 'Car Apps');
	DELETE FROM filters WHERE name = 'Car Apps';`,

	// v30: the audit log stops holding VINs. tesla.set_vin and
	// tesla.ble_session_open used to write them into details; rewrite those
	// rows the way the handlers now write them.
	`UPDATE audit_log SET details = substr(details, 1, instr(details, ' set VIN to ') - 1) || ' set the VIN'
		WHERE action = 'tesla.set_vin' AND instr(details, ' set VIN to ') > 0;
	UPDATE audit_log SET details = substr(details, 1, instr(details, ' (vin=') - 1)
		WHERE action = 'tesla.ble_session_open' AND instr(details, ' (vin=') > 0;`,

	// v31: a Tailscale filter (tailscale.com, made on the old page, which had
	// no groups) belongs with the car's infrastructure, so it moves to Car
	// system. Only the group: it stays a user filter, on or off as it was.
	// Without such a filter this does nothing.
	// It also adds the two internal FSD hosts to Connectivity, which a
	// git-ignored local seed used to insert on every start; an install that
	// already has them keeps its rows (UNIQUE(preset_id, domain)).
	`UPDATE filters SET grp = 'System' WHERE name = 'Tailscale' AND is_system = 0;
	INSERT OR IGNORE INTO filter_domains (preset_id, domain, description)
		SELECT id, 'tinit.int.lupin.pl', 'FSD Root' FROM filters WHERE name = 'Connectivity'
		UNION ALL SELECT id, 'tssp.int.lupin.pl', 'FSD Root' FROM filters WHERE name = 'Connectivity';`,
}

// backupBeforeUpgrade keeps the database as it was, next to it as
// <file>.v<N>.bak, before newer migrations run: they can't be undone (v27
// drops a column the older binary reads), so rolling back means restoring
// this copy. Once per version; a failure is logged, not fatal.
func backupBeforeUpgrade(db *sql.DB, from int) {
	var seq int
	var name, file string
	if err := db.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); err != nil || file == "" {
		return // in-memory
	}
	bak := fmt.Sprintf("%s.v%d.bak", file, from)
	if _, err := os.Stat(bak); err == nil {
		return
	}
	if _, err := db.Exec("VACUUM INTO ?", bak); err != nil {
		log.Printf("[DB] WARN couldn't back up the v%d database before upgrading: %v", from, err)
		return
	}
	log.Printf("[DB] Backed up the v%d database to %s before upgrading", from, bak)
}

func Migrate(db *sql.DB) error {
	var currentVersion int
	row := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version")
	if err := row.Scan(&currentVersion); err != nil {
		// Table might not exist yet — that's fine, start from 0
		currentVersion = 0
	}

	if currentVersion > 0 && currentVersion < len(migrations) {
		backupBeforeUpgrade(db, currentVersion)
	}

	for i := currentVersion; i < len(migrations); i++ {
		version := i + 1
		log.Printf("[DB] Applying migration v%d", version)

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration v%d: %w", version, err)
		}

		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration v%d: %w", version, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_version (version) VALUES (?)", version); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration v%d: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration v%d: %w", version, err)
		}

		log.Printf("[DB] Migration v%d applied", version)
	}

	return nil
}
