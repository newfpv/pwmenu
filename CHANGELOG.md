# Changelog

All notable changes to A_pwmenu are documented here.

## 1.4.1 — 2026-08-02

PWMenu 1.4.1 is a focused reliability and field-display release. It keeps the
1.4.0 storage format and Bluetooth-first Web UI, so no state migration is
required. Existing PCAPs, map sidecars, credentials, history, cloud queues,
whitelist settings, and backups remain compatible.

### Visible recovered networks on the Pwnagotchi display

- The integrated password display now consumes Pwnagotchi's unfiltered AP
  scan. When a recovered network is currently visible, its live SSID and
  password replace the generic most-recent credential on the device screen.
- The unfiltered callback intentionally runs before Pwnagotchi applies its
  whitelist. A recovered owner network can therefore appear on the display
  even when it is excluded from capture and attack selection.
- Visible matches use the exact BSSID first. Legacy name-only credentials are
  accepted only when their exact or punctuation-normalized name resolves to a
  single password; conflicting passwords for one BSSID are never guessed.
- Multiple recovered APs rotate strongest-signal first. The scan TTL, rotation
  interval, and the complete feature can be configured independently. After
  the scan expires, the display falls back to the latest enabled password
  source as before.
- Visible state is bounded to the latest scan and kept only in memory. It is
  cleared on plugin unload and does not add passwords, scan results, or signal
  values to the persistent PWMenu state or normal logs.
- Added `display_password_visible_enabled`, `display_password_visible_ttl`,
  and `display_password_visible_cycle_seconds`. All existing source switches,
  length limits, orientation settings, and display coordinates continue to
  apply.

### Configurable Other layout

- Added a numeric `other_card_order_*` option for every Other card: cleanup,
  identity, transfer, OHC, WPA-sec, whitelist, activity, conflicts, and the
  author credit. Lower numbers appear first and the defaults preserve the
  existing interface order.
- Order values are parsed as integers and safely clamped. Equal values retain
  document order, conditional cards still disappear when they have nothing to
  report, and the same configured order is used by phone and desktop layouts.
- Card ordering is applied with per-page CSS custom properties, so the large
  cacheable stylesheet remains shared while each installation can choose its
  own compact Other layout.

### Capture Cleanup confirmation hotfix

- Fixed cleanup confirmations being rejected when the Web UI grouped
  candidates in a different order from the deletion request or when a
  human-readable quality summary refreshed between the two requests.
- Cleanup tokens now use a canonical path/signature/category set. The
  protection remains strict: every PCAP is still signature-checked and
  reanalyzed immediately before deletion, and a file that is no longer empty,
  uncrackable, or unusable is preserved.
- Display-only reason text and list ordering no longer change the confirmation
  identity. Real changes to the resolved file path, file signature, or cleanup
  category still invalidate the old confirmation and require a fresh review.
- Added regression coverage for reversed group ordering, refreshed quality
  summaries, successful deletion after a valid confirmation, and the existing
  stale-token rejection. Together with the visible-AP and configurable-layout
  coverage, the complete suite now contains 93 passing tests.
- Made WPA-sec request User-Agent versioning derive from the plugin version so
  future patch releases cannot advertise a stale PWMenu version.

### Release and cache metadata

- Bumped the plugin version to `1.4.1` and the UI revision to
  `20260802-16`. Browsers receive one revision-triggered refresh while
  content-hashed CSS and JavaScript keep their normal immutable caching.
- Updated the tagged-install command and the complete configuration example
  for the new display and Other-layout controls.
- Verified the release with Python compilation and all 93 unit tests covering
  storage, backup/restore, password verification, capture quality, OHC,
  WPA-sec, conflicts, whitelist safety, and Bluetooth Web UI transport.

## 1.4.0 — 2026-07-30

### Pwnagotchi-native storage discovery

- Replaced hardcoded capture directories with the active Pwnagotchi
  `bettercap.handshakes` setting supplied by the agent. PWMenu now derives its
  PCAP, sidecar, credential, OHC snapshot and persistent-state locations from
  that configured directory.
- Deferred all storage access, capture analysis, QuickDic, quality scanning and
  cloud queues until `on_ready(agent)` supplies the complete Pwnagotchi
  configuration. A dynamic user-home fallback is used only when older forks do
  not expose the setting; the filesystem root is rejected.
- Added a non-destructive compatibility migration that merges legacy
  credentials, map/history/state records and the OHC submission snapshot from
  the previous runtime-home capture folder into the configured directory.
  Existing configured data is preserved in the merge and in a one-time
  pre-migration backup.
- Legacy locations are discovered from system account home directories rather
  than a list of device-specific paths, covering forks that run Pwnagotchi
  under different users. Per-source completion markers make this migration
  idempotent and prevent older state from being reapplied on later starts.

### Bluetooth-first Web UI transport

- Rebuilt the Web UI response as a thin, immediately renderable shell instead
  of retransmitting the complete interface, every tab, every expanded capture,
  all map records, CSS, JavaScript, and repeated inline SVG paths in one large
  HTML document.
- The selected tab now loads first through a compact JSON fragment. Remaining
  tabs preload sequentially during browser idle time, so switching later still
  feels instant without competing with the first useful screen over Bluetooth
  PAN. Background preloading can be disabled with
  `web_background_preload = false`.
- Replaced the generic rectangular list skeleton on Map with a dedicated
  full-map loading state, animated location indicator, and clear map-loading
  copy.
- Added true server-side pagination for Cracked and Handshakes. The first 24
  cards arrive immediately; lightweight full-height placeholders reserve the
  final scroll length and are replaced in small background batches with a
  fade-in. The current scroll position is never reset, and server-side search
  remains complete across records not yet transferred to the browser.
- Moved expanded credential and handshake contents out of the initial response.
  After each list arrives, its details preload as one compressed background
  batch, keeping the first screen small while making card expansion immediate;
  an individual on-demand endpoint remains as a race-safe fallback. A card
  opens its loading surface immediately even if tapped before that preload
  finishes.
- Added revision-bound snapshot identifiers and a small bounded snapshot
  history. Background pages remain pinned to the snapshot that created their
  placeholders even if a new handshake arrives, preventing list replacement
  and the resulting jump back up the page.
- Split the monolithic inline styling and behavior into cacheable `app.css` and
  `app.js` resources and consolidated repeated icons into one SVG sprite.
  Content-hashed resource URLs, strong ETags, precompressed gzip responses, and
  immutable browser caching keep repeat visits small without leaving a phone
  stuck on stale code after an update.
- Added a short-lived pre-rendered page snapshot and debounced background model
  warmup after data changes. File actions remain immediately consistent while
  the next expensive rebuild happens outside the HTTP request whenever
  possible.
- Preserved the existing compact desktop and mobile interface: no new permanent
  panels, controls, or visual clutter were added for this performance work.
- Added complete portable backup/restore for every PCAP handshake, GPS/MAP
  point, PWMenu configuration/state/activity record, submission memory and
  credential potfile. Creation and restoration stream through bounded
  disk-backed temporary storage instead of placing the capture collection in
  RAM. The intentionally unencrypted archive contains a versioned manifest and
  SHA-256 for every entry; restore accepts only known destinations, verifies all
  content before writing, writes atomically, and restarts only the Pwnagotchi
  service.
- Added automatic best-capture presentation. One strongest capture receives
  PCAP/22000 and cloud actions; weaker or repeated captures remain accessible
  under **Other captures**. Direct and ZIP download routes also resolve to one
  best capture per AP.
- Added a conditional conflict center for BSSIDs with multiple ESSIDs or
  recovered passwords, name-only credentials, and repeated captures. Harmless
  punctuation-only ESSID aliases and uniquely matched legacy zero-BSSID
  records are reconciled automatically. A password conflict has an explicit
  local verify-and-fix action that rejects candidates only when exactly one
  password is cryptographically confirmed; missing hashes never alter data.
- Added a bounded activity history for important Pwnagotchi lifecycle,
  connectivity, peer and handshake events plus PWMenu password, map,
  whitelist, cleanup, import, backup and cloud-sync actions. It now shows only
  the newest 24 hours or 200 records and needs no Load more control.
- Added one-click, message-ready text exports for every Conflict Center item
  and the complete retained Activity History.
- Reordered Other by operational priority. Conditional capture cleanup comes
  first, Level expands its achievements in place, transfer/import/backup
  actions share one compact results card, OHC owns its password-storage warning,
  and Activity History is immediately followed by Conflict Center. Healthy
  storage or empty cleanup no longer creates a card.
- Rebuilt the whitelist with the same compact card, counter, bounded list and
  status rows used by Conflict Center and Activity History. Add/remove updates
  the component in place without a page reload, and every entry is present in
  the swipeable list without a Show more control.
- Shortened the whitelist, Activity History and Conflict Center list viewports
  by approximately one row to leave more room for page scrolling. Reordered
  transfer actions into three exact two-button rows; one Import picker now
  accepts both result files and complete PWMenu backups.
- Made password-conflict verification a persistent background job with visible
  per-candidate progress, polling and retry feedback. The button changes to
  **Checking...** immediately and the row remains informative during slow
  local aircrack/hcxtools work. Moved toast notifications out of the lazily
  loaded Map fragment so actions on every tab always show feedback.
- Fixed the rendered **Verify & fix** inline handler: JSON string quoting could
  terminate its HTML attribute before JavaScript ran, making the button appear
  clickable while producing no request or status change.
- Handshake placeholders now backfill even while the tab is hidden. An active
  list switches to larger, faster batches, while inactive work stays gentler;
  defaults remain configurable. Detail preloading for later cards waits until
  their placeholders are filled, so it cannot compete with the visible list.
  The Map fragment is prioritized and the Yandex Maps library warms in the
  background before Map is opened.
- Added a conditional **System attention** panel for low available memory, low
  system storage, GPS outages beyond a grace period, delayed OHC work, and a
  stopped WPA-sec queue. The panel is absent when the system is healthy.
- Added a one-time UI revision cookie and cache-clear response in addition to
  content-hashed assets, forcing browsers that retained an early 1.4.0 shell to
  replace it while preserving normal long-lived asset caching afterwards.
- Added lazy-transport, stable snapshot, placeholder backfill, best-capture,
  conflict, activity history, full-capture backup/restore, health-state, and
  configured-storage migration regression coverage. The suite now contains
  89 passing tests.

## 1.3.10 — 2026-07-30

### Web UI hot-path acceleration

- Added an incremental page-model cache for parsed credentials, grouped
  captures, map clusters, no-GPS entries, cleanup candidates, achievements,
  and aggregate counters. Repeated requests reuse the model until an input
  actually changes.
- Added metadata-only source fingerprints and explicit invalidation after
  state, password, QuickDic, WPA-sec, OHC, map, and capture changes. Passwords
  are never placed in a cache key or persisted by the cache.
- Added short inventory and credential-metadata verification windows,
  configurable with `web_inventory_cache_seconds` and
  `web_credential_cache_seconds`. PWMenu actions invalidate them immediately;
  external filesystem changes are periodically rechecked.
- Replaced repeated capture and QuickDic globs with `os.scandir`, indexed
  cracked credentials once per scan instead of searching every credential for
  every PCAP, and reused scan metadata in Capture Cleanup.
- Removed blocking GPSD socket polling from HTTP page assembly. Live GPSD
  polling remains in the display/capture path, while the Web UI consumes its
  current cached fix.
- Added browser `content-visibility` containment to long credential and
  handshake lists so off-screen cards do not delay the first usable frame.
- Removed the redundant self-copy from map history for networks that have only
  one capture, reducing JSON parsing and memory on the common mobile view.
- On the 179-PCAP development dataset, a repeated gzip page response dropped
  from roughly 285 ms to about 27 ms in the local benchmark. The expensive data
  model itself dropped from roughly 540 ms cold to about 27 ms before the
  metadata hot-path cache, with exact results depending on storage and
  transport.
- Added five cache/invalidation regression tests; the suite now contains 64
  passing tests.

## 1.3.9 — 2026-07-29

### Web UI performance and behavior

- Cached the compiled Jinja template per Flask environment instead of parsing
  and compiling the approximately 400 KB source template on every request.
- Stopped rewriting `.a_pwmenu_data.json` and its backup during ordinary page
  views when achievement state did not change.
- Changed the default HTML compression level from gzip 6 to gzip 1 to avoid
  multi-second compression stalls on Raspberry Pi while retaining a compressed
  response. Added `web_gzip_level` with a validated range of 1–9.
- Removed the duplicated nested copy of every singleton map point from the page
  payload. Cluster members remain complete when a real multi-network cluster
  exists.
- Added `web_notification_duration_ms`, clamped to 250–60000 milliseconds, and
  applied it consistently to server notifications and transient Web UI toasts.
- Confirmed on the development Pwnagotchi that repeated compressed page
  responses dropped from roughly six seconds to approximately 1.3–1.6 seconds;
  actual results depend on capture count, storage, and transport.

### Manual password verification

- Kept `aircrack-ng` verification for captures containing a usable EAPOL
  exchange.
- Added PMKID-only verification: `hcxpcapngtool` extracts the exact WPA*01
  record, then PWMenu derives the PMK with PBKDF2-HMAC-SHA1, calculates the
  PMKID, and compares it in constant time inside the plugin.
- Avoided placing manually entered passwords in a spawned verifier command
  line. Incorrect candidates remain rejected and are never written to a
  potfile.
- Added a precise rejection for incomplete PCAPs:
  `Password cannot be verified because this capture contains no usable
  WPA/PMKID hash. Recapture the access point.`
- Added success, duplicate, rejection, and inconclusive verification logging
  without logging the submitted password.

### Capture quality, Cleanup, and OHC

- Kept the diagnostic quality distinction between `Partial` (EAPOL material
  exists) and `Unusable` (no WPA/PMKID material), while making Hashcat
  suitability explicit: only captures that produce a mode 22000 hash are
  crackable.
- Listed `Partial` captures with zero extractable WPA/PMKID hashes as
  **uncrackable** Capture Cleanup candidates. Deletion still requires the
  owner's browser confirmation and revalidates the report token, file signature,
  and current quality immediately before removing anything.
- Required local WPA/PMKID extraction before OHC submission. Zero-hash PCAPs are
  not sent to the API, are marked with `No usable WPA or PMKID hash found`, and
  are counted in the OHC status panel with a pointer to Capture Cleanup.
- Made per-capture OHC actions return the stored exclusion reason when nothing
  can be queued instead of reporting a misleading upload start for zero files.
- Preserved the existing BSSID-first deduplication, last imported OHC export,
  live task reconciliation, one-best-capture selection, and persistent retry
  queue for captures that pass the local suitability gate.

### Map consistency and validation

- Updated the matching Handshakes card immediately after successful manual map
  placement: the location badge becomes **MAP** and the action becomes **Move**
  without a full page reload.
- Added regression coverage for template caching, gzip configuration, compact
  map payloads, immediate map DOM updates, PMKID success and mismatch, missing
  hash errors, uncrackable cleanup, and zero-queue OHC reasons. The v1.3.9 suite
  contains 59 passing tests.

## 1.3.8 — 2026-07-29

- Parsed WPA-sec result files with compact 12-hex BSSID and station fields, preserving exact AP identity instead of creating `Name-only credential` entries.
- Merged WPA-sec results with OHC, Handshake Lab, Manual, and QuickDic records by exact BSSID and password while retaining separate access points that share the same ESSID and password.
- Preserved passwords containing colons in the compact WPA-sec result format and added regression coverage for both supported potfile encodings.

## 1.3.7 — 2026-07-29

- Fully integrated WPA-sec automatic uploads, persistent per-BSSID submission history, migration from the stock plugin report, atomic result downloads, manual synchronization, and status reporting.
- Corrected WPA-sec authentication to use the service key cookie and removed the need for the standalone `wpa-sec` and `wpa-sec-list` plugins.
- Required every manually entered or edited password to pass an `aircrack-ng` check against a matching capture before it can be stored.
- Added exact handshake placement with a fixed center pin and explicit confirmation: choose **Map/Move**, pan the map, then press the check mark, or add the capture to an existing point/cluster. Manually assigned locations are labeled **Map**, while measured locations remain **GPS**.
- Changed the TXT password export to sorted UTF-8 TSV with BOM, CRLF lines, explicit ESSID/BSSID/PASSWORD/SOURCE columns, and lossless passwords containing colons.
- Collapsed whitelist entries only after the list exceeds 15 items: the first 10 remain visible and the rest move under an expandable control.
- Added clickable OnlineHashCrack and WPA-sec service links and fixed duplicate-filename capture selection across multiple handshake directories.
- Made the last imported OHC task export and persistent local hash history hard pre-queue filters by BSSID, so already submitted access points never re-enter the queue and only the best unresolved capture per AP is queued.
- Added an optional OHC-only VLESS route through a loopback Xray HTTP proxy; leaving `ohc_vless_url` empty retains direct access and no other Pwnagotchi traffic is proxied.
- Added an explicit VLESS flow override for provider links whose advertised flow does not match the server-side account.

## 1.3.6 — 2026-07-26

- Fixed the uncracked ZIP to exclude every AP whose exact BSSID already has an imported password, without re-exporting it when a redundant capture-level aircrack verification fails.
- Resolved legacy or malformed capture filenames through the analyzed WPA hash identity before filtering and deduplication, including BSSID-only filenames without an underscore.
- Kept exactly one highest-quality export candidate per resolved BSSID, even when captures use different filenames.
- Preserved the last real OHC task snapshot when Handshake Lab results are imported, so its BSSID list cannot be replaced by an unrelated results file.
- Suppressed APs already present in the last OHC export and submitted at most one hash from the best capture for each BSSID per upload run.

## 1.3.5 — 2026-07-25

- Integrated the standalone `display-password` and `better_quickdic` features into A_pwmenu with independent module switches and detailed display, dictionary, queue, timeout, and Telegram settings.
- Moved QuickDic work to a bounded background queue so Pwnagotchi's handshake callback is not held for several minutes.
- Made QuickDic verify locally known passwords against each newly captured handshake before attempting wordlists.
- Changed the uncracked ZIP to include every crackable access point without a cryptographically verified password, while retaining only the best unresolved capture for each exact BSSID.
- Cached password-verification results by capture and credential-source revisions without storing password material in the state file.
- Renamed the public guide from `/wiki/pwnagochi` to `/wiki/pwmenu` and expanded module configuration and migration documentation.

## 1.3.4 — 2026-07-25

- Fixed OHC candidate and pending-queue filtering after the credential store became BSSID-aware, preventing locally known networks from being uploaded again.
- Resolved whitelist additions to the exact SSID from recovered BSSID data or the capture’s WPA hash.
- Added a conservative startup migration that replaces punctuation-stripped whitelist aliases only when one unambiguous exact SSID exists in recovered data, capture metadata or the imported OHC task snapshot.
- Stored exact SSID/BSSID metadata in capture-quality records so uncracked groups retain dashes, underscores and other punctuation.

## 1.3.3 — 2026-07-25

- Added a versioned Handshake Lab result format with exact ESSID/BSSID fields and persistent `Handshake Lab` provenance.
- Matched recovered credentials and uncracked exports by BSSID first, with conservative normalized-ESSID fallback only when no BSSID exists.
- Merged display duplicates for the same BSSID and password while preserving the original exported ESSID.
- Made manual password add, edit, and delete actions BSSID-aware.

## 1.3.2 — 2026-07-20

- Fixed uncracked ZIP selection to match known credentials by exact `ESSID + BSSID` instead of treating every access point with the same ESSID as cracked.
- Deduplicated captures from the same exact access point and exported only the best candidate by quality rank, usable hash count, authorized exchange evidence, recency, and file size.
- Kept captures with missing or malformed BSSID data separate so the exporter cannot incorrectly suppress an unrelated access point.
- Renamed the UI action to `Download Best Uncracked` and added regression coverage for shared ESSIDs and duplicate captures.

## 1.3.1 — 2026-07-20

- Added an Excellent-only whitelist action to map clusters, with server-side quality validation.
- Changed map network whitelist controls into live Allow/Remove toggles that update without reloading the page.
- Changed map OHC and WPA-sec submissions to compact asynchronous requests, preserving the open map and details card over slow Bluetooth links.
- Added duplicate-request protection and in-page success or error notifications for asynchronous map actions.

## 1.3.0 — 2026-07-20

- Rebuilt the web interface as a responsive field console with a compact mobile layout, desktop workspace, redesigned capture actions, persistent bottom navigation, and improved map details.
- Added six accent presets plus a custom color picker, with the selected theme saved locally in the browser.
- Added in-app Pwnagotchi network whitelist management with exact-name validation, atomic `config.toml` updates, an automatic backup, and immediate runtime synchronization.
- Replaced separate destructive cleanup actions with one preview-and-confirm workflow for empty and analyzed-unusable captures; every path, signature, and current quality result is revalidated immediately before deletion.
- Removed the broad “nuke all” web action so routine cleanup cannot erase every capture and local potfile in one click.
- Added PCAP, OHC, WPA-sec, whitelist, and delete actions directly to the redesigned handshake and map views.
- Added gzip compression for large HTML responses, reducing the static interface payload from roughly 139 KB to 28 KB before dynamic capture data.
- Changed Yandex Maps to load asynchronously only when the Map tab is opened, so the main page no longer waits for an external map script.
- Added transport regression tests for gzip negotiation and the uncompressed UTF-8 fallback; updated UI and cleanup regression coverage.
- Moved the complete user guide to [neewfpv.com/wiki/pwmenu](https://neewfpv.com/wiki/pwmenu) and reduced the repository README to installation and essential configuration.

## 1.2.0 — 2026-07-18

- Added signature-aware `Excellent`, `Usable`, `Partial`, and `Unusable` capture quality analysis based on the installed `hcxpcapngtool` report and generated mode 22000 hashes.
- Added automatic in-place quality upgrades when a PCAP gains better handshake material.
- Added reversible archival of older weak captures when a newer usable capture for the same BSSID exists; empty 24-byte PCAP files are explicitly excluded.
- Added a preview-and-confirm cleanup flow that removes only valid 24-byte PCAP headers and rejects stale confirmation reports.
- Kept same-location cluster markers neutral while retaining red status for individual OHC-unusable captures.
- Added regression coverage for quality grading, replacement rules, and confirmation-bound empty cleanup.

## 1.1.8 — 2026-07-18

- Rendered OHC-unusable captures and clusters as red markers on both the Yandex map and the fallback map.
- Changed the `OHC Unusable` status chip from yellow to red.

## 1.1.7 — 2026-07-18

- Removed the persistent `OHC found ...` message from the Pwnagotchi status line while preserving OHC result tracking in the web interface.
- Serialized OHC upload worker creation to prevent the scheduler and handshake callback from starting duplicate workers for the same queued capture.
- Replaced the ambiguous `OHC Invalid` capture label with `OHC Unusable` and a clearer WPA/PMKID extraction reason.

## 1.1.6 — 2026-07-18

- Added a crash-safe, password-free snapshot of task identities from the latest valid OHC JSON or CSV import.
- Added conservative pre-upload deduplication by BSSID and BSSID/ESSID in addition to exact persistent hashes and `list_tasks` results.
- Made imports report the number of OHC task identities saved for upload deduplication.
- Preserved the last valid snapshot when an invalid or unrelated file is imported.
- Added regression tests for WPA mode 22000, PMKID, reconnection-safe snapshots, password exclusion, and unrelated BSSIDs.

## 1.1.5 — 2026-07-14

- Updated the OnlineHashCrack `add_tasks` payload to match the private API v2 schema by removing the unsupported `receive_email` field.
- Made `list_tasks` reconciliation advisory for transient failures while continuing to respect the API's per-key hourly rate limit.
- Persisted reported hashes and hash-to-file metadata after every successful batch, reducing duplicate work after sudden power loss.
- Removed locally cracked captures from the persistent OHC queue and stopped the resulting busy retry loop.
- Documented OHC's server-side `already_sent` deduplication behavior and the revised queue states.

## 1.1.4 — 2026-07-13

- Added automatic UTF-8 potfile normalization with NUL removal and credential-level deduplication.
- Made potfile updates atomic and durable with file and directory synchronization.
- Added detailed CSV/JSON import results for added, existing, duplicate, ignored, and invalid rows.
- Added an OHC Password Storage health panel to the Other tab.
- Hardened potfile parsing for Unicode ESSIDs and concurrent imports.

## 1.1.3 — 2026-07-13

- Added a 10-second safety margin to the `Retry-After` delay returned by OHC.
- Fixed same-location marker counts in the Cracked map filter to count only the cracked members shown in the details sheet.

## 1.1.2 — 2026-07-13

- Moved **Send all missing to OHC** and its persistent queue status to the Other tab.
- Fixed Handshakes rows being rendered but hidden by the tab controller after the v1.1.1 layout change.
- Confirmed that existing PCAP files and OHC queue state remain untouched by the UI correction.

## 1.1.1 — 2026-07-13

- Added a **Send all missing to OHC** reconciliation action.
- Added a persistent OHC queue that survives service restarts and sudden power loss.
- Changed OHC tracking from path-only markers to file signatures and individual mode 22000 hashes.
- Changed modified PCAP files to be re-extracted while already submitted hashes remain deduplicated.
- Added an OHC retry scheduler that automatically resumes after `Retry-After` expires.
- Added crash-safe primary and backup state files with file and directory `fsync()`.
- Added automatic recovery from the newest valid state copy.
- Fixed new handshakes being forgotten when captured during an active OHC backoff window.

## 1.1.0 — 2026-07-13

- Added independent WPA-sec and OnlineHashCrack upload paths.
- Added OnlineHashCrack API v2 batching, result synchronization, and persistent rate-limit backoff.
- Added PwnDroid WebSocket GPS, automatic Bluetooth gateway discovery, GPSD fallback, and cached GPS fixes.
- Added a compact `G C` / `G -` on-device GPS indicator.
- Added GPS sidecars, map filtering, capture clustering, and no-GPS reporting.
- Added safe streamed downloads, spooled ZIP exports, atomic state writes, and import limits.
- Hardened filename validation, path handling, subprocess execution, temporary files, and CSRF-protected actions.
- Improved background worker locking, recovery behavior, and diagnostic logging.

## 1.0.0

- Initial public release.
