# Changelog

All notable changes to A_pwmenu are documented here.

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
