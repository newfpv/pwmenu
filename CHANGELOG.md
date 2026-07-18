# Changelog

All notable changes to A_pwmenu are documented here.

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
