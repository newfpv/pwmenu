# Changelog

All notable changes to A_pwmenu are documented here.

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
