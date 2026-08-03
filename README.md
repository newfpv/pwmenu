# PWMenu for Pwnagotchi

<p align="center">
  <a href="https://neewfpv.com/wiki/pwmenu">
    <img
      src="https://img.shields.io/badge/OPEN%20THE%20COMPLETE%20PWMENU%20WIKI-20E4F4?style=for-the-badge&amp;logo=readthedocs&amp;logoColor=20E4F4&amp;labelColor=071012"
      height="52"
      alt="Open the complete PWMenu Wiki"
    >
  </a>
</p>

**One fast, mobile-first field console for captures, verified credentials,
Hashcat preparation, map intelligence, WPA-sec, OnlineHashCrack, QuickDic,
exports, whitelists, and safe cleanup.**

## One plugin, the complete workflow

PWMenu turns the Pwnagotchi capture folder into an organized audit workspace.
It keeps exact access-point identity, explains whether a capture is actually
usable, prevents repeated cloud submissions, verifies passwords before saving
them, and keeps the same workflow comfortable on a desktop or phone.
The folder is resolved from the active Pwnagotchi
`bettercap.handshakes` setting before any scanner or cloud worker starts;
PWMenu does not hardcode a device-specific capture location.

| Capture intelligence | Credential control | Field map |
|---|---|---|
| Inspect every concrete PCAP, group by exact BSSID, grade quality, convert to mode 22000, and keep the best unresolved capture. | Merge WPA-sec, OHC, Handshake Lab, QuickDic, and manual results without destroying punctuation or confusing similarly named APs. | Combine PwnDroid, browser GPS, GPSD, and manual placement with clustering, history, filters, and actions directly on the map. |
| **Cloud without duplicate work** | **Responsive by design** | **Safe persistent state** |
| WPA-sec and OHC are integrated with local suitability gates, remembered submissions, last-export comparison, live reconciliation, and durable retry queues. | A purpose-built desktop layout and a compact bottom-navigation phone UI share the same actions and update without unnecessary page reloads. | Atomic writes, recovery copies, bounded workers, explicit confirmations, path validation, and last-second cleanup rechecks protect the device and its data. |

## What PWMenu can do

### Capture intelligence

- Index `.pcap` captures and keep every concrete filename available.
- Resolve the access point by exact BSSID, including legacy or sanitized
  filenames, while preserving spaces, hyphens, underscores, and punctuation.
- Group repeated captures without collapsing different APs that share an ESSID.
- Analyze PMKID/EAPOL material and grade captures as **Excellent**, **Usable**,
  **Partial**, or **Unusable**.
- Use successful Hashcat mode 22000 extraction—not raw EAPOL frame counts—as the
  final local suitability gate.
- Convert and download individual mode 22000 hashes, individual PCAPs, selected
  clusters, all captures, or only the best unresolved APs.
- Keep one best capture per BSSID and optionally archive an older weak capture
  when a better one arrives.
- Show the exact file, BSSID, size, date, quality, location source, tested
  methods, and available actions in one expandable card.

### Password and result hub

- Merge credentials from integrated WPA-sec results, OnlineHashCrack imports,
  Handshake Lab exports, QuickDic sidecars, and manual entry.
- Match BSSID first and use conservative ESSID fallback only when exact identity
  is unavailable.
- Verify a manually entered password before storing it:
  `aircrack-ng` for EAPOL and local PBKDF2/PMKID verification for PMKID-only
  captures.
- Reject wrong passwords and explain when verification is impossible because
  the capture contains no usable WPA/PMKID hash.
- Add, edit, delete, reveal, and copy credentials without a full-page refresh.
- Preserve colons and other valid password characters in storage and export.
- Export a sorted UTF-8, Windows-friendly credential list with ESSID, BSSID,
  password, and source.
- Copy a clean Telegram-ready block containing the dictionaries, masks, rules,
  and pattern builders already tested against a capture.

### Map and field workflow

- Receive live coordinates from **PwnDroid over Bluetooth PAN**, browser
  geolocation, or GPSD.
- Save location sidecars when captures arrive and show GPS age, accuracy, and
  source.
- Place or move a concrete handshake manually: open Map, move the map under the
  fixed center pin, then confirm.
- Mark manually positioned captures as **MAP** and measured coordinates as
  **GPS**.
- Attach a handshake directly to an existing point or network cluster.
- Search, filter cracked APs, inspect capture history, and open same-location
  groups.
- Download captures, submit eligible work, add a verified password, or update
  the whitelist directly from the map.
- Keep the current map, marker, search, and filters open after in-place actions.

### Built-in integrations

| Integration | What PWMenu owns |
|---|---|
| **WPA-sec** | One-best-capture selection, persistent submitted-BSSID memory, upload queue, authenticated potfile download, result merge, status, and manual sync. The separate `wpa-sec` and `wpa-sec-list` plugins are not required. |
| **OnlineHashCrack** | Local mode 22000 extraction before upload, one best PCAP per BSSID, comparison with local history, the latest imported OHC export and live tasks, persistent backoff/retry, result imports, and an exact reason when a file is excluded. |
| **Optional VLESS/Xray** | Routes only OHC API traffic through a loopback Xray proxy when a VLESS URL is configured; every other Pwnagotchi connection remains direct. No URL means no proxy. |
| **QuickDic** | Bounded background dictionary worker, configurable wordlist folders, known-password precheck, result sidecars, display feedback, optional Telegram notification, and recovery events. |
| **Display password** | Configurable on-device password/status element with source filters, placement, orientation, length, and empty-state text. A separate `display-password` plugin is not required. |
| **Handshake Lab** | Imports exact ESSID/BSSID/password/source records and exports one locally usable unresolved capture per AP for GPU work. |

### Control, automation, and safety

- Enable or disable Web UI, GPS, quality, whitelist, WPA-sec, OHC, time sync,
  display-password, and QuickDic modules independently.
- Add exact SSIDs to the whitelist without losing punctuation; every entry
  remains visible inside one bounded, swipeable list.
- Add only server-verified **Excellent** networks from a selected map group.
- Preview empty, incomplete zero-hash, and analyzed unusable cleanup candidates.
- Delete cleanup candidates only after explicit confirmation, report-token
  validation, file-signature comparison, and immediate quality reanalysis.
- Keep OHC/WPA-sec queues and recovery state across service restarts.
- Use atomic state and potfile replacement, locks around shared workers, bounded
  temporary archives, strict filenames, and path-traversal rejection.
- Reuse an automatically invalidated page model instead of reparsing every
  potfile, PCAP, map cluster, and cleanup candidate on each request.
- Open a thin first screen while the active tab loads independently; remaining
  tabs, card details, and the map library warm progressively in the background.
- Load the first 24 Cracked and Handshake cards immediately, reserve the final
  list height with lightweight card placeholders, and replace them in small
  background batches with a fade-in. Hidden Handshakes continue filling before
  the tab is opened; active lists automatically switch to larger fast batches.
  New captures cannot reset the active scroll position, while server-side
  search still covers the complete list.
- Select one strongest capture per exact AP for PCAP/22000 downloads and cloud
  actions. Additional captures stay available under a compact **Other
  captures** disclosure instead of crowding every card.
- Reuse browser-cached CSS, JavaScript, and one SVG icon sprite instead of
  retransmitting the complete interface on every visit.
- Tune Web gzip, snapshots, background preload, source-verification windows,
  model warmup, and notification duration for slow Raspberry Pi storage and
  Bluetooth PAN links.
- Change the interface accent while retaining the same dark field-console
  design.
- Download and restore a complete portable PWMenu backup containing every PCAP,
  GPS/MAP point, configuration file, activity record, submission state and
  credential potfile. Large collections stream through disk-backed temporary
  storage instead of Raspberry RAM. Backups are not encrypted, so they must be
  protected like the original device.
- Review a conditional conflict center for multiple identities/passwords,
  name-only credentials and repeated captures. Punctuation-only ESSID aliases
  reconcile automatically; a real password conflict can be repaired only
  after local cryptographic verification. Verification runs in the background
  with visible candidate progress, so closing the tab does not cancel it. The
  complete safe summary copies as one message-ready block without exposing
  passwords.
- Keep the newest 24 hours or 200 important Pwnagotchi and PWMenu events in a
  bounded, swipeable **Other** list without turning the main interface into a
  log viewer. One action copies the complete visible history.
- Use the priority-sorted **Other** workspace: conditional problems first,
  expandable Level achievements, one compact results/export/import/backup
  block, OHC and WPA-sec, whitelist, Activity History, and then Conflict Center.
  Healthy OHC password storage and an empty cleanup report do not consume
  separate cards.
- Show a compact **System attention** panel only when memory or storage is low,
  GPS remains unavailable beyond its grace period, or an OHC/WPA-sec queue
  appears stalled.

## Quick install

Install the current tested release:

```bash
sudo wget -O /usr/local/share/pwnagotchi/custom-plugins/A_pwmenu.py \
  https://raw.githubusercontent.com/newfpv/pwmenu/v1.4.2/A_pwmenu.py
```

Enable it in `/etc/pwnagotchi/config.toml`:

```toml
main.plugins.A_pwmenu.enabled = true
```

Apply the configuration by restarting only the service:

```bash
sudo systemctl restart pwnagotchi
```

Then open:

```text
http://<pwnagotchi-ip>:8080/plugins/A_pwmenu/
```

Installation requirements, upgrades, backups, every configuration option,
WPA-sec/OHC keys, VLESS/Xray installation, GPS/PwnDroid, exports, cleanup, and
troubleshooting live in the **[complete PWMenu Wiki](https://neewfpv.com/wiki/pwmenu)**.

## Use and privacy

> Use PWMenu only with networks you own or have explicit permission to audit.

PCAPs, hashes, credentials, API keys, VLESS URLs, network identifiers, and
coordinates are sensitive. Keep the Pwnagotchi Web UI authenticated, do not
publish its state files, and do not expose the Web UI directly to the internet.

## Links

- [Complete Wiki and setup guide](https://neewfpv.com/wiki/pwmenu)
- [Latest release](https://github.com/newfpv/pwmenu/releases/latest)
- [Changelog](./CHANGELOG.md)
- [Issue tracker](https://github.com/newfpv/pwmenu/issues)
- [GPL-3.0 License](./LICENSE)

Made by [NewFPV](https://neewfpv.com/).
