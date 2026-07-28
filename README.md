# A_pwmenu

A fast, mobile-first capture and password manager for Pwnagotchi. It combines PCAP quality analysis, local passwords, GPS mapping, WPA-sec, OnlineHashCrack, exports, imports, a persistent upload queue, and safe cleanup in one web interface.

[![Version](https://img.shields.io/badge/version-1.3.7-20e4f4)](./CHANGELOG.md)
[![Tests](https://github.com/newfpv/pwmenu/actions/workflows/test.yml/badge.svg)](https://github.com/newfpv/pwmenu/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-GPL--3.0-30d158)](./LICENSE)

> Use A_pwmenu only with networks you own or have explicit permission to audit.

## What you get

- Responsive Cracked, Handshakes, Map, and Other workspaces.
- `Excellent` / `Usable` / `Partial` / `Unusable` PCAP quality grades.
- GPS from PwnDroid, browser geolocation, or GPSD.
- Fully integrated WPA-sec automatic upload/result download and OnlineHashCrack uploads with persistent BSSID deduplication, last-export comparison, and backoff.
- Integrated password display and background QuickDic, plus manual passwords, OHC imports, exports, and ZIP downloads.
- Cryptographic `aircrack-ng` validation before a manually entered or edited password is accepted.
- Place or move an exact handshake capture on the map: choose **Map** beside its PCAP, move the map under the centered pin, and press the check mark. You can also open an existing point or cluster and add the capture there. Password add/edit/delete actions work directly on the map without a page reload.
- In-app Pwnagotchi whitelist management, including Excellent-only map groups, and confirmation-bound capture cleanup.
- BSSID-aware uncracked exports that exclude exact APs with known passwords and keep only the best unresolved capture for every crackable access point, including legacy filenames resolved from WPA hash data.
- Gzip-compressed HTML, lazy map loading, and in-place map actions for faster Bluetooth access.

## What's new in 1.3.7

- **WPA-sec is fully integrated.** PWMenu uploads one best unresolved capture
  per BSSID, remembers submitted access points, migrates the stock plugin
  report, downloads the account potfile atomically, and exposes manual sync and
  status controls. The standalone `wpa-sec` and `wpa-sec-list` plugins are no
  longer required.
- **Manual passwords are verified before storage.** Add and edit actions run
  `aircrack-ng` against a matching capture; an incorrect password or a password
  without a matching handshake is rejected. Map password actions update in
  place without reloading the page.
- **Individual handshakes can be positioned on the map.** Press **Map** beside
  a PCAP, pan the map beneath the fixed center pin, and confirm, or add the
  capture to an existing point or cluster. Manual positions are labeled
  **Map**, measured positions remain **GPS**, and the delete action now sits
  beside the exact capture filename.
- **Password TXT export is lossless and spreadsheet-friendly.** The export is
  sorted UTF-8 TSV with BOM, CRLF lines, explicit
  `ESSID / BSSID / PASSWORD / SOURCE` columns, and correct preservation of
  passwords containing colons.
- **Whitelist management is safer and more compact.** Exact SSID punctuation is
  retained, additions and removals update without a page reload, and lists over
  15 entries show the first 10 with the remainder under an expandable control.
- **OHC deduplication now happens before queueing.** PWMenu compares BSSIDs
  against the last imported OHC task export, persistent local hash history, and
  the live `list_tasks` response. Already submitted access points never enter
  the upload queue, and only the best unresolved PCAP for each BSSID is kept.
- **OHC can use an isolated VLESS route.** When `ohc_vless_url` is set, PWMenu
  starts a loopback-only Xray HTTP proxy and sends only OHC API requests through
  it. Empty means direct access; `ohc_vless_flow` can override a provider link
  whose advertised flow differs from its server account. The link is not
  copied to PWMenu state, exports, logs, or this repository.
- **Service links and capture identity handling were tightened.** OHC and
  WPA-sec links are clickable, legacy or duplicate filenames resolve through
  their analyzed BSSID, and exact AP identity is retained across imports,
  exports, map actions, and queues.

## Install

```bash
sudo cp /usr/local/share/pwnagotchi/custom-plugins/A_pwmenu.py \
  /root/A_pwmenu.py.backup 2>/dev/null || true

sudo wget -O /usr/local/share/pwnagotchi/custom-plugins/A_pwmenu.py \
  https://raw.githubusercontent.com/newfpv/pwmenu/v1.3.7/A_pwmenu.py

sudo chown root:root /usr/local/share/pwnagotchi/custom-plugins/A_pwmenu.py
sudo chmod 644 /usr/local/share/pwnagotchi/custom-plugins/A_pwmenu.py

/home/pi/.pwn/bin/python3 -m py_compile \
  /usr/local/share/pwnagotchi/custom-plugins/A_pwmenu.py
```

Add the minimum configuration to `/etc/pwnagotchi/config.toml`:

```toml
main.plugins.A_pwmenu.enabled = true
```

Then restart Pwnagotchi:

```bash
sudo systemctl restart pwnagotchi
```

Open `http://<pwnagotchi-ip>:8080/plugins/A_pwmenu/`.

## Module switches and optional integrations

```toml
# Every subsystem can be disabled independently.
main.plugins.A_pwmenu.module_web_enabled = true
main.plugins.A_pwmenu.module_gps_enabled = true
main.plugins.A_pwmenu.module_ohc_enabled = true
main.plugins.A_pwmenu.module_wpa_sec_enabled = true
main.plugins.A_pwmenu.module_quality_enabled = true
main.plugins.A_pwmenu.module_whitelist_enabled = true
main.plugins.A_pwmenu.module_time_sync_enabled = true
main.plugins.A_pwmenu.module_display_password_enabled = true
main.plugins.A_pwmenu.module_quickdic_enabled = true

# WPA-sec
main.plugins.A_pwmenu.wpa_sec_key = "REPLACE_ME"
main.plugins.A_pwmenu.wpa_sec_auto_upload = true
main.plugins.A_pwmenu.wpa_sec_download_results = true
main.plugins.A_pwmenu.wpa_sec_sync_interval = 3600

# PWMenu now owns WPA-sec completely; keep the old plugins disabled.
main.plugins.wpa-sec.enabled = false
main.plugins.wpa-sec-list.enabled = false

# OnlineHashCrack API v2
main.plugins.A_pwmenu.ohc_enabled = true
main.plugins.A_pwmenu.ohc_api_key = "sk_REPLACE_ME"
main.plugins.A_pwmenu.ohc_auto_upload = true
# Optional: only OHC uses this route. Empty means a direct connection.
main.plugins.A_pwmenu.ohc_vless_url = ""
main.plugins.A_pwmenu.ohc_vless_flow = "auto"

# PwnDroid over Bluetooth PAN
main.plugins.A_pwmenu.pwndroid_ws_enabled = true
main.plugins.A_pwmenu.pwndroid_mac = "AA:BB:CC:DD:EE:FF"
main.plugins.A_pwmenu.pwndroid_gateway = ""
main.plugins.A_pwmenu.pwndroid_port = 8080

# Integrated display-password and better_quickdic
main.plugins.A_pwmenu.display_password_max_length = 22
main.plugins.A_pwmenu.quickdic_wordlist_folder = "/home/pi/wordlists/"
main.plugins.A_pwmenu.quickdic_recursive = false
main.plugins.A_pwmenu.quickdic_timeout = 300
```

See [`config.example.toml`](./config.example.toml) for the complete configuration template.

When `ohc_vless_url` contains a VLESS link, PWMenu starts the configured Xray
binary as a loopback-only HTTP proxy and routes only OnlineHashCrack API
requests through it. An empty value disables the proxy and keeps normal direct
OHC behavior. The link remains in root-owned `config.toml`; it is not copied to
PWMenu state, exports, logs, or the repository.
`ohc_vless_flow = "auto"` honors the shared link. An explicit value overrides
it; an empty string supports servers whose account is configured without flow.
Install the matching Xray binary at the configured `ohc_xray_binary` path
before setting a VLESS link. PWMenu does not download or update Xray itself.

## Full PWMenu wiki

The full guide covers installation, every option and module switch, migration from `display-password` and `better_quickdic`, the interface, uncracked verification, capture quality, cleanup safety, integrations, backups, routes, and troubleshooting:

### **[Open the complete PWMenu wiki →](https://neewfpv.com/wiki/pwmenu)**

Release history is in [`CHANGELOG.md`](./CHANGELOG.md). Bugs and feature requests are welcome in [GitHub Issues](https://github.com/newfpv/pwmenu/issues).

## Requirements

- Pwnagotchi 2.x and its Flask web UI.
- Python 3.11 environment used by Pwnagotchi.
- `requests`; `websockets` for PwnDroid.
- `hcxpcapngtool` for quality analysis and mode 22000 conversion.

## License

[GPL-3.0](./LICENSE) © NewFPV.
