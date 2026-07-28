# A_pwmenu

[![Open PWMenu Wiki](https://img.shields.io/badge/OPEN%20THE%20FULL%20PWMENU%20WIKI-20E4F4?style=for-the-badge&logo=readthedocs&logoColor=071012)](https://neewfpv.com/wiki/pwmenu)

A fast, mobile-first capture, password, and audit workflow manager for
Pwnagotchi. PWMenu combines handshake inspection, password verification,
mapping, WPA-sec, OnlineHashCrack, exports, imports, persistent queues, and safe
cleanup in one web interface.

[![Tests](https://github.com/newfpv/pwmenu/actions/workflows/test.yml/badge.svg)](https://github.com/newfpv/pwmenu/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-GPL--3.0-30d158)](./LICENSE)

> Use A_pwmenu only with networks you own or have explicit permission to audit.
> PCAP files, network identifiers, passwords, and coordinates can contain
> sensitive information.

## What PWMenu does

PWMenu adds four responsive workspaces to the Pwnagotchi Web UI:

- **Cracked** — recovered networks, exact ESSID/BSSID identity, password source,
  reveal/copy controls, verified manual password editing, and deletion.
- **Handshakes** — capture groups, concrete PCAP files, quality reports,
  downloads, conversion, map placement, whitelist controls, cloud submissions,
  and precise deletion.
- **Map** — measured and manually assigned locations, clustering, search,
  cracked filtering, capture history, and live password or whitelist actions.
- **Other** — integrations, persistent queues, imports, exports, whitelist
  management, time synchronization, achievements, and safe cleanup.

The interface is designed for desktop and phone use. HTML compression, lazy map
loading, compact background requests, and in-place updates reduce traffic over a
Bluetooth PAN connection.

## Capture management and quality

- Indexes `.pcap` files from the Pwnagotchi handshake directory.
- Resolves exact AP identity from capture analysis and WPA hash data, including
  legacy filenames that do not contain a BSSID.
- Groups duplicate captures by exact BSSID while keeping every concrete file
  individually accessible.
- Converts captures to Hashcat mode 22000 with `hcxpcapngtool`.
- Grades captures as **Excellent**, **Usable**, **Partial**, or **Unusable**.
- Caches quality reports against the file signature and recalculates them when a
  file changes.
- Can archive an older weak capture after a newer usable capture appears for the
  same BSSID.
- Provides individual PCAP/22000 downloads, selected ZIP downloads, and a full
  capture archive.
- Places the Delete action beside the exact PCAP filename so the selected file
  is unambiguous.

### Uncracked export

`Download All Uncracked APs` does not trust an ESSID or filename match alone.
PWMenu:

1. Rejects captures that cannot produce a usable WPA mode 22000 record.
2. Collects known password candidates from every local source.
3. Tests those candidates against each concrete capture with `aircrack-ng`.
4. Excludes only captures for which a password is cryptographically verified.
5. Keeps one best unresolved capture for each exact BSSID.

This prevents an already recovered AP from being exported several times while
still retaining a newer handshake when the stored password does not actually
match it.

## Password handling

PWMenu combines credentials from:

- integrated WPA-sec results;
- OnlineHashCrack imports;
- Handshake Lab CSV exports;
- integrated QuickDic `.cracked` files;
- manually entered passwords.

Manual add and edit actions are verified with `aircrack-ng` against a matching
capture before anything is written. An incorrect password, verification timeout,
or missing matching capture is rejected. Successful add, update, and delete
actions refresh the affected UI without reloading the page.

The TXT export is sorted UTF-8 TSV with a byte-order mark and Windows-compatible
CRLF lines. It contains the columns `ESSID`, `BSSID`, `PASSWORD`, and `SOURCE`;
colons inside passwords are preserved.

## Map and location workflow

Location can come from:

- PwnDroid over Bluetooth PAN;
- browser geolocation;
- GPSD;
- manual placement in PWMenu.

Choose **Map** or **Move** beside a concrete handshake to place it manually.
PWMenu opens the Map workspace with a fixed pin in the center: move the map
under the pin, then confirm or cancel using the bottom controls. A capture can
also be attached directly to an existing point or cluster.

Coordinates set by the user are labeled **Map**. Coordinates measured through
PwnDroid, browser geolocation, or GPSD are labeled **GPS**. Manual placement,
password actions, and whitelist actions keep the current map, marker, filters,
and search state open.

## Integrated WPA-sec

The complete WPA-sec client is built into PWMenu. Separate `wpa-sec` and
`wpa-sec-list` plugins are not required.

PWMenu:

- selects one best unresolved capture per exact BSSID;
- uploads new captures automatically or on demand;
- remembers submitted BSSIDs persistently;
- migrates the stock WPA-sec upload report;
- authenticates result downloads with the configured service key;
- downloads the account potfile through a temporary file and atomic replacement;
- provides manual synchronization, current status, and clickable service links.

Recommended configuration:

```toml
main.plugins.A_pwmenu.module_wpa_sec_enabled = true
main.plugins.A_pwmenu.wpa_sec_key = "REPLACE_ME"
main.plugins.A_pwmenu.wpa_sec_api_url = "https://wpa-sec.stanev.org"
main.plugins.A_pwmenu.wpa_sec_auto_upload = true
main.plugins.A_pwmenu.wpa_sec_download_results = true
main.plugins.A_pwmenu.wpa_sec_sync_interval = 3600

# Keep the old standalone clients disabled.
main.plugins.wpa-sec.enabled = false
main.plugins.wpa-sec-list.enabled = false
```

## OnlineHashCrack

PWMenu converts captures to mode 22000, maintains a durable upload queue, submits
in batches, downloads results, and preserves server backoff across restarts.

Before work enters the queue, it is compared with:

- persistent local BSSID and hash submission history;
- identities from the latest imported OHC task export;
- the current authenticated OHC `list_tasks` response.

Already known tasks are recorded instead of submitted again. `Send all missing
to OHC` scans unresolved captures, selects one best PCAP per BSSID, and queues
only work that is absent from all three sources.

```toml
main.plugins.A_pwmenu.module_ohc_enabled = true
main.plugins.A_pwmenu.ohc_enabled = true
main.plugins.A_pwmenu.ohc_api_key = "sk_REPLACE_ME"
main.plugins.A_pwmenu.ohc_auto_upload = true
main.plugins.A_pwmenu.ohc_sync_interval = 3600
main.plugins.A_pwmenu.ohc_retry_poll_interval = 60
```

### Optional OHC-only VLESS route

VLESS is optional. Leave `ohc_vless_url` empty when the authenticated OHC API is
available directly. When a link is configured, PWMenu starts an Xray HTTP proxy
bound to `127.0.0.1` and routes only OHC API requests through it. WPA-sec, maps,
time synchronization, and normal Pwnagotchi traffic remain direct.

PWMenu creates and protects the temporary Xray configuration, starts the
process, checks the loopback port, and stops the process when it is no longer
needed. The Xray executable itself is installed separately so the user can
select the correct build for the Raspberry Pi architecture and update it
independently.

#### Install Xray on the Pwnagotchi

The official XTLS installer supports Debian/systemd and automatically selects a
supported architecture:

```bash
sudo apt update
sudo apt install -y ca-certificates curl unzip

sudo bash -c \
  "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" \
  @ install
```

The installer places the executable at `/usr/local/bin/xray`. Verify it:

```bash
test -x /usr/local/bin/xray
/usr/local/bin/xray version
```

PWMenu launches its own isolated Xray process, so the standalone Xray systemd
service is not needed:

```bash
sudo systemctl disable --now xray
```

Configure PWMenu after the executable has been verified:

```toml
main.plugins.A_pwmenu.ohc_vless_url = "vless://REPLACE_WITH_YOUR_PRIVATE_LINK"
main.plugins.A_pwmenu.ohc_vless_flow = "auto"
main.plugins.A_pwmenu.ohc_xray_binary = "/usr/local/bin/xray"
main.plugins.A_pwmenu.ohc_proxy_port = 10809
```

`ohc_vless_flow = "auto"` follows the shared link. An explicit value overrides
it; an empty string supports servers whose account is configured without flow.
The VLESS URL is a secret: keep it only in root-owned `config.toml` and never
paste it into screenshots, logs, issues, or commits.

After PWMenu is running, verify the local proxy when VLESS is enabled:

```bash
ss -lntp | grep ':10809'
grep -E 'A_pwmenu.*(VLESS|Xray|proxy)|OHC' \
  /etc/pwnagotchi/log/pwnagotchi.log | tail -100
```

Official installer and documentation:

- [XTLS/Xray-install](https://github.com/XTLS/Xray-install)
- [Project X installation documentation](https://xtls.github.io/en/document/install.html)

## Whitelist and cleanup

- Adds and removes exact SSIDs without stripping hyphens, underscores, spaces,
  or other valid punctuation.
- Writes `config.toml` atomically, preserves its ownership and mode, and creates
  a backup before whitelist changes.
- Updates the active agent configuration immediately.
- Shows the first 10 whitelist entries and moves the remainder under an
  expander only after the list grows beyond 15 entries.
- Can add only server-verified **Excellent** networks from a map cluster.
- Uses preview tokens and last-second file revalidation for capture cleanup.
- Removes only explicitly confirmed empty or currently **Unusable** captures and
  their known derivative files.

## Integrated display and QuickDic

PWMenu includes the functionality of `display-password` and
`better_quickdic`:

- configurable password source filters, orientation, length, position, and
  empty-state text on the physical display;
- a bounded background QuickDic worker;
- recursive or non-recursive wordlist folders;
- configurable timeout, queue size, display message, and optional Telegram
  notification;
- known-password verification before dictionary work begins.

Keep standalone copies disabled to avoid duplicate display elements or duplicate
dictionary work:

```toml
main.plugins.display-password.enabled = false
main.plugins.better_quickdic.enabled = false
```

## Install PWMenu

Back up an existing plugin, install the tested release, set ownership and mode,
then compile the file before restarting the service:

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

Apply the configuration by restarting only the Pwnagotchi service:

```bash
sudo systemctl restart pwnagotchi
sudo systemctl status pwnagotchi --no-pager -l
```

Open:

```text
http://<pwnagotchi-ip>:8080/plugins/A_pwmenu/
```

See [`config.example.toml`](./config.example.toml) for every module switch and
configuration option.

## Independent module switches

Each subsystem can be disabled without disabling the complete plugin:

```toml
main.plugins.A_pwmenu.module_web_enabled = true
main.plugins.A_pwmenu.module_gps_enabled = true
main.plugins.A_pwmenu.module_ohc_enabled = true
main.plugins.A_pwmenu.module_wpa_sec_enabled = true
main.plugins.A_pwmenu.module_quality_enabled = true
main.plugins.A_pwmenu.module_whitelist_enabled = true
main.plugins.A_pwmenu.module_time_sync_enabled = true
main.plugins.A_pwmenu.module_display_password_enabled = true
main.plugins.A_pwmenu.module_quickdic_enabled = true
```

## Requirements

- Pwnagotchi 2.x with its Flask Web UI.
- The Python 3.11 environment used by Pwnagotchi.
- `requests`.
- `websockets` when PwnDroid is enabled.
- `hcxpcapngtool` for quality analysis and mode 22000 conversion.
- `aircrack-ng` for manual password verification and integrated QuickDic.
- Xray only when OHC VLESS routing is enabled.

## Persistent data and security

PWMenu keeps its durable state in `/root/handshakes`. State and potfile updates
use temporary files, `fsync`, atomic replacement, and recovery copies where
appropriate.

Do not publish:

- `config.toml`;
- API keys or VLESS URLs;
- PCAP, 22000, potfile, or `.cracked` files;
- GPS sidecars or screenshots containing coordinates;
- `.a_pwmenu_data.json` or OHC export snapshots.

Enable Pwnagotchi Web UI authentication and do not expose port 8080 directly to
the public internet.

## Documentation and support

[![Open PWMenu Wiki](https://img.shields.io/badge/OPEN%20THE%20FULL%20PWMENU%20WIKI-20E4F4?style=for-the-badge&logo=readthedocs&logoColor=071012)](https://neewfpv.com/wiki/pwmenu)

The wiki covers every configuration option, interface workflow, backup and
restore, HTTP routes, GPS and Bluetooth setup, OHC/WPA-sec diagnostics, and
troubleshooting.

- [Release history](./CHANGELOG.md)
- [GitHub Issues](https://github.com/newfpv/pwmenu/issues)

## License

[GPL-3.0](./LICENSE) © NewFPV.
