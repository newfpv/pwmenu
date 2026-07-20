# A_pwmenu

A fast, mobile-first capture and password manager for Pwnagotchi. It combines PCAP quality analysis, local passwords, GPS mapping, WPA-sec, OnlineHashCrack, exports, imports, a persistent upload queue, and safe cleanup in one web interface.

[![Version](https://img.shields.io/badge/version-1.3.1-20e4f4)](./CHANGELOG.md)
[![Tests](https://github.com/newfpv/pwmenu/actions/workflows/test.yml/badge.svg)](https://github.com/newfpv/pwmenu/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-GPL--3.0-30d158)](./LICENSE)

> Use A_pwmenu only with networks you own or have explicit permission to audit.

## What you get

- Responsive Cracked, Handshakes, Map, and Other workspaces.
- `Excellent` / `Usable` / `Partial` / `Unusable` PCAP quality grades.
- GPS from PwnDroid, browser geolocation, or GPSD.
- WPA-sec and OnlineHashCrack uploads with persistent deduplication and backoff.
- Manual passwords, OHC imports, QuickDic results, exports, and ZIP downloads.
- In-app Pwnagotchi whitelist management, including Excellent-only map groups, and confirmation-bound capture cleanup.
- Gzip-compressed HTML, lazy map loading, and in-place map actions for faster Bluetooth access.

## Install

```bash
sudo cp /usr/local/share/pwnagotchi/custom-plugins/A_pwmenu.py \
  /root/A_pwmenu.py.backup 2>/dev/null || true

sudo wget -O /usr/local/share/pwnagotchi/custom-plugins/A_pwmenu.py \
  https://raw.githubusercontent.com/newfpv/pwmenu/v1.3.1/A_pwmenu.py

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

## Optional integrations

```toml
# WPA-sec
main.plugins.A_pwmenu.wpa_sec_key = "REPLACE_ME"

# OnlineHashCrack API v2
main.plugins.A_pwmenu.ohc_enabled = true
main.plugins.A_pwmenu.ohc_api_key = "sk_REPLACE_ME"
main.plugins.A_pwmenu.ohc_auto_upload = true

# PwnDroid over Bluetooth PAN
main.plugins.A_pwmenu.pwndroid_ws_enabled = true
main.plugins.A_pwmenu.pwndroid_mac = "AA:BB:CC:DD:EE:FF"
main.plugins.A_pwmenu.pwndroid_gateway = ""
main.plugins.A_pwmenu.pwndroid_port = 8080
```

See [`config.example.toml`](./config.example.toml) for the complete configuration template.

## Documentation

The full guide covers installation, every option, the interface, capture quality, cleanup safety, WPA-sec, OHC, GPS/PwnDroid, backups, security, routes, and troubleshooting:

**[neewfpv.com/wiki/pwnagochi](https://neewfpv.com/wiki/pwnagochi)**

Release history is in [`CHANGELOG.md`](./CHANGELOG.md). Bugs and feature requests are welcome in [GitHub Issues](https://github.com/newfpv/pwmenu/issues).

## Requirements

- Pwnagotchi 2.x and its Flask web UI.
- Python 3.11 environment used by Pwnagotchi.
- `requests`; `websockets` for PwnDroid.
- `hcxpcapngtool` for quality analysis and mode 22000 conversion.

## License

[GPL-3.0](./LICENSE) © NewFPV.
