# Pwmenu  
**Ultimate Password Manager for Pwnagotchi**

A powerful plugin for managing captured passwords and handshakes directly on your Pwnagotchi.  
Beautiful iOS-style dark interface, WPA-Sec integration, achievements, and convenient tools for working with `.pcap` files.

[🇷🇺 Перевести на русский язык](https://github.com/Newfpv/pwmenu/blob/main/READMERU.md)

![image](https://github.com/Newfpv/pwmenu/blob/main/image.webp)

## ✨ Features
- **Beautiful Web Interface:** dark iOS-style theme, tabs, animations, easy navigation.
- **Network Grouping:** all captured handshakes for a network (ESSID) grouped together.
- **Password Manager:**
  - view all cracked passwords;
  - manually add, edit, delete entries;
  - import passwords from `.json` and `.csv` (e.g., OnlineHashCrack exports).
- **File Management:**
  - download `.pcap` files;
  - automatic conversion to `.hc22000` (Hashcat format) on-device;
  - delete individual files;
  - bulk download all handshakes as a ZIP.
- **WPA-Sec Integration:** upload handshakes to wpa-sec.stanev.org with one click.
- **Maintenance Tools:**
  - detect and remove broken/empty captures;
  - full wipe (“Nuke All”).
- **Achievement System:** XP, levels, and badges.
- **Time Sync:** one-button time sync via Google.

## 🚀 Installation
```bash
ssh pi@10.0.0.2
cd /usr/local/share/pwnagotchi/custom-plugins/
sudo wget https://raw.githubusercontent.com/newfpv/pwmenu/main/A_pwmenu.py
sudo nano /etc/pwnagotchi/config.toml
```
Add plugin config:
```toml
main.plugins.A_pwmenu.enabled = true
main.plugins.A_pwmenu.wpa_sec_key = "YOUR_WPA_SEC_KEY"
main.plugins.A_pwmenu.timezone = 3
```
Restart:
```bash
sudo systemctl restart pwnagotchi
```

## 📖 User Guide
### "Cracked" Tab
Shows all discovered passwords.
- **Source badge** indicates where the password came from (WPA-Sec, OHC, Manual, QuickDic).
- **✏️ Edit** — modify password.
- **✖ Delete** — remove entry.

### "Handshakes" Tab
List of captured networks.
- click a network to expand all `.pcap` files for that ESSID;
- green network name = password already found.

Actions inside group:
- **WPA:** upload file to wpa-sec;
- **22000:** download `.hc22000` version;
- **PCAP:** download original capture;
- **Delete** file;
- **Add** password.

### "Other" Tab
- **Achievements:** level, XP and badges.
- **Stats:** global statistics.
- **Export:** ESSID:PASSWORD list or ZIP with all files.
- **Import:** upload `.json`/`.csv` password files.
- **Danger Zone:** remove broken files or wipe everything.

## 🛠 Troubleshooting
### Conversion Failed
The `.pcap` is empty or doesn’t contain valid PMKID/EAPOL. Use **Clean Broken Files**.

### No WPA-Sec Button
Add `main.plugins.A_pwmenu.wpa_sec_key` to `config.toml`.

### Incorrect Time
Adjust `main.plugins.A_pwmenu.timezone`.

## 🤝 Acknowledgments
Thanks to the Pwnagotchi community!

## ☕ Support
<div align="left"><a href="https://www.donationalerts.com/r/newfpv"><img src="https://img.shields.io/badge/Donate-Buy%20Me%20A%20Coffee-yellow.svg" alt="Donate"></a></div>
