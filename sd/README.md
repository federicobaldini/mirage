# sd/ — Mirage SD Card Utilities

This directory contains host-side tools and files meant to be used alongside
the Mirage firmware. Nothing here goes into the firmware binary.

## SD card layout (on-device)

```
SD root/
└── mirage/
    ├── config.ini            # persistent target/defended selection (auto-saved)
    ├── recon_<ts>.pcap       # passive scan captures (Reconnaissance)
    ├── handshake_<ts>.pcap   # 4-way handshake captures (Infiltration)
    ├── pmkid_<ts>.pcap       # PMKID frames (Infiltration)
    ├── deauth_<ts>.pcap      # deauth flood captures (Detection)
    ├── awareness_<ts>.pcap   # traffic collection (Awareness)
    ├── hardening_<ts>.pcap   # scan during hardening audit (Hardening)
    ├── creds_<ts>.log        # captive portal credentials (plaintext)
    └── report_<ts>.log       # hardening/awareness text reports
```

### config.ini format

```ini
# Mirage config — auto-generated
TGT_SSID=MyNetwork
TGT_BSSID=AA:BB:CC:DD:EE:FF
TGT_CH=6
TGT_RSSI=-62
TGT_PASS=optional_password
TGT_VALID=1
DEF_SSID=HomeNetwork
DEF_BSSID=11:22:33:44:55:66
DEF_CH=11
DEF_RSSI=-45
DEF_PASS=my_wifi_password
DEF_VALID=1
```

- Written automatically whenever a target or defended AP is confirmed
- Loaded at boot — selection survives reboots
- Password field is empty string if skipped
- For open networks the password field is empty

`<ts>` is seconds since boot (millis()/1000 at file open time).

## tools/

| Script | Purpose |
|--------|---------|
| `tools/pcap_summary.py` | Summarise one or more `.pcap` files from Mirage |
| `tools/creds_dump.py`   | Pretty-print captive-portal credential logs |

## Usage

Copy the whole `mirage/` folder from the SD card to your machine, then:

```bash
python3 tools/pcap_summary.py /path/to/mirage/*.pcap
python3 tools/creds_dump.py   /path/to/mirage/creds_*.log
```

Requirements: `scapy` (`pip install scapy`) for pcap_summary.py; no deps for creds_dump.py.
