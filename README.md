# Mirage

WiFi security lab tool for the **M5Stack Cardputer ADV** (ESP32-S3).
Dual RED / BLUE team interface for authorised penetration testing, security research, and CTF competitions.

> **LEGAL NOTICE** — Use only on networks you own or have explicit written permission to test.
> Unauthorised use is illegal in most jurisdictions (CFAA, Computer Misuse Act, EU Directive 2013/40/EU).
> The authors accept no liability for misuse.

---

## Hardware

| Component | Spec |
|-----------|------|
| MCU | ESP32-S3 (M5Stack StampS3) |
| Display | ST7789 240×135 px |
| Keyboard | TCA8418 I2C matrix controller (addr 0x34, INT on GPIO11) |
| SD card | SPI — CS=12, MOSI=14, MISO=39, SCK=40 |
| Flash | 8 MB (QIO) |
| PSRAM | OPI mode |

---

## Features

### RED team
| Module | Steps |
|--------|-------|
| **KNOW THE FIELD** (Reconnaissance) | Passive channel scan · Active probe sweep · Probe-request sniff · AP fingerprinting · Channel interference map · Target ranking |
| **GET INSIDE** (Infiltration) | Target classification · WPS Pixie Dust · PMKID capture · Deauth + handshake harvest · Captive portal |
| **CONFUSE** (Deception) | Evil Twin AP · Deauth flood · Fake probe requests · Captive portal · Association monitor |
| **CAUSE CHAOS** (CauseChaoS) | SSID beacon storm (128 fake SSIDs) |

### BLUE team
| Module | Steps |
|--------|-------|
| **SEE EVERYTHING** (Awareness) | Passive frame collection · Traffic rate analysis · RSSI anomaly detection · MAC classification · Log export |
| **DETECT THREATS** (Detection) | Deauth flood detection · Handshake-harvest detection · Evil Twin detection · Rogue AP detection · Beacon flood detection · WPS brute-force detection |
| **LOCK IT DOWN** (Hardening) | WiFi scan · Encryption & PMF audit · AP isolation check · Channel congestion · Client risk assessment · Hardening report |

---

## Navigation

| Key | Action |
|-----|--------|
| `;` | Up |
| `.` | Down |
| `Enter` | Select / Run |
| `` ` `` | Back / Abort |
| `Tab` | Switch RED ↔ BLUE mode |
| `Fn + i/k/j/l` | Up / Down / Left / Right (alternative) |

---

## Project structure

```
mirage/
├── include/
│   └── config.h          # All tunable parameters
├── src/
│   ├── main.cpp           # Setup, loop, mode switcher
│   ├── IModule.h          # Module interface (init/run/stop/getSteps)
│   ├── PcapLogger.h       # Raw frame capture to SD (.pcap)
│   ├── WiFiUtils.h        # 802.11 frame helpers, OUI table, inject_frame
│   ├── red/
│   │   ├── Reconnaissance.{h,cpp}
│   │   ├── Infiltration.{h,cpp}
│   │   ├── Deception.{h,cpp}
│   │   └── CauseChaoS.{h,cpp}
│   ├── blue/
│   │   ├── Awareness.{h,cpp}
│   │   ├── Detection.{h,cpp}
│   │   └── Hardening.{h,cpp}
│   └── ui/
│       ├── Theme.h        # RGB565 palette + layout constants
│       ├── MenuRed.{h,cpp}
│       └── MenuBlue.{h,cpp}
├── platformio.ini
└── README.md
```

SD card logs are written to `/mirage/` (created automatically).

---

## Build & flash

**Requirements:** [PlatformIO](https://platformio.org/) (CLI or VS Code extension).

```bash
# Build
pio run -e m5stack-cardputer

# Build and upload via USB
pio run -e m5stack-cardputer -t upload

# Serial monitor
pio device monitor -e m5stack-cardputer
```

### Keyboard diagnostic (standalone)

```bash
pio run -e kb-test -t upload
pio device monitor -e kb-test
```

Tests board detection, I2C scan, TCA8418 presence, and dumps every key event to both the display and serial.

---

## SD card output

| File | Description |
|------|-------------|
| `/mirage/recon_<t>.json` | Ranked AP list (SSID, BSSID, RSSI, encryption, WPS, vendor) |
| `/mirage/recon_<t>.pcap` | Raw 802.11 management frames |
| `/mirage/channel_map_<t>.txt` | Per-channel AP count |
| `/mirage/awareness_<t>.json` | Passive monitor log |
| `/mirage/hardening_<t>.txt` | Hardening audit report |

---

## Configuration

All runtime parameters are in `include/config.h`:

```c
SCAN_DWELL_MS          // Dwell time per channel (default 120 ms)
SCAN_CHANNEL_MIN/MAX   // Channel range (default 1–13)
DEAUTH_FLOOD_THRESHOLD // Frames/s to flag deauth flood (default 20)
BEACON_FLOOD_COUNT     // Fake SSIDs in chaos mode (default 128)
PCAP_MAX_FILE_SIZE     // PCAP rotation size (default 4 MB)
```

---

## Known limitations

- **WPS Pixie Dust / PIN** — attack stubs; full WPS crypto not implemented.
- **AP isolation detection** — heuristic only; requires extended passive capture.
- **OUI table** — abbreviated (~20 vendors); extend `WiFiUtils.h` as needed.
- **PMF audit** — conservative: flags all WPA2 APs without verified RSN capabilities field.
- **CAUSE CHAOS** — runs indefinitely until aborted with `` ` ``.

---

## Dependencies

Managed automatically by PlatformIO:

- [`m5stack/M5Unified`](https://github.com/m5stack/M5Unified) `^0.2.2`
- [`m5stack/M5Cardputer`](https://github.com/m5stack/M5Cardputer) `^1.0.1`
- ESP-IDF Arduino core (via `espressif32 ^6.9.0`) — provides `esp_wifi`, `WebServer`

---

## License

For educational and authorised security testing use only. See legal notice above.
