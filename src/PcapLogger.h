#pragma once

#include <Arduino.h>
#include <SD.h>
#include <cstdint>
#include "config.h"

// ============================================================
//  PcapLogger — writes raw 802.11 frames to SD in PCAP format
// ============================================================

// PCAP link type for 802.11 with radiotap header
#define PCAP_LINK_80211_RADIOTAP   127
#define PCAP_LINK_80211            105

#pragma pack(push, 1)
struct pcap_global_hdr {
    uint32_t magic_number  = 0xA1B2C3D4;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    int32_t  thiszone      = 0;
    uint32_t sigfigs       = 0;
    uint32_t snaplen       = 65535;
    uint32_t network       = PCAP_LINK_80211;
};

struct pcap_rec_hdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)

class PcapLogger {
public:
    PcapLogger() = default;

    // Open a new .pcap file on SD with timestamped name.
    // prefix: e.g. "recon", "deauth", "handshake"
    bool open(const char* prefix) {
        if (!SD.exists(SD_LOG_DIR)) {
            SD.mkdir(SD_LOG_DIR);
        }
        char path[64];
        uint32_t ts = millis() / 1000;
        snprintf(path, sizeof(path), "%s/%s_%lu.pcap",
                 SD_LOG_DIR, prefix, ts);
        _file = SD.open(path, FILE_WRITE);
        if (!_file) return false;

        pcap_global_hdr hdr{};
        hdr.network = PCAP_LINK_80211;
        _file.write(reinterpret_cast<const uint8_t*>(&hdr), sizeof(hdr));
        _file.flush();
        _open   = true;
        _bytes  = sizeof(hdr);
        return true;
    }

    // Append one frame.
    bool write(const uint8_t* data, uint32_t len) {
        if (!_open) return false;
        if (_bytes + sizeof(pcap_rec_hdr) + len > PCAP_MAX_FILE_SIZE) {
            return false;   // caller should rotate
        }
        uint32_t now_us = micros();
        pcap_rec_hdr rec{};
        rec.ts_sec  = now_us / 1000000;
        rec.ts_usec = now_us % 1000000;
        rec.incl_len = len;
        rec.orig_len = len;
        _file.write(reinterpret_cast<const uint8_t*>(&rec), sizeof(rec));
        _file.write(data, len);
        _file.flush();
        _bytes += sizeof(rec) + len;
        _count++;
        return true;
    }

    void close() {
        if (_open) { _file.close(); _open = false; }
    }

    bool     isOpen()  const { return _open;  }
    uint32_t count()   const { return _count; }
    uint32_t bytes()   const { return _bytes; }

private:
    File     _file;
    bool     _open   = false;
    uint32_t _count  = 0;
    uint32_t _bytes  = 0;
};
