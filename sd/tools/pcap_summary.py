#!/usr/bin/env python3
"""
pcap_summary.py — Mirage PCAP analyser
Summarises 802.11 captures produced by the Mirage firmware.

Usage:
    python3 pcap_summary.py [file1.pcap [file2.pcap ...]]
    python3 pcap_summary.py /path/to/mirage/*.pcap

Requires: scapy  (pip install scapy)
"""

import sys
import os
from collections import defaultdict, Counter

try:
    from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11ProbeReq, \
                          Dot11ProbeResp, Dot11Deauth, Dot11Disas, \
                          Dot11EAPOL, Dot11Elt
except ImportError:
    sys.exit("ERROR: scapy not found. Install with: pip install scapy")


# ── helpers ──────────────────────────────────────────────────────────────────

def mac(addr):
    return addr.upper() if addr else "FF:FF:FF:FF:FF:FF"

def ssid_from_beacon(pkt):
    if pkt.haslayer(Dot11Elt):
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 0:
                try:
                    return elt.info.decode(errors="replace") or "<hidden>"
                except Exception:
                    return "<hidden>"
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    return "<unknown>"

def channel_from_beacon(pkt):
    if pkt.haslayer(Dot11Elt):
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 3 and elt.len == 1:
                return int.from_bytes(elt.info, "big")
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    return None

def encryption_from_beacon(pkt):
    cap = getattr(pkt, "cap", None)
    tags = []
    if pkt.haslayer(Dot11Elt):
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 48:
                tags.append("WPA2")
            elif elt.ID == 221 and elt.info[:4] == b'\x00\x50\xf2\x01':
                tags.append("WPA")
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    if not tags:
        if cap and cap & 0x10:
            return "WEP"
        return "OPEN"
    return "/".join(dict.fromkeys(tags))   # deduplicated, order-preserved


# ── per-file analysis ─────────────────────────────────────────────────────────

def analyse(path):
    print(f"\n{'='*60}")
    print(f"  {os.path.basename(path)}")
    print(f"{'='*60}")

    try:
        pkts = rdpcap(path)
    except Exception as e:
        print(f"  ERROR reading file: {e}")
        return

    total = len(pkts)
    print(f"  Total frames : {total}")
    if total == 0:
        return

    aps       = {}          # bssid -> {ssid, channel, enc, rssi}
    probes    = defaultdict(set)   # client_mac -> set of probed SSIDs
    deauths   = Counter()   # (src, dst) -> count
    handshake = defaultdict(set)   # bssid -> set of EAPOL msg numbers seen
    frame_types = Counter()

    for pkt in pkts:
        if not pkt.haslayer(Dot11):
            continue

        d = pkt[Dot11]
        ftype = (d.type, d.subtype)
        frame_types[ftype] += 1

        # Beacons / Probe Responses → AP inventory
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = mac(d.addr3)
            if bssid not in aps:
                aps[bssid] = {
                    "ssid":  ssid_from_beacon(pkt),
                    "ch":    channel_from_beacon(pkt),
                    "enc":   encryption_from_beacon(pkt),
                    "rssi":  getattr(pkt, "dBm_AntSignal", None),
                }

        # Probe Requests → client behaviour
        elif pkt.haslayer(Dot11ProbeReq):
            client = mac(d.addr2)
            ssid   = ssid_from_beacon(pkt)
            probes[client].add(ssid)

        # Deauth / Disassoc
        elif pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            deauths[(mac(d.addr2), mac(d.addr1))] += 1

        # EAPOL (4-way handshake)
        elif pkt.haslayer(Dot11EAPOL):
            bssid = mac(d.addr3)
            # EAPOL Key Descriptor byte 6 bit 3 = Install, bit 7 = ACK
            # Simple heuristic: count unique EAPOL frames per BSSID
            handshake[bssid].add(bytes(pkt[Dot11EAPOL])[:4])

    # ── AP summary ──
    if aps:
        print(f"\n  APs seen ({len(aps)})")
        print(f"  {'BSSID':<19} {'CH':>3}  {'ENC':<8} {'SSID'}")
        print(f"  {'-'*19}  {'-'*3}  {'-'*8}  {'-'*30}")
        for bssid, info in sorted(aps.items(), key=lambda x: x[1]["ssid"]):
            ch  = str(info["ch"]) if info["ch"] else "?"
            enc = info["enc"]
            print(f"  {bssid:<19} {ch:>3}  {enc:<8}  {info['ssid']}")

    # ── Deauth summary ──
    if deauths:
        print(f"\n  Deauth / Disassoc frames ({sum(deauths.values())} total)")
        top = deauths.most_common(10)
        for (src, dst), cnt in top:
            print(f"    {src}  →  {dst:<20}  {cnt:>4} frames")
        if len(deauths) > 10:
            print(f"    … and {len(deauths)-10} more pairs")

    # ── Probe requests ──
    if probes:
        print(f"\n  Probe requests from {len(probes)} client(s)")
        for client, ssids in sorted(probes.items()):
            ssid_str = ", ".join(sorted(ssids)[:5])
            if len(ssids) > 5:
                ssid_str += f" … (+{len(ssids)-5})"
            print(f"    {client}  →  {ssid_str}")

    # ── Handshake ──
    if handshake:
        print(f"\n  EAPOL frames captured for {len(handshake)} BSSID(s)")
        for bssid, frames in handshake.items():
            ssid = aps.get(bssid, {}).get("ssid", "?")
            print(f"    {bssid}  ({ssid})  — {len(frames)} unique EAPOL frame(s)")

    # ── Frame type breakdown ──
    print(f"\n  Frame type breakdown")
    labels = {
        (0, 0): "Assoc Req",   (0, 1): "Assoc Resp",
        (0, 2): "Reassoc Req", (0, 4): "Probe Req",
        (0, 5): "Probe Resp",  (0, 8): "Beacon",
        (0,10): "Disassoc",    (0,11): "Auth",
        (0,12): "Deauth",      (1, 0): "Block Ack Req",
        (1, 1): "Block Ack",   (2, 0): "Data",
        (2, 4): "Null",        (2, 8): "QoS Data",
    }
    for ftype, cnt in frame_types.most_common(12):
        label = labels.get(ftype, f"type={ftype[0]}/sub={ftype[1]}")
        print(f"    {label:<20}  {cnt:>6}")


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    files = sys.argv[1:]
    if not files:
        # try current directory
        files = [f for f in os.listdir(".") if f.endswith(".pcap")]
        if not files:
            sys.exit("Usage: pcap_summary.py file1.pcap [file2.pcap ...]")

    for f in files:
        analyse(f)

    print()

if __name__ == "__main__":
    main()
