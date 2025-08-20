#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Local Port Auditor — Python 3.13
فقط پورت‌های در حال LISTEN روی همین دستگاه را گزارش می‌کند (بدون اسکن شبکه).
"""

from __future__ import annotations
import argparse, json
from collections import defaultdict
import psutil

def proto_name(c) -> str:
    # psutil returns socket type constants; map به TCP/UDP
    try:
        tname = c.type.name.lower()
    except Exception:
        tname = str(c.type).lower()
    if tname.startswith("sock_stream") or tname.startswith("tcp"):
        return "TCP"
    if tname.startswith("sock_dgram") or tname.startswith("udp"):
        return "UDP"
    return tname.upper()

def collect_listeners():
    listeners = defaultdict(list)
    for c in psutil.net_connections(kind="inet"):
        if not c.laddr:
            continue
        if c.status not in ("LISTEN", "NONE"):  # UDP معمولاً NONE
            continue
        proto = proto_name(c)
        ip, port = c.laddr.ip, c.laddr.port
        exe = None
        if c.pid:
            try:
                exe = psutil.Process(c.pid).name()
            except Exception:
                pass
        listeners[(proto, port)].append({"bind_ip": ip, "process": exe})
    return listeners

def print_table(listeners):
    if not listeners:
        print("No listening ports detected on this host.")
        return
    print(f"{'PROTO':<6} {'PORT':<6} {'BIND IP':<40} PROCESS")
    print("-" * 80)
    for (proto, port), items in sorted(listeners.items(), key=lambda t: (t[0][0], t[0][1])):
        for i, item in enumerate(items):
            proto_str = proto if i == 0 else ""
            port_str  = str(port) if i == 0 else ""
            print(f"{proto_str:<6} {port_str:<6} {item['bind_ip']:<40} {item['process'] or '-'}")

def main():
    ap = argparse.ArgumentParser(description="List local listening ports (no network scanning).")
    ap.add_argument("--json", action="store_true", help="Print results as JSON")
    ap.add_argument("--table", action="store_true", help="Print results as a text table (default)")
    ap.add_argument("--only", nargs="*", type=int, help="فقط پورت‌های مشخص‌شده را نشان بده (اختیاری)")
    args = ap.parse_args()

    listeners = collect_listeners()

    # فیلتر اختیاری
    if args.only:
        listeners = {k:v for k,v in listeners.items() if k[1] in set(args.only)}

    if args.json:
        out = []
        for (proto, port), items in listeners.items():
            out.append({
                "proto": proto, "port": port, "bindings": items,
                "well_known": {
                    22: "SSH", 53: "DNS", 80: "HTTP", 123: "NTP", 139: "NetBIOS",
                    443: "HTTPS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
                    6379: "Redis", 8000: "Dev HTTP", 8080: "Alt HTTP",
                }.get(port)
            })
        print(json.dumps(sorted(out, key=lambda x: (x["proto"], x["port"])), ensure_ascii=False, indent=2))
    else:
        print_table(listeners)

if __name__ == "__main__":
    main()