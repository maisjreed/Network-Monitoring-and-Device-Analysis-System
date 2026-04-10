"""
Fast ARP-based subnet scanner

Requirements:
  pip install scapy

Windows dependencies:
  - Run as Administrator (raw sockets need elevated privileges).
  - Install Npcap (https://npcap.com) — scapy's srp() requires a packet
    capture driver (Npcap or the legacy WinPcap) to send/receive layer-2
    frames.  Without it srp() raises "No valid interface" at runtime.
"""

import ipaddress
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
from scapy.sendrecv import srp            # type: ignore[import-untyped]


# ── Configuration ─────────────────────────────────────────────────────────────

SUBNET       = "192.168.1.0/24"   # Change to your local subnet
TIMEOUT      = 1                  # ARP reply wait time (seconds) — reduced for speed
MAX_WORKERS  = 64                 # Concurrent threads for DNS lookups
ARP_VERBOSE  = False              # Set True to see raw scapy output


# ── OUI / Vendor database ─────────────────────────────────────────────────────

_OUI_CACHE_FILE = "oui_cache.txt"

# Built-in fallback — used when the IEEE cache file is absent.
_OUI_BUILTIN: dict[str, str] = {
    "00:50:56": "VMware",       "00:0C:29": "VMware",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi", "00:1A:79": "Cisco",
    "00:0F:66": "Cisco",        "04:18:D6": "Cisco",
    "3C:22:FB": "Apple",        "A4:C3:F0": "Apple",
    "18:65:90": "Apple",        "AC:DE:48": "Apple",
    "00:15:5D": "Microsoft",    "00:E0:4C": "Realtek",
    "18:31:BF": "Amazon",       "10:02:B5": "Samsung",
    "F4:EC:38": "TP-Link",      "50:C7:BF": "TP-Link",
    "14:CC:20": "TP-Link",      "C8:3A:35": "Tenda",
    "00:1D:0F": "Netgear",      "20:4E:7F": "Netgear",
    "1C:3B:F3": "Netgear",      "00:1E:58": "D-Link",
    "00:1C:DF": "Belkin",       "B0:BE:76": "Huawei",
    "00:18:82": "Huawei",       "00:0A:F7": "Aruba",
}

_OUI_FULL: dict[str, str] = {}


def _load_oui_database() -> None:
    """Load the IEEE OUI database from the local cache file, if present."""
    if not os.path.exists(_OUI_CACHE_FILE):
        return
    try:
        with open(_OUI_CACHE_FILE, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                m = re.match(
                    r"([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)",
                    line,
                )
                if m:
                    prefix = m.group(1).upper().replace("-", ":")
                    _OUI_FULL[prefix] = m.group(2).strip()
    except Exception:
        pass


def lookup_vendor(mac: str) -> str:
    """Return the manufacturer name for a MAC address."""
    prefix = mac.upper().replace("-", ":")[:8]
    if _OUI_FULL:
        return _OUI_FULL.get(prefix, _OUI_BUILTIN.get(prefix, "Unknown"))
    return _OUI_BUILTIN.get(prefix, "Unknown")


# ── ARP host discovery ─────────────────────────────────────────────────────────

def arp_scan(subnet: str) -> list[dict]:
    """
    Send ARP broadcast requests for every host in `subnet`.
    Returns a list of {'ip': ..., 'mac': ...} dicts for hosts that replied.
    """
    network = ipaddress.ip_network(subnet, strict=False)

    # Build a single broadcast ARP request for the whole subnet
    arp_request = ARP(pdst=str(network))
    broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet      = broadcast / arp_request

    answered, _ = srp(packet, timeout=TIMEOUT, verbose=ARP_VERBOSE)

    hosts = []
    for sent, received in answered:
        mac = received.hwsrc.upper()
        hosts.append({
            "ip":     received.psrc,
            "mac":    mac,
            "vendor": lookup_vendor(mac),
        })

    # Sort numerically across all octets so /16 and other subnets sort correctly.
    hosts.sort(key=lambda h: tuple(int(o) for o in h["ip"].split(".")))
    return hosts


# ── Reverse DNS lookup ────────────────────────────────────────────────────────

def reverse_dns(ip: str) -> str:
    """Return the PTR hostname for `ip`, or the IP itself on failure."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except OSError:
        # Covers socket.herror (no PTR record), socket.gaierror (DNS error),
        # and socket.timeout (slow/unresponsive DNS server).
        return ip


# ── Enrich hosts with hostnames concurrently ──────────────────────────────────

def enrich_with_hostnames(hosts: list[dict], max_workers: int = MAX_WORKERS) -> list[dict]:
    """
    Perform reverse DNS lookups for all hosts in parallel.
    Adds a 'hostname' key to each host dict in-place.
    """
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {
            executor.submit(reverse_dns, host["ip"]): host
            for host in hosts
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                host["hostname"] = future.result()
            except Exception:
                # Fallback: use the IP if the lookup raised an unexpected error.
                host["hostname"] = host["ip"]

    return hosts


# ── Output ────────────────────────────────────────────────────────────────────

def print_results(hosts: list[dict]) -> None:
    if not hosts:
        print("No active hosts found.")
        return

    # Clamp column widths to be at least as wide as the header labels.
    col_ip       = max(len(h["ip"])       for h in hosts)
    col_mac      = max(len(h["mac"])      for h in hosts)
    col_hostname = max(len(h["hostname"]) for h in hosts)
    col_vendor   = max(len(h["vendor"])   for h in hosts)
    col_ip       = max(col_ip,       len("IP ADDRESS"))
    col_mac      = max(col_mac,      len("MAC ADDRESS"))
    col_hostname = max(col_hostname, len("HOSTNAME"))
    col_vendor   = max(col_vendor,   len("VENDOR / BRAND"))

    header = (
        f"{'IP ADDRESS':<{col_ip}}  "
        f"{'MAC ADDRESS':<{col_mac}}  "
        f"{'VENDOR / BRAND':<{col_vendor}}  "
        f"{'HOSTNAME':<{col_hostname}}"
    )
    separator = "-" * len(header)

    print(f"\nScan results for {SUBNET}")
    print(separator)
    print(header)
    print(separator)
    for h in hosts:
        print(
            f"{h['ip']:<{col_ip}}  "
            f"{h['mac']:<{col_mac}}  "
            f"{h['vendor']:<{col_vendor}}  "
            f"{h['hostname']:<{col_hostname}}"
        )
    print(separator)
    print(f"Total active hosts: {len(hosts)}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    _load_oui_database()
    print(f"Scanning {SUBNET} via ARP …")
    hosts = arp_scan(SUBNET)
    print(f"ARP sweep complete — {len(hosts)} host(s) responded. Resolving hostnames …")
    enrich_with_hostnames(hosts)
    print_results(hosts)


if __name__ == "__main__":
    main()
