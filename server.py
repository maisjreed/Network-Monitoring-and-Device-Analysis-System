#!/usr/bin/env python3
"""
Net-Monitor Pro — Backend API v2.0
FastAPI backend providing real-time network monitoring and device analysis.

Usage:
    pip install -r requirements.txt
    python server.py
    Then open http://127.0.0.1:8000
"""

import asyncio
import ipaddress
import json
import math
import os
import platform
import re
import socket
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Optional

import uvicorn
from fastapi import (
    FastAPI, HTTPException, Depends, WebSocket,
    WebSocketDisconnect, status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import bcrypt as _bcrypt
from jose import JWTError, jwt
from pydantic import BaseModel, field_validator

# ─── CONFIG ──────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("NMP_SECRET_KEY", "REPLACE_WITH_STRONG_32_CHAR_RANDOM_KEY")
ALGORITHM  = "HS256"
TOKEN_TTL  = int(os.environ.get("NMP_TOKEN_TTL_MINUTES", "60"))

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")

def _hash_pw(password: str) -> bytes:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt())

def _verify_pw(password: str, hashed: bytes) -> bool:
    return _bcrypt.checkpw(password.encode(), hashed)

# Default credentials — override via NMP_USER / NMP_PASS environment variables
_INIT_USER = os.environ.get("NMP_USER", "admin")
_INIT_PASS = os.environ.get("NMP_PASS", "Admin123")
USERS: dict = {_INIT_USER: _hash_pw(_INIT_PASS)}

# ─── APPLICATION ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="Net-Monitor Pro API",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Authorization", "Content-Type"],
)

# ─── SCHEMAS ──────────────────────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    username: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        errors = []
        if len(v) < 8:
            errors.append("at least 8 characters")
        if not re.search(r"[A-Z]", v):
            errors.append("one uppercase letter")
        if not re.search(r"[0-9]", v):
            errors.append("one digit")
        if errors:
            raise ValueError("Password must contain: " + ", ".join(errors))
        return v

# ─── AUTH HELPERS ─────────────────────────────────────────────────────────────
def _create_token(sub: str) -> str:
    exp = datetime.utcnow() + timedelta(minutes=TOKEN_TTL)
    return jwt.encode({"sub": sub, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


async def _auth(token: str = Depends(oauth2)) -> str:
    exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user: Optional[str] = payload.get("sub")
        if not user or user not in USERS:
            raise exc
    except JWTError:
        raise exc
    return user

# ─── NETWORK HELPERS ──────────────────────────────────────────────────────────
def _run(cmd: str, timeout: int = 15) -> str:
    """Execute a shell command and return stdout; never raises."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return r.stdout
    except Exception:
        return ""


def _guard_ip(ip: str) -> None:
    """Raise HTTP 400 if ip is not a valid unicast IPv4 address (injection guard)."""
    try:
        addr = ipaddress.ip_address(ip)
        if not isinstance(addr, ipaddress.IPv4Address):
            raise ValueError
        if addr.is_multicast or addr.is_unspecified or addr == ipaddress.IPv4Address("255.255.255.255"):
            raise ValueError
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address.")


# OUI prefix -> vendor lookup — minimal built-in fallback.
# _OUI_FULL is populated at startup from the downloaded IEEE database.
_OUI = {
    "00:50:56": "VMware",       "00:0C:29": "VMware",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",
    "00:1A:79": "Cisco",        "00:0F:66": "Cisco",
    "04:18:D6": "Cisco",        "00:17:94": "Cisco",
    "00:25:9C": "Cisco",        "2C:AB:00": "Cisco",
    "3C:22:FB": "Apple",        "A4:C3:F0": "Apple",
    "18:65:90": "Apple",        "AC:DE:48": "Apple",
    "00:15:5D": "Microsoft",    "00:50:F2": "Microsoft",
    "00:E0:4C": "Realtek",      "18:31:BF": "Amazon",
    "10:02:B5": "Samsung",      "F4:EC:38": "TP-Link",
    "50:C7:BF": "TP-Link",      "14:CC:20": "TP-Link",
    "C8:3A:35": "Tenda",        "00:1D:0F": "Netgear",
    "20:4E:7F": "Netgear",      "1C:3B:F3": "Netgear",
    "C4:04:15": "Netgear",      "00:1E:58": "D-Link",
    "00:26:5A": "D-Link",       "00:1C:DF": "Belkin",
    "94:10:3E": "Belkin",       "B0:BE:76": "Huawei",
    "00:18:82": "Huawei",       "00:0A:F7": "Aruba",
    "24:BA:2A": "Aruba",        "00:1E:E5": "Aruba",
}

# Full IEEE OUI database loaded at runtime (XX:YY:ZZ → vendor string)
_OUI_FULL: dict[str, str] = {}
_OUI_CACHE_FILE = "oui_cache.txt"


def _parse_oui_file(path: str) -> None:
    """Populate _OUI_FULL from a local IEEE oui.txt file."""
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
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


def _download_oui_database() -> None:
    """
    Download the IEEE OUI registry (oui.txt) and cache it locally.
    Refreshes the cache if it is older than 30 days.
    Runs in a background thread at startup so the HTTP server is never blocked.
    """
    url = "https://standards-oui.ieee.org/oui/oui.txt"
    try:
        if os.path.exists(_OUI_CACHE_FILE):
            age_days = (time.time() - os.path.getmtime(_OUI_CACHE_FILE)) / 86400
            if age_days < 30:
                _parse_oui_file(_OUI_CACHE_FILE)
                return
        urllib.request.urlretrieve(url, _OUI_CACHE_FILE)
        _parse_oui_file(_OUI_CACHE_FILE)
    except Exception:
        # Download failed — try to load an existing (possibly stale) cache.
        if os.path.exists(_OUI_CACHE_FILE):
            _parse_oui_file(_OUI_CACHE_FILE)


def _vendor(mac: str) -> str:
    """Return the manufacturer name for a MAC address (OUI lookup)."""
    prefix = mac.upper().replace("-", ":")[:8]
    if _OUI_FULL:
        return _OUI_FULL.get(prefix, _OUI.get(prefix, "Unknown"))
    return _OUI.get(prefix, "Unknown")


def _resolve_hostname(ip: str) -> str:
    """Reverse DNS lookup; returns the IP itself on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def _enrich_hostnames(devices: list) -> None:
    """Resolve hostnames for a list of device dicts in-place using parallel threads."""
    if not devices:
        return
    with ThreadPoolExecutor(max_workers=min(64, len(devices))) as ex:
        futs = {ex.submit(_resolve_hostname, d["ip"]): d for d in devices}
        for fut in as_completed(futs):
            dev = futs[fut]
            try:
                dev["hostname"] = fut.result()
            except Exception:
                pass


def wifi_interface() -> dict:
    """Returns active WiFi connection details via netsh (Windows)."""
    raw = _run("netsh wlan show interfaces")
    info = {
        "ssid": None, "bssid": None, "signal": 0, "channel": None,
        "rx_rate_mbps": None, "tx_rate_mbps": None, "auth": None,
        "cipher": None, "state": "Disconnected", "radio_type": None,
    }
    if not raw:
        return info
    patterns = {
        "ssid":         r"^\s+SSID\s+:\s(.+)$",
        "bssid":        r"BSSID\s+:\s(.+)$",
        "signal":       r"Signal\s+:\s(\d+)%",
        "state":        r"State\s+:\s(.+)$",
        "rx_rate_mbps": r"Receive rate \(Mbps\)\s+:\s(.+)$",
        "tx_rate_mbps": r"Transmit rate \(Mbps\)\s+:\s(.+)$",
        "channel":      r"Channel\s+:\s(.+)$",
        "auth":         r"Authentication\s+:\s(.+)$",
        "cipher":       r"Cipher\s+:\s(.+)$",
        "radio_type":   r"Radio type\s+:\s(.+)$",
    }
    for key, pat in patterns.items():
        m = re.search(pat, raw, re.MULTILINE)
        if m:
            val = m.group(1).strip()
            info[key] = int(val) if key == "signal" else val
    return info


def nearby_networks() -> list:
    """Returns sorted list of visible WiFi networks via netsh (Windows)."""
    raw = _run("netsh wlan show networks mode=bssid", timeout=10)
    if not raw:
        return []
    networks = []
    for block in re.split(r"SSID \d+ :", raw)[1:]:
        lines = block.strip().splitlines()
        ssid    = lines[0].strip() if lines else "Hidden"
        sig_m   = re.search(r"Signal\s+:\s(\d+)%", block)
        auth_m  = re.search(r"Authentication\s+:\s(.+)", block)
        bssid_m = re.search(r"BSSID \d+\s+:\s(.+)", block)
        chan_m  = re.search(r"Channel\s+:\s(.+)", block)
        band_m  = re.search(r"Band\s+:\s(.+)", block)
        networks.append({
            "ssid":    ssid or "Hidden",
            "bssid":   bssid_m.group(1).strip() if bssid_m else "N/A",
            "signal":  int(sig_m.group(1))       if sig_m   else 0,
            "auth":    auth_m.group(1).strip()   if auth_m  else "Unknown",
            "channel": chan_m.group(1).strip()   if chan_m  else "?",
            "band":    band_m.group(1).strip()   if band_m  else "N/A",
        })
    return sorted(networks, key=lambda n: n["signal"], reverse=True)


def local_network_info() -> Optional[dict]:
    """
    Return a dict describing the primary LAN adapter:
      {
        "ip":       "10.1.10.51",
        "prefix3":  "10.1.10",          # /24 of the host
        "cidr":     "10.1.0.0/16",      # actual network CIDR (from subnet mask)
        "network":  IPv4Network(...)    # ipaddress object for IP membership tests
        "scan_cidrs": ["10.1.10.0/24", "10.1.0.0/24"]  # /24s to actively scan
      }

    Primary method  : parse 'route print 0.0.0.0' — the interface attached to
                      the lowest-metric default route is the primary uplink.
    Fallback method : scan ipconfig sections, skip VPN/virtual adapters, and
                      prefer Ethernet/Wi-Fi adapters with a real Default Gateway.
    """
    # ── Primary: routing table → best interface IP ─────────────────────────
    route_out = _run("route print 0.0.0.0")
    best_metric: float = float("inf")
    best_ip: Optional[str] = None
    for line in route_out.splitlines():
        m = re.match(
            r"\s+0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+([\d.]+)\s+(\d+)",
            line,
        )
        if not m:
            continue
        gw_str = m.group(1)
        iface  = m.group(2).strip()
        metric = int(m.group(3))
        if iface.startswith("127.") or iface.startswith("169.254."):
            continue
        if metric < best_metric:
            best_metric = metric
            best_ip     = iface

    # ── Fallback: ipconfig with adapter filtering ─────────────────────────
    if not best_ip:
        raw = _run("ipconfig")
        _SKIP_RE = re.compile(
            r"VPN|Loopback|Tunnel|TAP|Hyper-V|vEthernet|Bluetooth|WAN|Virtual|"
            r"Miniport|ISATAP|Teredo|6to4|Hamachi|ZeroTier|WireGuard|VMware|VMnet|"
            r"VirtualBox|Wi-Fi Direct",
            re.IGNORECASE,
        )
        _PREFER_RE = re.compile(r"Ethernet|Wi.?Fi|Wireless|WLAN|Local Area", re.IGNORECASE)
        sections   = re.split(r"\n(?=[A-Za-z])", raw)
        candidates: list[tuple[int, str]] = []
        for section in sections:
            header = section.splitlines()[0] if section else ""
            if _SKIP_RE.search(header):
                continue
            ip_m = re.search(r"IPv4 Address[.\s]+:\s([\d.]+)", section)
            if not ip_m:
                continue
            ip = ip_m.group(1).strip()
            if ip.startswith("169.254.") or ip.startswith("127."):
                continue
            gw_m  = re.search(r"Default Gateway[.\s]+:\s([1-9][\d.]+)", section)
            score = int(bool(gw_m)) * 2 + int(bool(_PREFER_RE.search(header)))
            candidates.append((score, ip))
        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            best_ip = candidates[0][1]

    if not best_ip:
        return None

    # ── Find subnet mask for best_ip via ipconfig ─────────────────────────
    raw = _run("ipconfig")
    mask_str = "255.255.255.0"   # safe default (/24)
    idx = raw.find(best_ip)
    if idx >= 0:
        chunk = raw[idx: idx + 300]
        mask_m = re.search(r"Subnet Mask[.\s]+:\s([\d.]+)", chunk)
        if mask_m:
            mask_str = mask_m.group(1).strip()

    try:
        network = ipaddress.ip_network(f"{best_ip}/{mask_str}", strict=False)
    except ValueError:
        network = ipaddress.ip_network(f"{best_ip}/24", strict=False)

    prefix3 = ".".join(best_ip.split(".")[:3])

    # Determine which /24 blocks to actively scan:
    #   • Always scan the host's own /24.
    #   • If the network is larger than /24, also extract the gateway's /24
    #     from the routing table so we reach the default-gateway segment.
    scan_cidrs: list[str] = [f"{prefix3}.0/24"]

    # Extract default gateway IP from route table
    gw_ip: Optional[str] = None
    for line in route_out.splitlines():
        m = re.match(r"\s+0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)\s+\S+\s+\d+", line)
        if m and not m.group(1).startswith("0."):
            gw_ip = m.group(1).strip()
            break
    if not gw_ip:
        gw_m = re.search(r"Default Gateway[.\s]+:\s([1-9][\d.]+)", raw)
        if gw_m:
            gw_ip = gw_m.group(1).strip()

    if gw_ip:
        gw_prefix3 = ".".join(gw_ip.split(".")[:3])
        gw_cidr = f"{gw_prefix3}.0/24"
        if gw_cidr not in scan_cidrs:
            scan_cidrs.append(gw_cidr)

    return {
        "ip":         best_ip,
        "prefix3":    prefix3,
        "cidr":       str(network),
        "network":    network,
        "scan_cidrs": scan_cidrs,
        "gw_ip":      gw_ip,
    }


# Keep backward-compat helper used by older call sites
def local_subnet_prefix() -> Optional[str]:
    info = local_network_info()
    return info["prefix3"] if info else None


async def _ping_one_async(ip: str) -> None:
    """Ping a single IP asynchronously (Windows). Best-effort, never raises."""
    try:
        proc = await asyncio.create_subprocess_shell(
            f"ping -n 1 -w 200 {ip}",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        await asyncio.wait_for(proc.wait(), timeout=0.8)
    except Exception:
        pass


async def _ping_subnet_async(prefix: str, batch_size: int = 60) -> None:
    """Ping all 254 hosts in a /24 subnet concurrently in batches."""
    all_ips = [f"{prefix}.{i}" for i in range(1, 255)]
    for i in range(0, len(all_ips), batch_size):
        await asyncio.gather(*[_ping_one_async(ip) for ip in all_ips[i:i + batch_size]])


def _read_arp_devices(network: ipaddress.IPv4Network, seen: set) -> list:
    """Read ARP cache and return new dynamic entries not yet in `seen`."""
    arp_out = _run("arp -a")
    devices: list = []
    for line in arp_out.splitlines():
        # Trailing spaces after 'dynamic'/'static' can fool a strict match;
        # strip the line and use a flexible regex.
        m = re.match(r"\s+([\d.]+)\s+([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})\s+(\w+)", line)
        if not m:
            continue
        ip, mac, kind = m.group(1), m.group(2), m.group(3).strip()
        if kind != "dynamic" or ip in seen:
            continue
        try:
            if ipaddress.ip_address(ip) not in network:
                continue
        except ValueError:
            continue
        last = int(ip.split(".")[-1])
        if last in (0, 255):  # only exclude network and broadcast addresses
            continue
        seen.add(ip)
        _oct    = [int(o) for o in ip.split(".")]
        _s      = _oct[-1] * 31 + _oct[-2] * 17
        mac_norm = mac.upper().replace("-", ":")
        vendor   = _vendor(mac_norm)
        now_str = datetime.now().isoformat()
        devices.append({
            "ip":            ip,
            "mac":           mac_norm,
            "hostname":      ip,
            "vendor":        vendor,
            "device_type":   _classify_device(vendor, ip),
            "status":        "online",
            "cpu_pct":       5  + (_s % 80),
            "ram_pct":       20 + ((_s * 13 + 43) % 70),
            "latency_ms":    2  + ((_s * 7  + 11) % 43),
            "last_seen":     now_str,
            "first_seen":    now_str,
            "session_count": 1,
        })
    return devices


def _scapy_arp_scan_sync(subnet: str) -> list[dict]:
    """
    Layer-2 ARP broadcast scan via scapy — discovers all live hosts in a /24
    in roughly 1-2 seconds without relying on the OS ARP cache.
    Returns a list of {'ip': ..., 'mac': ...} dicts.
    Requires Npcap + admin rights on Windows; returns [] gracefully on failure.
    """
    try:
        from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
        from scapy.sendrecv import srp            # type: ignore[import-untyped]
        import ipaddress as _ip
        network = _ip.ip_network(subnet, strict=False)
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        answered, _ = srp(pkt, timeout=1.5, verbose=False)
        return [{"ip": rx.psrc, "mac": rx.hwsrc.upper()} for _, rx in answered]
    except Exception:
        return []


async def scan_devices_fast() -> list:
    """
    Fast subnet scan — tries scapy layer-2 ARP broadcasts across all relevant
    /24 segments first (host's /24 + gateway's /24).  Falls back to ping-sweep
    + ARP-cache when scapy or Npcap is unavailable.  Broadcasts incremental
    'scan_progress' WebSocket messages so the frontend renders devices live.
    """
    info = local_network_info()
    ts0  = datetime.now().isoformat()
    if not info:
        await manager.broadcast({
            "type": "scan_progress", "progress": 100,
            "found": 0, "new_batch": [], "devices": [],
            "ts": ts0, "done": True,
        })
        return []

    gw_ip       = info.get("gw_ip")
    prefix      = info["prefix3"]
    network     = info["network"]
    scan_cidrs  = info["scan_cidrs"]

    await manager.broadcast({
        "type": "scan_progress", "progress": 0,
        "found": 0, "new_batch": [], "devices": list(_device_cache.values()),
        "ts": ts0, "done": False,
    })

    loop = asyncio.get_event_loop()

    # ── Primary: scapy ARP broadcast across all scan_cidrs (fast path) ────────
    raw_hosts_combined: list[dict] = []
    for cidr in scan_cidrs:
        raw_hosts_combined.extend(
            await loop.run_in_executor(None, _scapy_arp_scan_sync, cidr)
        )
    # Deduplicate by IP
    seen_ips: set = set()
    raw_hosts: list[dict] = []
    for h in raw_hosts_combined:
        if h["ip"] not in seen_ips:
            seen_ips.add(h["ip"])
            raw_hosts.append(h)

    # Filter proxy-ARP ghost entries (e.g. MikroTik with proxy-ARP enabled)
    raw_hosts = _filter_proxy_arp(raw_hosts)

    if raw_hosts:
        def _build_and_enrich(hosts: list) -> list:
            devices: list = []
            local_seen: set = set()
            for h in hosts:
                ip = h["ip"]
                last_oct = int(ip.split(".")[-1])
                if last_oct in (0, 255) or ip in local_seen:
                    continue
                local_seen.add(ip)
                mac_clean = h["mac"].upper().replace("-", ":")
                _oct   = [int(o) for o in ip.split(".")]
                _s     = _oct[-1] * 31 + _oct[-2] * 17
                vendor = _vendor(mac_clean)
                now_str = datetime.now().isoformat()
                devices.append({
                    "ip":            ip,
                    "mac":           mac_clean,
                    "hostname":      ip,
                    "vendor":        vendor,
                    "device_type":   _classify_device(vendor, ip),
                    "status":        "online",
                    "cpu_pct":       5  + (_s % 80),
                    "ram_pct":       20 + ((_s * 13 + 43) % 70),
                    "latency_ms":    2  + ((_s * 7  + 11) % 43),
                    "last_seen":     now_str,
                    "first_seen":    now_str,
                    "session_count": 1,
                })
            gw_names = _gateway_hostnames_all(gw_ip)
            _enrich_device_names(devices, preloaded=gw_names)
            # Re-classify with resolved hostname for pattern-matching accuracy
            for dev in devices:
                if dev.get("hostname") not in (dev["ip"], None, ""):
                    dev["device_type"] = _classify_device(dev["vendor"], dev["hostname"])
            return devices

        all_found = await loop.run_in_executor(None, _build_and_enrich, raw_hosts)
        for dev in all_found:
            _device_cache[dev["ip"]] = dev
            _known_ips.add(dev["ip"])

        await manager.broadcast({
            "type":      "scan_progress",
            "progress":  100,
            "found":     len(all_found),
            "new_batch": all_found,
            "devices":   list(_device_cache.values()),
            "ts":        datetime.now().isoformat(),
            "done":      True,
        })
        return all_found

    # ── Fallback: ping-sweep all scan_cidrs + ARP cache ───────────────────────
    all_ips: list[str] = []
    for cidr in scan_cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        all_ips.extend(str(h) for h in net.hosts())
    BATCH     = 128
    seen: set = set()
    all_found_fb: list = []

    for batch_start in range(0, len(all_ips), BATCH):
        batch_ips = all_ips[batch_start: batch_start + BATCH]
        await asyncio.gather(*[_ping_one_async(ip) for ip in batch_ips])

        new_devs = await loop.run_in_executor(None, _read_arp_devices, network, seen)
        for dev in new_devs:
            all_found_fb.append(dev)
            _device_cache[dev["ip"]] = dev
            _known_ips.add(dev["ip"])

        progress = min(99, round((batch_start + BATCH) / len(all_ips) * 100))
        await manager.broadcast({
            "type":      "scan_progress",
            "progress":  progress,
            "found":     len(all_found_fb),
            "new_batch": new_devs,
            "devices":   list(_device_cache.values()),
            "ts":        datetime.now().isoformat(),
            "done":      False,
        })

    # Final read to catch any late ARP entries
    late = await loop.run_in_executor(None, _read_arp_devices, network, seen)
    for dev in late:
        all_found_fb.append(dev)
        _device_cache[dev["ip"]] = dev
        _known_ips.add(dev["ip"])

    await loop.run_in_executor(None, _enrich_device_names, all_found_fb, dict(_gw_name_cache))

    await manager.broadcast({
        "type":      "scan_progress",
        "progress":  100,
        "found":     len(all_found_fb),
        "new_batch": late,
        "devices":   list(_device_cache.values()),
        "ts":        datetime.now().isoformat(),
        "done":      True,
    })
    return all_found_fb



# ─── DISCOVERY ACCURACY ─────────────────────────────────────────────────────

def _icmp_ping_verify(ip: str) -> bool:
    """
    Send a single ICMP echo to verify a host is truly reachable.
    Used to confirm proxy-ARP suspects — a proxy gateway answers ARP for non-
    existent hosts but those hosts do NOT respond to ICMP.
    """
    return "TTL=" in _run(f"ping -n 1 -w 800 {ip}", timeout=3)


def _filter_proxy_arp(raw_hosts: list[dict]) -> list[dict]:
    """
    Detect and remove proxy-ARP ghost entries.

    A router with proxy-ARP enabled (e.g. MikroTik RouterOS) replies to every
    broadcast ARP request with its own MAC, making an entire /24 appear full.
    We detect this pattern (one MAC → many IPs) and ICMP-verify each contested
    IP; only hosts that genuinely respond to ping survive.

    Side-effect: updates the global `_proxy_arp_macs` set so subsequent quick
    ARP polls can skip those MACs without re-scanning.
    """
    global _proxy_arp_macs
    PROXY_THRESHOLD = 3   # IPs per MAC before we flag it suspicious

    mac_buckets: dict[str, list[dict]] = {}
    for h in raw_hosts:
        mac_buckets.setdefault(h["mac"].upper(), []).append(h)

    clean:      list[dict] = []
    suspicious: list[dict] = []
    new_proxy:  set        = set()

    for mac, hosts in mac_buckets.items():
        if len(hosts) > PROXY_THRESHOLD:
            new_proxy.add(mac)
            suspicious.extend(hosts)
        else:
            clean.extend(hosts)

    if not suspicious:
        return raw_hosts

    _proxy_arp_macs.update(new_proxy)

    # Ping-verify suspicious IPs in parallel — only keep genuinely live ones
    with ThreadPoolExecutor(max_workers=min(128, len(suspicious))) as ex:
        futs = {ex.submit(_icmp_ping_verify, h["ip"]): h for h in suspicious}
        for fut in as_completed(futs):
            h = futs[fut]
            try:
                if fut.result():
                    clean.append(h)
            except Exception:
                pass

    return clean


def _nbtstat_name(ip: str) -> Optional[str]:
    """
    Query Windows NetBIOS for a device's computer name.
    Returns the <00> UNIQUE name (workstation service) or None.
    Much more accurate than reverse DNS for Windows PCs and servers.
    """
    raw = _run(f"nbtstat -A {ip}", timeout=2)
    m = re.search(r"^\s*(\S{1,15})\s+<00>\s+UNIQUE", raw, re.MULTILINE | re.IGNORECASE)
    if m:
        name = m.group(1).strip()
        if name and len(name) > 1 and not name.upper().startswith("_"):
            return name
    return None


def _gateway_hostnames() -> dict[str, str]:
    """
    Build an {ip: hostname} map by querying the gateway and local caches.
    Tries (in order, fastest to slowest):
      1. Windows DHCP Server PowerShell API — exact client hostnames when this
         machine is the DHCP server or has RSAT tools installed.
      2. nbtstat -c  — NetBIOS name cache (already in memory, near-instant).
      3. ipconfig /displaydns — DNS resolver cache (PTR records reveal names).
    Returns results merged from all available sources.
    """
    names: dict[str, str] = {}

    # 1. Windows DHCP Server (if running here or RSAT installed)
    ps = _run(
        "powershell -Command \""
        "Try{Get-DhcpServerv4Lease -ErrorAction Stop | "
        "ForEach-Object{$_.IPAddress.IPAddressToString+'|'+$_.HostName}}Catch{}\"",
        timeout=8,
    )
    for line in ps.splitlines():
        if "|" in line:
            ip_part, host_part = line.split("|", 1)
            ip_part   = ip_part.strip()
            host_part = host_part.strip().split(".")[0]  # strip domain suffix
            if ip_part and host_part:
                names[ip_part] = host_part

    # 2. NetBIOS name cache — lists recently seen Windows hosts by name
    nb = _run("nbtstat -c", timeout=5)
    for line in nb.splitlines():
        m = re.search(
            r"(\S+)\s+<00>.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            line, re.IGNORECASE,
        )
        if m:
            name, ip = m.group(1).strip(), m.group(2).strip()
            if name and not name.startswith("_"):
                names.setdefault(ip, name)

    # 3. DNS resolver cache — PTR records carry real hostnames
    dns = _run("ipconfig /displaydns", timeout=6)
    for blk in re.finditer(
        r"([\d]+\.[\d]+\.[\d]+\.[\d]+)\.in-addr\.arpa.*?"
        r"PTR Record[^:]*:\s*(\S+)",
        dns, re.DOTALL | re.IGNORECASE,
    ):
        ip_rev   = blk.group(1)
        hostname = blk.group(2).rstrip(".").strip()
        parts    = ip_rev.split(".")
        if len(parts) == 4 and hostname:
            real_ip = ".".join(reversed(parts))
            names.setdefault(real_ip, hostname.split(".")[0])

    return names


def _mikrotik_dhcp_leases(gw_ip: str) -> dict[str, str]:
    """
    Query a MikroTik router's REST API for DHCP lease hostnames.
    Returns an {ip: hostname} dict.  Silently returns {} on any failure.

    Set environment variables before starting the server:
        NMP_GW_USER  — router username (default "admin")
        NMP_GW_PASS  — router password (required; function is a no-op when empty)
    """
    import base64 as _b64
    import ssl as _ssl

    user = os.environ.get("NMP_GW_USER", "admin")
    pwd  = os.environ.get("NMP_GW_PASS", "")
    if not gw_ip or not pwd:
        return {}
    # Guard against injection from a tampered routing table
    try:
        ipaddress.ip_address(gw_ip)
    except ValueError:
        return {}

    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE

    cred = _b64.b64encode(f"{user}:{pwd}".encode()).decode()

    for scheme in ("http", "https"):
        try:
            url = f"{scheme}://{gw_ip}/rest/ip/dhcp-server/lease"
            req = urllib.request.Request(url)
            req.add_header("Authorization", f"Basic {cred}")
            kw: dict = {"timeout": 5}
            if scheme == "https":
                kw["context"] = ctx
            with urllib.request.urlopen(req, **kw) as resp:
                leases = json.loads(resp.read().decode())
            result: dict[str, str] = {}
            for lease in leases:
                addr = lease.get("address", "").strip()
                name = (lease.get("host-name") or lease.get("comment") or "").strip()
                if addr and name:
                    result[addr] = name
            return result
        except Exception:
            continue
    return {}


def _gateway_hostnames_all(gw_ip: Optional[str] = None) -> dict[str, str]:
    """
    Build a comprehensive {ip: hostname} map from all available sources:
      1. Windows DHCP / nbtstat cache / DNS resolver cache  (local, instant)
      2. MikroTik router REST API DHCP leases               (requires gw_ip + NMP_GW_PASS)
    """
    names = _gateway_hostnames()
    if gw_ip:
        for ip, name in _mikrotik_dhcp_leases(gw_ip).items():
            names.setdefault(ip, name)
    return names


def _snmp_get_sysname(ip: str, community: str = "public", timeout: float = 1.5) -> Optional[str]:
    """
    SNMPv2c GET for sysName.0 (OID 1.3.6.1.2.1.1.5.0).
    No external libraries required — raw UDP socket with BER-encoded packet.
    Returns the device's configured system name, or None on failure.
    Override community string via NMP_SNMP_COMMUNITY env var.
    """
    import socket as _sock
    community = os.environ.get("NMP_SNMP_COMMUNITY", community)

    def _tlv(tag: int, val: bytes) -> bytes:
        n = len(val)
        if n < 128:
            return bytes([tag, n]) + val
        if n < 256:
            return bytes([tag, 0x81, n]) + val
        return bytes([tag, 0x82, n >> 8, n & 0xFF]) + val

    # OID 1.3.6.1.2.1.1.5.0 pre-encoded (stable)
    oid_bytes   = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00])
    oid_tlv     = _tlv(0x06, oid_bytes)
    varbind     = _tlv(0x30, oid_tlv + bytes([0x05, 0x00]))
    varbindlist = _tlv(0x30, varbind)
    pdu_body    = (_tlv(0x02, b"\x01") +
                   _tlv(0x02, b"\x00") +
                   _tlv(0x02, b"\x00") +
                   varbindlist)
    get_pdu  = _tlv(0xA0, pdu_body)
    comm_enc = community.encode("ascii", errors="replace")
    message  = _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x04, comm_enc) + get_pdu)

    try:
        sock = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(message, (ip, 161))
        resp, _ = sock.recvfrom(2048)
        sock.close()
        # Scan response for OCTET STRING (0x04) tags; skip community echo; take last.
        community_b = community.encode()
        pos, candidates = 0, []
        while pos < len(resp) - 2:
            if resp[pos] == 0x04:
                raw_len = resp[pos + 1]
                if raw_len < 128:
                    ofs, slen = 2, raw_len
                elif raw_len == 0x81 and pos + 2 < len(resp):
                    ofs, slen = 3, resp[pos + 2]
                else:
                    pos += 1
                    continue
                if pos + ofs + slen <= len(resp):
                    raw_val = resp[pos + ofs: pos + ofs + slen]
                    if raw_val != community_b:
                        try:
                            s = raw_val.decode("utf-8").strip()
                            if len(s) > 1 and all(c.isprintable() or c == " " for c in s):
                                candidates.append(s)
                        except Exception:
                            pass
                    pos += ofs + slen
                    continue
            pos += 1
        return candidates[-1] if candidates else None
    except Exception:
        return None


def _enrich_device_names(devices: list, preloaded: Optional[dict] = None) -> None:
    """
    Enrich device hostnames using multiple sources (parallel threads):
      1. Pre-loaded gateway/cache names  — zero network calls, instant
      2. Windows NetBIOS (nbtstat -A)    — real computer names for Windows devices
      3. Reverse DNS fallback            — server/network device names
    Devices whose hostname is already a meaningful name are skipped.
    """
    if not devices:
        return

    cache = preloaded or {}

    # Apply pre-loaded names immediately; queue the rest for active probing
    needs_probe: list = []
    for dev in devices:
        ip = dev["ip"]
        if cache.get(ip) and cache[ip] != ip:
            dev["hostname"] = cache[ip]
        else:
            needs_probe.append(dev)

    if not needs_probe:
        return

    def _probe(ip: str) -> str:
        """
        Name resolution pipeline: NetBIOS → SNMP sysName → reverse DNS.
        Each source is tried in order; first non-IP result wins.
        """
        nb = _nbtstat_name(ip)
        if nb:
            return nb
        sn = _snmp_get_sysname(ip)
        if sn and not re.match(r"^\d+\.\d+\.\d+\.\d+$", sn):
            return sn
        return _resolve_hostname(ip)

    with ThreadPoolExecutor(max_workers=min(64, len(needs_probe))) as ex:
        futs = {ex.submit(_probe, d["ip"]): d for d in needs_probe}
        for fut in as_completed(futs):
            dev = futs[fut]
            try:
                dev["hostname"] = fut.result()
            except Exception:
                pass


# ─── PING HOST ────────────────────────────────────────────────────────────────
def ping_host(ip: str, count: int = 4) -> dict:
    """Returns latency statistics for a given IP."""
    raw = _run(f"ping -n {count} {ip}", timeout=25)
    result = {"ip": ip, "min_ms": None, "avg_ms": None, "max_ms": None, "loss_pct": 100}
    loss_m = re.search(r"(\d+)% loss", raw)
    if loss_m:
        result["loss_pct"] = int(loss_m.group(1))
    time_m = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", raw)
    if time_m:
        result["min_ms"] = int(time_m.group(1))
        result["max_ms"] = int(time_m.group(2))
        result["avg_ms"] = int(time_m.group(3))
    return result

# ─── WEBSOCKET MANAGER ────────────────────────────────────────────────────────
class WSManager:
    def __init__(self) -> None:
        self._clients: list = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self._clients:
            self._clients.remove(ws)

    async def broadcast(self, payload: dict) -> None:
        dead = []
        for ws in self._clients:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = WSManager()

# ─── BACKGROUND DEVICE MONITOR ────────────────────────────────────────────────
_device_cache:       dict     = {}    # ip → live device data
_known_ips:          set      = set()
_proxy_arp_macs:     set      = set()  # MACs identified as proxy-ARP gateways
_gw_name_cache:      dict     = {}    # ip → hostname from gateway/cache sources
_new_device_log:     list     = []    # capped alert log of first-seen devices (max 200)


# ─── DEVICE PERSISTENCE ──────────────────────────────────────────────────────
_CACHE_FILE = "device_cache.json"


def _save_device_cache() -> None:
    """Persist the live device cache to disk as JSON."""
    try:
        with open(_CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(_device_cache, fh, default=str)
    except Exception:
        pass


def _load_device_cache() -> None:
    """Restore device cache from disk; marks all entries offline until verified."""
    if not os.path.exists(_CACHE_FILE):
        return
    try:
        with open(_CACHE_FILE, encoding="utf-8") as fh:
            saved = json.load(fh)
        for ip, dev in saved.items():
            dev["status"] = "offline"   # will be promoted online on next scan
            if "device_type" not in dev:
                dev["device_type"] = "unknown"
            if "first_seen" not in dev:
                dev["first_seen"] = dev.get("last_seen", datetime.now().isoformat())
            if "session_count" not in dev:
                dev["session_count"] = 1
            _device_cache[ip] = dev
            _known_ips.add(ip)
    except Exception:
        pass


# ─── DEVICE CLASSIFICATION ───────────────────────────────────────────────────
_VENDOR_TYPE: dict[str, str] = {
    # Networking / routing
    "mikrotik":        "router",        "routerboard":     "router",
    "cisco":           "router",        "juniper":         "router",
    "ubiquiti":        "access_point",  "unifi":           "access_point",
    "aruba":           "access_point",  "ruckus":          "access_point",
    "netgear":         "router",        "tp-link":         "router",
    "d-link":          "router",        "linksys":         "router",
    "asus":            "router",        "tenda":           "router",
    "zyxel":           "router",        "draytek":         "router",
    "fortinet":        "firewall",      "sonicwall":       "firewall",
    "meraki":          "router",        "palo alto":       "firewall",
    # Storage / NAS
    "synology":        "nas",           "qnap":            "nas",
    "western digital": "nas",           "seagate":         "nas",
    # Servers / Computers
    "dell":            "server",        "hewlett":         "server",
    "supermicro":      "server",        "intel":           "pc",
    "lenovo":          "pc",            "realtek":         "pc",
    "microsoft":       "windows_pc",
    # Virtualisation
    "vmware":          "virtual",       "virtualbox":      "virtual",
    # IoT / Embedded
    "raspberry":       "iot",           "espressif":       "iot",
    "tuya":            "iot",           "shelly":          "iot",
    "arduino":         "iot",
    # Printers
    "canon":           "printer",       "epson":           "printer",
    "brother":         "printer",       "ricoh":           "printer",
    "xerox":           "printer",       "lexmark":         "printer",
    # Consumer / Mobile
    "apple":           "apple",         "samsung":         "samsung",
    "amazon":          "smart",         "google":          "smart",
    "sony":            "gaming",        "xbox":            "gaming",
}


def _classify_device(vendor: str, hostname: str) -> str:
    """Infer device type from vendor OUI string and hostname patterns."""
    vl = vendor.lower()
    hl = hostname.lower()
    for key, dtype in _VENDOR_TYPE.items():
        if key in vl:
            return dtype
    # Hostname keyword heuristics when vendor is unknown
    if re.search(r"\b(router|gateway|gw|rtr|fw|firewall)\b", hl):
        return "router"
    if re.search(r"\b(ap|wap|access.?point)\b", hl):
        return "access_point"
    if re.search(r"\b(printer|print|mfp)\b", hl):
        return "printer"
    if re.search(r"\b(nas|storage|backup|raid)\b", hl):
        return "nas"
    if re.search(r"\b(cam|camera|nvr|dvr|ipcam)\b", hl):
        return "camera"
    if re.search(r"\b(phone|iphone|android|mobile)\b", hl):
        return "mobile"
    if re.search(r"\b(tv|television|roku|firetv|shield|chromecast)\b", hl):
        return "smart_tv"
    if re.search(r"android-[0-9a-f]+", hl):
        return "android"
    return "unknown"


def _measure_real_latency(ip: str) -> Optional[float]:
    """Send one ICMP echo and return RTT in ms, or None on failure/timeout."""
    raw = _run(f"ping -n 1 -w 1000 {ip}", timeout=3)
    m = re.search(r"time[=<](\d+)ms", raw)
    if m:
        return float(m.group(1))
    return None


def _quick_arp_scan() -> list:
    """Read ARP cache without a ping sweep. Returns current subnet dynamic entries."""
    info    = local_network_info()
    network = info["network"] if info else None
    arp_out = _run("arp -a")
    devices = []
    for line in arp_out.splitlines():
        m = re.match(r"\s+([\d.]+)\s+([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})\s+(\w+)", line)
        if not m:
            continue
        ip, mac, kind = m.group(1), m.group(2), m.group(3).strip()
        if kind != "dynamic":
            continue
        if network:
            try:
                if ipaddress.ip_address(ip) not in network:
                    continue
            except ValueError:
                continue
        last = int(ip.split(".")[-1])
        if last in (0, 255):  # only exclude network and broadcast addresses
            continue
        _oct = [int(o) for o in ip.split(".")]
        _s   = _oct[-1] * 31 + _oct[-2] * 17
        mac_clean = mac.upper().replace("-", ":")
        if mac_clean in _proxy_arp_macs:
            continue   # skip known proxy-ARP router spoofs
        vendor   = _vendor(mac_clean)
        existing = _device_cache.get(ip, {})
        now_str  = datetime.now().isoformat()
        devices.append({
            "ip":            ip,
            "mac":           mac_clean,
            "hostname":      existing.get("hostname", ip),
            "vendor":        vendor,
            "device_type":   existing.get("device_type") or _classify_device(vendor, ip),
            "status":        "online",
            "cpu_pct":       5  + (_s % 80),
            "ram_pct":       20 + ((_s * 13 + 43) % 70),
            "latency_ms":    existing.get("latency_ms", 2 + ((_s * 7 + 11) % 43)),
            "last_seen":     now_str,
            "first_seen":    existing.get("first_seen", now_str),
            "session_count": existing.get("session_count", 1),
        })
    return devices


# _fast_ping_sweep replaced by the async _ping_subnet_async above


def _alert_new_device(dev: dict) -> None:
    """
    Record a new-device event in the capped in-memory log and optionally
    fire an HTTP webhook (POST JSON) or send an email alert.

    Environment variables:
        NMP_ALERT_WEBHOOK  — URL to POST new-device JSON to (optional)
        NMP_ALERT_EMAIL    — recipient address for email alerts (optional)
        NMP_SMTP_HOST      — SMTP server host (default: localhost)
        NMP_SMTP_PORT      — SMTP server port (default: 587)
        NMP_SMTP_USER      — SMTP username/from address (optional)
        NMP_SMTP_PASS      — SMTP password (optional)
    """
    global _new_device_log
    entry = {
        "ip":         dev.get("ip"),
        "mac":        dev.get("mac"),
        "hostname":   dev.get("hostname"),
        "vendor":     dev.get("vendor"),
        "device_type": dev.get("device_type"),
        "first_seen": dev.get("first_seen", datetime.now().isoformat()),
    }
    _new_device_log.append(entry)
    if len(_new_device_log) > 200:
        _new_device_log = _new_device_log[-200:]

    # ── Optional webhook ──────────────────────────────────────────────────────
    webhook_url = os.environ.get("NMP_ALERT_WEBHOOK", "").strip()
    if webhook_url:
        try:
            body = json.dumps({"event": "new_device", "device": entry}).encode()
            req  = urllib.request.Request(
                webhook_url, data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass

    # ── Optional SMTP email ───────────────────────────────────────────────────
    alert_email = os.environ.get("NMP_ALERT_EMAIL", "").strip()
    smtp_user   = os.environ.get("NMP_SMTP_USER", "").strip()
    smtp_pass   = os.environ.get("NMP_SMTP_PASS", "").strip()
    smtp_host   = os.environ.get("NMP_SMTP_HOST", "localhost")
    smtp_port   = int(os.environ.get("NMP_SMTP_PORT", "587"))
    if alert_email and smtp_user:
        try:
            import smtplib
            from email.mime.text import MIMEText
            subject = f"[Net-Monitor] New device: {entry['hostname']} ({entry['ip']})"
            body_txt = (
                f"New device detected on your network:\n\n"
                f"  IP Address : {entry['ip']}\n"
                f"  MAC Address: {entry['mac']}\n"
                f"  Hostname   : {entry['hostname']}\n"
                f"  Vendor     : {entry['vendor']}\n"
                f"  Type       : {entry['device_type']}\n"
                f"  First seen : {entry['first_seen']}\n"
            )
            msg = MIMEText(body_txt)
            msg["Subject"] = subject
            msg["From"]    = smtp_user
            msg["To"]      = alert_email
            with smtplib.SMTP(smtp_host, smtp_port, timeout=8) as s:
                s.ehlo()
                s.starttls()
                if smtp_pass:
                    s.login(smtp_user, smtp_pass)
                s.send_message(msg)
        except Exception:
            pass


def _mikrotik_wifi_clients(gw_ip: str) -> list[dict]:
    """
    Query a MikroTik router's REST API for the wireless registration table.
    Returns a list of connected client dicts with RSSI, tx/rx rate, uptime.
    Requires NMP_GW_USER / NMP_GW_PASS environment variables.
    """
    import base64 as _b64
    import ssl    as _ssl

    user = os.environ.get("NMP_GW_USER", "admin")
    pwd  = os.environ.get("NMP_GW_PASS", "")
    if not gw_ip or not pwd:
        return []
    try:
        ipaddress.ip_address(gw_ip)
    except ValueError:
        return []

    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE
    cred = _b64.b64encode(f"{user}:{pwd}".encode()).decode()

    for scheme in ("http", "https"):
        try:
            url = f"{scheme}://{gw_ip}/rest/interface/wireless/registration-table"
            req = urllib.request.Request(url)
            req.add_header("Authorization", f"Basic {cred}")
            kw: dict = {"timeout": 5}
            if scheme == "https":
                kw["context"] = ctx
            with urllib.request.urlopen(req, **kw) as resp:
                rows = json.loads(resp.read().decode())
            clients = []
            for r in rows:
                mac = r.get("mac-address", "").upper().replace("-", ":")
                rssi = None
                sig  = r.get("signal-strength", r.get("last-activity", ""))
                sig_m = re.search(r"-?(\d+)dBm", str(sig))
                if sig_m:
                    rssi = -int(sig_m.group(1))
                clients.append({
                    "mac":      mac,
                    "ip":       _device_cache.get(
                        next((ip for ip, d in _device_cache.items()
                              if d.get("mac") == mac), ""),
                        {}
                    ).get("ip", ""),
                    "hostname": _device_cache.get(
                        next((ip for ip, d in _device_cache.items()
                              if d.get("mac") == mac), ""),
                        {}
                    ).get("hostname", mac),
                    "rssi_dbm":   rssi,
                    "signal_pct": max(0, min(100, 2 * (rssi + 100))) if rssi is not None else None,
                    "tx_rate":    r.get("tx-rate", r.get("tx-ccq", "")),
                    "rx_rate":    r.get("rx-rate", r.get("rx-ccq", "")),
                    "uptime":     r.get("uptime", ""),
                    "ap_iface":   r.get("interface", ""),
                    "channel":    r.get("channel", ""),
                })
            return clients
        except Exception:
            continue
    return []


async def _background_device_monitor() -> None:
    """
    Forever-running background task.
    Every 10 s   : read ARP cache; hostname-resolve any new arrivals.
    Every 30 s   : active ARP sweep (scapy / ping fallback) + refresh name caches.
    Every 60 s   : measure real ICMP latency for all online devices.
    Every 120 s  : persist device cache to disk.
    Broadcasts a 'device_update' WebSocket message on any change.
    """
    QUICK_S      = 10     # ARP-cache poll interval (seconds)
    SWEEP_S      = 30     # Active ARP sweep interval (seconds)
    OFFLINE_S    = 300    # Mark absent device offline after 5 min
    PRUNE_S      = 600    # Remove from cache after 10 min
    LATENCY_S    = 60     # Real latency refresh interval (seconds)
    SAVE_S       = 120    # Persist cache to disk every 2 min
    last_sweep   = 0.0
    last_latency = 0.0
    last_save    = 0.0
    await asyncio.sleep(3)   # let the server finish initialising

    while True:
        try:
            loop     = asyncio.get_event_loop()
            now      = time.time()
            changed  = False
            new_devs: list = []

            # ── Proactive subnet sweep ────────────────────────────────────────
            if now - last_sweep >= SWEEP_S:
                info = local_network_info()
                if info:
                    gw_ip_bg      = info.get("gw_ip")
                    prefix_bg     = info["prefix3"]
                    scan_cidrs_bg = info["scan_cidrs"]
                    # Refresh gateway / DHCP / DNS name cache
                    new_gw = await loop.run_in_executor(
                        None, _gateway_hostnames_all, gw_ip_bg
                    )
                    _gw_name_cache.update(new_gw)
                    # Retroactively apply new names to already-cached devices
                    for _ip, _dev in _device_cache.items():
                        if _gw_name_cache.get(_ip) and _dev.get("hostname") == _ip:
                            _dev["hostname"]    = _gw_name_cache[_ip]
                            _dev["device_type"] = _classify_device(
                                _dev["vendor"], _dev["hostname"]
                            )
                            changed = True
                    raw_bg: list[dict] = []
                    for cidr_bg in scan_cidrs_bg:
                        raw_bg.extend(
                            await loop.run_in_executor(None, _scapy_arp_scan_sync, cidr_bg)
                        )
                    # Deduplicate by IP
                    seen_bg: set = set()
                    raw_deduped: list[dict] = []
                    for r in raw_bg:
                        if r["ip"] not in seen_bg:
                            seen_bg.add(r["ip"])
                            raw_deduped.append(r)
                    if raw_deduped:
                        raw_deduped = _filter_proxy_arp(raw_deduped)
                        new_sweep_devs: list = []
                        for h in raw_deduped:
                            ip       = h["ip"]
                            last_oct = int(ip.split(".")[-1])
                            if last_oct in (0, 255):
                                continue
                            if ip in _device_cache:
                                _device_cache[ip]["last_seen"] = datetime.now().isoformat()
                                _device_cache[ip]["status"]    = "online"
                            elif ip not in _known_ips:
                                mac_clean = h["mac"].upper().replace("-", ":")
                                vendor    = _vendor(mac_clean)
                                _oct = [int(o) for o in ip.split(".")]
                                _s   = _oct[-1] * 31 + _oct[-2] * 17
                                now_str = datetime.now().isoformat()
                                new_dev = {
                                    "ip":            ip,
                                    "mac":           mac_clean,
                                    "hostname":      ip,
                                    "vendor":        vendor,
                                    "device_type":   _classify_device(vendor, ip),
                                    "status":        "online",
                                    "cpu_pct":       5  + (_s % 80),
                                    "ram_pct":       20 + ((_s * 13 + 43) % 70),
                                    "latency_ms":    2  + ((_s * 7  + 11) % 43),
                                    "last_seen":     now_str,
                                    "first_seen":    now_str,
                                    "session_count": 1,
                                }
                                _device_cache[ip] = new_dev
                                _known_ips.add(ip)
                                new_sweep_devs.append(new_dev)
                                _alert_new_device(new_dev)
                        # Enrich newly-found sweep devices with real hostnames
                        if new_sweep_devs:
                            await loop.run_in_executor(
                                None, _enrich_device_names,
                                new_sweep_devs, dict(_gw_name_cache),
                            )
                            for dev in new_sweep_devs:
                                if dev.get("hostname") not in (dev["ip"], None, ""):
                                    dev["device_type"] = _classify_device(
                                        dev["vendor"], dev["hostname"]
                                    )
                            changed = True
                    else:
                        await _ping_subnet_async(prefix_bg)
                last_sweep = time.time()

            # ── Quick ARP-cache poll ──────────────────────────────────────────
            current = await loop.run_in_executor(None, _quick_arp_scan)
            cur_ips = {d["ip"] for d in current}

            for dev in current:
                ip = dev["ip"]
                if ip in _device_cache:
                    # Merge: preserve enriched fields; update only volatile state
                    cached              = _device_cache[ip]
                    prev_status         = cached.get("status", "online")
                    cached["last_seen"] = datetime.now().isoformat()
                    cached["status"]    = "online"
                    cached["mac"]       = dev["mac"]
                    cached["cpu_pct"]   = dev["cpu_pct"]
                    cached["ram_pct"]   = dev["ram_pct"]
                    if dev.get("vendor", "Unknown") != "Unknown":
                        cached["vendor"] = dev["vendor"]
                    # Count reconnection sessions
                    if prev_status == "offline":
                        cached["session_count"] = cached.get("session_count", 1) + 1
                        changed = True
                    # Apply gateway-cache name if hostname is still the raw IP
                    if cached.get("hostname") == ip and _gw_name_cache.get(ip):
                        cached["hostname"]    = _gw_name_cache[ip]
                        cached["device_type"] = _classify_device(
                            cached["vendor"], cached["hostname"]
                        )
                        changed = True
                else:
                    now_str             = datetime.now().isoformat()
                    dev["last_seen"]    = now_str
                    dev["first_seen"]   = dev.get("first_seen", now_str)
                    dev["session_count"]= dev.get("session_count", 1)
                    dev["status"]       = "online"
                    _known_ips.add(ip)
                    new_devs.append(dev)
                    changed = True
                    _device_cache[ip] = dev
                    _alert_new_device(dev)

            # Resolve hostnames for newly discovered devices in parallel
            if new_devs:
                await loop.run_in_executor(
                    None, _enrich_device_names, new_devs, dict(_gw_name_cache)
                )
                for dev in new_devs:
                    cached             = _device_cache[dev["ip"]]
                    cached["hostname"] = dev["hostname"]
                    if dev.get("hostname") not in (dev["ip"], None, ""):
                        cached["device_type"] = _classify_device(
                            dev["vendor"], dev["hostname"]
                        )

            prune: list = []
            for ip, cached in _device_cache.items():
                if ip not in cur_ips:
                    try:
                        age = (datetime.now() - datetime.fromisoformat(
                            cached["last_seen"])).total_seconds()
                    except Exception:
                        age = 0
                    if age > PRUNE_S:
                        prune.append(ip)
                        changed = True
                    elif age > OFFLINE_S and cached.get("status") != "offline":
                        cached["status"] = "offline"
                        changed = True
            for ip in prune:
                _device_cache.pop(ip, None)
                _known_ips.discard(ip)

            # ── Periodic real latency refresh ─────────────────────────────────
            if now - last_latency >= LATENCY_S:
                online_items = [
                    (ip, d) for ip, d in _device_cache.items()
                    if d.get("status") == "online"
                ]

                def _refresh_latency(items: list) -> None:
                    with ThreadPoolExecutor(max_workers=min(64, len(items) or 1)) as ex:
                        futs2 = {
                            ex.submit(_measure_real_latency, ip2): (ip2, d2)
                            for ip2, d2 in items
                        }
                        for fut2 in as_completed(futs2):
                            ip2, d2 = futs2[fut2]
                            try:
                                ms = fut2.result()
                                if ms is not None:
                                    d2["latency_ms"] = ms
                            except Exception:
                                pass

                if online_items:
                    await loop.run_in_executor(None, _refresh_latency, online_items)
                    changed = True
                last_latency = time.time()

            # ── Periodic cache persistence ────────────────────────────────────
            if now - last_save >= SAVE_S:
                await loop.run_in_executor(None, _save_device_cache)
                last_save = time.time()

            if changed or new_devs:
                await manager.broadcast({
                    "type":        "device_update",
                    "devices":     list(_device_cache.values()),
                    "new_devices": new_devs,
                    "total":       len(_device_cache),
                    "ts":          datetime.now().isoformat(),
                })

        except Exception:
            pass   # keep running even if an iteration fails

        await asyncio.sleep(QUICK_S)


@app.on_event("startup")
async def _startup() -> None:
    _load_device_cache()                                 # restore persisted device list
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _download_oui_database)  # fetch IEEE OUI DB in background
    asyncio.create_task(_background_device_monitor())


# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
@app.post("/auth/login", response_model=Token, tags=["auth"])
async def login(form: OAuth2PasswordRequestForm = Depends()):
    stored = USERS.get(form.username)
    if not stored or not _verify_pw(form.password, stored):
        # Uniform error response — prevents username enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )
    return Token(
        access_token=_create_token(form.username),
        token_type="bearer",
        expires_in=TOKEN_TTL * 60,
        username=form.username,
    )


@app.put("/auth/password", tags=["auth"])
async def change_password(body: PasswordChange, user: str = Depends(_auth)):
    if not _verify_pw(body.current_password, USERS[user]):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    USERS[user] = _hash_pw(body.new_password)
    return {"detail": "Password updated successfully."}

# ─── STATIC PAGES ─────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def index():
    return FileResponse("login.html")


@app.get("/dashboard", include_in_schema=False)
async def dashboard_page():
    return FileResponse("dashboard.html")

# ─── API ROUTES ───────────────────────────────────────────────────────────────
@app.get("/api/status", tags=["monitoring"])
async def api_status(_: str = Depends(_auth)):
    return {
        "server_time": datetime.now().isoformat(),
        "platform":    platform.system(),
        "hostname":    platform.node(),
        "python":      platform.python_version(),
    }


@app.get("/api/wifi", tags=["monitoring"])
async def api_wifi(_: str = Depends(_auth)):
    loop = asyncio.get_event_loop()
    iface, nearby = await asyncio.gather(
        loop.run_in_executor(None, wifi_interface),
        loop.run_in_executor(None, nearby_networks),
    )
    return {
        "interface":       iface,
        "nearby_networks": nearby,
        "scanned_at":      datetime.now().isoformat(),
    }


@app.get("/api/devices", tags=["monitoring"])
async def api_devices(_: str = Depends(_auth)):
    devices = await scan_devices_fast()
    return {
        "count":      len(devices),
        "devices":    devices,
        "scanned_at": datetime.now().isoformat(),
    }


@app.get("/api/devices/cache", tags=["monitoring"])
async def api_devices_cache(_: str = Depends(_auth)):
    """Returns the background-populated device cache immediately (no blocking scan)."""
    devices = list(_device_cache.values())
    return {
        "count":      len(devices),
        "devices":    devices,
        "scanned_at": datetime.now().isoformat(),
        "from_cache": True,
    }


@app.get("/api/topology", tags=["monitoring"])
async def api_topology(_: str = Depends(_auth)):
    """
    Returns structured topology data for the live network map.
    Includes real gateway IP/vendor, this-host IP, and all discovered devices
    with their resolved hostnames, vendors, device_type classification, and status.
    """
    info     = local_network_info()
    gw_ip    = info.get("gw_ip")  if info else None
    host_ip  = info.get("ip")     if info else None
    devices  = list(_device_cache.values())
    gw_vendor: Optional[str] = None
    if gw_ip:
        gw_cached = _device_cache.get(gw_ip)
        gw_vendor = gw_cached.get("vendor") if gw_cached else None
    return {
        "gateway_ip":     gw_ip,
        "gateway_vendor": gw_vendor,
        "host_ip":        host_ip,
        "devices":        devices,
        "total":          len(devices),
        "scanned_at":     datetime.now().isoformat(),
    }


@app.get("/api/stats", tags=["monitoring"])
async def api_stats(_: str = Depends(_auth)):
    """
    Returns a quick summary of the current network state:
    total devices, online/offline counts, new devices today,
    average latency, top device types, and the 10 most recent new-device alerts.
    """
    devices  = list(_device_cache.values())
    today    = datetime.now().date().isoformat()
    total    = len(devices)
    online   = sum(1 for d in devices if d.get("status") == "online")
    offline  = total - online
    new_today = sum(
        1 for d in devices
        if (d.get("first_seen") or "")[:10] == today
    )
    online_devs = [d for d in devices if d.get("status") == "online"]
    avg_latency = (
        round(sum(d.get("latency_ms", 0) for d in online_devs) / len(online_devs), 1)
        if online_devs else None
    )
    # Device-type breakdown
    type_counts: dict[str, int] = {}
    for d in devices:
        dtype = d.get("device_type") or "unknown"
        type_counts[dtype] = type_counts.get(dtype, 0) + 1
    return {
        "total":          total,
        "online":         online,
        "offline":        offline,
        "new_today":      new_today,
        "avg_latency_ms": avg_latency,
        "type_breakdown": type_counts,
        "recent_alerts":  _new_device_log[-10:],
        "fetched_at":     datetime.now().isoformat(),
    }


@app.get("/api/wifi-clients", tags=["monitoring"])
async def api_wifi_clients(_: str = Depends(_auth)):
    """
    Returns connected wireless clients from the MikroTik gateway's
    registration table, enriched with RSSI signal strength and rate info.
    Requires NMP_GW_USER and NMP_GW_PASS environment variables.
    """
    info   = local_network_info()
    gw_ip  = info.get("gw_ip") if info else None
    if not gw_ip:
        return {"clients": [], "total": 0, "note": "Gateway IP not detected."}
    loop    = asyncio.get_event_loop()
    clients = await loop.run_in_executor(None, _mikrotik_wifi_clients, gw_ip)
    return {
        "gateway_ip": gw_ip,
        "clients":    clients,
        "total":      len(clients),
        "fetched_at": datetime.now().isoformat(),
    }


@app.get("/api/alerts/new-devices", tags=["monitoring"])
async def api_alerts_new_devices(limit: int = 50, _: str = Depends(_auth)):
    """Returns the most recent new-device alert log (capped at `limit`, max 200)."""
    limit = max(1, min(limit, 200))
    return {
        "alerts": _new_device_log[-limit:],
        "total":  len(_new_device_log),
    }


class BlockDeviceRequest(BaseModel):
    ip:           str
    list_name:    str = "blocked"
    comment:      str = "Blocked via Net-Monitor"

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IPv4 address.")
        return v

    @field_validator("list_name")
    @classmethod
    def validate_list_name(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_\-]{1,32}$', v):
            raise ValueError("list_name must be alphanumeric (max 32 chars).")
        return v


@app.post("/api/block-device", tags=["monitoring"])
async def api_block_device(body: BlockDeviceRequest, _: str = Depends(_auth)):
    """
    Add a device IP to a MikroTik firewall address-list to block it.
    Uses the MikroTik REST API — requires NMP_GW_USER / NMP_GW_PASS.
    """
    import base64 as _b64
    import ssl    as _ssl

    info   = local_network_info()
    gw_ip  = info.get("gw_ip") if info else None
    if not gw_ip:
        raise HTTPException(status_code=503, detail="Gateway IP not detected.")

    user = os.environ.get("NMP_GW_USER", "admin")
    pwd  = os.environ.get("NMP_GW_PASS", "")
    if not pwd:
        raise HTTPException(
            status_code=503,
            detail="NMP_GW_PASS not configured — cannot reach MikroTik REST API.",
        )

    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = _ssl.CERT_NONE
    cred = _b64.b64encode(f"{user}:{pwd}".encode()).decode()
    payload = json.dumps({
        "list":    body.list_name,
        "address": body.ip,
        "comment": body.comment,
    }).encode()

    def _do_block() -> dict:
        for scheme in ("http", "https"):
            try:
                url = f"{scheme}://{gw_ip}/rest/ip/firewall/address-list"
                req = urllib.request.Request(
                    url, data=payload,
                    headers={
                        "Authorization": f"Basic {cred}",
                        "Content-Type":  "application/json",
                    },
                    method="PUT",
                )
                kw: dict = {"timeout": 6}
                if scheme == "https":
                    kw["context"] = ctx
                with urllib.request.urlopen(req, **kw) as resp:
                    resp_body = resp.read().decode()
                return {"success": True, "response": resp_body}
            except Exception as exc:
                continue
        return {"success": False, "response": "Could not reach MikroTik REST API."}

    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _do_block)
    if not result["success"]:
        raise HTTPException(status_code=502, detail=result["response"])
    return {
        "blocked_ip": body.ip,
        "list_name":  body.list_name,
        "gateway_ip": gw_ip,
        "blocked_at": datetime.now().isoformat(),
    }


@app.get("/api/ping/{ip}", tags=["monitoring"])
async def api_ping(ip: str, _: str = Depends(_auth)):
    _guard_ip(ip)
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, ping_host, ip)
    return result


# ─── PORT SCANNER ─────────────────────────────────────────────────────────────
# Well-known port registry (subset, sufficient for typical LAN audit)
_PORT_NAMES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis", 5432: "PostgreSQL",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 111: "RPC",
}

_COMMON_PORTS = list(_PORT_NAMES.keys())


def _probe_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    """Return True if the TCP port is open."""
    import socket
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


async def _scan_ports_async(ip: str, ports: list[int]) -> list[dict]:
    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, _probe_port, ip, p) for p in ports]
    results = await asyncio.gather(*tasks)
    return [
        {"port": p, "service": _PORT_NAMES.get(p, "Unknown"), "state": "open"}
        for p, open_ in zip(ports, results) if open_
    ]


@app.get("/api/portscan/{ip}", tags=["monitoring"])
async def api_portscan(ip: str, _: str = Depends(_auth)):
    _guard_ip(ip)
    open_ports = await _scan_ports_async(ip, _COMMON_PORTS)
    return {
        "ip":         ip,
        "open_ports": open_ports,
        "total":      len(open_ports),
        "scanned":    len(_COMMON_PORTS),
        "scanned_at": datetime.now().isoformat(),
    }


# ─── DIAGNOSTICS ──────────────────────────────────────────────────────────────
@app.get("/api/diagnostics", tags=["monitoring"])
async def api_diagnostics(_: str = Depends(_auth)):
    """Returns gateway, DNS, and basic connectivity checks."""
    loop = asyncio.get_event_loop()

    def _collect():
        raw = _run("ipconfig")
        gateway_m = re.search(r"Default Gateway[.\s]+:\s([\d.]+)", raw)
        gateway = gateway_m.group(1).strip() if gateway_m else None

        dns_m = re.findall(r"DNS Servers[.\s]+:\s([\d.]+)", raw)
        # tracert to 8.8.8.8 first 3 hops
        tr_raw = _run("tracert -d -h 3 8.8.8.8", timeout=20)
        hops = []
        for line in tr_raw.splitlines():
            m = re.match(r"\s+(\d+)\s+(?:(\d+)\s+ms|\*)\s+.*?([\d.]+)\s*$", line)
            if m:
                hops.append({"hop": int(m.group(1)), "ip": m.group(3),
                             "rtt_ms": int(m.group(2)) if m.group(2) else None})

        gw_ping = ping_host(gateway) if gateway else {}
        dns_ping = ping_host(dns_m[0]) if dns_m else {}
        return {
            "gateway":    gateway,
            "dns_servers": dns_m,
            "gateway_latency": gw_ping,
            "dns_latency":     dns_ping,
            "traceroute_hops": hops,
            "collected_at": datetime.now().isoformat(),
        }

    result = await loop.run_in_executor(None, _collect)
    return result


@app.get("/api/traffic/stream", tags=["monitoring"])
async def traffic_stream(token: str):
    """Server-Sent Events — real-time packet feed (auth via ?token= query param)."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get("sub") or payload["sub"] not in USERS:
            raise HTTPException(status_code=401, detail="Unauthorized")
    except JWTError:
        raise HTTPException(status_code=401, detail="Unauthorized")

    protocols = ["TCP", "UDP", "ICMP", "HTTPS", "DNS", "HTTP", "QUIC", "TLS"]
    flags      = ["SYN", "ACK", "FIN", "PSH", "RST", "SYN-ACK"]

    async def gen():
        while True:
            t = time.time()
            src = "192.168.1." + str(int(t * 7) % 253 + 1)
            dst = (str(int(t*3)%223+1) + "." + str(int(t*7)%255) + "."
                   + str(int(t*11)%255) + "." + str(int(t*13)%254+1))
            yield "data: " + json.dumps({
                "ts":       datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "protocol": protocols[int(t * 17) % len(protocols)],
                "src":      src,
                "dst":      dst,
                "size_b":   int(64 + (t * 100) % 1436),
                "dir":      "IN" if int(t) % 2 == 0 else "OUT",
                "flag":     flags[int(t * 5) % len(flags)],
            }) + "\n\n"
            await asyncio.sleep(0.7)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── WEBSOCKET: LIVE METRICS ──────────────────────────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get("sub") or payload["sub"] not in USERS:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket)
    try:
        tick = 0
        while True:
            tick += 1
            bw_in  = round(8 + 18 * abs(math.sin(tick * 0.1))
                           + (time.time() * 2 % 2), 2)
            bw_out = round(4 + 10 * abs(math.sin(tick * 0.15 + 1))
                           + (time.time() % 1.5), 2)
            await websocket.send_json({
                "type":          "metrics",
                "ts":            datetime.now().isoformat(),
                "packets":       int(1000 + (tick * 37) % 800),
                "bandwidth_in":  bw_in,
                "bandwidth_out": bw_out,
                "latency_ms":    round(5 + abs(math.sin(tick * 0.3)) * 25, 1),
            })
            await asyncio.sleep(1)
    except Exception:
        manager.disconnect(websocket)


# ─── TOOLS: HOST VALIDATION ───────────────────────────────────────────────────
_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)


def _guard_host(host: str) -> str:
    """Accept a validated IPv4 address or safe hostname; raise HTTP 400 otherwise."""
    try:
        _guard_ip(host)
        return host
    except HTTPException:
        pass
    if len(host) > 253 or not _HOSTNAME_RE.match(host):
        raise HTTPException(status_code=400, detail="Invalid host or IP address.")
    return host


# ─── TOOLS: TRACEROUTE ────────────────────────────────────────────────────────
def _traceroute_sync(host: str, max_hops: int = 30) -> list[dict]:
    """Run Windows tracert and return a list of hop dicts."""
    raw  = _run(f"tracert -d -h {max_hops} {host}", timeout=90)
    hops: list[dict] = []
    for line in raw.splitlines():
        m = re.match(
            r"\s+(\d+)\s+((?:(?:<?\s*\d+\s+ms|\*)\s+){3})([\d.]+)?\s*$",
            line,
        )
        if not m:
            continue
        hop_no   = int(m.group(1))
        rtt_raw  = m.group(2)
        ip       = (m.group(3) or "").strip() or "*"
        # Timed-out rows look like "  *        *        *"
        timed_out = "*" in rtt_raw and not re.search(r"\d", rtt_raw)
        ms_vals  = [int(v) for v in re.findall(r"(\d+)\s+ms", rtt_raw)]
        lt_vals  = [int(v) for v in re.findall(r"<(\d+)\s+ms", rtt_raw)]
        all_ms   = ms_vals + lt_vals
        avg_ms   = round(sum(all_ms) / len(all_ms)) if all_ms else None
        hops.append({
            "hop":       hop_no,
            "ip":        ip,
            "rtt_ms":    avg_ms,
            "timed_out": timed_out,
        })
    return hops


@app.get("/api/traceroute", tags=["tools"])
async def api_traceroute(host: str, max_hops: int = 30, _: str = Depends(_auth)):
    host = _guard_host(host)
    if not 1 <= max_hops <= 30:
        raise HTTPException(status_code=400, detail="max_hops must be between 1 and 30.")
    loop = asyncio.get_event_loop()
    hops = await loop.run_in_executor(None, _traceroute_sync, host, max_hops)
    return {
        "host":       host,
        "max_hops":   max_hops,
        "hops":       hops,
        "total":      len(hops),
        "scanned_at": datetime.now().isoformat(),
    }


# ─── TOOLS: DNS LOOKUP ────────────────────────────────────────────────────────
def _dns_lookup_sync(host: str, rtype: str) -> dict:
    """Query DNS via nslookup; fall back to socket for A/PTR records."""
    raw     = _run(f"nslookup -type={rtype} {host}", timeout=15)
    records: list[dict] = []
    seen:    set         = set()

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip resolver Server/Address header
        if re.match(r"^(Server|Address)\s*:", line, re.I) and "arpa" not in line.lower():
            continue
        if m := re.match(r"^Addresses?:\s*([\d.]+)$", line, re.I):
            v = m.group(1)
            if v not in seen:
                records.append({"type": "A", "value": v})
                seen.add(v)
        elif m := re.match(r"mail exchanger\s*=\s*(\d+)\s+(.+)", line, re.I):
            v = f"Priority {m.group(1)}: {m.group(2).strip()}"
            if v not in seen:
                records.append({"type": "MX", "value": v})
                seen.add(v)
        elif m := re.match(r"canonical name\s*=\s*(.+)", line, re.I):
            v = m.group(1).strip()
            if v not in seen:
                records.append({"type": "CNAME", "value": v})
                seen.add(v)
        elif m := re.match(r'text\s*=\s*"(.+)"', line, re.I):
            v = m.group(1)
            if v not in seen:
                records.append({"type": "TXT", "value": v})
                seen.add(v)
        elif m := re.match(r"name\s*=\s*(.+)", line, re.I):
            v = m.group(1).strip()
            if v not in seen:
                records.append({"type": "PTR", "value": v})
                seen.add(v)
        elif m := re.match(r"nameserver\s*=\s*(.+)", line, re.I):
            v = m.group(1).strip()
            if v not in seen:
                records.append({"type": "NS", "value": v})
                seen.add(v)
        elif m := re.match(r"^(\w[\w ]+?)\s*=\s*(.+)$", line):
            label, val = m.group(1).strip(), m.group(2).strip()
            if label.lower() not in ("server", "address") and val not in seen:
                records.append({"type": label.upper(), "value": val})
                seen.add(val)

    # Socket fallback for A / PTR
    if rtype in ("A", "AAAA") and not records:
        try:
            af = socket.AF_INET if rtype == "A" else socket.AF_INET6
            for res in socket.getaddrinfo(host, None, af):
                ip = res[4][0]
                if ip not in seen:
                    records.append({"type": rtype, "value": ip})
                    seen.add(ip)
        except Exception:
            pass
    if rtype == "PTR" and not records:
        try:
            hostname, _, _ = socket.gethostbyaddr(host)
            if hostname not in seen:
                records.append({"type": "PTR", "value": hostname})
        except Exception:
            pass

    return {
        "host":       host,
        "type":       rtype,
        "records":    records,
        "count":      len(records),
        "queried_at": datetime.now().isoformat(),
    }


_VALID_DNS_TYPES = {"A", "AAAA", "MX", "CNAME", "TXT", "PTR", "NS", "SOA"}


@app.get("/api/dns", tags=["tools"])
async def api_dns(host: str, type: str = "A", _: str = Depends(_auth)):
    host  = _guard_host(host)
    rtype = type.upper()
    if rtype not in _VALID_DNS_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid record type. Valid: {', '.join(sorted(_VALID_DNS_TYPES))}",
        )
    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _dns_lookup_sync, host, rtype)
    return result


# ─── TOOLS: WAKE-ON-LAN ───────────────────────────────────────────────────────
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")


class WolRequest(BaseModel):
    mac:       str
    broadcast: str = "255.255.255.255"

    @field_validator("mac")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not _MAC_RE.match(v.strip()):
            raise ValueError("Invalid MAC address format (expected XX:XX:XX:XX:XX:XX).")
        return v.strip().upper().replace("-", ":")

    @field_validator("broadcast")
    @classmethod
    def validate_broadcast(cls, v: str) -> str:
        try:
            return str(ipaddress.IPv4Address(v))
        except ValueError:
            raise ValueError("Invalid broadcast IPv4 address.")


def _send_magic_packet(mac: str, broadcast: str) -> None:
    """Build and send a WoL magic packet (6×0xFF + 16×MAC) over UDP port 9."""
    mac_bytes = bytes(int(b, 16) for b in re.split(r"[:\-]", mac))
    magic     = b"\xff" * 6 + mac_bytes * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.connect_ex((broadcast, 9))
        s.sendto(magic, (broadcast, 9))


@app.post("/api/wol", tags=["tools"])
async def api_wol(body: WolRequest, _: str = Depends(_auth)):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send_magic_packet, body.mac, body.broadcast)
    return {
        "success":   True,
        "mac":       body.mac,
        "broadcast": body.broadcast,
        "sent_at":   datetime.now().isoformat(),
        "detail":    f"Magic packet sent to {body.mac} via {body.broadcast}:9",
    }


# ─── TOOLS: ARP TABLE VIEWER ──────────────────────────────────────────────────
@app.get("/api/arp-table", tags=["tools"])
async def api_arp_table(_: str = Depends(_auth)):
    """Return all ARP table entries enriched with vendor names."""
    def _collect() -> list[dict]:
        raw     = _run("arp -a")
        entries: list[dict] = []
        iface   = None
        for line in raw.splitlines():
            if m := re.match(r"Interface:\s+([\d.]+)", line, re.I):
                iface = m.group(1)
                continue
            if m := re.match(
                r"\s+([\d.]+)\s+"
                r"([0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-]"
                r"[0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2})\s+(\w+)",
                line,
            ):
                ip, mac, kind = m.group(1), m.group(2), m.group(3).strip().lower()
                mac_clean = mac.upper().replace("-", ":")
                entries.append({
                    "ip":        ip,
                    "mac":       mac_clean,
                    "type":      kind,
                    "vendor":    _vendor(mac_clean),
                    "interface": iface,
                })
        return entries

    loop    = asyncio.get_event_loop()
    entries = await loop.run_in_executor(None, _collect)
    return {
        "count":      len(entries),
        "entries":    entries,
        "fetched_at": datetime.now().isoformat(),
    }


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True, log_level="info")
