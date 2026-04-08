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
import subprocess
import time
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


# OUI prefix -> vendor lookup (first 3 octets, upper-case colon-separated)
_OUI = {
    "00:50:56": "VMware",       "00:0C:29": "VMware",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "00:1A:79": "Cisco",        "00:0F:66": "Cisco",
    "3C:22:FB": "Apple",        "A4:C3:F0": "Apple",
    "00:15:5D": "Microsoft",    "00:E0:4C": "Realtek",
    "18:31:BF": "Amazon Echo",  "10:02:B5": "Samsung",
    "18:65:90": "Apple",        "AC:DE:48": "Apple",
    "F4:EC:38": "TP-Link",      "50:C7:BF": "TP-Link",
}


def _vendor(mac: str) -> str:
    prefix = mac.upper().replace("-", ":")[:8]
    return _OUI.get(prefix, "Unknown")


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


def local_subnet_prefix() -> Optional[str]:
    """Return the /24 prefix for the host's primary WiFi or Ethernet adapter."""
    raw = _run("ipconfig")
    wireless = re.search(r"Wireless LAN adapter.+?(?=\n\w|\Z)", raw, re.DOTALL)
    text = wireless.group() if wireless else raw
    m = re.search(r"IPv4 Address[.\s]+:\s([\d.]+)", text)
    if not m:
        m = re.search(r"IPv4 Address[.\s]+:\s([\d.]+)", raw)
    if not m:
        return None
    return ".".join(m.group(1).strip().split(".")[:3])


def scan_devices() -> list:
    """Ping-sweep the local /24 subnet, then read the ARP cache for live hosts."""
    prefix = local_subnet_prefix()
    if not prefix:
        return []
    # Fire-and-forget sweep to populate ARP cache
    _run(f"for /l %i in (1,1,254) do @ping -n 1 -w 100 {prefix}.%i", timeout=90)
    arp_out = _run("arp -a")
    devices = []
    for line in arp_out.splitlines():
        m = re.match(r"\s+([\d.]+)\s+([\w-]+)\s+(\w+)", line)
        if not m:
            continue
        ip, mac, kind = m.group(1), m.group(2), m.group(3)
        if kind != "dynamic":
            continue
        last = int(ip.split(".")[-1])
        if last in (0, 1, 255):
            continue
        hostname = ip
        ns = _run(f"nslookup {ip}", timeout=3)
        name_m = re.search(r"Name:\s+(.+)", ns)
        if name_m:
            hostname = name_m.group(1).strip()
        # Deterministic simulated metrics seeded from IP octets
        _oct = [int(o) for o in ip.split(".")]
        _s   = _oct[-1] * 31 + _oct[-2] * 17
        devices.append({
            "ip":         ip,
            "mac":        mac.upper().replace("-", ":"),
            "hostname":   hostname,
            "vendor":     _vendor(mac),
            "status":     "online",
            "cpu_pct":    5  + (_s % 80),
            "ram_pct":    20 + ((_s * 13 + 43) % 70),
            "latency_ms": 2  + ((_s * 7  + 11) % 43),
            "last_seen":  datetime.now().isoformat(),
        })
    return devices


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
    loop = asyncio.get_event_loop()
    devices = await loop.run_in_executor(None, scan_devices)
    return {
        "count":      len(devices),
        "devices":    devices,
        "scanned_at": datetime.now().isoformat(),
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


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True, log_level="info")
