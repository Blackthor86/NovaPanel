import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlencode, quote

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.sessions import SessionMiddleware

APP_VERSION = "0.2.0"
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("NOVAPANEL_DATA_DIR", str(ROOT_DIR / "data"))).expanduser()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "novapanel.sqlite3"
SESSION_SECRET = os.getenv("NOVAPANEL_SECRET_KEY") or secrets.token_urlsafe(48)
COOKIE_SECURE = os.getenv("NOVAPANEL_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"}
PASSWORD_ROUNDS = 600_000
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_ENGINE_LOCK = threading.Lock()
_ENGINE_PROCESS: subprocess.Popen | None = None
_ENGINE_LOG_HANDLE = None


class Capability(BaseModel):
    status: Literal["available", "unavailable", "unknown"]
    detail: str


class HostReport(BaseModel):
    platform: str
    python_version: str
    data_directory: str
    capabilities: dict[str, Capability]


class SetupInput(BaseModel):
    username: str = Field(min_length=3, max_length=48, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=14, max_length=256)


class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=48)
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    quota_gb: int | None = Field(default=None, ge=1, le=1_000_000)
    expires_at: str | None = Field(default=None, max_length=40)
    enabled: bool = True


class UserUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    quota_gb: int | None = Field(default=None, ge=1, le=1_000_000)
    expires_at: str | None = Field(default=None, max_length=40)
    enabled: bool | None = None


class ConnectionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    address: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    transport: Literal["ws", "grpc", "httpupgrade", "xhttp"] = "ws"
    path: str = Field(default="/", min_length=1, max_length=200)
    service_name: str = Field(default="novapanel", max_length=200)
    host_header: str | None = Field(default=None, max_length=253)
    server_name: str | None = Field(default=None, max_length=253)
    certificate_file: str | None = Field(default=None, max_length=500)
    private_key_file: str | None = Field(default=None, max_length=500)
    enabled: bool = True

    @field_validator("address", "host_header", "server_name")
    @classmethod
    def validate_host(cls, value: str | None) -> str | None:
        if value is None:
            return value
        value = value.strip()
        if not value or any(c in value for c in "/?#@ "):
            raise ValueError("Enter a hostname or IP address, not a URL.")
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*", value):
                raise ValueError("Invalid hostname.")
            return value.lower()

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value.startswith("/") or any(c in value for c in "\r\n?#"):
            raise ValueError("Path must start with / and contain no query or fragment.")
        return value

    @field_validator("certificate_file", "private_key_file")
    @classmethod
    def validate_file_path(cls, value: str | None) -> str | None:
        if value is not None and ("\n" in value or "\r" in value):
            raise ValueError("Invalid file path.")
        return value


class Capability(BaseModel):
    status: Literal["available", "unavailable", "unknown"]
    detail: str


app = FastAPI(title="NovaPanel API", description="NovaPanel control API", version=APP_VERSION)
origins = [x.strip() for x in os.getenv("NOVAPANEL_CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["Content-Type"])
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, session_cookie="novapanel_session", same_site="strict", https_only=COOKIE_SECURE, max_age=12 * 60 * 60)


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vpn_users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                client_uuid TEXT NOT NULL UNIQUE,
                quota_gb INTEGER,
                expires_at TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS connections (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                transport TEXT NOT NULL,
                path TEXT NOT NULL,
                service_name TEXT NOT NULL,
                host_header TEXT,
                server_name TEXT,
                certificate_file TEXT,
                private_key_file TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
        """)


init_db()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def password_hash(password: str, salt: bytes | None = None) -> tuple[str, str]:
    actual_salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), actual_salt, PASSWORD_ROUNDS)
    return actual_salt.hex(), derived.hex()


def check_password(password: str, salt_hex: str, expected_hex: str) -> bool:
    _, got = password_hash(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(got, expected_hex)


def get_admin(request: Request) -> dict:
    admin_id = request.session.get("admin_id")
    if not isinstance(admin_id, int):
        raise HTTPException(status_code=401, detail="Please sign in.")
    with db() as conn:
        row = conn.execute("SELECT id, username FROM admins WHERE id = ?", (admin_id,)).fetchone()
    if row is None:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Please sign in.")
    return dict(row)


def admin_count() -> int:
    with db() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0])


def engine_binary() -> str | None:
    configured = os.getenv("NOVAPANEL_XRAY_BINARY")
    if configured:
        path = Path(configured).expanduser()
        return str(path) if path.is_file() else None
    return shutil.which("xray")


def clean_user(row: sqlite3.Row) -> dict:
    return {"id": row["id"], "name": row["name"], "uuid": row["client_uuid"], "quota_gb": row["quota_gb"], "expires_at": row["expires_at"], "enabled": bool(row["enabled"]), "created_at": row["created_at"]}


def clean_connection(row: sqlite3.Row) -> dict:
    return {key: row[key] for key in ("id", "name", "address", "port", "transport", "path", "service_name", "host_header", "server_name", "certificate_file", "private_key_file", "created_at")} | {"enabled": bool(row["enabled"]), "tls_ready": bool(row["certificate_file"] and row["private_key_file"] and Path(row["certificate_file"]).is_file() and Path(row["private_key_file"]).is_file())}


def client_link(user: dict, connection: dict) -> str:
    params = {"encryption": "none", "security": "tls", "sni": connection.get("server_name") or connection["address"], "type": connection["transport"], "fp": "chrome"}
    if connection["transport"] in {"ws", "httpupgrade", "xhttp"}:
        params["path"] = connection["path"]
        if connection.get("host_header"):
            params["host"] = connection["host_header"]
    if connection["transport"] == "grpc":
        params["serviceName"] = connection["service_name"]
    label = quote(f'{connection["name"]} · {user["name"]}', safe="")
    return f'vless://{user["uuid"]}@{connection["address"]}:{connection["port"]}?{urlencode(params)}#{label}'


def build_xray_config() -> dict:
    with db() as conn:
        user_rows = conn.execute("SELECT * FROM vpn_users WHERE enabled = 1").fetchall()
        connection_rows = conn.execute("SELECT * FROM connections WHERE enabled = 1 ORDER BY created_at").fetchall()
    if not connection_rows:
        raise ValueError("Create and enable at least one connection first.")
    if not user_rows:
        raise ValueError("Create and enable at least one user first.")

    inbounds = []
    for row in connection_rows:
        item = dict(row)
        cert = item.get("certificate_file")
        key = item.get("private_key_file")
        if not cert or not key or not Path(cert).is_file() or not Path(key).is_file():
            raise ValueError(f'TLS certificate and private key are required for "{item["name"]}".')
        clients = [{"id": client["client_uuid"], "email": f'np-{client["id"]}@local'} for client in user_rows]
        stream: dict = {"network": item["transport"], "security": "tls", "tlsSettings": {"minVersion": "1.2", "alpn": ["h2", "http/1.1"], "certificates": [{"certificateFile": cert, "keyFile": key}]}}
        if item["transport"] == "ws":
            stream["wsSettings"] = {"path": item["path"], "headers": ({"Host": item["host_header"]} if item["host_header"] else {})}
        elif item["transport"] == "httpupgrade":
            stream["httpupgradeSettings"] = {"path": item["path"], "host": item["host_header"] or ""}
        elif item["transport"] == "grpc":
            stream["grpcSettings"] = {"serviceName": item["service_name"], "multiMode": False}
        elif item["transport"] == "xhttp":
            stream["xhttpSettings"] = {"path": item["path"], "host": item["host_header"] or "", "mode": "auto"}
        inbounds.append({"tag": f'novapanel-{item["id"][:8]}', "listen": "0.0.0.0", "port": item["port"], "protocol": "vless", "settings": {"clients": clients, "decryption": "none"}, "streamSettings": stream, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}})
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "blocked"}], "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"}]}}


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "app": "NovaPanel", "version": APP_VERSION}


@app.get("/api/setup/status")
def setup_status() -> dict[str, bool]:
    return {"setup_required": admin_count() == 0}


@app.post("/api/setup")
def setup(data: SetupInput, request: Request) -> dict:
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0]:
            raise HTTPException(status_code=409, detail="Initial setup is already complete.")
        salt, digest = password_hash(data.password)
        cur = conn.execute("INSERT INTO admins(username, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?)", (data.username, salt, digest, now_iso()))
        admin_id = cur.lastrowid
    request.session.clear()
    request.session["admin_id"] = int(admin_id)
    return {"username": data.username}


@app.post("/api/login")
def login(data: LoginInput, request: Request) -> dict:
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    recent = [stamp for stamp in _LOGIN_ATTEMPTS.get(ip, []) if now - stamp < 900]
    if len(recent) >= 10:
        raise HTTPException(status_code=429, detail="Too many attempts. Try again in 15 minutes.")
    with db() as conn:
        row = conn.execute("SELECT * FROM admins WHERE username = ? COLLATE NOCASE", (data.username,)).fetchone()
    if row is None or not check_password(data.password, row["password_salt"], row["password_hash"]):
        recent.append(now)
        _LOGIN_ATTEMPTS[ip] = recent
        raise HTTPException(status_code=401, detail="Username or password is incorrect.")
    _LOGIN_ATTEMPTS.pop(ip, None)
    request.session.clear()
    request.session["admin_id"] = int(row["id"])
    return {"username": row["username"]}


@app.post("/api/logout")
def logout(request: Request, _: dict = Depends(get_admin)) -> dict[str, bool]:
    request.session.clear()
    return {"ok": True}


@app.get("/api/me")
def me(admin: dict = Depends(get_admin)) -> dict:
    return admin


@app.get("/api/host", response_model=HostReport)
def host_report(_: dict = Depends(get_admin)) -> HostReport:
    data_dir_writable = os.access(DATA_DIR, os.W_OK)
    xray = engine_binary()
    return HostReport(
        platform=platform.system() or "unknown",
        python_version=platform.python_version(),
        data_directory=str(DATA_DIR),
        capabilities={
            "persistent_storage": Capability(status="available" if data_dir_writable else "unavailable", detail="The configured data directory is writable." if data_dir_writable else "The configured data directory is not writable."),
            "separate_processes": Capability(status="available" if hasattr(subprocess, "Popen") else "unavailable", detail="The Python runtime can launch managed processes. Provider policies and process lifetime still need verification."),
            "xray_binary": Capability(status="available" if xray else "unknown", detail=f"Xray detected at {xray}." if xray else "Xray is not installed or NOVAPANEL_XRAY_BINARY is not configured."),
            "inbound_tcp_udp": Capability(status="unknown", detail="Network reachability cannot be verified from inside this process."),
        },
    )


@app.get("/api/dashboard")
def dashboard(_: dict = Depends(get_admin)) -> dict:
    with db() as conn:
        users = conn.execute("SELECT COUNT(*) FROM vpn_users").fetchone()[0]
        active_users = conn.execute("SELECT COUNT(*) FROM vpn_users WHERE enabled = 1").fetchone()[0]
        connections = conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
        enabled_connections = conn.execute("SELECT COUNT(*) FROM connections WHERE enabled = 1").fetchone()[0]
    return {"users_total": users, "users_enabled": active_users, "connections_total": connections, "connections_enabled": enabled_connections, "engine": engine_status()["status"], "version": APP_VERSION}


@app.get("/api/users")
def list_users(_: dict = Depends(get_admin)) -> list[dict]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM vpn_users ORDER BY created_at DESC").fetchall()
    return [clean_user(row) for row in rows]


@app.post("/api/users", status_code=201)
def create_user(data: UserCreate, _: dict = Depends(get_admin)) -> dict:
    user_id = str(uuid.uuid4())
    client_id = str(uuid.uuid4())
    with db() as conn:
        conn.execute("INSERT INTO vpn_users(id, name, client_uuid, quota_gb, expires_at, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (user_id, data.name.strip(), client_id, data.quota_gb, data.expires_at, int(data.enabled), now_iso()))
        row = conn.execute("SELECT * FROM vpn_users WHERE id = ?", (user_id,)).fetchone()
    return clean_user(row)


@app.put("/api/users/{user_id}")
def update_user(user_id: str, data: UserUpdate, _: dict = Depends(get_admin)) -> dict:
    changes = data.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No changes supplied.")
    columns = {"name": "name", "quota_gb": "quota_gb", "expires_at": "expires_at", "enabled": "enabled"}
    values = []
    parts = []
    for key, value in changes.items():
        if key not in columns:
            continue
        parts.append(f'{columns[key]} = ?')
        values.append(int(value) if key == "enabled" and value is not None else (value.strip() if key == "name" and value is not None else value))
    if not parts:
        raise HTTPException(status_code=400, detail="No editable fields supplied.")
    values.append(user_id)
    with db() as conn:
        conn.execute(f'UPDATE vpn_users SET {", ".join(parts)} WHERE id = ?', values)
        row = conn.execute("SELECT * FROM vpn_users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found.")
    return clean_user(row)


@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, _: dict = Depends(get_admin)) -> dict[str, bool]:
    with db() as conn:
        cur = conn.execute("DELETE FROM vpn_users WHERE id = ?", (user_id,))
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"ok": True}


@app.get("/api/connections")
def list_connections(_: dict = Depends(get_admin)) -> list[dict]:
    with db() as conn:
        rows = conn.execute("SELECT * FROM connections ORDER BY created_at DESC").fetchall()
    return [clean_connection(row) for row in rows]


@app.post("/api/connections", status_code=201)
def create_connection(data: ConnectionCreate, _: dict = Depends(get_admin)) -> dict:
    if bool(data.certificate_file) != bool(data.private_key_file):
        raise HTTPException(status_code=422, detail="Provide both certificate and private key paths, or leave both empty until setup.")
    connection_id = str(uuid.uuid4())
    with db() as conn:
        conn.execute("INSERT INTO connections(id, name, address, port, transport, path, service_name, host_header, server_name, certificate_file, private_key_file, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (connection_id, data.name.strip(), data.address, data.port, data.transport, data.path, data.service_name, data.host_header, data.server_name, data.certificate_file, data.private_key_file, int(data.enabled), now_iso()))
        row = conn.execute("SELECT * FROM connections WHERE id = ?", (connection_id,)).fetchone()
    return clean_connection(row)


@app.put("/api/connections/{connection_id}")
def update_connection(connection_id: str, data: ConnectionCreate, _: dict = Depends(get_admin)) -> dict:
    if bool(data.certificate_file) != bool(data.private_key_file):
        raise HTTPException(status_code=422, detail="Provide both certificate and private key paths, or leave both empty.")
    values = (data.name.strip(), data.address, data.port, data.transport, data.path, data.service_name, data.host_header, data.server_name, data.certificate_file, data.private_key_file, int(data.enabled), connection_id)
    with db() as conn:
        conn.execute("UPDATE connections SET name=?, address=?, port=?, transport=?, path=?, service_name=?, host_header=?, server_name=?, certificate_file=?, private_key_file=?, enabled=? WHERE id=?", values)
        row = conn.execute("SELECT * FROM connections WHERE id=?", (connection_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Connection not found.")
    return clean_connection(row)


@app.delete("/api/connections/{connection_id}")
def delete_connection(connection_id: str, _: dict = Depends(get_admin)) -> dict[str, bool]:
    with db() as conn:
        cur = conn.execute("DELETE FROM connections WHERE id = ?", (connection_id,))
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Connection not found.")
    return {"ok": True}


@app.get("/api/connections/{connection_id}/links")
def get_connection_links(connection_id: str, _: dict = Depends(get_admin)) -> list[dict]:
    with db() as conn:
        connection_row = conn.execute("SELECT * FROM connections WHERE id=?", (connection_id,)).fetchone()
        user_rows = conn.execute("SELECT * FROM vpn_users WHERE enabled=1 ORDER BY name").fetchall()
    if connection_row is None:
        raise HTTPException(status_code=404, detail="Connection not found.")
    connection = clean_connection(connection_row)
    if not connection["tls_ready"]:
        raise HTTPException(status_code=409, detail="TLS certificate and private key files are required before links can be generated.")
    return [{"user": user["name"], "link": client_link(clean_user(user), connection)} for user in user_rows]


def engine_status() -> dict[str, str]:
    global _ENGINE_PROCESS
    if _ENGINE_PROCESS is None:
        return {"status": "stopped"}
    return {"status": "running" if _ENGINE_PROCESS.poll() is None else "stopped"}


@app.get("/api/engine/status")
def get_engine_status(_: dict = Depends(get_admin)) -> dict[str, str]:
    return engine_status()


@app.post("/api/engine/config-test")
def test_engine_config(_: dict = Depends(get_admin)) -> dict:
    binary = engine_binary()
    if not binary:
        raise HTTPException(status_code=503, detail="Xray binary not found. Install a verified Xray release or set NOVAPANEL_XRAY_BINARY.")
    try:
        config = build_xray_config()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    config_path = DATA_DIR / "xray-config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    try:
        result = subprocess.run([binary, "run", "-test", "-config", str(config_path)], capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(status_code=500, detail=f"Could not test Xray config: {exc}") from exc
    if result.returncode != 0:
        raise HTTPException(status_code=422, detail=(result.stderr or result.stdout or "Xray rejected the configuration.")[-3000:])
    return {"ok": True, "message": "Xray accepted the configuration."}


@app.post("/api/engine/start")
def start_engine(_: dict = Depends(get_admin)) -> dict[str, str]:
    global _ENGINE_PROCESS, _ENGINE_LOG_HANDLE
    with _ENGINE_LOCK:
        if _ENGINE_PROCESS is not None and _ENGINE_PROCESS.poll() is None:
            return {"status": "running"}
        binary = engine_binary()
        if not binary:
            raise HTTPException(status_code=503, detail="Xray binary not found. Install a verified Xray release or set NOVAPANEL_XRAY_BINARY.")
        try:
            config = build_xray_config()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        config_path = DATA_DIR / "xray-config.json"
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        try:
            check = subprocess.run([binary, "run", "-test", "-config", str(config_path)], capture_output=True, text=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HTTPException(status_code=500, detail=f"Could not validate Xray config: {exc}") from exc
        if check.returncode != 0:
            raise HTTPException(status_code=422, detail=(check.stderr or check.stdout or "Xray rejected the configuration.")[-3000:])
        log_path = DATA_DIR / "xray.log"
        _ENGINE_LOG_HANDLE = log_path.open("a", encoding="utf-8")
        try:
            _ENGINE_PROCESS = subprocess.Popen([binary, "run", "-config", str(config_path)], stdin=subprocess.DEVNULL, stdout=_ENGINE_LOG_HANDLE, stderr=subprocess.STDOUT, close_fds=True)
            time.sleep(0.35)
            if _ENGINE_PROCESS.poll() is not None:
                _ENGINE_PROCESS = None
                raise HTTPException(status_code=500, detail="Xray exited immediately. Check the engine log.")
        except HTTPException:
            raise
        except OSError as exc:
            _ENGINE_PROCESS = None
            raise HTTPException(status_code=500, detail=f"Could not start Xray: {exc}") from exc
        return {"status": "running"}


@app.post("/api/engine/stop")
def stop_engine(_: dict = Depends(get_admin)) -> dict[str, str]:
    global _ENGINE_PROCESS, _ENGINE_LOG_HANDLE
    with _ENGINE_LOCK:
        if _ENGINE_PROCESS is None or _ENGINE_PROCESS.poll() is not None:
            _ENGINE_PROCESS = None
            return {"status": "stopped"}
        _ENGINE_PROCESS.terminate()
        try:
            _ENGINE_PROCESS.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _ENGINE_PROCESS.kill()
            _ENGINE_PROCESS.wait(timeout=3)
        _ENGINE_PROCESS = None
        if _ENGINE_LOG_HANDLE:
            _ENGINE_LOG_HANDLE.close()
            _ENGINE_LOG_HANDLE = None
        return {"status": "stopped"}


@app.get("/api/engine/log")
def get_engine_log(_: dict = Depends(get_admin)) -> dict[str, str]:
    log_path = DATA_DIR / "xray.log"
    if not log_path.is_file():
        return {"log": ""}
    return {"log": log_path.read_text(encoding="utf-8", errors="replace")[-12000:]}
