import "dotenv/config";
import express, { type NextFunction, type Request, type Response } from "express";
import cookieSession from "cookie-session";
import cors from "cors";
import Database from "better-sqlite3";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { accessSync, createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, pbkdf2Sync, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { WebSocket, WebSocketServer } from "ws";
import * as unzipper from "unzipper";
import { z } from "zod";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const VERSION = "0.6.0";
const AUTO_CONNECTION_ID = "novapanel-platform-ws";
const PLATFORM_WS_PORT = 10086;
const PASSWORD_ROUNDS = 600_000;
const DATA_DIR = resolve(process.env.NOVAPANEL_DATA_DIR || join(ROOT, "data"));
const DB_PATH = join(DATA_DIR, "novapanel.sqlite3");
const COOKIE_SECURE = /^(1|true|yes)$/i.test(process.env.NOVAPANEL_COOKIE_SECURE || "0");
const SESSION_SECRET = process.env.NOVAPANEL_SECRET_KEY || randomBytes(48).toString("base64url");
const app = express();
const db = (() => {
  mkdirSync(DATA_DIR, { recursive: true });
  const connection = new Database(DB_PATH);
  connection.pragma("foreign_keys = ON");
  connection.pragma("journal_mode = WAL");
  connection.pragma("busy_timeout = 10000");
  connection.exec(`
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
      subscription_token_hash TEXT UNIQUE,
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
    CREATE TABLE IF NOT EXISTS traffic_usage (
      user_id TEXT PRIMARY KEY REFERENCES vpn_users(id) ON DELETE CASCADE,
      up_bytes INTEGER NOT NULL DEFAULT 0,
      down_bytes INTEGER NOT NULL DEFAULT 0,
      last_synced_at TEXT
    );
  `);
  const columns = connection.prepare("PRAGMA table_info(vpn_users)").all() as Array<{name:string}>;
  if (!columns.some((column) => column.name === "subscription_token_hash")) {
    connection.exec("ALTER TABLE vpn_users ADD COLUMN subscription_token_hash TEXT");
  }
  connection.exec("INSERT OR IGNORE INTO traffic_usage(user_id) SELECT id FROM vpn_users");
  return connection;
})();

type Row = Record<string, any>;
type Capability = { status: "available" | "unavailable" | "unknown"; detail: string };
class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) { super(message); this.status = status; }
}

const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "+00:00");
const hashToken = (token: string) => createHash("sha256").update(token, "utf8").digest("hex");
function passwordHash(password: string, salt = randomBytes(16)): { salt: string; hash: string } {
  return { salt: salt.toString("hex"), hash: pbkdf2Sync(password, salt, PASSWORD_ROUNDS, 32, "sha256").toString("hex") };
}
function checkPassword(password: string, saltHex: string, expectedHex: string): boolean {
  try {
    const actual = Buffer.from(passwordHash(password, Buffer.from(saltHex, "hex")).hash, "hex");
    const expected = Buffer.from(expectedHex, "hex");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch { return false; }
}
function requestHost(req: Request): string | null {
  let candidate = (process.env.NOVAPANEL_PUBLIC_HOST || "").trim();
  if (!candidate && process.env.NOVAPANEL_PUBLIC_BASE_URL) {
    try { candidate = new URL(process.env.NOVAPANEL_PUBLIC_BASE_URL.includes("://") ? process.env.NOVAPANEL_PUBLIC_BASE_URL : "https://" + process.env.NOVAPANEL_PUBLIC_BASE_URL).hostname; } catch { /* invalid override */ }
  }
  if (!candidate) {
    for (const env of ["RAILWAY_PUBLIC_DOMAIN", "RENDER_EXTERNAL_HOSTNAME", "KOYEB_PUBLIC_DOMAIN", "SERVICE_FQDN"]) {
      if (process.env[env]) { candidate = process.env[env]!.trim(); break; }
    }
  }
  if (!candidate && process.env.FLY_APP_NAME) candidate = process.env.FLY_APP_NAME + ".fly.dev";
  if (!candidate && process.env.HEROKU_APP_NAME) candidate = process.env.HEROKU_APP_NAME + ".herokuapp.com";
  if (!candidate) candidate = (req.get("x-forwarded-host") || req.get("host") || req.hostname || "").split(",")[0].trim().split(":")[0];
  candidate = candidate.toLowerCase().replace(/^\[|\]$/g, "").replace(/^\s+|\s+$/g, "").replace(/^\.+|\.+$/g, "");
  if (!candidate || /[\/?#@\s]/.test(candidate)) return null;
  if (isIP(candidate)) return candidate;
  if (candidate.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(candidate)) return null;
  return candidate;
}
function deploymentMode(): "direct" | "paas_ws" {
  const configured = (process.env.NOVAPANEL_DEPLOYMENT_MODE || "auto").trim().toLowerCase();
  if (configured === "direct" || configured === "paas_ws") return configured;
  const markers = ["PORT", "SERVER_PORT", "RAILWAY_PUBLIC_DOMAIN", "RENDER_EXTERNAL_HOSTNAME", "KOYEB_PUBLIC_DOMAIN", "FLY_APP_NAME", "HEROKU_APP_NAME", "SERVICE_FQDN"];
  return markers.some((key) => process.env[key]) ? "paas_ws" : "direct";
}
const isPlatformWsMode = () => deploymentMode() === "paas_ws";
function publicOrigin(req: Request): string {
  const fromEnv = (process.env.NOVAPANEL_PUBLIC_BASE_URL || "").trim().replace(/\/$/, "");
  if (fromEnv) return fromEnv;
  if (isPlatformWsMode()) {
    const host = requestHost(req);
    if (host) return "https://" + host;
  }
  const proto = (req.get("x-forwarded-proto") || req.protocol).split(",")[0].trim();
  const host = (req.get("x-forwarded-host") || req.get("host") || req.hostname).split(",")[0].trim();
  return `${proto}://${host}`;
}
function engineBinary(): string | null {
  const configured = process.env.NOVAPANEL_XRAY_BINARY;
  const candidates = [configured, join(ROOT, "bin", "xray"), ...((process.env.PATH || "").split(":").map((dir) => join(dir, "xray")))];
  for (const candidate of candidates) {
    if (!candidate) continue;
    try { if (existsSync(candidate)) { accessSyncExecutable(candidate); return resolve(candidate); } } catch { /* not executable */ }
  }
  return null;
}
function accessSyncExecutable(path: string) { accessSync(path, constants.X_OK); }
function xrayEnvironment(binary: string): NodeJS.ProcessEnv {
  const env = { ...process.env };
  if (resolve(dirname(binary)) === resolve(ROOT, "bin")) env.XRAY_LOCATION_ASSET = join(ROOT, "bin");
  return env;
}
function initPlatformConnection(req?: Request): Row | null {
  if (!isPlatformWsMode()) return null;
  const host = req ? requestHost(req) : requestHostFromEnvironment();
  if (!host) return null;
  let row = db.prepare("SELECT * FROM connections WHERE id=?").get(AUTO_CONNECTION_ID) as Row | undefined;
  if (!row) {
    db.prepare(`INSERT INTO connections
      (id,name,address,port,transport,path,service_name,host_header,server_name,certificate_file,private_key_file,enabled,created_at)
      VALUES (?, ?, ?, 443, 'ws', ?, 'novapanel', ?, ?, NULL, NULL, 1, ?)`).run(
        AUTO_CONNECTION_ID, "اتصال خودکار میزبان", host, "/connect/" + randomBytes(24).toString("base64url"), host, host, nowIso()
      );
  } else {
    db.prepare("UPDATE connections SET address=?, port=443, transport='ws', host_header=?, server_name=?, certificate_file=NULL, private_key_file=NULL, enabled=1 WHERE id=?")
      .run(host, host, host, AUTO_CONNECTION_ID);
  }
  row = db.prepare("SELECT * FROM connections WHERE id=?").get(AUTO_CONNECTION_ID) as Row | undefined;
  return row || null;
}
function requestHostFromEnvironment(): string | null {
  const value = process.env.NOVAPANEL_PUBLIC_HOST || process.env.RAILWAY_PUBLIC_DOMAIN || process.env.RENDER_EXTERNAL_HOSTNAME || process.env.KOYEB_PUBLIC_DOMAIN || process.env.SERVICE_FQDN;
  if (!value) return null;
  const candidate = value.trim().toLowerCase().replace(/^\.+|\.+$/g, "");
  return candidate && !/[\/?#@\s]/.test(candidate) ? candidate : null;
}
function cleanUser(row: Row): Row {
  const up = Number(row.up_bytes || 0), down = Number(row.down_bytes || 0);
  return { id: row.id, name: row.name, uuid: row.client_uuid, quota_gb: row.quota_gb, expires_at: row.expires_at, enabled: Boolean(row.enabled), created_at: row.created_at, up_bytes: up, down_bytes: down, used_bytes: up + down, last_synced_at: row.last_synced_at ?? null };
}
function cleanConnection(row: Row): Row {
  let cert = false;
  try { cert = Boolean(row.certificate_file && row.private_key_file && existsSync(row.certificate_file) && existsSync(row.private_key_file)); } catch { /* unreadable */ }
  const managed = isPlatformWsMode() && row.id === AUTO_CONNECTION_ID && row.transport === "ws";
  return {
    id: row.id, name: row.name, address: row.address, port: row.port, transport: row.transport, path: row.path,
    service_name: row.service_name, host_header: row.host_header, server_name: row.server_name,
    certificate_file: row.certificate_file, private_key_file: row.private_key_file, enabled: Boolean(row.enabled),
    created_at: row.created_at, tls_ready: cert || managed, managed_by_platform: managed
  };
}
function clientLink(user: Row, connection: Row): string {
  const params = new URLSearchParams({
    encryption: "none", security: "tls", sni: connection.server_name || connection.address,
    type: connection.transport, fp: "chrome"
  });
  if (["ws", "httpupgrade", "xhttp"].includes(connection.transport)) {
    params.set("path", connection.path);
    if (connection.host_header) params.set("host", connection.host_header);
  }
  if (connection.transport === "grpc") params.set("serviceName", connection.service_name);
  const label = encodeURIComponent(`${connection.name} · ${user.name}`);
  return `vless://${user.uuid}@${connection.address}:${connection.port}?${params.toString()}#${label}`;
}
function disableExpiredUsers(): string[] {
  const disabled: string[] = [];
  const rows = db.prepare(`SELECT u.id,u.quota_gb,u.expires_at,COALESCE(t.up_bytes,0)+COALESCE(t.down_bytes,0) AS used_bytes
    FROM vpn_users u LEFT JOIN traffic_usage t ON t.user_id=u.id WHERE u.enabled=1`).all() as Row[];
  const now = Date.now();
  const update = db.prepare("UPDATE vpn_users SET enabled=0 WHERE id=?");
  for (const row of rows) {
    const expired = row.expires_at ? Date.parse(row.expires_at) <= now : false;
    const quota = row.quota_gb !== null && row.quota_gb !== undefined && Number(row.used_bytes) >= Number(row.quota_gb) * 1024 ** 3;
    if ((expired && Number.isFinite(Date.parse(row.expires_at))) || quota) {
      update.run(row.id); disabled.push(row.id);
    }
  }
  return disabled;
}
function buildXrayConfig(): Row {
  disableExpiredUsers();
  const auto = isPlatformWsMode();
  const users = db.prepare("SELECT * FROM vpn_users WHERE enabled=1").all() as Row[];
  const connections = (auto
    ? db.prepare("SELECT * FROM connections WHERE id=? AND enabled=1").all(AUTO_CONNECTION_ID)
    : db.prepare("SELECT * FROM connections WHERE enabled=1 ORDER BY created_at").all()) as Row[];
  if (!connections.length) throw new ApiError(422, "Create and enable at least one connection first.");
  if (!users.length) throw new ApiError(422, "Create and enable at least one user first.");
  const inbounds = connections.map((item) => {
    const clients = users.map((u) => ({ id: u.client_uuid, email: `np-${u.id}@local` }));
    let listen: string, port: number, stream: Row;
    if (auto && item.id === AUTO_CONNECTION_ID) {
      let internalPort = Number.parseInt(process.env.NOVAPANEL_XRAY_WS_PORT || String(PLATFORM_WS_PORT), 10);
      if (!Number.isFinite(internalPort) || internalPort < 1024 || internalPort > 65535 || internalPort === 10085) internalPort = PLATFORM_WS_PORT;
      listen = "127.0.0.1"; port = internalPort;
      stream = { method: "websocket", security: "none", wsSettings: { path: item.path, host: "" } };
    } else {
      if (!item.certificate_file || !item.private_key_file || !existsSync(item.certificate_file) || !existsSync(item.private_key_file)) {
        throw new ApiError(422, `TLS certificate and private key are required for "${item.name}".`);
      }
      listen = "0.0.0.0"; port = Number(item.port);
      const method: Row = { ws: "websocket", grpc: "grpc", httpupgrade: "httpupgrade", xhttp: "xhttp" };
      stream = { method: method[item.transport], security: "tls", tlsSettings: { minVersion: "1.2", alpn: ["h2", "http/1.1"], certificates: [{ certificateFile: item.certificate_file, keyFile: item.private_key_file }] } };
      if (item.transport === "ws") stream.wsSettings = { path: item.path, host: item.host_header || "" };
      else if (item.transport === "httpupgrade") stream.httpupgradeSettings = { path: item.path, host: item.host_header || "" };
      else if (item.transport === "grpc") stream.grpcSettings = { serviceName: item.service_name, multiMode: false };
      else if (item.transport === "xhttp") stream.xhttpSettings = { path: item.path, host: item.host_header || "", mode: "auto" };
    }
    return { tag: `novapanel-${String(item.id).slice(0, 8)}`, listen, port, protocol: "vless", settings: { clients, decryption: "none" }, streamSettings: stream, sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] } };
  });
  return {
    log: { loglevel: "warning" }, api: { tag: "api", listen: "127.0.0.1:10085", services: ["StatsService"] },
    stats: {}, policy: { levels: { "0": { statsUserUplink: true, statsUserDownlink: true } } }, inbounds,
    outbounds: [{ protocol: "freedom", tag: "direct" }, { protocol: "blackhole", tag: "blocked" }],
    routing: { rules: [{ type: "field", ip: ["geoip:private"], outboundTag: "blocked" }] }
  };
}

const setupSchema = z.object({ password: z.string().min(14).max(256) });
const loginSchema = z.object({ password: z.string().min(1).max(256) });
const expirySchema = z.string().max(40).refine((v) => /(?:Z|[+-]\d{2}:?\d{2})$/i.test(v) && Number.isFinite(Date.parse(v)), "Expiry must include a timezone.").transform((v) => new Date(v).toISOString());
const userCreateSchema = z.object({ name: z.string().min(1).max(80), quota_gb: z.number().int().min(1).max(1_000_000).nullable().optional(), expires_at: expirySchema.nullable().optional(), enabled: z.boolean().default(true) });
const userUpdateSchema = z.object({ name: z.string().min(1).max(80).optional(), quota_gb: z.number().int().min(1).max(1_000_000).nullable().optional(), expires_at: expirySchema.nullable().optional(), enabled: z.boolean().optional() });
const hostnameSchema = z.string().min(1).max(253).refine((value) => {
  const v = value.trim();
  return !/[\/?#@\s]/.test(v) && (isIP(v) !== 0 || /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/.test(v));
}, "Invalid hostname.").transform((v) => isIP(v.trim()) ? v.trim() : v.trim().toLowerCase());
const connectionSchema = z.object({
  name: z.string().min(1).max(80), address: hostnameSchema, port: z.number().int().min(1).max(65535),
  transport: z.enum(["ws", "grpc", "httpupgrade", "xhttp"]).default("ws"),
  path: z.string().min(1).max(200).default("/").refine((v) => v.startsWith("/") && !/[\r\n?#]/.test(v), "Path must start with / and contain no query or fragment."),
  service_name: z.string().max(200).default("novapanel"),
  host_header: hostnameSchema.nullable().optional(), server_name: hostnameSchema.nullable().optional(),
  certificate_file: z.string().max(500).nullable().optional(), private_key_file: z.string().max(500).nullable().optional(), enabled: z.boolean().default(true)
}).refine((v) => Boolean(v.certificate_file) === Boolean(v.private_key_file), "Provide both certificate and private key paths, or leave both empty.");

function body<T>(schema: z.ZodType<T>, req: Request): T {
  const result = schema.safeParse(req.body);
  if (!result.success) throw new ApiError(422, result.error.issues.map((issue) => `${issue.path.join(".") || "body"}: ${issue.message}`).join("; "));
  return result.data;
}
function adminCount() { return Number((db.prepare("SELECT COUNT(*) AS count FROM admins").get() as Row).count); }
function auth(req: Request, res: Response, next: NextFunction) {
  const id = req.session?.admin_id;
  if (!Number.isInteger(id)) return res.status(401).json({ detail: "Please sign in." });
  const row = db.prepare("SELECT id FROM admins WHERE id=?").get(id);
  if (!row) { req.session = null; return res.status(401).json({ detail: "Please sign in." }); }
  (req as any).admin = { id, username: "مدیر اصلی" };
  next();
}
function requireAdmin(req: Request): Row { return (req as any).admin as Row; }
function engineStatus() { return engineProcess && engineProcess.exitCode === null && !engineProcess.killed ? { status: "running" } : { status: "stopped" }; }
function writeXrayConfig(config: Row) {
  const file = join(DATA_DIR, "xray-config.json");
  writeFileSync(file, JSON.stringify(config, null, 2), "utf8");
  return file;
}
let engineProcess: ChildProcess | null = null;
let engineLogStream: ReturnType<typeof createWriteStream> | null = null;
let trafficTimer: NodeJS.Timeout | null = null;
let trafficSyncInProgress = false;
const loginAttempts = new Map<string, number[]>();

function syncTrafficCounters(): boolean {
  const binary = engineBinary();
  if (!binary) return false;
  try {
    const output = execFileSync(binary, ["api", "statsquery", "--server=127.0.0.1:10085", "--pattern", "user>>>", "--reset"], { encoding: "utf8", timeout: 8000, env: xrayEnvironment(binary), stdio: ["ignore", "pipe", "pipe"] });
    const payload = JSON.parse(output) as { stat?: Array<{name?: string;value?: number|string}> };
    const counters = new Map<string, {up:number;down:number}>();
    for (const item of payload.stat || []) {
      const parts = String(item.name || "").split(">>>");
      if (parts.length !== 4 || parts[0] !== "user" || parts[2] !== "traffic") continue;
      const email = parts[1] || "";
      if (!email.startsWith("np-") || !email.endsWith("@local") || !["uplink", "downlink"].includes(parts[3] || "")) continue;
      const id = email.slice(3, -6); const value = Math.max(0, Number(item.value) || 0);
      const current = counters.get(id) || { up: 0, down: 0 };
      if (parts[3] === "uplink") current.up += value; else current.down += value;
      counters.set(id, current);
    }
    const update = db.prepare("UPDATE traffic_usage SET up_bytes=up_bytes+?,down_bytes=down_bytes+?,last_synced_at=? WHERE user_id=?");
    const transaction = db.transaction(() => { for (const [id, count] of counters) update.run(count.up, count.down, nowIso(), id); });
    transaction(); return true;
  } catch { return false; }
}
function startTrafficMonitor() {
  if (trafficTimer) clearInterval(trafficTimer);
  trafficTimer = setInterval(async () => {
    if (trafficSyncInProgress || engineStatus().status !== "running") return;
    trafficSyncInProgress = true;
    try {
      syncTrafficCounters();
      const disabled = disableExpiredUsers();
      if (disabled.length) {
        await stopEngine();
        try { await startEngine(); } catch (error) {
          const logPath = join(DATA_DIR, "xray.log");
          const msg = `\n[NovaPanel] Engine restart failed after a quota or expiry limit was reached: ${String(error)}\n`;
          try { await writeFile(logPath, msg, { flag: "a" }); } catch { /* best effort */ }
        }
      }
    } catch { /* monitor must not take down the API */ }
    finally { trafficSyncInProgress = false; }
  }, 15_000);
}
function stopTrafficMonitor() { if (trafficTimer) clearInterval(trafficTimer); trafficTimer = null; }
async function startEngine(): Promise<Row> {
  if (engineStatus().status === "running") return { status: "running" };
  let binary = engineBinary();
  if (!binary && isPlatformWsMode()) {
    await ensureXrayInstalled();
    binary = engineBinary();
  }
  if (!binary) throw new ApiError(503, "Xray binary not found. Install a verified Xray release or set NOVAPANEL_XRAY_BINARY.");
  let config: Row;
  try { config = buildXrayConfig(); } catch (error) { if (error instanceof ApiError) throw error; throw new ApiError(422, String(error)); }
  const configPath = writeXrayConfig(config);
  try {
    execFileSync(binary, ["run", "-test", "-config", configPath], { encoding: "utf8", timeout: 20_000, env: xrayEnvironment(binary), stdio: ["ignore", "pipe", "pipe"] });
  } catch (error: any) {
    const detail = String(error?.stderr || error?.stdout || error?.message || "Xray rejected the configuration.").slice(-3000);
    throw new ApiError(422, detail);
  }
  const logPath = join(DATA_DIR, "xray.log");
  engineLogStream = createWriteStream(logPath, { flags: "a" });
  const child = spawn(binary, ["run", "-config", configPath], { stdio: ["ignore", engineLogStream, engineLogStream], env: xrayEnvironment(binary) });
  engineProcess = child;
  const spawnState: { error: Error | null } = { error: null };
  child.once("error", (error) => { spawnState.error = error; });
  await delay(350);
  if (spawnState.error || child.exitCode !== null) {
    engineProcess = null;
    engineLogStream.end(); engineLogStream = null;
    throw new ApiError(500, `Xray exited immediately. Check the engine log. ${spawnState.error ? spawnState.error.message : ""}`);
  }
  child.once("exit", () => { if (engineProcess === child) { engineProcess = null; stopTrafficMonitor(); } });
  startTrafficMonitor();
  return { status: "running" };
}
async function stopEngine(): Promise<Row> {
  stopTrafficMonitor();
  const child = engineProcess;
  if (!child || child.exitCode !== null) {
    engineProcess = null;
    if (engineLogStream) { engineLogStream.end(); engineLogStream = null; }
    return { status: "stopped" };
  }
  child.kill("SIGTERM");
  await Promise.race([new Promise<void>((resolveDone) => child.once("exit", () => resolveDone())), delay(5000)]);
  if (child.exitCode === null) { child.kill("SIGKILL"); await Promise.race([new Promise<void>((resolveDone) => child.once("exit", () => resolveDone())), delay(3000)]); }
  if (engineProcess === child) engineProcess = null;
  if (engineLogStream) { engineLogStream.end(); engineLogStream = null; }
  return { status: "stopped" };
}
async function reconcileEngine(): Promise<Row> {
  if (engineStatus().status !== "running") return { engine_applied: false, message: "ذخیره شد؛ تغییرات در اجرای بعدی Xray اعمال می‌شوند." };
  syncTrafficCounters();
  await stopEngine();
  try { await startEngine(); return { engine_applied: true, message: "تغییرات ذخیره شد و Xray با تنظیمات جدید راه‌اندازی شد." }; }
  catch (error) { return { engine_applied: false, message: "تنظیمات ذخیره شد، اما Xray شروع نشد: " + (error instanceof Error ? error.message : String(error)) }; }
}
let autoEngineStartup: Promise<void> | null = null;
function scheduleAutoEngineStart(): void {
  if (autoEngineStartup) return;
  autoEngineStartup = (async () => {
    try {
      if (!engineBinary()) await ensureXrayInstalled();
      if (!engineBinary()) {
        console.warn("[NovaPanel] Xray is unavailable; the panel remains online.");
        return;
      }
      const clients = Number((db.prepare("SELECT COUNT(*) AS n FROM vpn_users WHERE enabled=1").get() as Row).n);
      const profile = Number((db.prepare("SELECT COUNT(*) AS n FROM connections WHERE id=? AND enabled=1").get(AUTO_CONNECTION_ID) as Row).n);
      if (isPlatformWsMode() && clients && profile && engineStatus().status !== "running") await startEngine();
    } catch (error) {
      console.error("[NovaPanel] Automatic Xray startup failed; panel remains online:", error);
    } finally {
      autoEngineStartup = null;
    }
  })();
}
async function maybeStartAutoEngine(): Promise<Row> {
  if (!isPlatformWsMode() || engineStatus().status === "running") return {};
  const clients = Number((db.prepare("SELECT COUNT(*) AS n FROM vpn_users WHERE enabled=1").get() as Row).n);
  const profile = Number((db.prepare("SELECT COUNT(*) AS n FROM connections WHERE id=? AND enabled=1").get(AUTO_CONNECTION_ID) as Row).n);
  if (!clients || !profile) return {};
  if (!engineBinary()) {
    scheduleAutoEngineStart();
    return { engine_applied: false, message: "کاربر ساخته شد؛ نصب و اجرای موتور Xray در پس‌زمینه انجام می‌شود و پنل آنلاین می‌ماند." };
  }
  try { await startEngine(); return { engine_applied: true, message: "موتور اتصال خودکار اجرا شد." }; }
  catch (error) { return { engine_applied: false, message: "اتصال خودکار ساخته شد، اما Xray اجرا نشد: " + (error instanceof Error ? error.message : String(error)) }; }
}

app.disable("x-powered-by");
app.set("trust proxy", true);
app.use(express.json({ limit: "64kb" }));
const origins = (process.env.NOVAPANEL_CORS_ORIGINS || "http://127.0.0.1:5173,http://localhost:5173").split(",").map((v) => v.trim()).filter(Boolean);
app.use(cors({ origin: (origin, callback) => callback(null, !origin || origins.includes(origin)), credentials: true, methods: ["GET", "POST", "PUT", "DELETE"], allowedHeaders: ["Content-Type"] }));
app.use(cookieSession({ name: "novapanel_session", keys: [SESSION_SECRET], maxAge: 12 * 60 * 60 * 1000, httpOnly: true, sameSite: "strict", secure: COOKIE_SECURE }));
app.use((req, _res, next) => { if (req.url.startsWith("/api/") && req.method === "OPTIONS") return next(); next(); });

app.get("/api/health", (_req, res) => res.json({ status: "ok", app: "NovaPanel", version: VERSION }));
app.get("/api/setup/status", (_req, res) => res.json({ setup_required: adminCount() === 0 }));
app.post("/api/setup", (req, res, next) => {
  try {
    const data = body(setupSchema, req);
    const create = db.transaction(() => {
      if (adminCount() > 0) throw new ApiError(409, "Initial setup is already complete.");
      const { salt, hash } = passwordHash(data.password);
      const result = db.prepare("INSERT INTO admins(username,password_salt,password_hash,created_at) VALUES('admin',?,?,?)").run(salt, hash, nowIso());
      return Number(result.lastInsertRowid);
    });
    const id = create();
    req.session = { admin_id: id };
    initPlatformConnection(req);
    res.json({ ok: true });
  } catch (error) { next(error); }
});
app.post("/api/login", (req, res, next) => {
  try {
    const data = body(loginSchema, req);
    const ip = req.ip || req.socket.remoteAddress || "unknown";
    const now = Date.now(); const recent = (loginAttempts.get(ip) || []).filter((stamp) => now - stamp < 900_000);
    if (recent.length >= 10) throw new ApiError(429, "Too many attempts. Try again in 15 minutes.");
    const row = db.prepare("SELECT * FROM admins ORDER BY id ASC LIMIT 1").get() as Row | undefined;
    if (!row || !checkPassword(data.password, row.password_salt, row.password_hash)) {
      recent.push(now); loginAttempts.set(ip, recent); throw new ApiError(401, "رمز عبور مدیر نادرست است.");
    }
    loginAttempts.delete(ip); req.session = { admin_id: Number(row.id) }; res.json({ ok: true });
  } catch (error) { next(error); }
});
app.post("/api/logout", auth, (req, res) => { req.session = null; res.json({ ok: true }); });
app.get("/api/me", auth, (req, res) => res.json(requireAdmin(req)));
app.get("/api/deployment", auth, async (req, res, next) => {
  try {
    const mode = deploymentMode(); const profile = mode === "paas_ws" ? initPlatformConnection(req) : null;
    const autoEngine = await maybeStartAutoEngine(); const host = profile?.address || requestHost(req);
    const message = profile
      ? "پروفایل خودکار ساخته شده؛ میزبان باید WebSocket Upgrade و اجرای Xray را مجاز بداند."
      : mode === "direct" ? "حالت مستقیم فعال است؛ اتصال و گواهی TLS سرور را یک‌بار تعریف کن."
      : "دامنه عمومی میزبان تشخیص داده نشد؛ NOVAPANEL_PUBLIC_HOST را در متغیرهای محیطی تنظیم کن.";
    res.json({ mode, public_host: host, auto_connection: Boolean(profile), xray_available: Boolean(engineBinary()), engine_status: engineStatus().status, websocket_ingress: "requires-provider-support", message, ...autoEngine });
  } catch (error) { next(error); }
});
app.get("/api/host", auth, (_req, res) => {
  let writable = false; try { accessSyncWritable(DATA_DIR); writable = true; } catch { /* report unavailable */ }
  const binary = engineBinary();
  const capabilities: Record<string, Capability> = {
    persistent_storage: { status: writable ? "available" : "unavailable", detail: writable ? "The configured data directory is writable." : "The configured data directory is not writable." },
    separate_processes: { status: "available", detail: "The Node.js runtime can launch managed processes. Provider policies and process lifetime still need verification." },
    xray_binary: { status: binary ? "available" : "unknown", detail: binary ? `Xray detected at ${binary}.` : "Xray is not installed or NOVAPANEL_XRAY_BINARY is not configured." },
    inbound_tcp_udp: { status: "unknown", detail: "Network reachability cannot be verified from inside this process." }
  };
  res.json({ platform: process.platform, node_version: process.version, data_directory: DATA_DIR, capabilities });
});
function accessSyncWritable(path: string) { accessSync(path, constants.W_OK); }

app.get("/api/dashboard", auth, (_req, res) => {
  disableExpiredUsers();
  const users = Number((db.prepare("SELECT COUNT(*) AS n FROM vpn_users").get() as Row).n);
  const active = Number((db.prepare("SELECT COUNT(*) AS n FROM vpn_users WHERE enabled=1").get() as Row).n);
  const connections = Number((db.prepare("SELECT COUNT(*) AS n FROM connections").get() as Row).n);
  const enabledConnections = Number((db.prepare("SELECT COUNT(*) AS n FROM connections WHERE enabled=1").get() as Row).n);
  const totalBytes = Number((db.prepare("SELECT COALESCE(SUM(up_bytes+down_bytes),0) AS n FROM traffic_usage").get() as Row).n);
  res.json({ users_total: users, users_enabled: active, connections_total: connections, connections_enabled: enabledConnections, total_bytes: totalBytes, engine: engineStatus().status, version: VERSION });
});
app.get("/api/users", auth, (_req, res) => {
  disableExpiredUsers();
  const rows = db.prepare("SELECT u.*,t.up_bytes,t.down_bytes,t.last_synced_at FROM vpn_users u LEFT JOIN traffic_usage t ON t.user_id=u.id ORDER BY u.created_at DESC").all() as Row[];
  res.json(rows.map(cleanUser));
});
app.post("/api/users", auth, async (req, res, next) => {
  try {
    const data = body(userCreateSchema, req); const id = randomUUID(); const clientId = randomUUID();
    const create = db.transaction(() => {
      db.prepare("INSERT INTO vpn_users(id,name,client_uuid,quota_gb,expires_at,enabled,created_at) VALUES(?,?,?,?,?,?,?)").run(id, data.name.trim(), clientId, data.quota_gb ?? null, data.expires_at ?? null, Number(data.enabled), nowIso());
      db.prepare("INSERT INTO traffic_usage(user_id) VALUES(?)").run(id);
    });
    create();
    const row = db.prepare("SELECT u.*,t.up_bytes,t.down_bytes,t.last_synced_at FROM vpn_users u LEFT JOIN traffic_usage t ON t.user_id=u.id WHERE u.id=?").get(id) as Row;
    if (isPlatformWsMode()) {
      const startup = await maybeStartAutoEngine();
      res.status(201).json({ ...cleanUser(row), ...(Object.keys(startup).length ? startup : { engine_applied: engineStatus().status === "running", message: "کاربر ساخته شد؛ پروفایل خودکار میزبان استفاده می‌شود. وضعیت واقعی اتصال به پشتیبانی WebSocket میزبان وابسته است." }) });
    } else res.status(201).json({ ...cleanUser(row), ...(await reconcileEngine()) });
  } catch (error) { next(error); }
});
app.post("/api/users/:userId/subscription", auth, (req, res, next) => {
  try {
    disableExpiredUsers();
    const user = db.prepare("SELECT enabled FROM vpn_users WHERE id=?").get(req.params.userId) as Row | undefined;
    if (!user) throw new ApiError(404, "User not found.");
    if (!user.enabled) throw new ApiError(409, "Enable this user before creating a subscription.");
    const token = randomBytes(32).toString("base64url");
    const result = db.prepare("UPDATE vpn_users SET subscription_token_hash=? WHERE id=? AND enabled=1").run(hashToken(token), req.params.userId);
    if (!result.changes) throw new ApiError(409, "The user is disabled.");
    res.json({ url: publicOrigin(req) + "/api/subscriptions/" + token, message: "Subscription link created. Creating another link will revoke this one." });
  } catch (error) { next(error); }
});
app.get("/api/subscriptions/:token", (req, res, next) => {
  try {
    disableExpiredUsers();
    const tokenHash = hashToken(req.params.token);
    const user = db.prepare("SELECT u.*,t.up_bytes,t.down_bytes,t.last_synced_at FROM vpn_users u LEFT JOIN traffic_usage t ON t.user_id=u.id WHERE u.subscription_token_hash=? AND u.enabled=1").get(tokenHash) as Row | undefined;
    const connections = db.prepare("SELECT * FROM connections WHERE enabled=1 ORDER BY created_at").all() as Row[];
    if (!user) throw new ApiError(404, "Subscription not found or inactive.");
    const cleaned = cleanUser(user);
    const links = connections.map(cleanConnection).filter((connection) => connection.tls_ready || (isPlatformWsMode() && connection.id === AUTO_CONNECTION_ID)).map((connection) => clientLink(cleaned, connection));
    if (!links.length) throw new ApiError(409, "No enabled connection with TLS certificate files is available.");
    res.set({ "Cache-Control": "no-store, max-age=0", Pragma: "no-cache", "Content-Type": "text/plain; charset=utf-8" }).send(Buffer.from(links.join("\n"), "utf8").toString("base64"));
  } catch (error) { next(error); }
});
app.put("/api/users/:userId", auth, async (req, res, next) => {
  try {
    const data = body(userUpdateSchema, req);
    const entries = Object.entries(data).filter(([key]) => ["name", "quota_gb", "expires_at", "enabled"].includes(key));
    if (!entries.length) throw new ApiError(400, "No changes supplied.");
    const mapping: Record<string,string> = { name: "name", quota_gb: "quota_gb", expires_at: "expires_at", enabled: "enabled" };
    const assignments = entries.map(([key]) => `${mapping[key]}=?`).join(",");
    const values = entries.map(([key, value]) => key === "enabled" ? Number(value) : key === "name" && typeof value === "string" ? value.trim() : value);
    const result = db.prepare(`UPDATE vpn_users SET ${assignments} WHERE id=?`).run(...values, req.params.userId);
    if (!result.changes) throw new ApiError(404, "User not found.");
    const row = db.prepare("SELECT u.*,t.up_bytes,t.down_bytes,t.last_synced_at FROM vpn_users u LEFT JOIN traffic_usage t ON t.user_id=u.id WHERE u.id=?").get(req.params.userId) as Row;
    res.json({ ...cleanUser(row), ...(await reconcileEngine()) });
  } catch (error) { next(error); }
});
app.delete("/api/users/:userId", auth, async (req, res, next) => {
  try {
    const result = db.prepare("DELETE FROM vpn_users WHERE id=?").run(req.params.userId);
    if (!result.changes) throw new ApiError(404, "User not found.");
    res.json({ ok: true, ...(await reconcileEngine()) });
  } catch (error) { next(error); }
});
app.post("/api/users/:userId/reset-traffic", auth, (req, res, next) => {
  try {
    const exists = db.prepare("SELECT 1 FROM vpn_users WHERE id=?").get(req.params.userId);
    if (!exists) throw new ApiError(404, "User not found.");
    if (engineStatus().status === "running" && !syncTrafficCounters()) throw new ApiError(503, "Could not synchronize Xray counters. Traffic was not reset; try again.");
    db.prepare("UPDATE traffic_usage SET up_bytes=0,down_bytes=0,last_synced_at=? WHERE user_id=?").run(nowIso(), req.params.userId);
    res.json({ ok: true, message: "Traffic counters were reset." });
  } catch (error) { next(error); }
});
app.get("/api/connections", auth, (_req, res) => res.json((db.prepare("SELECT * FROM connections ORDER BY created_at DESC").all() as Row[]).map(cleanConnection)));
app.post("/api/connections", auth, async (req, res, next) => {
  try {
    if (isPlatformWsMode()) throw new ApiError(409, "این میزبان از پروفایل خودکار استفاده می‌کند؛ برای ورودی مستقیم NOVAPANEL_DEPLOYMENT_MODE=direct تنظیم کن.");
    const data = body(connectionSchema, req); const id = randomUUID();
    db.prepare("INSERT INTO connections(id,name,address,port,transport,path,service_name,host_header,server_name,certificate_file,private_key_file,enabled,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
      .run(id, data.name.trim(), data.address, data.port, data.transport, data.path, data.service_name, data.host_header ?? null, data.server_name ?? null, data.certificate_file ?? null, data.private_key_file ?? null, Number(data.enabled), nowIso());
    const row = db.prepare("SELECT * FROM connections WHERE id=?").get(id) as Row;
    res.status(201).json({ ...cleanConnection(row), ...(await reconcileEngine()) });
  } catch (error) { next(error); }
});
app.put("/api/connections/:connectionId", auth, async (req, res, next) => {
  try {
    if (isPlatformWsMode()) throw new ApiError(409, "پروفایل اتصال در حالت میزبان خودکار مدیریت می‌شود.");
    const data = body(connectionSchema, req);
    const result = db.prepare("UPDATE connections SET name=?,address=?,port=?,transport=?,path=?,service_name=?,host_header=?,server_name=?,certificate_file=?,private_key_file=?,enabled=? WHERE id=?")
      .run(data.name.trim(), data.address, data.port, data.transport, data.path, data.service_name, data.host_header ?? null, data.server_name ?? null, data.certificate_file ?? null, data.private_key_file ?? null, Number(data.enabled), req.params.connectionId);
    if (!result.changes) throw new ApiError(404, "Connection not found.");
    const row = db.prepare("SELECT * FROM connections WHERE id=?").get(req.params.connectionId) as Row;
    res.json({ ...cleanConnection(row), ...(await reconcileEngine()) });
  } catch (error) { next(error); }
});
app.delete("/api/connections/:connectionId", auth, async (req, res, next) => {
  try {
    if (isPlatformWsMode()) throw new ApiError(409, "پروفایل اتصال در حالت میزبان خودکار قابل حذف نیست.");
    const result = db.prepare("DELETE FROM connections WHERE id=?").run(req.params.connectionId);
    if (!result.changes) throw new ApiError(404, "Connection not found.");
    res.json({ ok: true, ...(await reconcileEngine()) });
  } catch (error) { next(error); }
});
app.get("/api/connections/:connectionId/links", auth, (req, res, next) => {
  try {
    disableExpiredUsers();
    const row = db.prepare("SELECT * FROM connections WHERE id=?").get(req.params.connectionId) as Row | undefined;
    const users = db.prepare("SELECT u.*,t.up_bytes,t.down_bytes,t.last_synced_at FROM vpn_users u LEFT JOIN traffic_usage t ON t.user_id=u.id WHERE u.enabled=1 ORDER BY u.name").all() as Row[];
    if (!row) throw new ApiError(404, "Connection not found.");
    const conn = cleanConnection(row);
    if (!conn.enabled) throw new ApiError(409, "This connection is disabled.");
    if (!conn.tls_ready) throw new ApiError(409, "TLS certificate and private key files are required before links can be generated.");
    res.json(users.map((user) => ({ user: user.name, link: clientLink(cleanUser(user), conn) })));
  } catch (error) { next(error); }
});
app.get("/api/engine/status", auth, (_req, res) => res.json(engineStatus()));
app.post("/api/engine/config-test", auth, (_req, res, next) => {
  try {
    const binary = engineBinary();
    if (!binary) throw new ApiError(503, "Xray binary not found. Install a verified Xray release or set NOVAPANEL_XRAY_BINARY.");
    const configPath = writeXrayConfig(buildXrayConfig());
    try {
      execFileSync(binary, ["run", "-test", "-config", configPath], { encoding: "utf8", timeout: 20_000, env: xrayEnvironment(binary), stdio: ["ignore", "pipe", "pipe"] });
    } catch (error: any) { throw new ApiError(422, String(error?.stderr || error?.stdout || error?.message || "Xray rejected the configuration.").slice(-3000)); }
    res.json({ ok: true, message: "Xray accepted the configuration." });
  } catch (error) { next(error); }
});
app.post("/api/engine/start", auth, async (_req, res, next) => { try { res.json(await startEngine()); } catch (error) { next(error); } });
app.post("/api/engine/stop", auth, async (_req, res, next) => { try { res.json(await stopEngine()); } catch (error) { next(error); } });
app.get("/api/engine/log", auth, (_req, res) => {
  const path = join(DATA_DIR, "xray.log");
  if (!existsSync(path)) return res.json({ log: "" });
  try { res.json({ log: readFileSync(path, "utf8").slice(-12_000) }); } catch { res.json({ log: "" }); }
});
app.get("/openapi.json", (_req, res) => res.json({ openapi: "3.0.0", info: { title: "NovaPanel API", version: VERSION }, paths: {} }));

app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) return res.status(404).json({ detail: "Not found." });
  next();
});
const FRONTEND_DIST = join(ROOT, "frontend", "dist");
if (existsSync(FRONTEND_DIST)) {
  const assets = join(FRONTEND_DIST, "assets");
  if (existsSync(assets)) app.use("/assets", express.static(assets, { immutable: true, maxAge: "1y" }));
  app.use(express.static(FRONTEND_DIST, { index: false }));
  app.get(/.*/, (req, res, next) => {
    if (req.path.startsWith("/api/") || req.path === "/openapi.json") return next();
    const index = join(FRONTEND_DIST, "index.html");
    if (!existsSync(index)) return next();
    res.sendFile(index);
  });
}
app.use((error: any, _req: Request, res: Response, _next: NextFunction) => {
  if (res.headersSent) return;
  const status = error instanceof ApiError ? error.status : error?.status && Number.isInteger(error.status) ? error.status : 500;
  const detail = status >= 500 ? "Internal server error." : String(error?.message || "Request failed.");
  if (status >= 500) console.error("[NovaPanel] Request failed:", error);
  res.status(status).json({ detail });
});

let xrayBootstrapPromise: Promise<boolean> | null = null;
function ensureXrayInstalled(): Promise<boolean> {
  if (engineBinary()) return Promise.resolve(true);
  if (/^(0|false|no)$/i.test(process.env.NOVAPANEL_AUTO_INSTALL_XRAY || "1")) return Promise.resolve(false);
  if (!isPlatformWsMode() || process.platform !== "linux") return Promise.resolve(false);
  if (!xrayBootstrapPromise) {
    xrayBootstrapPromise = bootstrapXray().finally(() => { xrayBootstrapPromise = null; });
  }
  return xrayBootstrapPromise;
}

async function bootstrapXray(): Promise<boolean> {
  if (engineBinary()) return true;
  if (!isPlatformWsMode() || process.platform !== "linux") return false;
  const machine = process.arch.toLowerCase();
  const assets: Record<string, { name: string; digest: string }> = {
    x64: { name: "Xray-linux-64.zip", digest: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae" },
    arm64: { name: "Xray-linux-arm64-v8a.zip", digest: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c" }
  };
  const asset = assets[machine];
  if (!asset) { console.warn(`[NovaPanel] Xray auto-install does not support ${machine}.`); return false; }
  try {
    const version = "v26.3.27";
    const url = `https://github.com/XTLS/Xray-core/releases/download/${version}/${asset.name}`;
    console.log(`[NovaPanel] Downloading official Xray-core ${version}.`);
    const response = await fetch(url, { signal: AbortSignal.timeout(90_000), headers: { "User-Agent": "NovaPanel-bootstrap/0.6.0" } });
    if (!response.ok) throw new Error(`Download returned HTTP ${response.status}`);
    const payload = Buffer.from(await response.arrayBuffer());
    const digest = createHash("sha256").update(payload).digest("hex");
    if (digest !== asset.digest) throw new Error("Xray archive SHA-256 mismatch; refusing to install an unverified binary.");
    const directory = await unzipper.Open.buffer(payload);
    const wanted = new Set(["xray", "geoip.dat", "geosite.dat", "LICENSE", "README.md"]);
    await mkdir(join(ROOT, "bin"), { recursive: true });
    const copied = new Set<string>();
    for (const entry of directory.files) {
      const name = entry.path.split("/").pop() || "";
      if (!wanted.has(name)) continue;
      const data = await entry.buffer();
      const output = join(ROOT, "bin", name);
      await writeFile(output, data);
      if (name === "xray") chmodSync(output, 0o755);
      copied.add(name);
    }
    if (!copied.has("xray") || !engineBinary()) throw new Error("Expected executable not found after extraction.");
    console.log("[NovaPanel] Official Xray release verified and installed.");
    if (!copied.has("geoip.dat") || !copied.has("geosite.dat")) console.warn("[NovaPanel] Xray geodata files were not included.");
    return true;
  } catch (error) { console.error("[NovaPanel] Xray auto-install failed; panel will remain available:", error); return false; }
}

const server = createServer(app);
const wss = new WebSocketServer({ noServer: true, maxPayload: 0, perMessageDeflate: false });
server.on("upgrade", (request, socket, head) => {
  const url = new URL(request.url || "/", "http://localhost");
  if (!isPlatformWsMode()) { socket.end("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"); return; }
  initPlatformConnectionFromUpgrade();
  const profile = db.prepare("SELECT * FROM connections WHERE id=? AND enabled=1").get(AUTO_CONNECTION_ID) as Row | undefined;
  if (!profile || url.pathname.replace(/^\//, "") !== String(profile.path).replace(/^\//, "")) {
    socket.end("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"); return;
  }
  wss.handleUpgrade(request, socket, head, (client) => {
    let upstream: WebSocket;
    let settled = false;
    const closeBoth = (code = 1000, reason = "closed") => {
      if (client.readyState === WebSocket.OPEN || client.readyState === WebSocket.CONNECTING) client.close(code, reason.slice(0, 120));
      if (upstream && (upstream.readyState === WebSocket.OPEN || upstream.readyState === WebSocket.CONNECTING)) upstream.close(code, reason.slice(0, 120));
    };
    const port = safeInternalPort();
    upstream = new WebSocket(`ws://127.0.0.1:${port}${profile.path}`, { perMessageDeflate: false, maxPayload: 0, handshakeTimeout: 10_000 });
    upstream.once("open", () => {
      settled = true;
      client.on("message", (data, binary) => { if (upstream.readyState === WebSocket.OPEN) upstream.send(data, { binary }); });
      upstream.on("message", (data, binary) => { if (client.readyState === WebSocket.OPEN) client.send(data, { binary }); });
      client.once("close", () => closeBoth());
      upstream.once("close", () => closeBoth());
    });
    upstream.once("error", () => {
      if (!settled) closeBoth(1011, "Xray upstream is unavailable");
      else closeBoth(1011, "upstream failure");
    });
    client.once("error", () => closeBoth(1011, "client failure"));
  });
});
function safeInternalPort(): number {
  let port = Number.parseInt(process.env.NOVAPANEL_XRAY_WS_PORT || String(PLATFORM_WS_PORT), 10);
  if (!Number.isFinite(port) || port < 1024 || port > 65535 || port === 10085) port = PLATFORM_WS_PORT;
  return port;
}
function initPlatformConnectionFromUpgrade() {
  if (!isPlatformWsMode()) return;
  const host = requestHostFromEnvironment();
  if (!host) return;
  const row = db.prepare("SELECT id FROM connections WHERE id=?").get(AUTO_CONNECTION_ID);
  if (!row) db.prepare("INSERT INTO connections(id,name,address,port,transport,path,service_name,host_header,server_name,certificate_file,private_key_file,enabled,created_at) VALUES(?,?,?,443,'ws',?,'novapanel',?,?,NULL,NULL,1,?)")
    .run(AUTO_CONNECTION_ID, "اتصال خودکار میزبان", host, "/connect/" + randomBytes(24).toString("base64url"), host, host, nowIso());
}

function listen() {
  // Botkeep assigns the application's reachable HTTP port through SERVER_PORT.
  // Prefer it over generic PORT when both happen to be present.
  const configuredPort = process.env.SERVER_PORT || process.env.PORT || "8000";
  const parsedPort = Number.parseInt(configuredPort, 10);
  const port = Number.isFinite(parsedPort) && parsedPort > 0 && parsedPort <= 65535 ? parsedPort : 8000;
  server.listen(port, "0.0.0.0", () => {
    console.log(`[NovaPanel] ${VERSION} listening on 0.0.0.0:${port}`);
    if (isPlatformWsMode() && !process.env.SERVER_PORT && process.env.PORT) {
      console.log("[NovaPanel] PORT detected; SERVER_PORT was not set. For Botkeep, confirm the assigned HTTP port.");
    }
  });
  // Do not download/unpack Xray on a cold start. The control panel should be fast
  // even before users need the connection engine; install it lazily when needed.
}
async function shutdown() {
  try { await stopEngine(); } catch { /* shutdown best effort */ }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 8_000).unref();
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  listen();
  process.once("SIGTERM", () => { void shutdown(); });
  process.once("SIGINT", () => { void shutdown(); });
}

export { app, db, VERSION, buildXrayConfig };
