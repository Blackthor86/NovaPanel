import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net, { isIP } from "node:net";
import http from "node:http";
import https from "node:https";
import http2 from "node:http2";
import tls from "node:tls";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import express from "express";
import * as unzipper from "unzipper";

const APP_NAME = "NovaPanel";
const VERSION = "0.8.0";
const DEFAULT_PANEL_PATH = "knight";
const SESSION_DAYS = 30;
const MIN_PASSWORD_LENGTH = 8;
const USER_AGENT = "NovaPanel/0.8.0";
const IS_MAIN = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), String(salt), 64).toString("hex");
}

function sign(secret, value) {
  return crypto.createHmac("sha256", String(secret)).update(String(value)).digest("hex");
}

function cleanHost(value) {
  let raw = String(value || "").trim().split(",")[0].trim();
  if (!raw) return "";
  try {
    if (raw.includes("://")) raw = new URL(raw).hostname;
    else raw = new URL("http://" + raw).hostname;
  } catch {
    raw = raw.replace(/:\d+$/, "");
  }
  raw = raw.replace(/^\[|\]$/g, "").toLowerCase();
  if (!raw || /[\/?#@\s]/.test(raw)) return "";
  if (isIP(raw)) return raw;
  if (raw.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(raw)) return "";
  return raw;
}

function asn1(tag, ...children) {
  const data = Buffer.concat(children);
  let size;
  if (data.length < 128) size = Buffer.from([data.length]);
  else if (data.length < 256) size = Buffer.from([0x81, data.length]);
  else if (data.length < 65536) size = Buffer.from([0x82, (data.length >> 8) & 255, data.length & 255]);
  else size = Buffer.from([0x83, (data.length >> 16) & 255, (data.length >> 8) & 255, data.length & 255]);
  return Buffer.concat([Buffer.from([tag]), size, data]);
}

function derSequence(...children) { return asn1(0x30, ...children); }
function derInteger(value) { return asn1(0x02, Buffer.isBuffer(value) ? value : Buffer.from([value])); }
function derOid(value) { return asn1(0x06, Buffer.from(value)); }
function derUtf8(value) { return asn1(0x0c, Buffer.from(value, "utf8")); }

function derUtcTime(date) {
  const two = (n) => String(n).padStart(2, "0");
  const value = String(date.getUTCFullYear()).slice(-2) + two(date.getUTCMonth() + 1) +
    two(date.getUTCDate()) + two(date.getUTCHours()) + two(date.getUTCMinutes()) +
    two(date.getUTCSeconds()) + "Z";
  return asn1(0x17, Buffer.from(value, "ascii"));
}

function createSelfSignedCertificate(commonName = "localhost") {
  const pair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const algorithm = derSequence(
    derOid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
    Buffer.from([0x05, 0x00])
  );
  const name = derSequence(asn1(0x31, derSequence(derOid([0x55, 0x04, 0x03]), derUtf8(commonName))));
  const now = new Date();
  const expiry = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
  const serial = crypto.randomBytes(8);
  // DER INTEGERs must be minimally encoded; forcing a nonzero first byte avoids rare invalid certificates.
  serial[0] = (serial[0] & 0x7f) | 0x01;
  const tbs = derSequence(
    asn1(0xa0, derInteger(2)),
    derInteger(serial),
    algorithm,
    name,
    derSequence(derUtcTime(now), derUtcTime(expiry)),
    name,
    pair.publicKey.export({ type: "spki", format: "der" })
  );
  const signature = crypto.sign("sha256", tbs, pair.privateKey);
  const certDer = derSequence(tbs, algorithm, asn1(0x03, Buffer.concat([Buffer.from([0]), signature])));
  const cert = "-----BEGIN CERTIFICATE-----\n" + certDer.toString("base64").match(/.{1,64}/g).join("\n") + "\n-----END CERTIFICATE-----\n";
  const key = pair.privateKey.export({ type: "pkcs8", format: "pem" });
  const parsed = new crypto.X509Certificate(cert);
  return { cert, key, fingerprint: parsed.fingerprint256.replace(/:/g, "").toLowerCase() };
}

function ensureCertificate(dataDir, host) {
  const certPath = path.join(dataDir, "cert", "cert.pem");
  const keyPath = path.join(dataDir, "cert", "key.pem");
  try {
    const cert = fs.readFileSync(certPath, "utf8");
    const key = fs.readFileSync(keyPath, "utf8");
    const parsed = new crypto.X509Certificate(cert);
    const remaining = new Date(parsed.validTo).getTime() - Date.now();
    if (cert.includes("BEGIN CERTIFICATE") && key.includes("PRIVATE KEY") && remaining > 3 * 24 * 60 * 60 * 1000) {
      return { cert, key, fingerprint: parsed.fingerprint256.replace(/:/g, "").toLowerCase(), certPath, keyPath };
    }
  } catch { /* first run or invalid/expired certificate */ }

  fs.mkdirSync(path.dirname(certPath), { recursive: true });
  const generated = createSelfSignedCertificate(host || "localhost");
  fs.writeFileSync(certPath, generated.cert, { encoding: "utf8", mode: 0o644 });
  fs.writeFileSync(keyPath, generated.key, { encoding: "utf8", mode: 0o600 });
  try { fs.chmodSync(keyPath, 0o600); } catch { /* platform may not support POSIX modes */ }
  return { ...generated, certPath, keyPath };
}

function chooseDataDirectory() {
  const candidates = [
    process.env.NOVAPANEL_DATA_DIR,
    process.env.BK_DATA_DIR,
    process.env.FILE_PATH,
    process.env.RAILWAY_VOLUME_MOUNT_PATH,
    path.join(process.cwd(), "bk-data"),
    path.join(os.tmpdir(), "novapanel-data")
  ].filter((x) => typeof x === "string" && x.trim());
  for (const candidate of candidates) {
    try {
      fs.mkdirSync(candidate, { recursive: true });
      fs.accessSync(candidate, fs.constants.W_OK);
      const probe = path.join(candidate, ".novapanel-write-check");
      fs.writeFileSync(probe, "ok");
      fs.unlinkSync(probe);
      return path.resolve(candidate);
    } catch { /* try next writable directory */ }
  }
  throw new Error("NovaPanel could not find a writable data directory. Set NOVAPANEL_DATA_DIR to a writable persistent path.");
}

function readJson(file, fallback) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : fallback;
  } catch {
    return fallback;
  }
}

function writeJson(file, value, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = file + ".tmp";
  fs.writeFileSync(temporary, JSON.stringify(value, null, 2), { encoding: "utf8", mode });
  try { fs.chmodSync(temporary, mode); } catch { /* ignored on non-POSIX systems */ }
  fs.renameSync(temporary, file);
}

function ensurePersistentState(dataDir) {
  const stateFile = path.join(dataDir, "state.json");
  const authFile = path.join(dataDir, "auth.json");
  const state = readJson(stateFile, {});
  const auth = readJson(authFile, {});

  if (!state.uuid || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(state.uuid)) {
    state.uuid = crypto.randomUUID();
  }
  if (!state.subscriptionToken || typeof state.subscriptionToken !== "string") {
    state.subscriptionToken = crypto.randomBytes(24).toString("base64url");
  }
  if (!state.paths || typeof state.paths !== "object") state.paths = {};
  for (const kind of ["vless", "vmess", "trojan", "vlessHu", "vmessHu", "trojanHu", "grpc", "xhttp", "ss"]) {
    if (typeof state.paths[kind] !== "string" || !state.paths[kind].startsWith("/")) {
      state.paths[kind] = "/connect/" + kind.toLowerCase() + "-" + crypto.randomBytes(10).toString("base64url");
    }
  }
  if (!state.grpcService || typeof state.grpcService !== "string") state.grpcService = "novapanel-" + crypto.randomBytes(4).toString("hex");
  if (!state.ssMethod || typeof state.ssMethod !== "string") state.ssMethod = "aes-256-gcm";
  if (!state.ssPassword || typeof state.ssPassword !== "string") state.ssPassword = crypto.randomBytes(18).toString("base64url");
  if (!state.reality || typeof state.reality !== "object") state.reality = {};
  if (!state.reality.privateKey || !state.reality.publicKey) {
    const pair = crypto.generateKeyPairSync("x25519");
    state.reality.privateKey = pair.privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32).toString("base64url");
    state.reality.publicKey = pair.publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("base64url");
  }
  if (!state.reality.shortId || !/^[0-9a-f]{8,16}$/i.test(state.reality.shortId)) state.reality.shortId = crypto.randomBytes(8).toString("hex");
  if (!state.reality.serverName || typeof state.reality.serverName !== "string") state.reality.serverName = String(process.env.NOVAPANEL_REALITY_SNI || "www.microsoft.com").trim().toLowerCase();
  if (!auth.secret || typeof auth.secret !== "string") auth.secret = crypto.randomBytes(32).toString("base64url");

  if (process.env.RESET_PANEL_PASSWORD === "true") {
    delete auth.salt;
    delete auth.hash;
    delete process.env.RESET_PANEL_PASSWORD;
  }
  const envPassword = String(process.env.PANEL_PASSWORD || "");
  if (envPassword && process.env.PANEL_PASSWORD && process.env.NOVAPANEL_RESET_PASSWORD !== "true" &&
      (!auth.hash || !auth.salt || !safeEqual(hashPassword(envPassword, auth.salt), auth.hash))) {
    if (envPassword.length < MIN_PASSWORD_LENGTH) {
      console.warn("[NovaPanel] PANEL_PASSWORD is shorter than 8 characters; ignoring it.");
    } else {
      auth.salt = crypto.randomBytes(16).toString("hex");
      auth.hash = hashPassword(envPassword, auth.salt);
      console.log("[NovaPanel] Admin password loaded from PANEL_PASSWORD.");
    }
  }
  writeJson(stateFile, state, 0o600);
  writeJson(authFile, auth, 0o600);
  return { stateFile, authFile, state, auth };
}

function normalizePanelPath(value) {
  const raw = String(value || DEFAULT_PANEL_PATH).replace(/^\/+|\/+$/g, "");
  if (!/^[a-zA-Z0-9_-]{1,60}$/.test(raw)) return DEFAULT_PANEL_PATH;
  return raw;
}

function normalizeLinkMode(env = process.env) {
  const selected = String(env.NOVAPANEL_LINK_MODE || env.LINK_MODE || "auto").toLowerCase();
  if (selected === "edge" || selected === "direct") return selected;
  if (env.RAILWAY_PUBLIC_DOMAIN || env.RENDER_EXTERNAL_HOSTNAME || env.REPLIT_DEPLOYMENT) return "edge";
  return "direct";
}

function requestPublicHost(req, state) {
  const fromEnv = cleanHost(process.env.NOVAPANEL_PUBLIC_HOST || process.env.DOMAIN ||
    process.env.FORCE_HOST || process.env.RAILWAY_PUBLIC_DOMAIN || process.env.RENDER_EXTERNAL_HOSTNAME ||
    process.env.KOYEB_PUBLIC_DOMAIN || process.env.BOTKEEP_PUBLIC_HOST || process.env.SERVICE_FQDN || "");
  if (fromEnv) return fromEnv;
  const fromRequest = cleanHost(req && (req.get("x-forwarded-host") || req.get("host")));
  if (fromRequest) {
    state.publicHost = fromRequest;
    return fromRequest;
  }
  return cleanHost(state.publicHost) || "127.0.0.1";
}

function requestOrigin(req, host) {
  const configured = String(process.env.NOVAPANEL_PUBLIC_BASE_URL || process.env.PUBLIC_BASE_URL || process.env.SUB_BASE_URL || "").trim();
  if (configured) {
    try { return new URL(configured).origin.replace(/\/$/, ""); } catch { /* ignore invalid override */ }
  }
  if (normalizeLinkMode() === "edge") return "https://" + host;
  const forwardedProto = String((req && req.get("x-forwarded-proto")) || "").split(",")[0].trim();
  const protocol = forwardedProto === "https" ? "https" : ((req && req.protocol) || "http");
  const forwardedHost = String((req && (req.get("x-forwarded-host") || req.get("host"))) || host).split(",")[0].trim();
  if (protocol === "https" && !forwardedHost.includes(":")) return "https://" + forwardedHost;
  return protocol + "://" + forwardedHost;
}

function listenPort(env = process.env) {
  const candidate = Number.parseInt(env.SERVER_PORT || env.PORT || env.NOVAPANEL_PORT || "8080", 10);
  if (!Number.isInteger(candidate) || candidate < 1 || candidate > 65535) {
    throw new Error("Invalid listen port. Set SERVER_PORT or PORT to a TCP port from 1 to 65535.");
  }
  return candidate;
}

function linkPort(env = process.env, mode = normalizeLinkMode(env), actualPort = listenPort(env)) {
  const override = Number.parseInt(env.NOVAPANEL_LINK_PORT || env.LINK_PORT || "", 10);
  if (Number.isInteger(override) && override > 0 && override <= 65535) return override;
  return mode === "edge" ? 443 : actualPort;
}

function formatHostForUri(host) {
  return isIP(host) === 6 && !host.startsWith("[") ? "[" + host + "]" : host;
}

function makeSubscriptionLinks(state, host, port, mode, fingerprint, env = process.env) {
  const linkHost = formatHostForUri(cleanHost(host) || "127.0.0.1");
  const plainHost = linkHost;
  const edge = mode === "edge";
  const prefix = String(env.NODE_PREFIX || "NovaPanel - ");
  const links = [];
  const tlsQuery = (query, useTls) => {
    if (useTls) {
      query.set("security", "tls");
      query.set("sni", linkHost);
      query.set("fp", String(env.LINK_FP || "chrome"));
      query.set("alpn", "http/1.1");
      if (!edge) {
        query.set("allowInsecure", "1");
        if (fingerprint) query.set("pcs", fingerprint);
      }
    } else {
      query.set("security", "none");
    }
  };
  const wsProtocols = [
    { key: "vless", protocol: "vless", title: "VLESS-WS" },
    { key: "vmess", protocol: "vmess", title: "VMess-WS" },
    { key: "trojan", protocol: "trojan", title: "Trojan-WS" }
  ];
  for (const useTls of (edge ? [true] : [false, true])) {
    for (const item of wsProtocols) {
      const name = prefix + item.title + (useTls ? "-TLS" : "");
      const wsPath = state.paths[item.key];
      let uri;
      if (item.key === "vmess") {
        const vmess = {
          v: "2", ps: name, add: linkHost, port: String(port), id: state.uuid, aid: "0", scy: "auto",
          net: "ws", type: "none", host: plainHost, path: wsPath, tls: useTls ? "tls" : "none"
        };
        if (useTls) {
          vmess.sni = linkHost; vmess.fp = String(env.LINK_FP || "chrome"); vmess.alpn = "http/1.1";
          if (!edge) { vmess.allowInsecure = true; if (fingerprint) vmess.pcs = fingerprint; }
        }
        uri = "vmess://" + Buffer.from(JSON.stringify(vmess), "utf8").toString("base64");
      } else {
        const query = new URLSearchParams();
        if (item.key === "vless") query.set("encryption", "none");
        tlsQuery(query, useTls);
        query.set("type", "ws"); query.set("host", plainHost); query.set("path", wsPath);
        uri = item.protocol + "://" + state.uuid + "@" + linkHost + ":" + port + "?" + query.toString() + "#" + encodeURIComponent(name);
      }
      links.push({ name, type: item.title + (useTls ? "-TLS" : ""), uri, protocol: item.key, transport: "ws", tls: useTls, path: wsPath });
    }
  }

  const huProtocols = [
    { key: "vless", protocol: "vless", title: "VLESS-HTTPUpgrade" },
    { key: "vmess", protocol: "vmess", title: "VMess-HTTPUpgrade" },
    { key: "trojan", protocol: "trojan", title: "Trojan-HTTPUpgrade" }
  ];
  for (const item of huProtocols) {
    const useTls = edge;
    const name = prefix + item.title + (useTls ? "-TLS" : "");
    const pathValue = state.paths[item.key + "Hu"];
    let uri;
    const query = new URLSearchParams();
    if (item.key === "vless") query.set("encryption", "none");
    tlsQuery(query, useTls);
    query.set("type", "httpupgrade"); query.set("host", plainHost); query.set("path", pathValue);
    if (item.key === "vmess") {
      const vmess = {
        v: "2", ps: name, add: linkHost, port: String(port), id: state.uuid, aid: "0", scy: "auto",
        net: "httpupgrade", type: "none", host: plainHost, path: pathValue, tls: useTls ? "tls" : ""
      };
      if (useTls) {
        vmess.sni = linkHost; vmess.fp = String(env.LINK_FP || "chrome"); vmess.alpn = "http/1.1";
        if (!edge) { vmess.allowInsecure = true; if (fingerprint) vmess.pcs = fingerprint; }
      }
      uri = "vmess://" + Buffer.from(JSON.stringify(vmess), "utf8").toString("base64");
    } else {
      uri = item.protocol + "://" + state.uuid + "@" + linkHost + ":" + port + "?" + query.toString() + "#" + encodeURIComponent(name);
    }
    links.push({ name, type: item.title + (useTls ? "-TLS" : ""), uri, protocol: item.key, transport: "httpupgrade", tls: useTls, path: pathValue });
  }

  if (!edge) {
    const grpcName = prefix + "VLESS-gRPC-TLS";
    const query = new URLSearchParams({
      encryption: "none", security: "tls", sni: linkHost,
      fp: String(env.LINK_FP || "chrome"), alpn: "h2", type: "grpc",
      serviceName: state.grpcService, mode: "gun"
    });
    query.set("allowInsecure", "1");
    if (fingerprint) query.set("pcs", fingerprint);
    links.push({ name: grpcName, type: "VLESS-gRPC-TLS", uri: "vless://" + state.uuid + "@" + linkHost + ":" + port + "?" + query.toString() + "#" + encodeURIComponent(grpcName),
      protocol: "vless", transport: "grpc", tls: true, path: state.grpcService });

    const xhttpName = prefix + "VLESS-XHTTP-TLS";
    const xhttpQuery = new URLSearchParams({
      encryption: "none", security: "tls", sni: linkHost, fp: String(env.LINK_FP || "chrome"),
      alpn: "http/1.1", type: "xhttp", path: state.paths.xhttp, mode: "auto", host: plainHost
    });
    xhttpQuery.set("allowInsecure", "1");
    if (fingerprint) xhttpQuery.set("pcs", fingerprint);
    links.push({ name: xhttpName, type: "VLESS-XHTTP-TLS", uri: "vless://" + state.uuid + "@" + linkHost + ":" + port + "?" + xhttpQuery.toString() + "#" + encodeURIComponent(xhttpName),
      protocol: "vless", transport: "xhttp", tls: true, path: state.paths.xhttp });

    const ssName = prefix + "Shadowsocks-WS";
    const userInfo = Buffer.from(state.ssMethod + ":" + state.ssPassword, "utf8").toString("base64").replace(/=+$/g, "");
    const plugin = "v2ray-plugin;mode=websocket;host=" + plainHost + ";path=" + state.paths.ss + ";mux=0";
    links.push({ name: ssName, type: "Shadowsocks-WS", uri: "ss://" + userInfo + "@" + linkHost + ":" + port + "/?plugin=" + encodeURIComponent(plugin) + "#" + encodeURIComponent(ssName),
      protocol: "shadowsocks", transport: "ws", tls: false, path: state.paths.ss });

    const realityName = prefix + "VLESS-Reality";
    const realityQuery = new URLSearchParams({
      encryption: "none", security: "reality", sni: state.reality.serverName,
      fp: String(env.LINK_FP || "chrome"), pbk: state.reality.publicKey, sid: state.reality.shortId,
      type: "tcp", headerType: "none"
    });
    links.push({ name: realityName, type: "VLESS-Reality", uri: "vless://" + state.uuid + "@" + linkHost + ":" + port + "?" + realityQuery.toString() + "#" + encodeURIComponent(realityName),
      protocol: "vless", transport: "tcp", tls: true, path: "" });
  }
  return links;
}

function buildXrayConfig(state, ports, dataDir) {
  const definitions = [
    { key: "vless", tag: "vless-ws", protocol: "vless", settings: { clients: [{ id: state.uuid, email: "np-vless-ws" }], decryption: "none" }, stream: { network: "ws", security: "none", wsSettings: { path: state.paths.vless } } },
    { key: "vmess", tag: "vmess-ws", protocol: "vmess", settings: { clients: [{ id: state.uuid, alterId: 0, security: "auto", email: "np-vmess-ws" }] }, stream: { network: "ws", security: "none", wsSettings: { path: state.paths.vmess } } },
    { key: "trojan", tag: "trojan-ws", protocol: "trojan", settings: { clients: [{ password: state.uuid, email: "np-trojan-ws" }] }, stream: { network: "ws", security: "none", wsSettings: { path: state.paths.trojan } } },
    { key: "vlessHu", tag: "vless-httpupgrade", protocol: "vless", settings: { clients: [{ id: state.uuid, email: "np-vless-hu" }], decryption: "none" }, stream: { network: "httpupgrade", security: "none", httpupgradeSettings: { path: state.paths.vlessHu } } },
    { key: "vmessHu", tag: "vmess-httpupgrade", protocol: "vmess", settings: { clients: [{ id: state.uuid, alterId: 0, security: "auto", email: "np-vmess-hu" }] }, stream: { network: "httpupgrade", security: "none", httpupgradeSettings: { path: state.paths.vmessHu } } },
    { key: "trojanHu", tag: "trojan-httpupgrade", protocol: "trojan", settings: { clients: [{ password: state.uuid, email: "np-trojan-hu" }] }, stream: { network: "httpupgrade", security: "none", httpupgradeSettings: { path: state.paths.trojanHu } } },
    { key: "grpc", tag: "vless-grpc", protocol: "vless", settings: { clients: [{ id: state.uuid, email: "np-vless-grpc" }], decryption: "none" }, stream: { network: "grpc", security: "none", grpcSettings: { serviceName: state.grpcService, multiMode: false } } },
    { key: "xhttp", tag: "vless-xhttp", protocol: "vless", settings: { clients: [{ id: state.uuid, email: "np-vless-xhttp" }], decryption: "none" }, stream: { network: "xhttp", security: "none", xhttpSettings: { path: state.paths.xhttp, host: "", mode: "auto" } } },
    { key: "ss", tag: "shadowsocks-ws", protocol: "shadowsocks", settings: { method: state.ssMethod, password: state.ssPassword, network: "tcp" }, stream: { network: "ws", security: "none", wsSettings: { path: state.paths.ss } } },
    { key: "reality", tag: "vless-reality", protocol: "vless", settings: { clients: [{ id: state.uuid, email: "np-vless-reality" }], decryption: "none" }, stream: {
      network: "tcp", security: "reality",
      realitySettings: { show: false, dest: state.reality.serverName + ":443", xver: 0, serverNames: [state.reality.serverName], privateKey: state.reality.privateKey, shortIds: [state.reality.shortId] }
    } }
  ];
  return {
    log: { loglevel: "warning", access: path.join(dataDir, "access.log"), error: path.join(dataDir, "xray-error.log") },
    stats: {},
    policy: { levels: { "0": { statsUserUplink: true, statsUserDownlink: true } } },
    inbounds: definitions.map((item) => ({
      tag: "np-" + item.tag, listen: "127.0.0.1", port: ports[item.key],
      protocol: item.protocol, settings: item.settings, streamSettings: item.stream, sniffing: { enabled: false }
    })),
    outbounds: [{ protocol: "freedom", tag: "direct" }, { protocol: "blackhole", tag: "blocked" }]
  };
}


function makeClientTls(link, host, state, mode, fingerprint) {
  if (link.type === "VLESS-Reality") {
    return {
      enabled: true,
      server_name: state.reality.serverName,
      insecure: false,
      utls: { enabled: true, fingerprint: "chrome" },
      reality: { enabled: true, public_key: state.reality.publicKey, short_id: state.reality.shortId }
    };
  }
  if (!link.tls) return undefined;
  const value = { enabled: true, server_name: host, insecure: mode !== "edge", utls: { enabled: true, fingerprint: "chrome" } };
  if (link.transport === "grpc") value.alpn = ["h2"];
  else value.alpn = ["http/1.1"];
  return value;
}

function makeSingBoxOutbound(link, state, host, port, mode, fingerprint) {
  const out = { type: link.protocol, tag: link.name, server: host, server_port: Number(port) };
  if (link.protocol === "vless") { out.uuid = state.uuid; out.packet_encoding = "xudp"; }
  else if (link.protocol === "vmess") { out.uuid = state.uuid; out.alter_id = 0; out.security = "auto"; }
  else if (link.protocol === "trojan") out.password = state.uuid;
  else if (link.protocol === "shadowsocks") { out.method = state.ssMethod; out.password = state.ssPassword; out.plugin = "v2ray-plugin"; out.plugin_opts = "mode=websocket;host=" + host + ";path=" + state.paths.ss + ";mux=0"; }
  const tls = makeClientTls(link, host, state, mode, fingerprint);
  if (tls) out.tls = tls;
  if (link.transport === "ws") out.transport = { type: "ws", path: link.path, headers: { Host: host } };
  else if (link.transport === "httpupgrade") out.transport = { type: "httpupgrade", path: link.path, host: host };
  else if (link.transport === "grpc") out.transport = { type: "grpc", service_name: state.grpcService };
  else if (link.transport === "xhttp") out.transport = { type: "xhttp", path: state.paths.xhttp, host: host, mode: "auto" };
  return out;
}

function makeXrayOutbound(link, state, host, port, mode, fingerprint) {
  let protocol = link.protocol;
  const out = { tag: link.name, protocol, settings: {} };
  if (protocol === "vless") out.settings.vnext = [{ address: host, port: Number(port), users: [{ id: state.uuid, encryption: "none" }] }];
  else if (protocol === "vmess") out.settings.vnext = [{ address: host, port: Number(port), users: [{ id: state.uuid, alterId: 0, security: "auto" }] }];
  else if (protocol === "trojan") out.settings.servers = [{ address: host, port: Number(port), password: state.uuid }];
  else if (protocol === "shadowsocks") out.settings.servers = [{ address: host, port: Number(port), method: state.ssMethod, password: state.ssPassword }];
  const stream = { network: link.transport === "tcp" ? "tcp" : link.transport, security: link.type === "VLESS-Reality" ? "reality" : (link.tls ? "tls" : "none") };
  if (link.transport === "ws") stream.wsSettings = { path: link.path, headers: { Host: host } };
  else if (link.transport === "httpupgrade") stream.httpupgradeSettings = { path: link.path, host: host };
  else if (link.transport === "grpc") stream.grpcSettings = { serviceName: state.grpcService, multiMode: false };
  else if (link.transport === "xhttp") stream.xhttpSettings = { path: state.paths.xhttp, host: host, mode: "auto" };
  if (link.type === "VLESS-Reality") {
    stream.realitySettings = { serverName: state.reality.serverName, fingerprint: "chrome", publicKey: state.reality.publicKey, shortId: state.reality.shortId, spiderX: "/" };
  } else if (link.tls) {
    stream.tlsSettings = { serverName: host, alpn: link.transport === "grpc" ? ["h2"] : ["http/1.1"], fingerprint: "chrome" };
    if (mode !== "edge") {
      stream.tlsSettings.allowInsecure = true;
      if (fingerprint) stream.tlsSettings.pinnedPeerCertSha256 = fingerprint;
    }
  }
  out.streamSettings = stream;
  return out;
}

function makeClashProxy(link, state, host, port, mode) {
  const proxy = { name: link.name, type: link.protocol, server: host, port: Number(port) };
  if (link.protocol === "vless") { proxy.uuid = state.uuid; proxy.encryption = "none"; }
  else if (link.protocol === "vmess") { proxy.uuid = state.uuid; proxy.alterId = 0; proxy.cipher = "auto"; }
  else if (link.protocol === "trojan") proxy.password = state.uuid;
  else if (link.protocol === "shadowsocks") { proxy.cipher = state.ssMethod; proxy.password = state.ssPassword; proxy.plugin = "v2ray-plugin"; proxy["plugin-opts"] = { mode: "websocket", host, path: state.paths.ss, tls: false, mux: false }; return proxy; }

  if (link.type === "VLESS-Reality") {
    proxy.tls = true; proxy.servername = state.reality.serverName; proxy["client-fingerprint"] = "chrome";
    proxy["reality-opts"] = { "public-key": state.reality.publicKey, "short-id": state.reality.shortId };
    proxy["skip-cert-verify"] = false;
    return proxy;
  }
  proxy.network = link.transport === "httpupgrade" ? "ws" : link.transport;
  if (link.transport === "ws") proxy["ws-opts"] = { path: link.path, headers: { Host: host } };
  else if (link.transport === "httpupgrade") proxy["ws-opts"] = { path: link.path, headers: { Host: host }, "v2ray-http-upgrade": true };
  else if (link.transport === "grpc") proxy["grpc-opts"] = { "grpc-service-name": state.grpcService };
  else if (link.transport === "xhttp") proxy["xhttp-opts"] = { path: state.paths.xhttp, mode: "auto", host: host };
  if (link.tls) {
    proxy.tls = true; proxy.servername = host; proxy.alpn = [link.transport === "grpc" ? "h2" : "http/1.1"];
    proxy["skip-cert-verify"] = mode !== "edge";
    if (mode === "direct") proxy["client-fingerprint"] = "chrome";
  } else proxy.tls = false;
  return proxy;
}

function buildSingBoxExport(state, links, host, port, mode, fingerprint) {
  const outbounds = links.map((link) => makeSingBoxOutbound(link, state, host, port, mode, fingerprint));
  const tags = outbounds.map((outbound) => outbound.tag);
  return {
    log: { level: "warn" },
    inbounds: [{ type: "mixed", tag: "mixed-in", listen: "127.0.0.1", listen_port: 2080 }],
    outbounds: [{ type: "selector", tag: "select", outbounds: tags.concat(["direct"]) }, { type: "direct", tag: "direct" }, { type: "block", tag: "block" }, ...outbounds],
    route: { final: "select", auto_detect_interface: true }
  };
}

function buildClashExport(state, links, host, port, mode) {
  const proxies = links.map((link) => makeClashProxy(link, state, host, port, mode));
  const quote = (value) => JSON.stringify(String(value));
  const lines = [
    "mixed-port: 7890", "allow-lan: false", "mode: rule", "log-level: warning", "ipv6: false",
    "proxies:"
  ];
  for (const proxy of proxies) {
    lines.push("  - name: " + quote(proxy.name));
    for (const [key, value] of Object.entries(proxy)) {
      if (key === "name") continue;
      lines.push("    " + key + ": " + (typeof value === "object" ? JSON.stringify(value) : (typeof value === "string" ? quote(value) : String(value))));
    }
  }
  lines.push("proxy-groups:", "  - name: " + quote("NovaPanel"), "    type: select", "    proxies:");
  for (const proxy of proxies) lines.push("      - " + quote(proxy.name));
  lines.push("      - DIRECT", "rules:", "  - MATCH,NovaPanel", "");
  return lines.join("\n");
}

function buildXrayExport(state, links, host, port, mode, fingerprint) {
  const outbounds = links.map((link) => makeXrayOutbound(link, state, host, port, mode, fingerprint));
  return {
    log: { loglevel: "warning" },
    inbounds: [{ listen: "127.0.0.1", port: 10808, protocol: "socks", settings: { auth: "noauth", udp: true }, tag: "socks-in" }],
    outbounds: [...outbounds, { protocol: "freedom", tag: "direct" }, { protocol: "blackhole", tag: "blocked" }],
    routing: { rules: [{ type: "field", inboundTag: ["socks-in"], outboundTag: outbounds.length ? outbounds[0].tag : "direct" }] }
  };
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const selected = address && typeof address === "object" ? address.port : 0;
      server.close((err) => err ? reject(err) : selected ? resolve(selected) : reject(new Error("Could not allocate a local port.")));
    });
  });
}

function isEnabled(value) {
  return !/^(0|false|no|off)$/i.test(String(value === undefined ? "1" : value).trim());
}

async function fetchText(url, timeout = 20000) {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(timeout),
    headers: { "User-Agent": USER_AGENT }
  });
  if (!response.ok) throw new Error("HTTP " + response.status + " fetching " + url);
  return response.text();
}

async function fetchBuffer(url, timeout = 90000) {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(timeout),
    headers: { "User-Agent": USER_AGENT }
  });
  if (!response.ok) throw new Error("HTTP " + response.status + " downloading Xray.");
  const data = Buffer.from(await response.arrayBuffer());
  if (data.length < 1024 * 1024) throw new Error("Xray download was unexpectedly small.");
  return data;
}

function xrayAssetForPlatform() {
  if (process.platform !== "linux") throw new Error("Automatic Xray installation currently supports Linux hosts only.");
  if (process.arch === "x64") return "Xray-linux-64.zip";
  if (process.arch === "arm64") return "Xray-linux-arm64-v8a.zip";
  throw new Error("Automatic Xray installation does not support architecture " + process.arch + ".");
}

function verifyXrayBinary(binary) {
  try {
    const result = spawnSync(binary, ["version"], { encoding: "utf8", timeout: 15000, stdio: ["ignore", "pipe", "pipe"] });
    if (result.status !== 0) return "";
    const output = String(result.stdout || "") + "\n" + String(result.stderr || "");
    const match = output.match(/Xray\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i);
    return match ? match[1] : "";
  } catch {
    return "";
  }
}

async function ensureXrayInstalled(dataDir) {
  const configuredBinary = String(process.env.NOVAPANEL_XRAY_BINARY || "").trim();
  const binary = configuredBinary || path.join(dataDir, "bin", "xray");
  if (fs.existsSync(binary)) {
    try { fs.chmodSync(binary, 0o755); } catch { /* ignored on non-POSIX systems */ }
    const version = verifyXrayBinary(binary);
    if (version) return { binary, version };
    if (configuredBinary) throw new Error("NOVAPANEL_XRAY_BINARY exists but is not a runnable Xray executable.");
  }
  if (!isEnabled(process.env.NOVAPANEL_AUTO_INSTALL_XRAY)) {
    throw new Error("Automatic Xray download is disabled by NOVAPANEL_AUTO_INSTALL_XRAY=0.");
  }

  const asset = xrayAssetForPlatform();
  const url = process.env.NOVAPANEL_XRAY_URL || ("https://github.com/XTLS/Xray-core/releases/latest/download/" + asset);
  console.log("[NovaPanel] Downloading the official Xray-core release for " + process.arch + ".");
  const payload = await fetchBuffer(url);
  let expected = "";
  try {
    const digestText = await fetchText(url + ".dgst", 20000);
    const match = digestText.match(/SHA2?-?256[^=]*=\s*([0-9a-f]{64})/i);
    if (match) expected = match[1].toLowerCase();
  } catch {
    console.warn("[NovaPanel] Xray digest file was not available; the archive will still be checked by the executable version.");
  }
  if (expected) {
    const actual = crypto.createHash("sha256").update(payload).digest("hex");
    if (actual !== expected) throw new Error("Xray archive SHA-256 did not match the official digest.");
    console.log("[NovaPanel] Xray archive SHA-256 verified.");
  }

  const archive = await unzipper.Open.buffer(payload);
  let entry = null;
  for (const item of archive.files) {
    if ((item.path.split("/").pop() || "") === "xray") { entry = item; break; }
  }
  if (!entry) throw new Error("The official Xray archive did not contain the xray executable.");
  const data = await entry.buffer();
  const binDir = path.join(dataDir, "bin");
  fs.mkdirSync(binDir, { recursive: true });
  const temporary = path.join(binDir, "xray.new");
  fs.writeFileSync(temporary, data, { mode: 0o755 });
  fs.chmodSync(temporary, 0o755);
  fs.renameSync(temporary, path.join(binDir, "xray"));
  const installedVersion = verifyXrayBinary(path.join(binDir, "xray"));
  if (!installedVersion) throw new Error("The downloaded Xray executable could not run on this host.");
  console.log("[NovaPanel] Xray-core " + installedVersion + " installed.");
  return { binary: path.join(binDir, "xray"), version: installedVersion };
}

function htmlEscape(value) {
  return String(value === undefined || value === null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function extractClientHelloServerName(buffer) {
  try {
    if (!Buffer.isBuffer(buffer) || buffer.length < 9 || buffer[0] !== 0x16 || buffer[5] !== 0x01) return "";
    let offset = 9;
    offset += 2 + 32;
    const sessionLength = buffer[offset++];
    offset += sessionLength;
    const cipherLength = buffer.readUInt16BE(offset); offset += 2 + cipherLength;
    const compressionLength = buffer[offset++]; offset += compressionLength;
    const extensionsLength = buffer.readUInt16BE(offset); offset += 2;
    const extensionEnd = Math.min(buffer.length, offset + extensionsLength);
    while (offset + 4 <= extensionEnd) {
      const type = buffer.readUInt16BE(offset);
      const length = buffer.readUInt16BE(offset + 2);
      offset += 4;
      if (offset + length > extensionEnd) return "";
      if (type === 0 && length >= 5) {
        let p = offset + 2;
        const end = offset + length;
        while (p + 3 <= end) {
          const nameType = buffer[p++];
          const nameLength = buffer.readUInt16BE(p); p += 2;
          if (p + nameLength > end) return "";
          if (nameType === 0) return buffer.subarray(p, p + nameLength).toString("ascii").toLowerCase();
          p += nameLength;
        }
        return "";
      }
      offset += length;
    }
  } catch { /* incomplete or non-ClientHello input */ }
  return "";
}

function parseCookies(req) {
  const result = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;
    const key = part.slice(0, index).trim();
    try { result[key] = decodeURIComponent(part.slice(index + 1).trim()); } catch { result[key] = ""; }
  }
  return result;
}

function requestIp(req) {
  return String(req.headers["x-forwarded-for"] || (req.socket && req.socket.remoteAddress) || "unknown").split(",")[0].trim();
}

function isHttpsRequest(req) {
  return Boolean(req.secure) || String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https";
}

function tailFile(file, limit = 5000) {
  try { return fs.readFileSync(file, "utf8").slice(-limit); } catch { return ""; }
}

function generateLoginPage(panelPath, mode, errorMessage, needsSetupKey) {
  const setup = mode === "setup";
  const title = setup ? "ساخت رمز مدیر" : "ورود به پنل";
  const description = setup ? "برای اولین اجرا یک رمز مدیر بسازید." : "رمز مدیر را وارد کنید تا پنل باز شود.";
  const error = errorMessage ? '<div class="error">' + htmlEscape(errorMessage) + "</div>" : "";
  const setupKey = needsSetupKey ? '<label>کلید راه‌اندازی<input type="password" name="setup_key" autocomplete="off" required></label>' : "";
  const confirm = setup ? '<label>تکرار رمز<input type="password" name="confirm" minlength="8" autocomplete="new-password" required></label>' : "";
  const css = "*,*:before,*:after{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#eef2ff;font:16px system-ui,Tahoma,Arial;padding:20px}.card{width:min(440px,100%);padding:28px;border:1px solid #273653;border-radius:20px;background:#111a2d;box-shadow:0 24px 80px #0005}h1{margin:0 0 8px;font-size:26px}p{line-height:1.8;color:#a8b6d1;margin:0 0 22px}.brand{color:#6ee7b7;font-size:12px;letter-spacing:2px;margin-bottom:10px}label{display:block;margin:16px 0;font-size:14px;color:#cbd5e1}input{display:block;width:100%;margin-top:8px;padding:13px 14px;border-radius:12px;border:1px solid #334766;background:#0b1325;color:#fff;font:inherit;direction:ltr}button{border:0;border-radius:12px;padding:13px 16px;width:100%;background:#34d399;color:#06281f;font-weight:700;font-size:15px;cursor:pointer}.error{padding:12px;margin:12px 0;background:#451d2a;border:1px solid #854052;border-radius:12px;color:#fecdd3}.hint{font-size:12px;color:#8da0bd;margin-top:16px}";
  return '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>' +
    title + " | NovaPanel</title><style>" + css + '</style></head><body><main class="card"><div class="brand">NOVAPANEL · ONE-PORT</div><h1>' +
    title + "</h1><p>" + description + "</p>" + error +
    '<form method="post" action="/' + panelPath + '/login">' + setupKey +
    '<label>رمز مدیر<input type="password" name="password" minlength="' + MIN_PASSWORD_LENGTH + '" autocomplete="' + (setup ? "new-password" : "current-password") + '" required></label>' +
    confirm + '<button type="submit">' + (setup ? "ساخت رمز و ادامه" : "ورود") + '</button></form><div class="hint">رمز روی همین میزبان نگهداری می‌شود؛ نام کاربری لازم نیست.</div></main></body></html>';
}

function buildPanelPage(panelPath, status) {
  const rows = status.links.map((link, index) =>
    '<article class="link-row"><div class="link-info"><span class="link-num">' + String(index + 1).padStart(2, "0") +
    '</span><div><strong>' + htmlEscape(link.name) + '</strong><small>' + htmlEscape(link.tls ? "TLS + WebSocket" : "WebSocket") +
    '</small></div></div><button class="copy small" data-copy="' + htmlEscape(link.uri) + '">کپی لینک</button></article>'
  ).join("");
  const css = "*,*:before,*:after{box-sizing:border-box}body{margin:0;background:#09101e;color:#e5edf9;font:15px system-ui,Tahoma,Arial;line-height:1.65;padding:20px}.wrap{max-width:900px;margin:0 auto}.bar{display:flex;justify-content:space-between;align-items:center;gap:16px;margin:8px 0 24px}.brand{font-size:23px;font-weight:800;letter-spacing:-.5px}.brand span{color:#6ee7b7}.muted{color:#8ea2bf;font-size:13px}.button,a.button,button{border:1px solid #334b68;border-radius:11px;padding:10px 14px;background:#13223a;color:#eaf2ff;text-decoration:none;cursor:pointer;font:inherit}.button.green,button.green{background:#34d399;color:#042b20;border-color:#34d399;font-weight:700}.hero{padding:22px;border-radius:20px;border:1px solid #263c58;background:linear-gradient(130deg,#142541,#101a2d);margin-bottom:16px}.hero h1{font-size:25px;margin:0 0 8px}.status{display:inline-flex;align-items:center;gap:8px;border:1px solid #334b68;background:#0b1527;padding:7px 11px;border-radius:99px;font-size:13px}.dot{width:8px;height:8px;border-radius:100%;background:#fbbf24}.dot.running{background:#34d399}.dot.error{background:#fb7185}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:16px 0}.metric{background:#101a2c;border:1px solid #223653;padding:15px;border-radius:15px}.metric label{display:block;color:#91a5c2;font-size:12px}.metric strong{display:block;margin-top:4px;font-size:17px;overflow-wrap:anywhere}.card{border:1px solid #223653;background:#101a2c;padding:18px;border-radius:17px;margin:14px 0}.card h2{font-size:17px;margin:0 0 7px}.subrow{display:flex;gap:8px;align-items:center}.subrow input{min-width:0;flex:1;direction:ltr;color:#d6e5fc;background:#0a1323;border:1px solid #334b68;border-radius:11px;padding:12px;font:12px ui-monospace,monospace}.link-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 0;border-bottom:1px solid #22334c}.link-row:last-child{border:0}.link-info{display:flex;align-items:center;gap:12px}.link-num{color:#6ee7b7;font-size:12px}.link-info strong,.link-info small{display:block}.link-info small{color:#849bb9;font-size:12px}.small{font-size:12px;white-space:nowrap}.warning{background:#3b2b16;border:1px solid #775523;color:#fce7b2;padding:12px;border-radius:12px;margin:12px 0}.errorbox{background:#3e1b29;border:1px solid #7c3748;color:#fecdd3;padding:12px;border-radius:12px;white-space:pre-wrap;overflow-wrap:anywhere}.foot{color:#788eab;text-align:center;font-size:12px;margin:24px 0}.copy:active{transform:scale(.98)}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}@media(max-width:640px){body{padding:12px}.bar{align-items:flex-start}.brand{font-size:20px}.grid{grid-template-columns:1fr}.subrow{align-items:stretch;flex-direction:column}.subrow input{min-height:44px}.link-row{align-items:flex-start}.link-info{gap:8px}.card,.hero{padding:15px}}";
  const engineLabel = status.engine_status === "running" ? "هسته فعال است" :
    status.engine_status === "installing" ? "در حال نصب Xray" :
    status.engine_status === "starting" ? "در حال شروع Xray" :
    status.engine_status === "disabled" ? "نصب خودکار خاموش است" :
    status.engine_status === "error" ? "هسته اجرا نشد" : "در انتظار راه‌اندازی";
  const engineClass = status.engine_status === "running" ? "running" : status.engine_status === "error" ? "error" : "";
  const problem = status.engine_error
    ? '<div class="errorbox" id="engine-error">' + htmlEscape(status.engine_error) + "</div>"
    : '<div class="muted" id="engine-error">اگر موتور هنوز نصب می‌شود، این صفحه را باز بگذارید؛ پنل در دسترس می‌ماند.</div>';
  return '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>NovaPanel</title><style>' +
    css + '</style></head><body><main class="wrap"><header class="bar"><div><div class="brand"><span>Nova</span>Panel</div><div class="muted">مدیریت سادهٔ اتصال و اشتراک</div></div><a class="button" href="/' +
    panelPath + '/logout">خروج</a></header><section class="hero"><h1>اتصال‌ها آمادهٔ استفاده‌اند</h1><p class="muted">یک لینک اشتراک بساز و فقط همان را در بخش Subscription برنامهٔ V2Ray وارد کن. به‌روزرسانی اشتراک، کانفیگ‌ها را خودکار دریافت می‌کند.</p><div class="status"><i class="dot ' +
    engineClass + '" id="engine-dot"></i><span id="engine-label">' + engineLabel + '</span></div></section><section class="grid"><div class="metric"><label>آدرس عمومی</label><strong id="public-host">' +
    htmlEscape(status.public_host) + '</strong></div><div class="metric"><label>پورت اتصال</label><strong id="public-port">' +
    htmlEscape(status.link_port) + '</strong></div><div class="metric"><label>نوع اتصال</label><strong id="link-mode">' +
    htmlEscape(status.link_mode === "edge" ? "TLS میزبان" : "تک‌پورت مستقیم") + '</strong></div></section><section class="card"><h2>۱. لینک اشتراک اصلی</h2><p class="muted">این لینک را به‌عنوان Subscription اضافه کن؛ آن را جای لینک تکی کانفیگ وارد نکن.</p><div class="subrow"><input id="subscription-url" readonly value="' +
    htmlEscape(status.subscription_url) + '"><button class="copy green" data-copy="' + htmlEscape(status.subscription_url) + '">کپی لینک اشتراک</button></div><div class="actions"><a class="button" href="' +
    htmlEscape(status.subscription_url) + '" target="_blank" rel="noreferrer">بازکردن خروجی اشتراک</a><a class="button" href="/sub?token=' +
    encodeURIComponent(status.subscription_token) + '" target="_blank" rel="noreferrer">نسخهٔ پایه۶۴</a></div></section><section class="card"><h2>۲. کانفیگ‌های تکی</h2><p class="muted">برای تست سریع می‌توانی یک لینک تکی هم کپی کنی؛ هر شش کانفیگ از همان پورت عمومی استفاده می‌کنند.</p>' +
    rows + '</section><section class="card"><h2>وضعیت موتور اتصال</h2><div id="engine-problem">' + problem + '</div><p class="muted">اگر وضعیت موتور «فعال» نیست، لینک اشتراک ساخته می‌شود ولی تا آماده‌شدن Xray اتصال برقرار نمی‌شود.</p></section><div class="foot">NovaPanel ' +
    VERSION + ' · Node.js تک‌Runtime · پورت عمومی مشترک برای پنل و WebSocket</div></main><script>' +
    'document.addEventListener("click",async function(e){var b=e.target.closest("[data-copy]");if(!b)return;var v=b.getAttribute("data-copy")||"";try{await navigator.clipboard.writeText(v);var old=b.textContent;b.textContent="کپی شد";setTimeout(function(){b.textContent=old},1400)}catch(_){var i=document.createElement("textarea");i.value=v;document.body.appendChild(i);i.select();document.execCommand("copy");i.remove();b.textContent="کپی شد";setTimeout(function(){b.textContent="کپی";},1400)}});' +
    'async function refreshStatus(){try{var r=await fetch("/api/status",{cache:"no-store"});if(!r.ok)return;var s=await r.json();var names={running:"هسته فعال است",installing:"در حال نصب Xray",starting:"در حال شروع Xray",disabled:"نصب خودکار خاموش است",error:"هسته اجرا نشد",stopped:"هسته متوقف است"};var label=document.getElementById("engine-label");if(label)label.textContent=names[s.engine_status]||"در انتظار راه‌اندازی";var dot=document.getElementById("engine-dot");if(dot)dot.className="dot "+(s.engine_status==="running"?"running":s.engine_status==="error"?"error":"");var box=document.getElementById("engine-problem");if(box){box.className=s.engine_error?"errorbox":"muted";box.textContent=s.engine_error||"پنل آنلاین است. وضعیت موتور به‌صورت خودکار به‌روزرسانی می‌شود."}}catch(_){}}setInterval(refreshStatus,3000);' +
    '</script></body></html>';
}

async function startRuntime() {
  const dataDir = chooseDataDirectory();
  const persistent = ensurePersistentState(dataDir);
  const state = persistent.state;
  const auth = persistent.auth;
  const panelPath = normalizePanelPath(process.env.PANEL_PATH);
  const actualPort = listenPort();
  const mode = normalizeLinkMode();
  const linkPublicPort = linkPort(process.env, mode, actualPort);
  const boot = {
    engine_status: isEnabled(process.env.NOVAPANEL_AUTO_INSTALL_XRAY) ? "installing" : "disabled",
    engine_error: "",
    engine_version: "",
    binary: "",
    child: null
  };
  const certHost = cleanHost(process.env.NOVAPANEL_PUBLIC_HOST || process.env.DOMAIN || process.env.FORCE_HOST || process.env.RAILWAY_PUBLIC_DOMAIN) || "localhost";
  const certificate = ensureCertificate(dataDir, certHost);
  const inbounds = {};
  const reservedPorts = new Set();
  for (const kind of ["vless", "vmess", "trojan", "vlessHu", "vmessHu", "trojanHu", "grpc", "xhttp", "ss", "reality"]) {
    let port;
    do { port = await getFreePort(); } while (reservedPorts.has(port));
    reservedPorts.add(port);
    inbounds[kind] = port;
  }
  const xrayConfigPath = path.join(dataDir, "xray.json");
  const xrayLogPath = path.join(dataDir, "xray.log");
  const xrayConfig = buildXrayConfig(state, inbounds, dataDir);
  writeJson(xrayConfigPath, xrayConfig, 0o600);
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", true);
  app.disable("etag");
  app.use((req, res, next) => {
    const pathname = String(req.url || "/").split("?")[0];
    if (req.httpVersion === "2.0" && mode === "direct" && pathname.startsWith("/" + state.grpcService + "/")) return;
    if (pathname === state.paths.xhttp || pathname.startsWith(state.paths.xhttp + "/")) {
      const headers = { ...req.headers, host: "127.0.0.1:" + inbounds.xhttp };
      delete headers.connection; delete headers["keep-alive"]; delete headers["proxy-connection"];
      const upstream = http.request({ host: "127.0.0.1", port: inbounds.xhttp, method: req.method, path: req.url, headers, timeout: 0 }, (upstreamResponse) => {
        const responseHeaders = { ...upstreamResponse.headers };
        delete responseHeaders.connection; delete responseHeaders["keep-alive"]; delete responseHeaders["transfer-encoding"];
        res.writeHead(upstreamResponse.statusCode || 502, responseHeaders);
        upstreamResponse.pipe(res);
      });
      upstream.on("error", (error) => {
        if (!res.headersSent) res.status(502).type("text/plain").send("XHTTP engine unavailable: " + error.message);
        else res.destroy(error);
      });
      req.on("aborted", () => upstream.destroy());
      res.on("close", () => { if (!res.writableEnded) upstream.destroy(); });
      req.pipe(upstream);
      return;
    }
    next();
  });
  app.use(express.urlencoded({ extended: false, limit: "12kb" }));

  function persistAuth() { writeJson(persistent.authFile, auth, 0o600); }
  function persistState() { writeJson(persistent.stateFile, state, 0o600); }
  function sessionValid(req) {
    const cookies = parseCookies(req);
    const raw = String(cookies.novapanel_session || "");
    const split = raw.split(".");
    if (split.length !== 2 || !split[0] || Number(split[0]) < Date.now()) return false;
    return safeEqual(split[1], sign(auth.secret, split[0]));
  }
  function setSession(req, res) {
    const expiry = String(Date.now() + SESSION_DAYS * 86400000);
    const secure = isHttpsRequest(req) ? "; Secure" : "";
    res.setHeader("Set-Cookie", "novapanel_session=" + encodeURIComponent(expiry + "." + sign(auth.secret, expiry)) +
      "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + (SESSION_DAYS * 86400) + secure);
  }
  function authRequired(req, res, next) {
    if (sessionValid(req)) return next();
    res.redirect(302, "/" + panelPath + "/login");
  }
  function getHost(req) {
    const host = requestPublicHost(req, state);
    if (host && host !== state.publicHost) {
      state.publicHost = host;
      persistState();
    }
    return host;
  }
  function getLinks(req) {
    const host = getHost(req);
    const requestMode = normalizeLinkMode();
    const port = linkPort(process.env, requestMode, actualPort);
    return makeSubscriptionLinks(state, host, port, requestMode, certificate.fingerprint);
  }
  function getSubscriptionUrl(req) {
    const host = getHost(req);
    return requestOrigin(req, host) + "/" + panelPath + "/sub?token=" + encodeURIComponent(state.subscriptionToken);
  }
  function getStatus(req) {
    const host = getHost(req);
    const links = getLinks(req);
    return {
      app: APP_NAME,
      version: VERSION,
      public_host: host,
      listen_port: actualPort,
      link_port: linkPublicPort,
      link_mode: mode,
      engine_status: boot.engine_status,
      engine_error: boot.engine_error,
      engine_version: boot.engine_version,
      xray_installed: Boolean(boot.binary),
      tls_fingerprint: certificate.fingerprint,
      subscription_token: state.subscriptionToken,
      subscription_url: getSubscriptionUrl(req),
      links
    };
  }
  function subscriptionHandler(req, res) {
    const token = typeof req.query.token === "string" ? req.query.token : "";
    if (!token || !safeEqual(token, state.subscriptionToken)) {
      res.set("Cache-Control", "no-store");
      return res.status(401).type("text/plain").send("Subscription token is missing or invalid.");
    }
    const links = getLinks(req).map((link) => link.uri);
    const raw = links.join("\n") + "\n";
    const base64 = Buffer.from(raw, "utf8").toString("base64");
    const isRaw = req.path.endsWith("/raw") || req.path === "/raw";
    res.set({
      "Cache-Control": "no-store, max-age=0",
      Pragma: "no-cache",
      "Content-Type": "text/plain; charset=utf-8",
      "Profile-Update-Interval": "24",
      "Subscription-Userinfo": "upload=0; download=0; total=1099511627776; expire=1893456000",
      "Content-Disposition": 'inline; filename="NovaPanel.txt"'
    });
    return res.send(isRaw ? raw : base64);
  }

  app.get("/api/health", (_req, res) => {
    res.set("Cache-Control", "no-store");
    res.json({
      status: "ok",
      app: APP_NAME,
      version: VERSION,
      listen_port: actualPort,
      engine_status: boot.engine_status,
      xray_installed: Boolean(boot.binary),
      inbound_count: xrayConfig.inbounds.length,
      link_mode: mode
    });
  });
  app.get("/health", (_req, res) => res.redirect(302, "/api/health"));

  app.get("/api/status", (req, res) => {
    if (!sessionValid(req)) return res.status(401).json({ detail: "Please sign in." });
    res.set("Cache-Control", "no-store");
    return res.json(getStatus(req));
  });

  app.get("/", (_req, res) => res.redirect(302, "/" + panelPath));
  app.get("/" + panelPath + "/login", (req, res) => {
    if (auth.hash && sessionValid(req)) return res.redirect(302, "/" + panelPath);
    res.set("Cache-Control", "no-store");
    res.type("html").send(generateLoginPage(panelPath, auth.hash ? "login" : "setup", "", Boolean(!auth.hash && process.env.SETUP_KEY)));
  });
  app.post("/" + panelPath + "/login", (req, res) => {
    const ip = requestIp(req);
    const now = Date.now();
    const recent = (loginFailures.get(ip) || []).filter((stamp) => now - stamp < 15 * 60 * 1000);
    if (recent.length >= 8) {
      return res.status(429).type("html").send(generateLoginPage(panelPath, auth.hash ? "login" : "setup", "تلاش زیاد است؛ ۱۵ دقیقه بعد دوباره امتحان کن.", Boolean(!auth.hash && process.env.SETUP_KEY)));
    }
    const input = req.body || {};
    if (!auth.hash) {
      if (process.env.SETUP_KEY && !safeEqual(String(input.setup_key || ""), process.env.SETUP_KEY)) {
        recent.push(now); loginFailures.set(ip, recent);
        return res.status(401).type("html").send(generateLoginPage(panelPath, "setup", "کلید راه‌اندازی اشتباه است.", true));
      }
      const password = String(input.password || "");
      if (password.length < MIN_PASSWORD_LENGTH) {
        return res.status(400).type("html").send(generateLoginPage(panelPath, "setup", "رمز باید حداقل ۸ کاراکتر باشد.", Boolean(process.env.SETUP_KEY)));
      }
      if (password !== String(input.confirm || "")) {
        return res.status(400).type("html").send(generateLoginPage(panelPath, "setup", "تکرار رمز با رمز اصلی یکسان نیست.", Boolean(process.env.SETUP_KEY)));
      }
      auth.salt = crypto.randomBytes(16).toString("hex");
      auth.hash = hashPassword(password, auth.salt);
      auth.secret = crypto.randomBytes(32).toString("base64url");
      persistAuth();
      setSession(req, res);
      loginFailures.delete(ip);
      return res.redirect(302, "/" + panelPath);
    }
    const supplied = hashPassword(String(input.password || ""), auth.salt || "");
    if (!auth.salt || !safeEqual(supplied, auth.hash)) {
      recent.push(now); loginFailures.set(ip, recent);
      return res.status(401).type("html").send(generateLoginPage(panelPath, "login", "رمز واردشده صحیح نیست.", false));
    }
    loginFailures.delete(ip);
    setSession(req, res);
    return res.redirect(302, "/" + panelPath);
  });
  app.get("/" + panelPath + "/logout", (req, res) => {
    res.setHeader("Set-Cookie", "novapanel_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    res.redirect(302, "/" + panelPath + "/login");
  });
  app.get(["/" + panelPath, "/" + panelPath + "/"], authRequired, (req, res) => {
    res.set("Cache-Control", "no-store");
    res.type("html").send(buildPanelPage(panelPath, getStatus(req)));
  });

  app.get(["/" + panelPath + "/sub", "/" + panelPath + "/base64", "/sub", "/base64"], subscriptionHandler);
  app.get(["/" + panelPath + "/raw", "/raw"], subscriptionHandler);

  const errorHandler = (err, _req, res, _next) => {
    console.error("[NovaPanel] HTTP request failed:", err);
    if (res.headersSent) return;
    res.status(500).json({ detail: "Internal server error." });
  };
  app.use(errorHandler);

  const upgradeKinds = ["vless", "vmess", "trojan", "vlessHu", "vmessHu", "trojanHu", "ss"];
  function relayUpgrade(server) {
    server.on("upgrade", (req, socket, head) => {
      let pathname;
      try { pathname = new URL(req.url || "/", "http://localhost").pathname; } catch { pathname = ""; }
      const route = upgradeKinds.find((kind) => state.paths[kind] === pathname);
      const localPort = route ? inbounds[route] : 0;
      if (!localPort) {
        socket.end("HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        return;
      }
      socket.setTimeout(0);
      socket.setNoDelay(true);
      const backend = net.connect(localPort, "127.0.0.1");
      let connected = false;
      backend.once("connect", () => {
        connected = true;
        let requestHeaders = String(req.method || "GET") + " " + String(req.url || "/") + " HTTP/" + String(req.httpVersion || "1.1") + "\r\n";
        for (let i = 0; i < req.rawHeaders.length; i += 2) {
          requestHeaders += req.rawHeaders[i] + ": " + req.rawHeaders[i + 1] + "\r\n";
        }
        requestHeaders += "\r\n";
        backend.write(requestHeaders);
        if (head && head.length) backend.write(head);
        socket.pipe(backend);
        backend.pipe(socket);
        socket.resume();
      });
      backend.on("error", (err) => {
        if (!connected) {
          try { socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); } catch { /* closed */ }
        } else {
          try { socket.destroy(); } catch { /* closed */ }
        }
        if (boot.engine_status === "running") {
          boot.engine_error = "اتصال WebSocket به موتور برقرار نشد: " + err.message;
        }
      });
      socket.on("error", () => { try { backend.destroy(); } catch { /* closed */ } });
      socket.on("close", () => { try { backend.destroy(); } catch { /* closed */ } });
      backend.on("close", () => { if (!socket.destroyed) socket.destroy(); });
    });
  }

  const httpServer = http.createServer(app);
  httpServer.keepAliveTimeout = 120000;
  httpServer.headersTimeout = 125000;
  httpServer.requestTimeout = 0;
  httpServer.timeout = 0;
  relayUpgrade(httpServer);

  const httpsServer = http2.createSecureServer({
    key: certificate.key,
    cert: certificate.cert,
    minVersion: "TLSv1.2",
    allowHTTP1: true,
    ALPNProtocols: ["h2", "http/1.1"]
  }, app);
  httpsServer.keepAliveTimeout = 120000;
  httpsServer.headersTimeout = 125000;
  httpsServer.requestTimeout = 0;
  httpsServer.timeout = 0;
  httpsServer.on("tlsClientError", () => { /* invalid TLS handshakes are expected on a shared TCP port */ });
  httpsServer.on("stream", (stream, headers) => {
    const requestPath = String(headers[":path"] || "/");
    if (mode !== "direct" || !requestPath.startsWith("/" + state.grpcService + "/")) return;
    const session = http2.connect("http://127.0.0.1:" + inbounds.grpc);
    const forwarded = {
      ":method": headers[":method"] || "POST",
      ":path": requestPath,
      ":scheme": "http",
      ":authority": "127.0.0.1:" + inbounds.grpc,
      "content-type": headers["content-type"] || "application/grpc",
      "te": "trailers"
    };
    const blocked = new Set([":authority", ":method", ":path", ":scheme", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "host", "te", "content-type"]);
    for (const [key, value] of Object.entries(headers)) {
      if (!key.startsWith(":") && !blocked.has(key.toLowerCase())) forwarded[key.toLowerCase()] = value;
    }
    const upstream = session.request(forwarded, { endStream: false });
    let responseTrailers = null;
    upstream.on("response", (responseHeaders) => {
      const outgoing = { ":status": Number(responseHeaders[":status"] || 200) };
      for (const [key, value] of Object.entries(responseHeaders)) {
        if (!key.startsWith(":") && !["connection", "transfer-encoding", "keep-alive"].includes(key.toLowerCase())) outgoing[key.toLowerCase()] = value;
      }
      try { stream.respond(outgoing, { waitForTrailers: true }); }
      catch { upstream.close(); session.close(); return; }
      upstream.pipe(stream);
    });
    upstream.on("trailers", (trailers) => { responseTrailers = trailers; });
    stream.on("wantTrailers", () => {
      const trailers = {};
      if (responseTrailers) {
        for (const [key, value] of Object.entries(responseTrailers)) if (!key.startsWith(":")) trailers[key.toLowerCase()] = value;
      }
      if (!trailers["grpc-status"]) trailers["grpc-status"] = "0";
      try { stream.sendTrailers(trailers); } catch { /* connection already closed */ }
    });
    upstream.on("error", () => {
      try { if (!stream.headersSent) stream.respond({ ":status": 502 }); stream.end(); } catch { /* closed */ }
      session.close();
    });
    stream.on("error", () => { try { upstream.close(); } catch { /* closed */ } });
    stream.on("close", () => { try { upstream.close(); session.close(); } catch { /* closed */ } });
    stream.pipe(upstream);
  });
  relayUpgrade(httpsServer);

  await new Promise((resolve, reject) => {
    httpsServer.once("error", reject);
    httpsServer.listen(0, "127.0.0.1", () => resolve());
  });
  const internalTlsPort = httpsServer.address().port;

  const tcpServer = net.createServer((socket) => {
    socket.setTimeout(0);
    socket.setKeepAlive(true, 10000);
    socket.setNoDelay(true);
    let first = Buffer.alloc(0);
    let decided = false;
    let timer = null;
    const detach = () => {
      socket.removeListener("data", onData);
      if (timer) clearTimeout(timer);
      timer = null;
    };
    const fail = () => {
      detach();
      try { socket.destroy(); } catch { /* closed */ }
    };
    const route = (kind) => {
      if (decided) return;
      decided = true;
      detach();
      socket.pause();
      if (kind === "http") {
        socket.unshift(first);
        httpServer.emit("connection", socket);
        socket.resume();
        return;
      }
      const upstreamPort = kind === "reality" ? inbounds.reality : internalTlsPort;
      const upstream = net.connect(upstreamPort, "127.0.0.1");
      upstream.once("connect", () => {
        upstream.write(first);
        socket.pipe(upstream);
        upstream.pipe(socket);
        socket.resume();
      });
      upstream.on("error", () => { try { socket.destroy(); } catch { /* closed */ } });
      socket.on("error", () => { try { upstream.destroy(); } catch { /* closed */ } });
      socket.on("close", () => { try { upstream.destroy(); } catch { /* closed */ } });
      upstream.on("close", () => { if (!socket.destroyed) socket.destroy(); });
    };
    const onData = (chunk) => {
      first = Buffer.concat([first, chunk]);
      if (first.length < 3) return;
      if (first[0] === 0x16 && first[1] === 0x03) {
        if (first.length < 5) return;
        const recordLength = first.readUInt16BE(3);
        if (first.length < recordLength + 5 && first.length < 65540) return;
        const sni = extractClientHelloServerName(first);
        if (mode === "direct" && sni && sni.toLowerCase() === String(state.reality.serverName).toLowerCase()) route("reality");
        else route("tls");
        return;
      }
      const prefix = first.toString("latin1", 0, Math.min(first.length, 16));
      if (/^(GET|POST|PUT|HEAD|OPTIONS|DELETE|PATCH|TRACE|CONNECT) /.test(prefix)) {
        route("http");
        return;
      }
      if (first.length >= 16) fail();
    };
    socket.on("data", onData);
    timer = setTimeout(() => {
      if (decided) return;
      if (first.length && first[0] === 0x16 && (first.length < 3 || first[1] === 0x03)) {
        const sni = extractClientHelloServerName(first);
        if (mode === "direct" && sni && sni.toLowerCase() === String(state.reality.serverName).toLowerCase()) route("reality");
        else route("tls");
      } else if (/^(GET|POST|PUT|HEAD|OPTIONS|DELETE|PATCH|TRACE|CONNECT) /.test(first.toString("latin1"))) route("http");
      else fail();
    }, 1500);
    timer.unref();
    socket.once("error", detach);
  });

  await new Promise((resolve, reject) => {
    tcpServer.once("error", reject);
    tcpServer.listen(actualPort, "0.0.0.0", () => resolve());
  });

  console.log("[NovaPanel] " + VERSION + " panel listening on 0.0.0.0:" + actualPort + ".");
  console.log("[NovaPanel] Panel URL: http://<public-host>:" + actualPort + "/" + panelPath);
  console.log("[NovaPanel] Data directory: " + dataDir);
  console.log("[NovaPanel] Single-port TCP mux ready; TLS fingerprint " + certificate.fingerprint + ".");

  async function startXray() {
    if (!isEnabled(process.env.NOVAPANEL_AUTO_INSTALL_XRAY)) {
      boot.engine_status = "disabled";
      boot.engine_error = "نصب خودکار موتور خاموش است. متغیر NOVAPANEL_AUTO_INSTALL_XRAY را حذف کن یا روی 1 قرار بده.";
      return;
    }
    try {
      boot.engine_status = "installing";
      const installed = await ensureXrayInstalled(dataDir);
      boot.binary = installed.binary;
      boot.engine_version = installed.version;
      const configWrite = spawnSync(installed.binary, ["run", "-test", "-config", xrayConfigPath], {
        encoding: "utf8",
        timeout: 20000,
        stdio: ["ignore", "pipe", "pipe"]
      });
      if (configWrite.status !== 0) {
        const details = String(configWrite.stderr || configWrite.stdout || "Xray rejected xray.json.").slice(-3000);
        throw new Error("Xray configuration check failed: " + details);
      }
      fs.mkdirSync(dataDir, { recursive: true });
      const log = fs.createWriteStream(xrayLogPath, { flags: "a" });
      const child = spawn(installed.binary, ["run", "-config", xrayConfigPath], {
        cwd: dataDir,
        env: { ...process.env, XRAY_LOCATION_ASSET: path.join(dataDir, "bin") },
        stdio: ["ignore", "pipe", "pipe"]
      });
      boot.child = child;
      child.stdout.pipe(log, { end: false });
      child.stderr.pipe(log, { end: false });
      child.once("error", (err) => {
        boot.engine_status = "error";
        boot.engine_error = err.message;
        console.error("[NovaPanel] Xray process error:", err);
        log.end();
      });
      child.once("exit", (code, signal) => {
        if (boot.child === child) boot.child = null;
        if (boot.engine_status !== "error") {
          boot.engine_status = code === 0 ? "stopped" : "error";
          if (code !== 0) boot.engine_error = "Xray exited (code=" + code + ", signal=" + signal + "). Check xray.log.";
        }
        log.end();
      });
      await new Promise((resolve) => setTimeout(resolve, 350));
      if (child.exitCode !== null) {
        throw new Error("Xray exited immediately. " + tailFile(xrayLogPath, 3000));
      }
      boot.engine_status = "running";
      boot.engine_error = "";
      console.log("[NovaPanel] Xray-core " + installed.version + " is running with VLESS, VMess and Trojan WebSocket inbounds.");
    } catch (err) {
      boot.engine_status = "error";
      boot.engine_error = String(err && err.message ? err.message : err);
      console.error("[NovaPanel] Xray startup failed; the panel remains available:", boot.engine_error);
    }
  }

  async function shutdown() {
    if (boot.child && boot.child.exitCode === null) {
      const child = boot.child;
      child.kill("SIGTERM");
      await Promise.race([new Promise((resolve) => child.once("exit", resolve)), new Promise((resolve) => setTimeout(resolve, 5000))]);
      if (child.exitCode === null) child.kill("SIGKILL");
    }
    await Promise.all([
      new Promise((resolve) => tcpServer.close(() => resolve())),
      new Promise((resolve) => httpsServer.close(() => resolve()))
    ]);
  }

  if (isEnabled(process.env.NOVAPANEL_AUTO_INSTALL_XRAY)) void startXray();
  else {
    boot.engine_status = "disabled";
    boot.engine_error = "نصب خودکار موتور خاموش است؛ برای اتصال واقعی باید Xray نصب شود.";
  }

  return { app, tcpServer, httpServer, httpsServer, dataDir, state, auth, boot, shutdown, actualPort, xrayConfig, certificate };
}

const loginFailures = new Map();

if (IS_MAIN) {
  let runtime;
  startRuntime().then((started) => {
    runtime = started;
    const shutdown = async () => {
      if (runtime) await runtime.shutdown().catch(() => {});
      process.exit(0);
    };
    process.once("SIGTERM", shutdown);
    process.once("SIGINT", shutdown);
  }).catch((err) => {
    console.error("[NovaPanel] Fatal startup error:", err);
    process.exit(1);
  });
}

export {
  APP_NAME,
  VERSION,
  buildXrayConfig,
  createSelfSignedCertificate,
  makeSubscriptionLinks,
  startRuntime
};
