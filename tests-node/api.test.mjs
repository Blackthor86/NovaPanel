import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { buildSingBoxConfig, buildXrayConfig, buildClashExport, buildSingBoxExport, buildXrayExport, makeSubscriptionLinks, VERSION } from "../index.js";

async function freePort() {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = address && typeof address === "object" ? address.port : 0;
      server.close((err) => err ? reject(err) : resolve(port));
    });
  });
}

test("one UUID produces VLESS, VMess, and Trojan profiles with persistent paths", () => {
  const state = {
    uuid: "e7f9b752-352f-4c6f-8e8c-10e4d8f3f001",
    grpcService: "novapanel-test",
    ssMethod: "aes-256-gcm",
    ssPassword: "test-ss-password",
    reality: { privateKey: "test-private-key", publicKey: "test-public-key", shortId: "0123456789abcdef", serverName: "www.cloudflare.com" },
    paths: {
      vless: "/connect/vless-unit-test",
      vmess: "/connect/vmess-unit-test",
      trojan: "/connect/trojan-unit-test",
      vlessHu: "/connect/vless-hu-unit-test",
      vmessHu: "/connect/vmess-hu-unit-test",
      trojanHu: "/connect/trojan-hu-unit-test",
      grpc: "/connect/grpc-unit-test",
      xhttp: "/connect/xhttp-unit-test",
      ss: "/connect/ss-unit-test"
    }
  };
  const links = makeSubscriptionLinks(state, "panel.example.test", 443, "edge", "a".repeat(64), {});
  assert.equal(links.length, 7);
  assert.deepEqual(links.map((link) => link.protocol), ["vless", "vmess", "trojan", "vless", "vmess", "trojan", "vless"]);
  const uriLinks = links.filter((link) => link.protocol !== "vmess");
  assert.ok(uriLinks.every((link) => link.uri.includes("@panel.example.test:443")));
  assert.ok(links.every((link) => link.uri.includes("security=tls") || link.protocol === "vmess"));
  assert.equal(new URL(links[0].uri).searchParams.get("path"), state.paths.vless);
  const vmessLink = links.find((link) => link.protocol === "vmess");
  assert.ok(vmessLink.uri.startsWith("vmess://"));
  const vmess = JSON.parse(Buffer.from(vmessLink.uri.slice("vmess://".length), "base64").toString("utf8"));
  assert.equal(vmess.path, state.paths.vmess);
  assert.equal(vmess.id, state.uuid);
  assert.equal(vmess.add, "panel.example.test");
  assert.equal(vmess.port, "443");
  const trojanLink = links.find((link) => link.protocol === "trojan");
  assert.ok(trojanLink.uri.startsWith("trojan://"));
  assert.ok(trojanLink.uri.includes("@panel.example.test:443"));
});

test("primary protocols run on sing-box and Xray is limited to XHTTP and Shadowsocks", () => {
  const state = {
    uuid: "e7f9b752-352f-4c6f-8e8c-10e4d8f3f001", grpcService: "novapanel-test",
    ssMethod: "aes-256-gcm", ssPassword: "test-ss-password",
    reality: { privateKey: "test-private-key", publicKey: "test-public-key", shortId: "0123456789abcdef", serverName: "www.cloudflare.com" },
    paths: {
      vless: "/connect/vless-unit-test", vmess: "/connect/vmess-unit-test", trojan: "/connect/trojan-unit-test",
      vlessHu: "/connect/vless-hu-unit-test", vmessHu: "/connect/vmess-hu-unit-test", trojanHu: "/connect/trojan-hu-unit-test",
      grpc: "/connect/grpc-unit-test", xhttp: "/connect/xhttp-unit-test", ss: "/connect/ss-unit-test"
    }
  };
  const ports = { vless: 22001, vmess: 22002, trojan: 22003, vlessHu: 22004, vmessHu: 22005, trojanHu: 22006, grpc: 22007, xhttp: 22008, ss: 22009, reality: 22010 };
  const sb = buildSingBoxConfig(state, ports, "direct");
  assert.equal(sb.inbounds.length, 8);
  assert.deepEqual(sb.inbounds.map((x) => x.type), ["vless", "vmess", "trojan", "vless", "vmess", "trojan", "vless", "vless"]);
  assert.deepEqual(sb.inbounds.map((x) => x.listen_port), [22001, 22002, 22003, 22004, 22005, 22006, 22007, 22010]);
  assert.ok(sb.inbounds.every((x) => x.listen === "127.0.0.1"));
  assert.deepEqual(sb.inbounds.slice(0, 3).map((x) => x.transport.path), [state.paths.vless, state.paths.vmess, state.paths.trojan]);
  assert.equal(sb.inbounds[6].transport.type, "grpc");
  assert.ok(sb.inbounds[7].tls.reality.enabled);
  const xr = buildXrayConfig(state, ports, "/tmp/novapanel-test", "direct");
  assert.equal(xr.inbounds.length, 2);
  assert.deepEqual(xr.inbounds.map((x) => x.protocol), ["vless", "shadowsocks"]);
  assert.deepEqual(xr.inbounds.map((x) => x.port), [22008, 22009]);
  assert.ok(xr.inbounds.every((x) => x.listen === "127.0.0.1"));
  assert.equal(buildSingBoxConfig(state, ports, "edge").inbounds.length, 6);
  assert.equal(buildXrayConfig(state, ports, "/tmp/novapanel-test", "edge").inbounds.length, 0);
});

test("standalone start binds SERVER_PORT, allows first-use password setup, and serves a usable base64 subscription", async () => {
  const root = path.resolve(".");
  const port = await freePort();
  const wrongPort = port === 65535 ? port - 1000 : port + 1;
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "novapanel-lite-test-"));
  const child = spawn(process.execPath, ["index.js"], {
    cwd: root,
    env: {
      ...process.env,
      SERVER_PORT: String(port),
      PORT: String(wrongPort),
      NOVAPANEL_DATA_DIR: dataDir,
      NOVAPANEL_PUBLIC_HOST: "127.0.0.1",
      NOVAPANEL_AUTO_INSTALL_XRAY: "0",
      NOVAPANEL_LINK_MODE: "direct",
      PANEL_PATH: "knight"
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let logs = "";
  child.stdout.on("data", (chunk) => { logs += chunk.toString(); });
  child.stderr.on("data", (chunk) => { logs += chunk.toString(); });

  const base = "http://127.0.0.1:" + port;
  const deadline = Date.now() + 10000;
  let health = null;
  try {
    while (Date.now() < deadline && child.exitCode === null) {
      try {
        const response = await fetch(base + "/api/health", { signal: AbortSignal.timeout(500) });
        if (response.ok) { health = await response.json(); break; }
      } catch { /* process is still binding the public socket */ }
      await delay(100);
    }
    assert.ok(health, "health endpoint never became ready; logs:\n" + logs);
    assert.equal(health.app, "NovaPanel");
    assert.equal(health.version, VERSION);
    assert.equal(health.listen_port, port);
    assert.equal(health.engine_status, "disabled");
    assert.equal(health.singbox_installed, false);
    assert.equal(health.xray_installed, false);

    const setupPage = await fetch(base + "/knight/login");
    assert.equal(setupPage.status, 200);
    assert.match(await setupPage.text(), /ساخت رمز مدیر/);

    const setup = await fetch(base + "/knight/login", {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ password: "test-password-strong", confirm: "test-password-strong" })
    });
    assert.equal(setup.status, 302);
    assert.equal(setup.headers.get("location"), "/knight");
    const setCookie = setup.headers.get("set-cookie");
    assert.ok(setCookie, "first-run password setup should create a session cookie");
    const cookie = setCookie.split(";")[0];

    const statusRes = await fetch(base + "/api/status", { headers: { cookie } });
    assert.equal(statusRes.status, 200);
    const status = await statusRes.json();
    assert.equal(status.engine_status, "disabled");
    assert.equal(status.links.length, 13);
    assert.equal(status.public_host, "127.0.0.1");
    assert.equal(status.link_port, port);
    assert.match(status.subscription_url, /\/knight\/sub\?token=/);

    const subRes = await fetch(status.subscription_url);
    assert.equal(subRes.status, 200);
    assert.match(subRes.headers.get("content-type") || "", /text\/plain/);
    assert.equal(subRes.headers.get("profile-update-interval"), "24");
    const links = Buffer.from(await subRes.text(), "base64").toString("utf8").trim().split(/\r?\n/);
    assert.equal(links.length, 13);
    assert.ok(links.some((line) => line.startsWith("vless://") && line.includes("security=none")));
    assert.ok(links.some((line) => line.startsWith("vless://") && line.includes("security=tls")));
    assert.ok(links.some((line) => line.startsWith("vmess://")));
    assert.ok(links.some((line) => line.startsWith("trojan://")));
    assert.ok(links.some((line) => line.includes("type=grpc")));
    assert.ok(links.some((line) => line.includes("type=xhttp")));
    assert.ok(links.some((line) => line.startsWith("ss://")));
    assert.ok(links.some((line) => line.includes("security=reality")));
    const rawOutput = await fetch(base + "/knight/raw?token=" + encodeURIComponent(status.subscription_token));
    assert.equal(rawOutput.status, 200);
    const rawLines = (await rawOutput.text()).trim().split(/\r?\n/);
    assert.equal(rawLines.length, 13);

    const clashResponse = await fetch(base + "/knight/clash?token=" + encodeURIComponent(status.subscription_token));
    assert.equal(clashResponse.status, 200);
    const clashText = await clashResponse.text();
    assert.match(clashText, /^proxies:/m);
    assert.match(clashText, /reality-opts:/);
    const singBoxResponse = await fetch(base + "/knight/sb?token=" + encodeURIComponent(status.subscription_token));
    const singBox = await singBoxResponse.json();
    assert.ok(singBox.outbounds.length >= 13);
    const xrayResponse = await fetch(base + "/knight/xray?token=" + encodeURIComponent(status.subscription_token));
    const xrayClient = await xrayResponse.json();
    assert.ok(xrayClient.outbounds.length >= 13);

    const formats = {
      vless: "vless://",
      vmess: "vmess://",
      trojan: "trojan://"
    };
    for (const line of links.filter((item) => item.startsWith("vless://") || item.startsWith("trojan://"))) {
      assert.ok(line.includes("@127.0.0.1:" + port + "?"), line);
    }

    const rawRes = await fetch(base + "/knight/raw?token=" + encodeURIComponent(status.subscription_token));
    assert.equal(rawRes.status, 200);
    const raw = await rawRes.text();
    assert.match(raw, /^vless:\/\//m);
    assert.match(raw, /^trojan:\/\//m);

    const tlsHealth = await fetchHttpsHealth(port);
    assert.equal(tlsHealth.status, 200);
    assert.equal(tlsHealth.body.app, "NovaPanel");
  } finally {
    if (child.exitCode === null) child.kill("SIGTERM");
    await new Promise((resolve) => {
      if (child.exitCode !== null) return resolve();
      const timer = setTimeout(resolve, 4000);
      child.once("exit", () => { clearTimeout(timer); resolve(); });
    });
    if (child.exitCode === null) child.kill("SIGKILL");
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

async function fetchHttpsHealth(port) {
  const { request } = await import("node:https");
  return await new Promise((resolve, reject) => {
    const req = request({
      hostname: "127.0.0.1",
      port,
      path: "/api/health",
      method: "GET",
      rejectUnauthorized: false,
      timeout: 4000
    }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body) }); }
        catch (error) { reject(error); }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("TLS health request timed out")));
    req.end();
  });
}
