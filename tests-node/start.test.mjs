import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import http from "node:http";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { buildXrayExport, makeSubscriptionLinks } from "../index.js";

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

function waitForHttpResponse(socket, marker, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => finish(new Error("Timed out waiting for " + marker)), timeoutMs);
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.includes(Buffer.from(marker))) finish(null, buffer.toString("utf8"));
    };
    const onError = (err) => finish(err);
    const onClose = () => finish(new Error("Socket closed before receiving " + marker));
    function finish(error, value) {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
      if (error) reject(error);
      else resolve(value);
    }
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

function readExactly(socket, count, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let total = 0;
    const timer = setTimeout(() => finish(new Error("Timed out waiting for " + count + " bytes")), timeoutMs);
    const onData = (chunk) => {
      chunks.push(chunk);
      total += chunk.length;
      if (total >= count) finish(null, Buffer.concat(chunks, total));
    };
    const onError = (err) => finish(err);
    const onClose = () => finish(new Error("Socket closed early"));
    function finish(error, buffer) {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
      if (error) reject(error);
      else {
        if (buffer.length > count) socket.unshift(buffer.subarray(count));
        resolve(buffer.subarray(0, count));
      }
    }
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

async function waitForHealth(base, child, getLogs) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline && child.exitCode === null) {
    try {
      const response = await fetch(base + "/api/health", { signal: AbortSignal.timeout(1000) });
      if (response.ok) return await response.json();
    } catch { /* wait for listener */ }
    await delay(150);
  }
  throw new Error("NovaPanel health endpoint never became ready.\n" + getLogs());
}

async function waitForEngine(base, cookie, child, getLogs) {
  const deadline = Date.now() + 180000;
  let lastStatus = null;
  while (Date.now() < deadline && child.exitCode === null) {
    try {
      const response = await fetch(base + "/api/status", { headers: { cookie }, signal: AbortSignal.timeout(1500) });
      if (response.ok) {
        lastStatus = await response.json();
        if (lastStatus.engine_status === "running") return lastStatus;
        if (lastStatus.engine_status === "error") {
          throw new Error("Xray failed to start: " + lastStatus.engine_error + "\n" + getLogs());
        }
      }
    } catch (error) {
      if (String(error && error.message || error).includes("Xray failed to start")) throw error;
    }
    await delay(500);
  }
  throw new Error("Xray did not become ready: " + JSON.stringify(lastStatus) + "\n" + getLogs());
}

test("real VLESS-over-TLS-WebSocket traffic passes through the assigned public TCP port", { timeout: 240000 }, async () => {
  const root = path.resolve(".");
  const port = await freePort();
  const socksPort = await freePort();
  const targetPort = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "novapanel-live-e2e-"));
  const appLogs = path.join(dataDir, "panel-process.log");
  const appLogStream = fs.createWriteStream(appLogs, { flags: "a" });
  let appLogsBuffer = "";
  let clientLogsBuffer = "";
  let targetServer;
  let appChild;
  let clientChild;
  let socksSocket;
  let passed = false;

  const logApp = (chunk) => {
    appLogsBuffer += chunk.toString();
    appLogStream.write(chunk);
  };
  const base = "http://127.0.0.1:" + port;
  try {
    targetServer = http.createServer((req, res) => {
      res.writeHead(200, { "content-type": "text/plain", "cache-control": "no-store", connection: "close" });
      res.end("novapanel-e2e-ok");
    });
    await new Promise((resolve, reject) => {
      targetServer.once("error", reject);
      targetServer.listen(targetPort, "127.0.0.1", resolve);
    });

    appChild = spawn(process.execPath, ["index.js"], {
      cwd: root,
      env: {
        ...process.env,
        SERVER_PORT: String(port),
        PORT: String(port === 65535 ? port - 1 : port + 1),
        NOVAPANEL_DATA_DIR: dataDir,
        NOVAPANEL_PUBLIC_HOST: "127.0.0.1",
        NOVAPANEL_AUTO_INSTALL_XRAY: "1",
        NOVAPANEL_LINK_MODE: "direct",
        NOVAPANEL_XRAY_LOGLEVEL: "debug",
        PANEL_PATH: "knight"
      },
      stdio: ["ignore", "pipe", "pipe"]
    });
    appChild.stdout.on("data", logApp);
    appChild.stderr.on("data", logApp);

    const health = await waitForHealth(base, appChild, () => appLogsBuffer);
    assert.equal(health.listen_port, port);
    assert.ok(["installing", "running"].includes(health.engine_status), "engine status should show startup in progress");

    const setup = await fetch(base + "/knight/login", {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ password: "novapanel-live-test-pass", confirm: "novapanel-live-test-pass" })
    });
    assert.equal(setup.status, 302);
    const setCookie = setup.headers.get("set-cookie");
    assert.ok(setCookie, "setup must establish an admin session");
    const cookie = setCookie.split(";")[0];

    const status = await waitForEngine(base, cookie, appChild, () => appLogsBuffer);
    assert.equal(status.links.length, 13);
    const state = JSON.parse(fs.readFileSync(path.join(dataDir, "state.json"), "utf8"));
    const profile = status.links.find((link) => link.type === "VLESS-WS-TLS");
    assert.ok(profile, "TLS WebSocket VLESS profile must be generated");
    const uri = new URL(profile.uri);
    assert.equal(uri.searchParams.get("type"), "ws");
    assert.equal(uri.searchParams.get("security"), "tls");

    const subscription = await fetch(status.subscription_url);
    assert.equal(subscription.status, 200);
    const subscriptionLines = Buffer.from(await subscription.text(), "base64").toString("utf8").trim().split(/\r?\n/);
    assert.equal(subscriptionLines.length, 13);
    assert.ok(subscriptionLines.some((line) => line.startsWith("vless://") && line.includes("security=tls")));

    const clientConfigPath = path.join(dataDir, "xray-client.json");
    const clientLogPath = path.join(dataDir, "xray-client.log");
    const clientConfig = {
      log: { loglevel: "warning", error: clientLogPath },
      inbounds: [{
        listen: "127.0.0.1",
        port: socksPort,
        protocol: "socks",
        settings: { auth: "noauth", udp: false }
      }],
      outbounds: [{
        protocol: "vless",
        tag: "proxy",
        settings: {
          vnext: [{
            address: "127.0.0.1",
            port,
            users: [{ id: state.uuid, encryption: "none" }]
          }]
        },
        streamSettings: {
          network: "ws",
          security: "tls",
          tlsSettings: {
            serverName: "127.0.0.1",
            pinnedPeerCertSha256: status.tls_fingerprint,
            alpn: ["http/1.1"]
          },
          wsSettings: {
            path: uri.searchParams.get("path"),
            headers: { Host: "127.0.0.1" }
          }
        }
      }]
    };
    fs.writeFileSync(clientConfigPath, JSON.stringify(clientConfig, null, 2));
    const binary = path.join(dataDir, "bin", "xray");
    const validation = spawn(binary, ["run", "-test", "-config", clientConfigPath], {
      cwd: dataDir,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let validationLogs = "";
    validation.stdout.on("data", (chunk) => { validationLogs += chunk.toString(); });
    validation.stderr.on("data", (chunk) => { validationLogs += chunk.toString(); });
    const validationCode = await new Promise((resolve) => validation.once("exit", resolve));
    assert.equal(validationCode, 0, "client Xray config was rejected: " + validationLogs);

    clientChild = spawn(binary, ["run", "-config", clientConfigPath], {
      cwd: dataDir,
      stdio: ["ignore", "pipe", "pipe"]
    });
    clientChild.stdout.on("data", (chunk) => { clientLogsBuffer += chunk.toString(); });
    clientChild.stderr.on("data", (chunk) => { clientLogsBuffer += chunk.toString(); });

    let connected = false;
    const socksDeadline = Date.now() + 10000;
    while (!connected && Date.now() < socksDeadline && clientChild.exitCode === null) {
      try {
        socksSocket = net.connect(socksPort, "127.0.0.1");
        await new Promise((resolve, reject) => {
          socksSocket.once("connect", resolve);
          socksSocket.once("error", reject);
        });
        connected = true;
      } catch {
        if (socksSocket) socksSocket.destroy();
        socksSocket = null;
        await delay(150);
      }
    }
    assert.ok(connected, "the client Xray SOCKS inbound never opened: " + clientLogsBuffer);
    socksSocket.setTimeout(15000);

    socksSocket.write(Buffer.from([0x05, 0x01, 0x00]));
    const greeting = await readExactly(socksSocket, 2);
    assert.deepEqual(Array.from(greeting), [0x05, 0x00], "SOCKS5 greeting failed");

    const request = Buffer.from([
      0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
      (targetPort >> 8) & 255, targetPort & 255
    ]);
    socksSocket.write(request);
    const connectReply = await readExactly(socksSocket, 10, 20000);
    assert.equal(connectReply[0], 0x05);
    assert.equal(connectReply[1], 0x00, "VLESS/TLS/WS tunnel could not connect to target");

    socksSocket.write("GET /check HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    const response = await waitForHttpResponse(socksSocket, "novapanel-e2e-ok", 20000);
    assert.match(response, /HTTP\/1\.[01] 200/);
    assert.match(response, /novapanel-e2e-ok/);

    // Verify other direct-mode routes over the same public port as real client traffic.
    const generatedLinks = makeSubscriptionLinks(state, "127.0.0.1", port, "direct", status.tls_fingerprint);
    const exported = buildXrayExport(state, generatedLinks, "127.0.0.1", port, "direct", status.tls_fingerprint);
    async function stopCurrentClient() {
      if (socksSocket) { socksSocket.destroy(); socksSocket = null; }
      const child = clientChild;
      if (!child || child.exitCode !== null) { clientChild = null; return; }
      child.kill("SIGTERM");
      await Promise.race([
        new Promise((resolve) => child.once("exit", resolve)),
        delay(2000)
      ]);
      if (child.exitCode === null) child.kill("SIGKILL");
      clientChild = null;
    }
    async function testProfile(profileType) {
      const link = generatedLinks.find((item) => item.type === profileType);
      assert.ok(link, "missing profile: " + profileType);
      const outbound = exported.outbounds.find((item) => item.tag === link.name);
      assert.ok(outbound, "missing Xray outbound for " + profileType);
      await stopCurrentClient();

      const localSocksPort = await freePort();
      const profileConfigPath = path.join(dataDir, "client-" + profileType.replace(/[^a-z0-9]/gi, "-") + ".json");
      const profileLogPath = path.join(dataDir, "client-" + profileType.replace(/[^a-z0-9]/gi, "-") + ".log");
      const clientConfig = {
        log: { loglevel: "warning", error: profileLogPath },
        inbounds: [{
          listen: "127.0.0.1",
          port: localSocksPort,
          protocol: "socks",
          tag: "socks-in",
          settings: { auth: "noauth", udp: false }
        }],
        outbounds: [outbound, { protocol: "freedom", tag: "direct" }, { protocol: "blackhole", tag: "blocked" }],
        routing: { rules: [{ type: "field", inboundTag: ["socks-in"], outboundTag: outbound.tag }] }
      };
      fs.writeFileSync(profileConfigPath, JSON.stringify(clientConfig, null, 2));
      const validation = spawn(binary, ["run", "-test", "-config", profileConfigPath], {
        cwd: dataDir,
        stdio: ["ignore", "pipe", "pipe"]
      });
      let validationLogs = "";
      validation.stdout.on("data", (chunk) => { validationLogs += chunk.toString(); });
      validation.stderr.on("data", (chunk) => { validationLogs += chunk.toString(); });
      const validationCode = await new Promise((resolve) => validation.once("exit", resolve));
      assert.equal(validationCode, 0, profileType + " client config rejected: " + validationLogs);

      clientChild = spawn(binary, ["run", "-config", profileConfigPath], {
        cwd: dataDir,
        stdio: ["ignore", "pipe", "pipe"]
      });
      clientChild.stdout.on("data", (chunk) => { clientLogsBuffer += chunk.toString(); });
      clientChild.stderr.on("data", (chunk) => { clientLogsBuffer += chunk.toString(); });

      let readySocket = false;
      const readyDeadline = Date.now() + 10000;
      while (!readySocket && Date.now() < readyDeadline && clientChild.exitCode === null) {
        try {
          socksSocket = net.connect(localSocksPort, "127.0.0.1");
          await new Promise((resolve, reject) => {
            socksSocket.once("connect", resolve);
            socksSocket.once("error", reject);
          });
          readySocket = true;
        } catch {
          if (socksSocket) socksSocket.destroy();
          socksSocket = null;
          await delay(100);
        }
      }
      assert.ok(readySocket, profileType + " Xray client did not start: " + clientLogsBuffer);
      socksSocket.setTimeout(20000);
      socksSocket.write(Buffer.from([0x05, 0x01, 0x00]));
      const hello = await readExactly(socksSocket, 2);
      assert.deepEqual(Array.from(hello), [0x05, 0x00], profileType + " SOCKS greeting failed");
      socksSocket.write(Buffer.from([
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
        (targetPort >> 8) & 255, targetPort & 255
      ]));
      const reply = await readExactly(socksSocket, 10, 25000);
      assert.equal(reply[1], 0x00, profileType + " could not reach target: " + clientLogsBuffer + "\n" + appLogsBuffer);
      socksSocket.write("GET /" + encodeURIComponent(profileType) + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
      const payload = await waitForHttpResponse(socksSocket, "novapanel-e2e-ok", 25000).catch((error) => {
        const readTail = (file, limit) => fs.existsSync(file) ? fs.readFileSync(file, "utf8").slice(-limit) : "(not created)";
        const serverLog = readTail(path.join(dataDir, "xray.log"), 8000);
        const serverErrors = readTail(path.join(dataDir, "xray-error.log"), 10000);
        const serverAccess = readTail(path.join(dataDir, "access.log"), 6000);
        const profileLog = readTail(profileLogPath, 8000);
        throw new Error(profileType + " HTTP response failed: " + error.message + "\nClient stdout/stderr:\n" + clientLogsBuffer + "\nClient Xray log:\n" + profileLog + "\nServer Xray log:\n" + serverLog + "\nServer Xray errors:\n" + serverErrors + "\nServer access log:\n" + serverAccess + "\nRouter logs:\n" + appLogsBuffer);
      });
      assert.match(payload, /HTTP\/1\.[01] 200/, profileType + " returned non-200 response");
      assert.match(payload, /novapanel-e2e-ok/, profileType + " did not tunnel the response");
    }

    for (const type of ["VLESS-HTTPUpgrade", "VLESS-gRPC-TLS", "VLESS-XHTTP-TLS", "VLESS-Reality"]) {
      await testProfile(type);
    }
    passed = true;
  } finally {
    if (socksSocket) socksSocket.destroy();
    if (clientChild && clientChild.exitCode === null) clientChild.kill("SIGTERM");
    if (appChild && appChild.exitCode === null) appChild.kill("SIGTERM");
    if (targetServer) await new Promise((resolve) => targetServer.close(() => resolve()));
    for (const child of [clientChild, appChild]) {
      if (child && child.exitCode === null) {
        await Promise.race([
          new Promise((resolve) => child.once("exit", resolve)),
          delay(2500)
        ]);
        if (child.exitCode === null) child.kill("SIGKILL");
      }
    }
    appLogStream.end();
    if (fs.existsSync(dataDir)) {
      // Preserve diagnostic logs only on a failed test; successful runs are cleaned up.
      if (passed) fs.rmSync(dataDir, { recursive: true, force: true });
      else console.error("[NovaPanel E2E diagnostics] " + dataDir + "\n" + appLogsBuffer + "\n" + clientLogsBuffer + "\n--- xray.log ---\n" + (fs.existsSync(path.join(dataDir, "xray.log")) ? fs.readFileSync(path.join(dataDir, "xray.log"), "utf8").slice(-12000) : "(no xray.log)"));
    }
  }
});
