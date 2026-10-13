import { test, before } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.NOVAPANEL_DATA_DIR = mkdtempSync(join(tmpdir(), "novapanel-node-test-"));
process.env.NOVAPANEL_DEPLOYMENT_MODE = "direct";
process.env.NOVAPANEL_SECRET_KEY = "test-only-secret-that-is-long-enough-for-tests";
process.env.NOVAPANEL_XRAY_BINARY = "";

let request;
let client;
let app;

before(async () => {
  ({ default: request } = await import("supertest"));
  ({ app } = await import("../build/server/index.js"));
  client = request.agent(app);
});

test("health and initial setup", async () => {
  const health = await client.get("/api/health").expect(200);
  assert.equal(health.body.app, "NovaPanel");
  assert.equal(health.body.version, "0.6.0");
  const setup = await client.get("/api/setup/status").expect(200);
  assert.equal(setup.body.setup_required, true);
  await client.post("/api/setup").send({ password: "a-long-and-secure-test-passphrase" }).expect(200);
  await client.get("/api/me").expect(200);
  await client.get("/api/setup/status").expect(200).then((response) => assert.equal(response.body.setup_required, false));
  await client.post("/api/setup").send({ password: "another-long-and-secure-passphrase" }).expect(409);
});

test("user lifecycle and subscription token behavior", async () => {
  const unauthorized = request(app);
  await unauthorized.get("/api/users").expect(401);
  const created = await client.post("/api/users").send({ name: "Test User", quota_gb: 25 }).expect(201);
  assert.equal(created.body.name, "Test User");
  assert.equal(created.body.quota_gb, 25);
  assert.ok(created.body.uuid);
  const users = await client.get("/api/users").expect(200);
  assert.equal(users.body.length, 1);
  assert.equal(users.body[0].name, "Test User");

  const connection = await client.post("/api/connections").send({
    name: "Test WS", address: "vpn.example.com", port: 443, transport: "ws", path: "/ray"
  }).expect(201);
  assert.equal(connection.body.tls_ready, false);

  const sub = await client.post(`/api/users/${created.body.id}/subscription`).expect(200);
  assert.match(sub.body.url, /\/api\/subscriptions\//);
  await client.get(new URL(sub.body.url).pathname).expect(409);

  await client.put(`/api/users/${created.body.id}`).send({ enabled: false, name: "Disabled User" }).expect(200);
  await client.post(`/api/users/${created.body.id}/subscription`).expect(409);
  await client.delete(`/api/users/${created.body.id}`).expect(200);
  await client.get("/api/users").expect(200).then((response) => assert.equal(response.body.length, 0));
});

test("host capabilities are explicit and API errors are JSON", async () => {
  const host = await client.get("/api/host").expect(200);
  assert.ok(host.body.node_version);
  assert.equal(host.body.capabilities.inbound_tcp_udp.status, "unknown");
  const invalid = await client.post("/api/connections").send({
    name: "Bad", address: "https://example.com/path", port: 443
  }).expect(422);
  assert.ok(invalid.body.detail);
  await client.get("/openapi.json").expect(200);
});
