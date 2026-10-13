import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

test("single start command serves health endpoint from built artifact", async () => {
  const root = resolve(".");
  const port = 19000 + (process.pid % 10000);
  const dataDir = mkdtempSync(join(tmpdir(), "novapanel-start-test-"));
  const child = spawn(process.execPath, ["scripts/start.mjs"], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(port),
      SERVER_PORT: "",
      NOVAPANEL_DATA_DIR: dataDir,
      NOVAPANEL_SECRET_KEY: "test-only-secret-that-is-long-enough-for-start-test",
      NOVAPANEL_DEPLOYMENT_MODE: "direct",
      NOVAPANEL_XRAY_BINARY: ""
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let logs = "";
  child.stdout.on("data", (chunk) => { logs += chunk.toString(); });
  child.stderr.on("data", (chunk) => { logs += chunk.toString(); });
  const exited = new Promise((resolveExit) => child.once("exit", resolveExit));
  let response = null;
  try {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      if (child.exitCode !== null) break;
      try {
        const candidate = await fetch(`http://127.0.0.1:${port}/api/health`, { signal: AbortSignal.timeout(400) });
        if (candidate.ok) {
          response = await candidate.json();
          break;
        }
      } catch { /* server is still starting */ }
      await delay(100);
    }
    assert.ok(response, `NovaPanel did not serve the health route. Output: ${logs}`);
    assert.equal(response.app, "NovaPanel");
    assert.equal(response.version, "0.6.0");
  } finally {
    if (child.exitCode === null) child.kill("SIGTERM");
    await Promise.race([exited, delay(3000)]);
    if (child.exitCode === null) child.kill("SIGKILL");
  }
});
