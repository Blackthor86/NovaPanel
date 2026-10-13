import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const builtServer = join(root, "build", "server", "index.js");
const builtFrontend = join(root, "frontend", "dist", "index.html");

function run(command, args, options = {}) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      cwd: root,
      env: process.env,
      stdio: "inherit",
      shell: process.platform === "win32",
      ...options,
    });
    child.once("error", rejectRun);
    child.once("exit", (code, signal) => {
      if (signal) return rejectRun(new Error(`${command} exited from signal ${signal}`));
      resolveRun(code ?? 1);
    });
  });
}

if (!existsSync(builtServer) || !existsSync(builtFrontend)) {
  console.log("[NovaPanel] Build files are missing; building the API and dashboard.");
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const code = await run(npm, ["run", "build"]);
  if (code !== 0) process.exit(code);
}

const child = spawn(process.execPath, [builtServer], { cwd: root, env: process.env, stdio: "inherit" });
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    if (child.exitCode === null) child.kill(signal);
  });
}
child.once("error", (error) => {
  console.error("[NovaPanel] Could not start the API:", error);
  process.exitCode = 1;
});
child.once("exit", (code, signal) => {
  if (signal) process.exitCode = 1;
  else process.exitCode = code ?? 1;
});
