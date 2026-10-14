# NovaPanel

NovaPanel is a compact, single-process Node.js connection panel designed for hosts that expose one public TCP port.

## Core behavior

- First visit opens the setup page; choose an admin password and no username is required.
 - One TCP listener handles the web panel plus compatible proxy transports. The public listener prefers `PORT`, then `SERVER_PORT`.
- sing-box is the primary native engine for VLESS, VMess, and Trojan WebSocket/HTTPUpgrade, plus direct-mode gRPC. Xray-core handles XHTTP, Shadowsocks-over-WebSocket, and Reality. Node.js handles the panel, subscription endpoints, TLS termination, and the one-port traffic router.
- UUID, private subscription token, random transport paths, TLS certificate, and Reality keys are saved under the persistent data directory.
- One Base64 subscription URL returns the current profile list; a V2Ray-compatible client can update that subscription without copying profiles individually.
- Profile formats include VLESS, VMess, and Trojan WebSocket; HTTPUpgrade variants; VLESS gRPC TLS and XHTTP; Shadowsocks WebSocket; and VLESS Reality for direct TCP hosts.
- Dedicated endpoints provide Clash YAML, sing-box JSON, and Xray client JSON exports.

## Run it

Use Node.js 22 (Node.js 20+ is supported):

\`\`\`sh
npm install
npm start
\`\`\`

Set the host's start command to `npm start`. Let the platform inject `PORT` (preferred) or `SERVER_PORT`. Set `NOVAPANEL_DATA_DIR` to a writable persistent volume, and keep that folder between restarts. If automatic engine installation is enabled, the panel starts while sing-box (and, in direct mode, Xray for XHTTP/Shadowsocks) downloads and starts. Wait until the engine status shows **running** before testing a proxy connection.

Open \`/knight/login\` on the app's public web URL and set the initial password. After login, copy the **subscription URL**, add it in the client's Subscription section, and use Update/Refresh. Do not use an individual \`vless://\` link as the subscription URL.

## Subscription and export endpoints

All endpoints below require the generated subscription token as a query parameter:

| Endpoint | Format |
|---|---|
| \`/knight/sub?token=…\` | Base64 V2Ray-compatible subscription |
| \`/knight/raw?token=…\` | Plain list of individual links |
| \`/knight/clash?token=…\` | Clash YAML |
| \`/knight/sb?token=…\` | sing-box JSON |
| \`/knight/xray?token=…\` | Xray client JSON |

The standard subscription URL is shown in the panel. Treat it as a secret: anyone who has it can import the profiles.

## Direct and edge links

By default, NovaPanel generates direct links for a host that exposes the app's assigned raw TCP port. Direct TLS uses a self-signed certificate; generated links include its pin and client-side compatibility option. Use \`NOVAPANEL_LINK_MODE=edge\` only when the hosting provider terminates HTTPS and supports WebSocket upgrades through its public domain. Edge mode cannot provide raw-TCP Reality, gRPC, or Shadowsocks profiles.

The host must allow native sing-box and (in direct mode) Xray child processes, outbound downloads when automatic installation is enabled, and traffic forwarding on its assigned port. A successful health endpoint does not prove that a proxy client can connect. Confirm the engine is running and test the subscription with a real client on the target host before sharing it.

## Environment variables

| Variable | Purpose |
|---|---|
 | `PORT` / `SERVER_PORT` | Public listener; `PORT` takes precedence |
| \`NOVAPANEL_DATA_DIR\` | Writable persistent data directory |
| \`NOVAPANEL_PUBLIC_HOST\` / \`DOMAIN\` | Optional public-host override |
| \`NOVAPANEL_PUBLIC_BASE_URL\` | Optional public subscription base URL |
| \`NOVAPANEL_LINK_MODE\` | \`direct\` or \`edge\` (default is automatic detection of common edge hosts, otherwise direct) |
| \`NOVAPANEL_LINK_PORT\` | Optional port placed in connection links |
| `NOVAPANEL_AUTO_INSTALL_ENGINES` | `1` enables automatic engine installation; `0` disables it (default: `1`) |
| `NOVAPANEL_SINGBOX_BINARY` | Optional path to an existing sing-box executable |
| `NOVAPANEL_SINGBOX_VERSION` | sing-box release version; default `1.11.15`, matching the BlueKnight baseline |
| `NOVAPANEL_SINGBOX_URL` | Optional override URL for the sing-box archive |
| `NOVAPANEL_XRAY_BINARY` | Optional path to an existing Xray executable |
| `NOVAPANEL_AUTO_INSTALL_XRAY` | Legacy alias for the all-engine install switch |
| \`NOVAPANEL_REALITY_SNI\` | Optional Reality SNI/target; defaults to \`www.cloudflare.com\`. Custom targets should support TLS 1.3 and HTTP/2. |
| \`PANEL_PASSWORD\` | Optional admin password set through a hosting secret |
| \`SETUP_KEY\` | Optional extra key for first-time password setup |
| \`SUB_TOKEN\` | Optional stable subscription token |
| \`PANEL_PATH\` | Panel route; default \`knight\` |

## Verify

- \`/api/health\` should return JSON with \`status: "ok"\` and the assigned listener port.
- The status panel should report \`engine_status: "running"\`.
- Import the subscription and test real client traffic. API tests alone are not a network-connectivity guarantee.

Run checks locally with \`npm test\`. CI validates generated profiles using real Xray client traffic against a controlled destination. Sing-box serves the primary WebSocket/HTTPUpgrade/gRPC inbounds; Xray serves XHTTP, Shadowsocks, and Reality. The suite tests these profiles through the shared public TCP port. Tests run on the GitHub runner; raw TCP forwarding and real-world speed on Botkeep or another provider must still be verified on that host.

## Security and license

Keep the data directory persistent and private. Do not publish the subscription token, admin password, or TLS private key. Review [SECURITY.md](SECURITY.md). NovaPanel is distributed under GNU AGPL-3.0-or-later; retain the project license and notices.
