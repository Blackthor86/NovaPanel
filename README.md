# NovaPanel

NovaPanel is a compact, single-process Node.js panel with a Blue Knight Gate–style first-run flow: choose an admin password, copy one subscription URL, and add it to a V2Ray-compatible client.

## What this version does

- One Node.js runtime and one assigned public TCP port (SERVER_PORT preferred, then PORT).
- First visit at /knight/login asks you to create an admin password; no username is needed.
- Stable state under bk-data/ (or NOVAPANEL_DATA_DIR), including UUID, subscription token, WebSocket paths, password hash and TLS certificate.
- One subscription URL serves a Base64 list of VLESS, VMess and Trojan WebSocket profiles. The same URL reflects future profile updates.
- One TCP listener routes plain HTTP to the panel and TLS traffic to the internal HTTPS handler, using the same public port. WebSocket upgrades are relayed to local Xray inbounds.
- Xray-core is installed automatically on supported Linux systems and starts in the background; the dashboard remains available while installation is running.
- Direct mode supports TLS profiles with a self-signed certificate pin. A platform-edge mode is available for supported providers that terminate HTTPS before passing requests to the app.

**Important:** this is a compact baseline, not a full feature-for-feature copy of every Blue Knight protocol. This version intentionally focuses on the shared-port web panel and V2Ray subscription path before adding gRPC, XHTTP, Clash, sing-box exports, traffic accounting or per-user administration.

## Deploy

Recommended runtime: **Node.js 22** (Node.js 20+ is supported).

1. On main, download the ZIP from the successful GitHub Actions artifact NovaPanel-node-deploy. While this feature is still being reviewed in its pull request, use the preview artifact NovaPanel-blue-knight-lite-preview instead. You can also upload the source files and run npm install.

The GitHub Actions artifact download is an outer ZIP containing the deployable file NovaPanel-blue-knight-lite.zip. Extract the downloaded artifact, then extract the inner ZIP for upload; make sure package.json is at the root of the deployed files, not one directory deeper.
2. Set the start command to npm start (node index.js).
3. Ensure the host assigns SERVER_PORT or PORT and exposes that port as the public web/TCP port.
4. Use persistent writable storage for NOVAPANEL_DATA_DIR so restarts do not change the UUID, subscription token, password or certificate.
5. Open http://<public-host>:<assigned-port>/knight or the public URL provided by the host. At first visit, create a password of at least 8 characters.
6. Copy the **subscription URL** (not an individual VLESS/VMess/Trojan link), add it as a subscription in your V2Ray client, and update the subscription.
7. Before sharing it, verify that /api/health reports engine_status: "running" and test actual connectivity in a client.

If the host exposes only an HTTPS reverse-proxy domain and does not route raw TCP/TLS on the assigned app port, set NOVAPANEL_LINK_MODE=edge only when the host also supports WebSocket upgrades. In that mode, generated links use the provider's HTTPS edge on port 443. For a raw TCP port host such as a typical game-panel allocation, leave the mode as direct.

## Environment variables

| Variable | Purpose |
|---|---|
| SERVER_PORT / PORT | Public listener; SERVER_PORT takes precedence. |
| NOVAPANEL_DATA_DIR | Persistent writable folder; defaults to ./bk-data. |
| NOVAPANEL_PUBLIC_HOST or DOMAIN | Override the hostname embedded in connection links. Otherwise the request host is learned and saved. |
| NOVAPANEL_PUBLIC_BASE_URL | Override the base URL used for the subscription endpoint. |
| NOVAPANEL_LINK_MODE | direct (default) or edge. |
| NOVAPANEL_LINK_PORT | Override the port embedded in proxy links. |
| NOVAPANEL_AUTO_INSTALL_XRAY | 1 by default. Set to 0 to run the web panel without the proxy engine. |
| NOVAPANEL_XRAY_BINARY | Use an existing executable Xray path instead of downloading one. |
| PANEL_PASSWORD | Optional initial/admin password supplied as a hosting secret. |
| SETUP_KEY | Optional extra key required only during first password setup. |
| SUB_TOKEN | Optional stable subscription token; otherwise generated randomly. |
| PANEL_PATH | Panel route; defaults to knight. |

Keep the bk-data/ directory. It stores the subscription token, UUID, routes, password hash and certificate. Deleting it creates new links and requires re-importing the subscription.

## Test locally

Run npm install, then npm test, then npm start.

CI includes a live tunnel test that starts Xray and checks real HTTP traffic through a VLESS + TLS + WebSocket client connection over the same public TCP port. This test is more meaningful than merely checking that the panel API returns HTTP 200; actual connectivity on the target hosting provider still needs a final provider-side test.

## Limitations in this baseline

Only VLESS, VMess and Trojan WebSocket profiles are generated. Direct TLS uses a self-signed certificate with a SHA-256 pin in the subscription URI; confirm your client honors it before production use. Usage quotas, client CRUD, Clash/sing-box output, Reality, gRPC and XHTTP are not implemented in this compact baseline.

## Security and license

Treat the subscription URL as a secret because it contains the subscription token. Use a persistent volume, a private/long admin password, and a setup key when the public URL is reachable by others. See SECURITY.md.

The project license is GNU AGPL-3.0-or-later. Keep all attribution and license notices.
