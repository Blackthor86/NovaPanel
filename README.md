# NovaPanel

NovaPanel 0.6.0 is a self-hosted connection-management panel with a **single Node.js runtime**. The web dashboard is React + TypeScript, and the API, local database, subscription delivery, WebSocket relay, and Xray process control run under Node.js. Python is not required.

**Project status:** active development. The app-host WebSocket mode is created automatically when supported hosting variables are detected. Actual external connectivity still depends on the host's networking, WebSocket routing, process permissions, storage persistence, and service policy. The project has not had an independent security review; harden it before exposing it publicly.

## What's included

- Persian RTL dashboard with jade/navy styling
- First-run admin setup and login using a password only (no username)
- Node.js API and local SQLite database
- Automatic app-host mode with generated WebSocket path and HTTPS subscription URLs
- Direct-server mode for hosts with public inbound sockets
- SHA-256-pinned official Xray download for compatible Linux hosts
- User UUIDs, enable/disable, expiry and traffic-quota controls
- WS, gRPC, HTTPUpgrade, and XHTTP connection profiles
- Per-user VLESS links and revocable Base64 subscriptions
- Xray configuration validation, process control, logs and per-user traffic polling
- Node API smoke tests and GitHub Actions validation

Traffic totals are polled from Xray approximately every 15 seconds while it is running. Quota/expiry enforcement may take one polling interval to apply. A generated profile or available TLS URL is not proof that a client can connect.

## Runtime

- Node.js 20+ (Node.js 22 recommended)
- TypeScript, Express, SQLite, React, Vite
- Xray-core is a separate native executable, not an application language dependency
- GNU AGPL-3.0-or-later

## Deploy on a Node.js app host

1. Upload the ZIP generated from the repository, or import the repository if the hosting provider supports the build dependencies.
2. Select Node.js 20 or 22.
3. Set the start command to `npm start`.
4. Set a stable random `NOVAPANEL_SECRET_KEY` and mount persistent storage for `NOVAPANEL_DATA_DIR`.
5. If the provider exposes `SERVER_PORT`, NovaPanel binds to that assigned HTTP port (it takes precedence over generic `PORT`). Automatic mode is selected by default for recognized app-host environments. You can explicitly set `NOVAPANEL_DEPLOYMENT_MODE=paas_ws`.
6. Open the public HTTPS domain and set an admin password of at least 14 characters.

`npm start` starts one Node.js application listening on `0.0.0.0:$SERVER_PORT` (or `$PORT` if `SERVER_PORT` is absent). The ready-to-deploy CI ZIP includes the compiled API and frontend, so it starts without a production build. If you upload the source ZIP instead, the first start builds the TypeScript API and React dashboard and will use more CPU until that build completes. There is no separate Python service to configure.

For the automatic profile, the hosting edge must forward WebSocket upgrades to the application. The dashboard starts without downloading Xray. When the first active user needs the engine, NovaPanel attempts to download the pinned official Xray release on compatible Linux systems in the background. If bootstrap fails, the dashboard remains available and reports that the engine is unavailable. On Botkeep, configure the public HTTP domain in Domains and use the assigned `SERVER_PORT`; the Network tab by itself is not a substitute for enabling HTTP domain routing.

## Local development

Install Node.js 20+ and run at the repository root:

```sh
npm install
npm start
```

The app prints the listening port; the local URL is normally `http://127.0.0.1:8000`. On first launch, choose a strong admin password of at least 14 characters. No username is needed.

To build without starting the service:

```sh
npm run build
```

Run API smoke tests:

```sh
npm test
```

## Direct-server mode

On a VPS/dedicated host with public inbound sockets allowed, set `NOVAPANEL_DEPLOYMENT_MODE=direct`, install and verify Xray, and add a connection once with its real host, port, TLS certificate, and private key paths. NovaPanel then generates each user's links/subscription automatically; no per-client server setup is needed.

## Configuration and security

See [SECURITY.md](SECURITY.md) before deployment. For a remote install, set a stable, high-entropy `NOVAPANEL_SECRET_KEY`, enable `NOVAPANEL_COOKIE_SECURE=1` behind HTTPS, restrict access to the admin dashboard, and use persistent storage. Never commit secrets, private keys, client links, or subscription tokens.

Network reachability is never inferred just from an open URL or runtime type. Test a generated subscription with a real client before sharing it. Do not expose a development server directly to the public internet.

## Project structure

- `server/` — Node.js API, SQLite, WebSocket relay, and Xray process management
- `frontend/` — React dashboard and Vite build
- `tests-node/` — Node API smoke tests
- `SECURITY.md` — deployment security notes

## Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md). Retain attribution and license notices. Forks should clearly distinguish modified projects and should not present them as the official NovaPanel release.

## Copyright and license

Copyright (C) 2026 Blackthor86.

Licensed under GNU Affero General Public License v3.0 or any later version. See [LICENSE](LICENSE). The software license does not grant trademark rights to the NovaPanel name or branding.
