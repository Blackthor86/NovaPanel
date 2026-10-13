# NovaPanel

NovaPanel 0.5.0 is a self-hosted management panel for proxy-engine deployments, built around a Python API and a responsive web interface.

**Project status:** active development. The current build includes the dashboard, one-time admin setup, session login, local SQLite storage, user and connection profile management, host capability reporting, and optional Xray process controls when an operator installs and verifies the engine. It has not yet had an independent security review and should not be exposed directly to the public internet.

## What is included

- Persian RTL dashboard with a jade and navy theme, responsive layout, and motion effects
- First-run admin password setup (no username) and password-only session login
- Automatic app-host mode with a generated WebSocket endpoint and HTTPS subscription URLs
- Direct inbound mode for a VPS/dedicated server with public TCP ports
- SHA-256-pinned official Xray bootstrap for compatible Linux app hosts
- User UUID generation and management, including traffic totals, quota and expiry enforcement
- Connection profile management for WS, gRPC, HTTPUpgrade, and XHTTP settings
- Individual VLESS link export when certificate and private-key paths are present
- Per-user base64 Subscription URL with one-time random token creation and revocation by rotation
- Host capability report that leaves network reachability as unknown until verified externally
- Xray configuration test and process control, using an installed binary supplied by the operator
- Local Xray statistics API and automatic collection of per-user uplink/downlink counters
- Backend tests and GitHub Actions checks

Xray per-user traffic counters are collected while the engine is running. Usage totals persist locally; quota and expiry checks run on the monitoring cycle and may take about 15 seconds to take effect. Certificate files being present does not prove the certificate is valid or trusted.

## Tech stack

- Python 3.11+, FastAPI, SQLite
- React, TypeScript, Vite, Lucide
- pytest
- GNU AGPL-3.0-or-later

## Windows quick start

Install Python 3.11+ and Node.js 20+.

1. Double-click `run-backend-windows.bat`. Keep its window open.
2. Double-click `run-frontend-windows.bat`. Keep its window open.
3. Open the local URL printed by Vite, usually `http://127.0.0.1:5173`.
4. On first launch, choose a strong admin password of at least 14 characters. No username is needed.

PowerShell users can also follow [the detailed Persian setup guide](docs/SETUP_FA.md). The launcher uses `npm.cmd` so it does not require changing PowerShell's script execution policy.

## Manual setup

### Backend

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`; interactive API docs are at `http://127.0.0.1:8000/docs`. For a public deployment, set `NOVAPANEL_PUBLIC_BASE_URL` to the public HTTPS origin so subscription URLs point to the right address.

### Frontend

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

## Run the built dashboard and API on a Linux host

### Automatic app-host mode

Upload the ZIP/repository and start it with `sh run-host.sh` on a Linux app host. Set `NOVAPANEL_DEPLOYMENT_MODE=paas_ws`, or leave `auto` on a host that provides `PORT`/`SERVER_PORT`. NovaPanel builds the dashboard, downloads a pinned official Xray release with SHA-256 verification if needed, infers the public hostname, creates a managed WebSocket endpoint, and generates subscription URLs. The hosting edge must forward WebSocket upgrades, allow the Xray child process, and permit outbound downloads during first boot. Mount persistent storage at `NOVAPANEL_DATA_DIR` and set a stable `NOVAPANEL_SECRET_KEY`.

### Direct server mode

Set `NOVAPANEL_DEPLOYMENT_MODE=direct` on a VPS/dedicated machine where public inbound sockets are allowed. Add a connection once in the admin panel with the real host, port, TLS certificate, and private key. Afterwards NovaPanel produces each user's VLESS/subscription links automatically—no per-client server setup is needed.

These modes are intentionally different. Public HTTPS at the panel domain is not proof that a provider forwards WebSocket upgrades or permits proxy workloads. The platform mode is marked as configured, not as externally verified; test a generated subscription with a real client before handing it out. If the provider blocks WebSocket upgrades, child processes, or proxy workloads, use a compatible host or direct mode.

## Xray integration

NovaPanel does not download or update Xray automatically. Install a release from a trusted official source, verify it, then set `NOVAPANEL_XRAY_BINARY` to its full path if it is not on PATH. Configure a connection with a valid TLS certificate and matching private key before testing the generated Xray configuration.

A saved connection is not a working connection by itself. DNS, firewall rules, the host provider's network policy, TLS validity, the client configuration, and the actual network path still need to be checked. The single-port web hosting launcher serves the management UI only; it does not multiplex client proxy traffic through the web port.

## Configuration and security

See [SECURITY.md](SECURITY.md) before any deployment. For remote use, set a stable, high-entropy `NOVAPANEL_SECRET_KEY`, enable `NOVAPANEL_COOKIE_SECURE=1` behind HTTPS, protect the admin interface with network access controls, and use persistent storage. Never commit secrets, private keys, or client links.

The development server must not be exposed to the public internet. Host policies differ; only deploy proxy features on infrastructure that explicitly permits them.

## Project structure

- `app/` — FastAPI API and local engine management
- `frontend/` — web dashboard
- `tests/` — backend tests
- `docs/` — roadmap and Persian setup guide
- `SECURITY.md` — deployment safety notes

## Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md). Retain attribution and license notices. Forks should clearly distinguish their modified projects and must not present themselves as the official NovaPanel release.

## Copyright and license

Copyright (C) 2026 Blackthor86.

Licensed under GNU Affero General Public License v3.0 or any later version. See [LICENSE](LICENSE). The software license does not grant trademark rights to the NovaPanel name or branding.
