# NovaPanel

NovaPanel is a self-hosted management panel for proxy-engine deployments, built around a Python API and a responsive web interface.

**Project status:** active development. The current build includes the dashboard, one-time admin setup, session login, local SQLite storage, user and connection profile management, host capability reporting, and optional Xray process controls when an operator installs and verifies the engine. It has not yet had an independent security review and should not be exposed directly to the public internet.

## What is included

- Persian RTL dashboard with a jade and navy theme, responsive layout, and motion effects
- First-run admin account creation and session-based login
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
4. On first launch, create an admin account with a username and a strong password of at least 14 characters.

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

If the provider has both Python and Node.js available, run `sh run-host.sh`. It installs the app dependencies, builds the React UI, then serves the dashboard and API from the same origin using the provider's `PORT` value (or port 8000 locally). Configure a stable `NOVAPANEL_SECRET_KEY`, `NOVAPANEL_COOKIE_SECURE=1` behind HTTPS, and `NOVAPANEL_PUBLIC_BASE_URL=https://your-public-panel.example` in the provider's environment settings. Keep a persistent volume mounted at `NOVAPANEL_DATA_DIR`.

This combines the web dashboard and API only. It does **not** make a provider's HTTP-only app port suitable for a separate raw Xray inbound. Xray still requires an installed/verified binary and a network path the provider explicitly permits. A hosting platform that only exposes a web-proxied port needs a separately designed, provider-permitted adapter; this build does not bypass host networking restrictions.

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
