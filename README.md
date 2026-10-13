# NovaPanel

NovaPanel is an open-source control panel project for managing proxy-engine deployments with a clean interface and a focus on security, observability, and host compatibility.

**Status:** early development. The current version is a UI and API foundation only. It does not configure or run Xray yet.

## Goals

- A focused dashboard that works well on desktop and mobile
- Python backend with a documented API
- Host capability reporting instead of assuming every hosting environment works the same way
- Safe configuration validation before any engine integration
- Tests and clear setup instructions
- A codebase that is easy for contributors to understand

## Tech stack

- Backend: Python, FastAPI
- Frontend: React, TypeScript, Vite
- Tests: pytest
- License: GNU AGPL v3.0 or any later version

## Run locally

### Backend

Python 3.11 or newer is recommended.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API will be available at `http://127.0.0.1:8000`, with interactive docs at `http://127.0.0.1:8000/docs`.

### Frontend

Use Node.js 20 or newer.

```bash
cd frontend
npm install
npm run dev
```

Vite prints the local URL when the development server starts. The frontend expects the API at `http://127.0.0.1:8000` while developing locally.

## Project layout

- `app/` — FastAPI application and host capability checks
- `frontend/` — React UI
- `tests/` — backend tests
- `docs/` — project notes

## Security

This project is under active development and is not production-ready. Do not expose the development server to the public internet or put real credentials, subscription URLs, private keys, or tokens in issues or logs.

Please report security issues privately to the repository owner rather than posting exploit details in public issues.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Copyright and license

Copyright (C) 2026 Blackthor86.

This project is licensed under the GNU Affero General Public License, version 3 or (at your option) any later version. See [LICENSE](LICENSE).

The NovaPanel name and branding are not granted as a trademark by this software license. Forks should clearly identify themselves as modified projects and must not imply that they are the official NovaPanel release.
