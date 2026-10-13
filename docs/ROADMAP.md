# NovaPanel roadmap

## Phase 1 — Foundation

- [x] Repository overview and license notice
- [x] FastAPI health endpoint
- [x] Initial host capability report
- [x] Backend API tests
- [ ] Dashboard UI and API connection
- [ ] Local setup guide verified on Windows and Linux

## Phase 2 — Configuration model

- Define validated configuration models
- Add export and import tests using harmless sample data
- Keep secrets out of logs and browser storage
- Document which engine and client versions are supported

## Phase 3 — Engine integration

- Integrate a pinned, verified Xray release
- Validate generated configurations before use
- Add safe start, stop, and status operations
- Never treat an unverified TLS certificate as secure

## Phase 4 — Host compatibility

- Document provider-specific limits
- Test persistent storage and process supervision
- Verify TCP/UDP reachability instead of inferring it
- Enable only features that the environment supports and the provider permits

## Phase 5 — Security and release

- Authentication and session protections
- Dependency and secret scanning
- Automated tests and reproducible release notes
- Independent security review before production use

NovaPanel is not production-ready in this phase. No proxy engine is installed or started by this code.
