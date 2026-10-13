# Security policy

NovaPanel is under active development. Do not expose the current build directly to the public internet or use it to protect important traffic until deployment hardening and independent testing are complete.

## Before deploying

- Use HTTPS and set `NOVAPANEL_COOKIE_SECURE=1`.
- Set a long, random, persistent `NOVAPANEL_SECRET_KEY`; never commit the real value.
- Keep the management interface behind a firewall or another access control layer.
- Use a persistent, access-controlled data directory and protect backups.
- Direct mode expects Xray to be installed and verified by the operator. Automatic Linux app-host mode downloads a pinned official Xray v26.3.27 release and checks its archive SHA-256 before use; review the version pin and digest before upgrading it.
- Use a valid TLS certificate and private key. Never disable certificate verification in clients to make a setup appear to work.
- Confirm the host provider explicitly permits the intended proxy service and required networking.
- Test restore procedures, authentication, logs, network access, and resource limits.

## Known limitations

- Traffic totals are polled from Xray every 15 seconds while it is running. Quota/expiry enforcement can lag by one polling interval; the final few seconds of traffic can be lost if the engine or host exits before the next successful poll.
- Network reachability is not inferred from the presence of a port or runtime. The PaaS WebSocket relay requires an app host that supports WebSocket upgrades and allows the Xray child process; its generated profile is not proof that traffic can connect.
- Engine process management and the traffic monitor are local to the API process and have not yet been hardened for multi-worker or production service supervision.
- The default session secret is temporary for local development; remote deployments must set a stable secret.

## Reporting a vulnerability

Please contact the repository owner privately with a concise report and reproduction steps. Do not publish access tokens, subscription links, private keys, or other secrets in issues.
