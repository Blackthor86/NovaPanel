# Security policy

NovaPanel is under active development. Do not expose a build directly to the public internet or use it to protect important traffic until deployment hardening and independent testing are complete.

## Before deploying

- Use HTTPS and set `NOVAPANEL_COOKIE_SECURE=1`.
- Set a long, random, persistent `NOVAPANEL_SECRET_KEY`; never commit the real value.
- Keep the management interface behind another access-control layer where possible.
- Use a persistent, access-controlled data directory and protect backups.
- Direct mode expects Xray to be installed and verified by the operator. Automatic Linux app-host mode downloads a pinned official Xray-core v26.3.27 release and checks the archive SHA-256 before use; review the version pin and digest before upgrading it.
- Use a valid TLS certificate and private key in direct mode. Never disable certificate verification in clients to make a setup appear to work.
- Confirm that the host provider explicitly permits the intended proxy service and required networking.
- Test restore procedures, authentication, logs, network access, and resource limits.

## Known limitations

- Traffic totals are polled from Xray approximately every 15 seconds while it is running. Quota/expiry enforcement can lag by one polling interval; the final few seconds of traffic can be lost if the engine or host exits before the next successful poll.
- Network reachability is not inferred from the presence of a port or runtime. The app-host WebSocket relay requires a host that supports WebSocket upgrades and allows the Xray child process; its generated profile is not proof of external connectivity.
- Engine process management and the traffic monitor are local to the API process and are not intended for multi-worker deployment without further supervision.
- The default session secret is temporary for local development. Remote deployments must set a stable secret.
- The first Node.js deployment builds the web dashboard from source. The host must be able to install the declared npm dependencies during startup.

## Reporting a vulnerability

Please contact the repository owner privately with a concise report and reproduction steps. Do not publish access tokens, subscription links, private keys, or other secrets in issues.
