# Security policy

NovaPanel is under active development. Do not expose the current build directly to the public internet or use it to protect important traffic until deployment hardening and independent testing are complete.

## Before deploying

- Use HTTPS and set `NOVAPANEL_COOKIE_SECURE=1`.
- Set a long, random, persistent `NOVAPANEL_SECRET_KEY`; never commit the real value.
- Keep the management interface behind a firewall or another access control layer.
- Use a persistent, access-controlled data directory and protect backups.
- Install Xray only from a trusted official source and verify the release before use.
- Use a valid TLS certificate and private key. Never disable certificate verification in clients to make a setup appear to work.
- Confirm the host provider explicitly permits the intended proxy service and required networking.
- Test restore procedures, authentication, logs, network access, and resource limits.

## Known limitations

- Traffic quotas and expiry metadata can be stored, but automatic traffic accounting and enforcement are not implemented yet.
- Network reachability is not inferred from the presence of a port or runtime.
- Engine process management is local to the API process and has not yet been hardened for multi-worker or production service supervision.
- The default session secret is temporary for local development; remote deployments must set a stable secret.

## Reporting a vulnerability

Please contact the repository owner privately with a concise report and reproduction steps. Do not publish access tokens, subscription links, private keys, or other secrets in issues.
