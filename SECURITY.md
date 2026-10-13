# Security policy

NovaPanel is a compact early baseline under active development. Do not expose it to the public internet or rely on it for important traffic until you have tested the installed Xray version, subscription behavior and host-specific networking.

## Before deploying

- Use a persistent, access-controlled data directory. It contains the UUID, subscription token, password hash, HMAC session secret, TLS certificate and private key.
- Keep the subscription URL private. Anyone holding its token can download the current Base64 subscription.
- Choose a strong admin password and configure SETUP_KEY when the first-visit login page is reachable by untrusted users.
- Use the public host and public port that are genuinely routed to this application. Generated links do not prove that inbound TCP/TLS or WebSocket upgrades work.
- Automatic Xray installation downloads an official release for Linux x64/arm64 and attempts to validate the published SHA-256 digest when available. Review the upstream release and digest before production use; use NOVAPANEL_XRAY_BINARY to supply a separately verified executable.
- The direct-mode TLS certificate is self-signed. Subscription links include a SHA-256 pin for clients that support the Xray pcs/pinnedPeerCertSha256 convention. Confirm the client recognizes it; do not broadly disable certificate verification as a workaround.
- Do not log or share session cookies, password values, subscription URLs, UUIDs or private keys.
- Confirm the hosting provider permits the workload and allows a child Xray process, downloadable binaries and the necessary network connections.

## Known limitations in this compact baseline

- It intentionally focuses on VLESS/VMess/Trojan over WebSocket and a single shared TCP listener.
- Traffic quotas, user CRUD, Clash/sing-box output, Reality, gRPC, XHTTP and per-user traffic accounting are not implemented in this baseline.
- The TLS certificate is self-signed and generated for the current hostname; only the client certificate pin is intended to establish trust. Recreate or rotate the pin when the certificate changes.
- Actual reachability still depends on the hosting provider's routing and network policy. Run the live tunnel test and confirm /api/health reports engine_status: "running" before testing an app client.
- This code has not undergone an independent security review. Restrict administrative access and preserve a recovery copy of the persistent data directory.

## Reporting a vulnerability

Please contact the repository owner privately with a concise report and reproduction steps. Do not publish session cookies, subscription URLs, private keys, or other secrets in issues.
