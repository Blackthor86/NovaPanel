# Security policy

NovaPanel is an early-stage, single-port Node.js panel. Do not use it for important traffic until you have tested the actual proxy client and host-specific networking.

## Before deployment

- Use a persistent, private data directory. It contains the UUID, subscription token, password hash, session secret, TLS certificate and private key, transport paths, and Reality keys.
- Keep the subscription URL private. Anyone holding the token can download the current subscription and its configuration exports.
- Choose a strong admin password. Configure \`SETUP_KEY\` when first-time setup is reachable by untrusted visitors.
- Confirm that the assigned public TCP port genuinely reaches this application. A generated link does not prove the port, HTTP/2, TLS, WebSocket Upgrade, or raw TCP routing is available.
- Automatic Xray installation downloads an official Linux release and attempts to verify its published SHA-256 digest when available. Review the upstream release; alternatively supply a separately verified executable via \`NOVAPANEL_XRAY_BINARY\`.
- Direct-mode TLS uses a self-signed certificate. Links include a certificate pin and compatibility option. Check whether the client honors these parameters; do not disable TLS verification broadly as a workaround.
- Do not log or share session cookies, subscription URLs, UUIDs, passwords or private keys.
- Confirm that the hosting provider allows child processes, binary downloads and the network connections needed by the engine.

## Known limitations

- This is an independent implementation of a compact one-port design, not an audited security product. The native Xray engine remains a separate executable managed by Node.js.
- Transport compatibility varies by client version. Import the generated subscription into the actual target client and test traffic for each profile you intend to use.
- The direct-mode TLS certificate is self-signed. The certificate pin must be refreshed if the certificate changes. Edge mode relies on the provider’s public HTTPS endpoint and WebSocket Upgrade support; raw-TCP transports are not available in edge mode.
- Traffic accounting, multiple separately managed users, quotas, and usage expiry are not implemented in this compact runtime.
- Actual reachability depends on host routing and policy. CI verifies an end-to-end VLESS TLS/WebSocket path locally, but that does not guarantee every protocol or every provider works.
- Restrict administrative access and keep a recovery copy of the persistent data directory.

## Reporting a vulnerability

Please contact the repository owner privately with concise reproduction steps. Do not publish session cookies, subscription URLs, private keys, or other secrets in issues.
