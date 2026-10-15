# NovaPanel

**A single-port, multi-protocol gateway with a navy-and-jade control panel.**

NovaPanel packages a self-hosted panel and runtime into a single Node.js entry file. The baseline preserves the V3 transport and routing architecture while replacing the inherited interface branding with NovaPanel's own visual identity.

## Highlights

- One assigned public port for the primary multiplexed transports.
- Web control panel, generated subscriptions, and client-format exports.
- VLESS, VMess, Trojan, and additional optional profiles.
- Generated configurations for supported clients, including Clash Meta, sing-box, and Xray-based clients.
- Password-protected panel with persisted state, UUID/token configuration, and TLS material.
- Responsive navy-and-jade UI without upstream sponsor placements.

## Requirements

- Node.js 18 or newer (Node.js 20 LTS is recommended).
- Outbound HTTPS access when the runtime needs to download sing-box or Xray-core.
- A writable, persistent data directory for state and certificate material.
- A deployment platform that provides a reachable TCP port.

## Quick start

1. Deploy or clone this repository to your Node.js host.
2. Install dependencies with **npm install**.
3. Start the service with **npm start**.
4. Open **http://<host>:<port>/knight** and follow first-run password setup.
5. Generate a subscription in the panel and import it into a compatible client.

The server honors PORT, then SERVER_PORT, then SB_PORT, with 8080 as a local fallback. Most managed hosts inject PORT automatically.

### Local run

**npm install**

**PORT=8080 npm start**

Then visit **http://127.0.0.1:8080/knight**.

## Runtime and data

The default dashboard HTML, CSS, and browser JavaScript are embedded in index.js; the default UI does not require a separate assets/ directory. Custom image assets remain optional through the existing asset handlers.

The runtime chooses the first writable data directory from the configured path, a Railway volume path, /data, and local bk-data fallbacks.

| Variable | Purpose |
|---|---|
| BK_DATA_DIR or FILE_PATH | Preferred writable state directory |
| RAILWAY_VOLUME_MOUNT_PATH | Persistent Railway volume mount |
| PANEL_PATH or SUB_PATH | Change the default /knight panel path |
| PANEL_PASSWORD | Configure the initial panel password (minimum 8 characters) |
| SETUP_KEY | Optional key for first-time password setup |
| RESET_PANEL_PASSWORD=true | Reset panel authentication on startup |
| UUID or SB_UUID | Set the UUID for generated configurations |
| SUB_TOKEN | Set the private subscription token |
| DOMAIN or SB_DOMAIN | Host/domain used in generated links |
| FORCE_HOST or CFIP | Override the host used when generating links |
| PUBLIC_BASE_URL or SUB_BASE_URL | Override the public base URL |
| NODE_PREFIX | Display-name prefix for generated client entries |
| PANEL_TOKEN | Optional panel/API token setting |
| FORCE_HTTPS=true | Force HTTPS URLs in generated links where supported |

**Persist the data directory.** It can hold panel authentication state, UUID/subscription settings, and TLS certificate/key material. Losing it may invalidate existing client imports. Keep subscription URLs and tokens private.

## Protocol options

Default profiles include VLESS WS/TLS, VMess WS/TLS, HTTPUpgrade, VLESS gRPC/TLS, Trojan WS/TLS and gRPC-TLS, VLESS Reality, Shadowsocks, and WireGuard. Optional profiles can be toggled with environment variables; transports that require separate protocol ports still use those ports.

| Variable | What it controls |
|---|---|
| ENABLE_VLESS_WS, ENABLE_VLESS_WS_TLS | VLESS WebSocket profiles |
| ENABLE_VMESS_WS, ENABLE_VMESS_WS_TLS | VMess WebSocket profiles |
| ENABLE_HTTPUPGRADE, ENABLE_VMESS_HTTPUPGRADE, ENABLE_TROJAN_HTTPUPGRADE | HTTPUpgrade profiles |
| ENABLE_VLESS_GRPC, ENABLE_VLESS_GRPC_TLS, ENABLE_TROJAN_GRPC_TLS | gRPC profiles |
| ENABLE_TROJAN_WS, ENABLE_TROJAN_WS_TLS | Trojan WebSocket profiles |
| ENABLE_REALITY | VLESS Reality |
| ENABLE_XHTTP | VLESS-XHTTP (Xray-based clients; edge hosts may enable it unless disabled) |
| ENABLE_SS, ENABLE_SS_WS | Shadowsocks and Shadowsocks-WebSocket profiles |
| ENABLE_WIREGUARD or ENABLE_WG | WireGuard |
| ENABLE_HYSTERIA2, ENABLE_TUIC | Optional UDP-based profiles |
| ENABLE_SHADOWTLS_VLESS | Optional ShadowTLS VLESS profile |
| ENABLE_SOCKS, ENABLE_HTTP_PROXY | Optional SOCKS and HTTP listeners |
| ENABLE_ARGO | Optional Argo mode |

Boolean switches accept true or 1 to enable and false or 0 to disable. Deployment environment variables can override the runtime defaults.

## TLS and client compatibility

Some TLS profiles use generated/self-signed certificate material and client links may include compatibility parameters or a certificate pin. Re-import a freshly generated subscription after certificate changes. Client handling of TLS validation and pinning differs by app/core, so verify the chosen client profile.

## Troubleshooting

- **Panel does not open:** verify the host-assigned port and the configured PANEL_PATH (default /knight).
- **Runtime components fail to download:** check outbound HTTPS access and host logs.
- **A profile is missing:** check its ENABLE_* variable and runtime logs; optional profiles may need Xray or sing-box.
- **Existing configs stop working after redeploy:** confirm the data directory persists and has not been reset.
- **TLS profile stopped working:** regenerate/re-import the subscription so the client has current certificate information.
- **Connection test looks inaccurate:** use a client-side real-delay/URL test rather than treating TCP reachability as end-to-end performance.

## Development and checks

**npm install**

**npm run check**

**npm test**

These checks cover syntax, primary defaults, port precedence, and embedded UI branding. They do not simulate a real remote tunnel or benchmark throughput on a particular host.

## License

NovaPanel is distributed under the MIT License. The upstream V3 copyright and permission notice is retained in [LICENSE](LICENSE); source provenance is documented in [UPSTREAM.md](UPSTREAM.md).

## Acknowledgements

NovaPanel's current runtime baseline is derived from [Blue-Knight-Panel-V3](https://github.com/BlueKnightNet/Blue-Knight-Panel-V3). Thank you to **Blue Knight Net** for publishing the upstream project under the MIT License. NovaPanel reworks the visual identity, UI palette, documentation, and packaging metadata while intentionally retaining the upstream transport/routing architecture as its baseline.
