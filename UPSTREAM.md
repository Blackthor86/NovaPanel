# Upstream provenance and scope

NovaPanel's current runtime baseline is derived from:

- Repository: [Blue-Knight-Panel-V3](https://github.com/BlueKnightNet/Blue-Knight-Panel-V3)
- Upstream branch: **blue-knight-net**
- Source commit: **2e6ee067e8c3c047ae1161959c46cf739dbbca74**

The upstream project is MIT-licensed. Its original copyright notice is preserved in [LICENSE](LICENSE).

## NovaPanel-specific changes

- Rebranded the dashboard and password/login page as NovaPanel.
- Applied a navy-and-jade palette, generated monogram, and asset-independent hero artwork.
- Removed upstream sponsor/social placements from the panel UI and console branding.
- Replaced upstream project copy with NovaPanel documentation and metadata.
- Added automated checks for syntax, baseline behavior, and embedded UI branding.

## Deliberately preserved

The transport engines, configuration generation and export pathways, primary single-port multiplexer, request/upgrade routing, authentication flow, and runtime state handling remain based on the V3 source. Internal compatibility paths such as /knight-assets and the upstream mux identifiers are deliberately retained to avoid changing transport behavior as part of a visual rebrand.
