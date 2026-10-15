# Contributing

Thanks for helping improve NovaPanel.

## Scope

The current project starts from the MIT-licensed Blue-Knight-Panel-V3 runtime. Keep the existing protocol/multiplexer architecture intact unless a change is explicitly intended to alter runtime behavior and includes protocol-level tests. The NovaPanel presentation layer uses a navy-and-jade visual system.

## Before opening a change

Run:

- **npm install**
- **npm run check**
- **npm test**

Describe whether a change affects only presentation/documentation or changes generated links, transport routing, persistence, or authentication. Do not include real subscription URLs, UUIDs, credentials, or deployment secrets in issues or pull requests.
