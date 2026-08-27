# ThickClientAllTheThings

**The desktop-app security testing reference nobody wrote down, so I did.**

### 📖 Read it as a site: **https://pa7ch3s.github.io/exploitnation/**

Searchable, navigable, dark-mode. The repo is the source; the site is how you actually use it.

---

Everyone points their tooling at web and mobile. Meanwhile the thick client sitting on someone's
machine, with local admin, a signing cert, an auto-updater, an IPC bus, and an entire browser engine
bolted inside it, gets a shrug. That's the gap. This is the map for it: how to test Electron, Tauri,
CEF/WebView2, .NET, Java, and native desktop apps, organized the way an attacker moves through one.

Methodology, not a weapon. Authorized testing only.

## Contents

1. [Reconnaissance & Unpacking](docs/recon-and-unpacking.md)
2. [Secrets & Data at Rest](docs/secrets-at-rest.md)
3. [Inter-Process Communication](docs/ipc.md)
4. [Embedded Web Layer](docs/embedded-web-layer.md)
5. [Update Mechanism](docs/update-mechanism.md)
6. [Binary Protections & Tampering](docs/binary-and-tampering.md)
7. [Network & API](docs/network-and-api.md)
8. [Runtime, Memory & Instrumentation](docs/runtime-and-memory.md)
9. [Auth, Licensing & Authorization](docs/auth-licensing-authz.md)
10. [Deep Links & Protocol Handlers](docs/deep-links-and-protocol-handlers.md)

Fast index: [CHECKLIST.md](docs/CHECKLIST.md).

## Author

Built and maintained by [pa7ch3s](https://github.com/Pa7ch3s), offensive security engineer. Welcome home.
