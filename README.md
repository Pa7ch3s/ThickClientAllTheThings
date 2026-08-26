# Thick Client Security

A field guide and testing methodology for desktop apps: Electron, Tauri, CEF/WebView2, native
C/C++, .NET, and Java. Everyone points their tooling at web and mobile. Meanwhile the desktop app
sitting on someone's machine, with local admin, a signing cert, an auto-updater, and an entire
browser engine bolted inside it, gets a shrug. That's the gap. This is the map for it.

It's methodology, not a weapon. Authorized testing only.

## Why this exists

Thick clients break differently than web apps, and pretending otherwise is how testers miss things.
The trust boundary isn't the network edge, it's the line between the process and the machine it runs
on. Secrets sit on disk. An IPC channel that assumes a friendly caller isn't one. An update mechanism
that pulls from the network is a supply line with your name on it. And an embedded web layer can turn
a boring rendering bug into code execution on the host.

I built this around those realities instead of stapling a web checklist onto a binary and calling it a day.

## Directory

| Area | What it covers |
|------|----------------|
| [`CHECKLIST.md`](CHECKLIST.md) | The full test-case checklist, by category |
| `recon/` | Framework fingerprinting, unpacking, resource extraction |
| `storage/` | Secrets at rest: config, registry, keychain, tokens |
| `ipc/` | Electron IPC, named pipes, COM, local sockets, DBus |
| `weblayer/` | Electron/CEF/WebView2 isolation, and sink-to-RCE |
| `updates/` | Update-channel integrity and rollback |
| `binary/` | Signing, integrity, anti-tamper, DLL search-order hijack |
| `runtime/` | Memory secrets, hooking, instrumentation |
| `reporting/` | Evidence standards and a finding template |

> Folders past `CHECKLIST.md` fill in over time. The checklist is the canonical index; start there.

## How to use it

1. Start at recon. Fingerprint the framework and unpack the app. Everything downstream depends on knowing what you're actually looking at.
2. Walk the checklist top to bottom per category. Each item is a question with a concrete way to answer it.
3. Write evidence as you go, using the finding template in `reporting/`. A finding is a reproducible path from a starting condition to an impact, not a scanner line you pasted in.
4. If a control can't be tested safely, say so. "Untested assumption" is an honest answer. A quiet "pass" it didn't earn is not.

## Scope and ethics

This is for testing software you're authorized to test. Written agreement, defined scope, explicit
rules of engagement. Nothing here is a packaged exploit; it's how you find the weak spots and close them.

## Contributing

Additions welcome if they're concrete and reproducible: a test case with a clear starting condition,
a way to verify it, and the impact if it holds. Vague is the enemy. Open an issue or a PR.

## Author

Maintained by [pa7ch3s](https://github.com/Pa7ch3s), offensive security engineer and founder of
[Wickmark Group](https://wickmarkgroup.org). A decade of breaking things on purpose, including a fair
amount of thick-client work that needed a methodology like this and didn't have one.
