<figure class="en-hero" markdown="0">
  <picture>
    <source media="(prefers-reduced-motion: reduce)" srcset="assets/logo.png">
    <source srcset="assets/en-hero.webp" type="image/webp">
    <img src="assets/en-hero.apng" alt="Exploit Nation">
  </picture>
</figure>

# ThickClientGalore

**This is simply my research and the repo I've always wanted.
Notes from everything I could find (WITH my own notes included); made pretty just for you.**

This maps: how to test Electron, Tauri, CEF/WebView2, .NET, Java, and native desktop apps, organized the way an attacker would move through one.

### `For Educational purposes only.`

## Contents

Start at recon (know what you're looking at), then walk the surface. Each book is a deep guide;
[`CHECKLIST.md`](CHECKLIST.md) is the fast index if you just want the questions.

1. [Reconnaissance & Unpacking](recon-and-unpacking.md) — fingerprint the framework, unpack the app, read what shipped
2. [Secrets & Data at Rest](secrets-at-rest.md) — hardcoded keys, token storage, secure-storage misuse, logs
3. [Inter-Process Communication](ipc.md) — Electron IPC, named pipes, COM, DBus, local sockets
4. [Embedded Web Layer](embedded-web-layer.md) — Electron/CEF/WebView2 isolation, and the XSS-to-RCE path
5. [Update Mechanism](update-mechanism.md) — update-channel integrity, signatures, downgrade
6. [Binary Protections & Tampering](binary-and-tampering.md) — signing, DLL search-order hijack, anti-tamper
7. [Network & API](network-and-api.md) — TLS pinning, cert validation, client-side trust, local servers
8. [Runtime, Memory & Instrumentation](runtime-and-memory.md) — Frida, hooking, memory secrets
9. [Auth, Licensing & Authorization](auth-licensing-authz.md) — client-side gates, license bypass, multi-user
10. [Deep Links & Protocol Handlers](deep-links-and-protocol-handlers.md) — custom URI schemes, argument injection

## Framework coverage

The techniques are framework-tagged throughout. Quick orientation for where each one bites hardest:

| Framework | Unpack with | Watches hardest |
|-----------|-------------|-----------------|
| Electron | `asar extract`, DevTools | web layer, IPC, nodeIntegration |
| Tauri | binary + bundled assets | IPC allowlist, the Rust/JS boundary |
| CEF / WebView2 | resource/pak extraction | remote content, message channels |
| .NET (WPF/WinForms) | ILSpy, dnSpy | decompilable IL, config, DPAPI |
| Java (Swing/JavaFX) | CFR, procyon, jd-gui | decompilable bytecode, JAR secrets |
| Native (C/C++, Qt, Delphi) | Ghidra, IDA, strings | memory, DLL hijack, anti-tamper |

## How to use it

1. Fingerprint and unpack first. Everything downstream depends on knowing what you're looking at.
2. Walk each book's techniques against your target. Every entry is a question with a concrete way to answer it.
3. Record evidence as you go. A finding is a reproducible path from a starting condition to an impact, not a scanner line you pasted in.
4. If a control can't be tested safely, say so. "Untested assumption" is honest. A quiet "pass" it didn't earn is not.

## Scope and ethics

Everything here is for testing software you are authorized to test. Written agreement, defined scope,
explicit rules of engagement. Nothing in this repository is a packaged exploit; it is how you find
the weak spots and close them.

## Author

Built and maintained by [pa7ch3s](https://github.com/Pa7ch3s).
