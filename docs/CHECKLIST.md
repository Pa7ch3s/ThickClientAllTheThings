# Thick Client Security Checklist

Test cases for desktop application assessments, grouped by category. Each item is a question, a way
to answer it, and the impact if it holds. Authorized testing only.

Legend: **Q** question · **How** how to check · **Impact** what it means if it fails.

---

## 1. Reconnaissance and unpacking

- **Q** What framework is this? **How** Inspect the install directory for `resources/app.asar` (Electron), a WebView2 runtime dependency, `.pak`/CEF artifacts, a bundled JRE (Java), or a .NET runtime and managed assemblies. **Impact** Framework dictates the entire attack surface below.
- **Q** Can the application bundle be unpacked? **How** `npx asar extract app.asar out/` for Electron; decompile .NET with ILSpy/dnSpy; decompile Java with CFR/procyon; pull strings and resources from native binaries. **Impact** Source-level review of a shipped client exposes secrets and logic.
- **Q** Is source or config shipped unobfuscated? **How** Read the unpacked JS/IL/bytecode. **Impact** Business logic, endpoints, and keys become readable.
- **Q** What does the app talk to? **How** Enumerate endpoints, hosts, and local ports referenced in the bundle. **Impact** Maps the backend and any local services the client stands up.

## 2. Secrets and data at rest

- **Q** Are credentials, API keys, or tokens hardcoded in the bundle? **How** Grep the unpacked source and strings for `key`, `secret`, `token`, `password`, base64 blobs, JWTs. **Impact** Extractable shared secrets, often the same across every install.
- **Q** Where are user tokens/sessions stored, and how? **How** Check config directories (`%APPDATA%`, `~/Library/Application Support`, `~/.config`), local SQLite/leveldb, and whether values are encrypted or plaintext. **Impact** Local token theft, session replay.
- **Q** Is OS-provided secure storage used correctly? **How** Verify use of DPAPI (Windows), Keychain (macOS), or libsecret, and whether entries are scoped to the user. **Impact** Secrets readable by other users or processes when secure storage is skipped.
- **Q** Does the app write sensitive data to logs or crash dumps? **How** Trigger flows and inspect log files, telemetry payloads, and crash reports. **Impact** Sensitive data leakage through diagnostics.
- **Q** Are file and registry permissions on stored data least-privilege? **How** Check ACLs on config files, install dir, and registry keys. **Impact** World-readable/writable secrets or tamperable config.

## 3. Inter-process communication (IPC)

- **Q** (Electron) Does the renderer reach privileged main-process functionality? **How** Review `ipcMain.handle`/`on` handlers and the preload bridge; look for handlers that execute arbitrary paths, shell commands, or filesystem ops on renderer-controlled input. **Impact** A renderer-side bug (or malicious content) reaches host code execution.
- **Q** Are named pipes / local sockets authenticated? **How** Enumerate pipes (`\\.\pipe\`), local TCP/Unix sockets the app opens; test connecting as another process/user and sending crafted messages. **Impact** Any local process can drive privileged actions.
- **Q** Are COM/DBus interfaces exposed with weak access control? **How** Enumerate registered interfaces and test invocation from a low-privilege context. **Impact** Local privilege escalation or unauthorized control.
- **Q** Is IPC input validated and typed? **How** Fuzz message shapes and arguments across each channel. **Impact** Injection, path traversal, or logic bypass across the process boundary.

## 4. Embedded web layer (Electron / CEF / WebView2)

- **Q** Is `nodeIntegration` disabled and `contextIsolation` enabled? **How** Inspect `webPreferences` for every `BrowserWindow`/`webview`. **Impact** With nodeIntegration on, any XSS is host code execution.
- **Q** Does the app render remote or untrusted content in a privileged context? **How** Identify windows that load remote URLs or user-supplied HTML. **Impact** Remote content inherits app privilege; XSS becomes RCE.
- **Q** Is `sandbox` enabled and the preload surface minimal? **How** Review preload scripts for over-broad APIs exposed via `contextBridge`. **Impact** A wide bridge re-opens the boundary contextIsolation was meant to close.
- **Q** Are `will-navigate`, `new-window`, and `setWindowOpenHandler` locked down? **How** Test navigation to arbitrary URLs and `window.open`. **Impact** Navigation to attacker content inside a trusted frame.
- **Q** Is there a Content-Security-Policy on rendered content? **How** Check response/meta CSP. **Impact** Missing CSP widens XSS-to-RCE paths.

## 5. Update mechanism

- **Q** Are updates fetched and verified over a trusted channel? **How** Proxy the update check; test HTTP downgrade, and whether the client validates TLS and a signature on the update payload. **Impact** MITM delivers a malicious update, full host compromise.
- **Q** Is the update signature checked before execution? **How** Serve a tampered/unsigned package and observe whether it installs. **Impact** Unsigned code execution as the updater's privilege.
- **Q** Can the update be rolled back to a vulnerable version? **How** Offer an older signed build; check version-pinning. **Impact** Downgrade to a known-vulnerable client.

## 6. Binary protections and tampering

- **Q** Is the application code-signed, and is the signature enforced at runtime? **How** Verify signatures (`signtool`, `codesign`); test running a modified binary. **Impact** Tampered clients run unnoticed.
- **Q** Is the app vulnerable to DLL search-order hijacking or sideloading? **How** Enumerate imported libraries; drop a proxy DLL in a writable search path. **Impact** Code execution in the app's context, common persistence and privilege vector.
- **Q** Are anti-tamper / integrity checks present where they matter? **How** Patch a check and observe behavior. **Impact** Integrity assumptions that do not hold.
- **Q** Does the installer or app write to world-writable locations then execute from them? **How** Inspect install and runtime paths and ACLs. **Impact** Local privilege escalation.

## 7. Network and API

- **Q** Is transport encrypted and certificate validation enforced? **How** Proxy traffic (Burp/mitmproxy); test cert pinning and whether validation can be disabled. **Impact** Interception and manipulation of client-server traffic.
- **Q** Does the client trust the server too much (client-side-only checks)? **How** Modify responses and observe whether client-enforced restrictions can be bypassed. **Impact** Logic and authorization bypass.
- **Q** Does the app stand up a local HTTP/websocket server? **How** Enumerate listening ports bound to localhost; test unauthenticated access and CSRF from a browser. **Impact** A local server reachable by any process or a malicious web page.

## 8. Runtime and memory

- **Q** Do secrets persist in memory longer than needed? **How** Instrument with Frida; dump and search process memory. **Impact** Secrets recoverable from a running process.
- **Q** Can the app be hooked or instrumented to bypass controls? **How** Attach Frida/debugger; hook auth or license checks. **Impact** Client-side controls defeated at runtime.

## 9. Authentication, licensing, and authorization

- **Q** Are auth or license checks enforced server-side or only in the client? **How** Patch/hook the check; replay offline. **Impact** Client-only gates are bypassable by definition.
- **Q** Is multi-user separation respected on a shared host? **How** Test whether one user can read another's stored data or session. **Impact** Cross-user data exposure.

## 10. Deep links and protocol handlers

- **Q** Does the app register a custom URI scheme, and is its input validated? **How** Enumerate registered handlers; invoke with crafted payloads (path traversal, argument injection, script). **Impact** A single click on a link drives app actions or code paths.
- **Q** Are handler arguments passed unsafely to shells or file operations? **How** Trace the handler to its sink. **Impact** Argument injection to command execution.

---

## Finding template

```
Title:        <control> allows <impact>
Component:    <window / channel / binary / endpoint>
Precondition: <access/state required>
Steps:        1. ... 2. ... 3. ...
Evidence:     <screens / logs / request-response / memory dump ref>
Impact:       <what an attacker gains>
Remediation:  <specific fix, not "add validation">
```

A finding is a reproducible path from a starting condition to an impact. If it cannot be reproduced,
it is a note, not a finding.
