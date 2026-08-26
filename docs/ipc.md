# Inter-Process Communication

Thick clients rarely live alone. They split themselves across a privileged broker and an untrusted UI, talk to helper services, and expose local endpoints "just for the frontend" that turn out to be reachable by anything on the box. IPC is where trust boundaries are drawn on a whiteboard and then quietly erased in code, so it is where a lot of local privilege escalation and sandbox-escape lives. Everything below assumes you are testing software you are authorized to test.

- Electron `ipcMain` handlers and the `contextBridge` preload surface
- Windows named pipes: enumeration, ACLs, authentication, message fuzzing
- COM/DCOM: registered interfaces, access control, local privilege escalation
- D-Bus (Linux): introspection and low-privilege method invocation
- Local Unix-domain and loopback TCP sockets the app opens
- Input validation and fuzzing across every channel

---

### Electron IPC handler abuse

**What & why**
Electron's security model relies on the renderer being untrusted and the main process being the broker. Every `ipcMain.handle`/`ipcMain.on` is a function the (potentially compromised, XSS-driven) renderer can call. If a handler shells out, reads/writes arbitrary paths, spawns processes, or reflects renderer input into `eval`/`Function`/`child_process`, then renderer JS execution becomes main-process (Node) code execution and full sandbox escape.

**How to test**
Unpack the app and read the channel surface directly.

```bash
# Extract the app bundle (asar archive)
npx @electron/asar extract app.asar out/     # modern
# or: npx asar extract app.asar out/

# Map the IPC attack surface
grep -rnE "ipcMain\.(handle|on|handleOnce)" out/
grep -rnE "contextBridge\.exposeInMainWorld" out/
grep -rnE "child_process|execSync|exec\(|spawn|shell\.openExternal|require\(" out/

# Static analysis for known Electron misconfig + IPC issues
npx @doyensec/electronegativity -i out/ -o findings.csv
```

Then exercise handlers from the renderer DevTools console (or an injected XSS payload) and watch what the main process does:

```js
// In the renderer (or via a bridged API exposed on window)
await window.electron.invoke('open-file', '/etc/passwd')
await window.api.someBridgedMethod('../../../../etc/hostname')
```

Focus on: path parameters (traversal), command/argument parameters (injection), URL parameters passed to `shell.openExternal` (e.g. `file:`, `smb:`, custom protocols), and any handler that returns secrets or writes to disk.

**Framework notes**
Check `webPreferences`: `contextIsolation: false` or `nodeIntegration: true` collapses the boundary entirely (Node in the renderer, no IPC needed). With `contextIsolation` on, the real surface is exactly what the preload exposes via `contextBridge` — audit that allowlist. `sandbox: true` limits the preload's own Node access. `shell.openExternal` on renderer-controlled input is a recurring finding.

**Impact** Renderer/XSS to main-process RCE; arbitrary file read/write; local command execution.

**Remediation** Never pass renderer input straight to filesystem/process/`openExternal` APIs. Validate and canonicalize paths, allowlist commands and protocols, expose the narrowest possible bridge API, keep `contextIsolation: true`/`nodeIntegration: false`/`sandbox: true`, and validate the `event.senderFrame` origin inside handlers.

---

### Named pipe enumeration and ACL review (Windows)

**What & why**
Windows services and privileged brokers frequently expose `\\.\pipe\<name>` endpoints. The risk is a pipe with a weak DACL or a NULL DACL that a low-privileged or cross-user process can open, letting an attacker reach privileged functionality. First map the pipes, then read their security descriptors.

**How to test**
```powershell
# Enumerate pipes (built-in)
Get-ChildItem \\.\pipe\

# Sysinternals: list pipes and instance counts
pipelist.exe /accepteula

# James Forshaw's NtObjectManager (PowerShell Gallery) - rich inspection
Install-Module NtObjectManager
Import-Module NtObjectManager
ls NtObject:\Device\NamedPipe\ | Select Name
# Read the security descriptor / DACL of a specific pipe
Get-NtNamedPipeFile "\\.\pipe\TargetPipe" | Get-NtSecurityDescriptor | Format-NtSecurityDescriptor
```

```cmd
:: accesschk: who can access the pipe object (look for low-priv principals)
accesschk.exe -accepteula -w \pipe\TargetPipe
accesschk.exe -accepteula -L \pipe\TargetPipe
```

Map which process owns a pipe with Process Explorer / Process Hacker (System Informer) by searching handles for the pipe name, and watch live traffic/setup with Sysinternals **Process Monitor** (filter Operation = CreatePipe / path contains `\Device\NamedPipe`).

**Framework notes**
Look for `Everyone`, `Authenticated Users`, or `NULL` DACL granting `FILE_WRITE_DATA`/`GENERIC_WRITE`. Note whether the server calls `ImpersonateNamedPipeClient` — if it does and it is reachable, a client can potentially trigger token impersonation flows; if it does not, the server runs actions with its own (often SYSTEM) token on client-controlled input.

**Impact** Cross-user/cross-session access to privileged functionality; local privilege escalation.

**Remediation** Set explicit least-privilege DACLs on `CreateNamedPipe`, set `PIPE_REJECT_REMOTE_CLIENTS`, cap `nMaxInstances`, validate/authorize the client, and treat every message as untrusted input.

---

### Named pipe authentication and message fuzzing

**What & why**
Once a pipe is reachable, the questions are: does it authenticate the caller at all, and does it safely parse messages? Many local IPC protocols are hand-rolled length-prefixed or JSON blobs with no auth and optimistic parsing.

**How to test**
Connect as a normal client and speak the protocol. `pywin32` gives direct pipe I/O:

```python
import win32file
h = win32file.CreateFile(
    r"\\.\pipe\TargetPipe",
    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
    0, None, win32file.OPEN_EXISTING, 0, None)
win32file.WriteFile(h, b'{"cmd":"ping"}')
print(win32file.ReadFile(h, 65536))
```

Cross-language quick test with `ncat`:

```bash
ncat --recv-only //./pipe/TargetPipe        # read banner/behavior
```

For structured fuzzing, drive the pipe with **boofuzz** (define a session whose transport writes to the pipe handle) or mutate captured messages with **radamsa** and replay them, watching the service process under **WinDbg** / Time Travel Debugging for crashes:

```bash
# Mutate a captured message corpus and replay each variant
for i in $(seq 1 5000); do radamsa seed.bin > case_$i.bin; done
```

Test authentication by connecting from a **different, lower-privileged user context** (e.g. via `runas` / a low-IL process) and confirming whether privileged commands still execute.

**Framework notes**
.NET apps commonly use `NamedPipeServerStream` — check the `PipeSecurity` passed and whether `impersonationLevel`/token checks exist. Node/Electron on Windows exposes pipes through `net`/libuv; look for a shared secret in the pipe name or first message and whether it is actually verified.

**Impact** Unauthenticated command execution, memory-corruption crashes/RCE in the server, auth bypass.

**Remediation** Authenticate and authorize every client (verify SID/token, not just pipe name secrecy), use message-mode with strict length/schema validation, and fail closed on malformed input.

---

### COM/DCOM interface enumeration and privilege escalation

**What & why**
COM servers register CLSIDs and interfaces that other processes activate. Weak launch/access permissions, servers running as a privileged identity, or missing argument validation let a low-privileged caller drive privileged actions — a classic local privilege escalation path.

**How to test**
Use **OleViewDotNet** (James Forshaw) — GUI and PowerShell module — to enumerate classes, interfaces, and their access/launch permissions:

```powershell
Install-Module OleViewDotNet
Import-Module OleViewDotNet
$db = Get-ComDatabase                       # build the COM registration DB
# Find classes runnable/launchable by low-priv users, or with weak permissions
Get-ComClass -Database $db | Where-Object { $_.LaunchPermission -match 'Everyone|Users' }
Select-ComAccess -Database $db -Principal "S-1-5-32-545"   # what 'Users' can reach
```

```powershell
# Instantiate and probe an interface
$obj = [Activator]::CreateInstance([Type]::GetTypeFromCLSID('{CLSID-HERE}'))
$obj | Get-Member
```

Registry ground truth lives under `HKCR\CLSID\{...}` (`LocalServer32`/`InprocServer32`, `AppID`) and `HKCR\AppID\{...}` (`LaunchPermission`, `AccessPermission`). Inspect DCOM-wide settings with `dcomcnfg`. Observe live activation and the security identity with **Process Monitor** and **Process Explorer**. For deeper RPC/DCOM interface mapping use **RPCView** or Forshaw's `NtObjectManager` RPC tooling.

**Framework notes**
High-value targets: `LocalServer32` COM servers whose `RunAs` is `Interactive User` or a service account (privileged execution), servers accepting file paths/commands, and known auto-elevating/CMSTP-style patterns. Distinguish in-proc (`InprocServer32`, runs in caller) from out-of-proc/local server (crosses a trust boundary — the interesting case).

**Impact** Local privilege escalation, code execution as the server's identity, DACL/permission bypass.

**Remediation** Set explicit least-privilege launch/access permissions per AppID, avoid `Interactive User`/SYSTEM where not required, validate all method arguments, and require authentication level `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` or higher.

---

### D-Bus introspection and low-privilege method invocation (Linux)

**What & why**
Desktop Linux apps and their helper daemons expose methods on the session or system bus. System-bus services run privileged and gate callers with **polkit** policies. Missing or permissive policy rules, or trusting caller-supplied data, let an unprivileged user invoke privileged methods.

**How to test**
```bash
# List bus names, then introspect a service's objects/interfaces/methods
busctl list
busctl tree   org.example.Service
busctl introspect org.example.Service /org/example/Object

# Call a method (system bus example)
busctl call org.example.Service /org/example/Object \
       org.example.Interface MethodName "s" "argument"

# gdbus equivalents
gdbus introspect --system --dest org.example.Service --object-path /org/example/Object
gdbus call --system --dest org.example.Service \
      --object-path /org/example/Object --method org.example.Interface.MethodName "arg"
```

GUI/introspection: **D-Feet**. Monitor live traffic to learn the protocol and find called methods:

```bash
dbus-monitor --system            # or --session
busctl monitor org.example.Service
```

Check the service's polkit policy and try methods as an unprivileged user:

```bash
ls /usr/share/dbus-1/system-services/     # activatable services
ls /usr/share/polkit-1/actions/           # action policies (look for allow_active/allow_any)
pkcheck --action-id org.example.action --process $$
```

**Framework notes**
Service definitions in `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/` control who may talk to a name. Absence of a polkit check inside a privileged method (or `<allow send_destination>` open to all) is the finding. For fuzzing, script `busctl call` over mutated argument sets, respecting the introspected type signatures.

**Impact** Local privilege escalation, unauthorized privileged operations, information disclosure.

**Remediation** Enforce polkit authorization inside every privileged method, restrict bus policy to required principals, and validate all argument types/values server-side.

---

### Local Unix-domain and loopback TCP sockets

**What & why**
Apps expose "internal" control or API sockets — a Unix socket in `/tmp`, an abstract socket, or an HTTP/JSON-RPC server on `127.0.0.1:<port>`. Loopback is not an authentication boundary: any local user (and, via CSRF/DNS-rebinding, any web page the user visits) can reach an unauthenticated localhost service.

**How to test**
```bash
# Linux: list listening sockets + owning process
ss -xlp                      # unix-domain listeners
ss -tlnp                     # loopback TCP listeners
lsof -U ; lsof -i @127.0.0.1

# Talk to a unix socket / loopback port
socat - UNIX-CONNECT:/tmp/app.sock
ncat -U /tmp/app.sock
curl -s http://127.0.0.1:PORT/ ; curl -s http://127.0.0.1:PORT/rpc -d '{"method":"..."}'
```

```powershell
# Windows loopback listeners + owning PID
netstat -ano | findstr LISTENING
Get-NetTCPConnection -State Listen | ? LocalAddress -match '127.0.0.1|::1'
```

Check filesystem permissions on Unix sockets (`ls -l /tmp/app.sock`), whether the server uses `SO_PEERCRED`/`getpeereid` to authenticate the peer, and whether a loopback HTTP service validates `Origin`/`Host` (DNS-rebinding and CSRF exposure). Fuzz the wire protocol with **boofuzz** for binary framing, or standard web tooling (Burp/ZAP, `ffuf`) for localhost HTTP/RPC.

**Framework notes**
Electron/Chromium apps sometimes open a debug port — an exposed `--inspect`/`--remote-debugging-port` on loopback is remote-ish code execution via the DevTools protocol; confirm it is disabled in production. Language runtimes (Node, Java, .NET) each have their own local RPC servers worth checking.

**Impact** Unauthenticated local (and web-reachable) access to privileged app functions; RCE via exposed debug protocols.

**Remediation** Authenticate peers (`SO_PEERCRED`/token), lock socket file permissions, bind debug/inspect ports off by default, and enforce `Origin`/`Host` checks plus per-request tokens on loopback HTTP services.

---

### Cross-channel input validation and fuzzing

**What & why**
Every IPC endpoint is an attacker-controlled parser boundary. The recurring bugs are the same across transports: path traversal, command/argument injection, deserialization of untrusted data, integer/length mishandling in binary framing, and "the client said so" authorization.

**How to test**
- Capture a legitimate message corpus per channel (ProcMon/dbus-monitor/socat tees), then mutate with **radamsa** or drive a grammar-aware campaign with **boofuzz**.
- For memory-unsafe servers (native/C++), attach **WinDbg**/**Time Travel Debugging** (Windows) or run the daemon under **AddressSanitizer** + coverage-guided **AFL++** where you can build/harness it.
- Systematically test each string parameter for traversal (`../`, absolute paths, UNC/`\\?\`), each command param for shell metacharacters, and every deserializer for type-confusion/gadget input.
- Re-run the highest-value calls from a genuinely lower-privileged context to prove the authorization gap, not just the reachability.

**Framework notes**
JSON/`JSON.parse` is comparatively safe; native deserializers (Java `ObjectInputStream`, .NET `BinaryFormatter`, Python `pickle`, `Marshal`) reachable over IPC are critical findings. Length-prefixed binary protocols are where integer-overflow crashes hide.

**Impact** Memory corruption/RCE, injection, deserialization RCE, authorization bypass.

**Remediation** Schema-validate every message, canonicalize and allowlist paths/commands, never deserialize untrusted data with unsafe formats, enforce length bounds, and authorize on the server-verified caller identity rather than message content.
