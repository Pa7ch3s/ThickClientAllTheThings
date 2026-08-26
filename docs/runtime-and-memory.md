# Runtime, Memory & Instrumentation

Static analysis tells you what a binary *could* do; runtime instrumentation tells you what it *actually does* with real keys, tokens, and decisions in flight. This chapter covers attaching to live desktop processes, hooking the functions that gate auth/license/crypto, and prying secrets out of process memory. All of it assumes you own the app or have written authorization to test it: attaching a debugger to someone else's process is the same primitive whether you call it research or malware.

- Frida: attach, enumerate modules/exports, hook, and bypass client-side checks
- Native debuggers: x64dbg, WinDbg, gdb/lldb attach and patch
- Managed runtimes: dnSpy for .NET, `-javaagent`/JVMTI for Java
- Hooking auth / license / crypto at runtime
- Memory secret extraction: dumping a process and mining the dump
- Anti-debugging: what it detects and how it's neutralized

---

### Frida: attach and enumerate the target

**What & why**
Frida is a dynamic instrumentation toolkit that injects a JS engine into a live process, letting you enumerate loaded modules and exports, read/write memory, and replace function behavior without recompiling. It is the fastest way to map attack surface at runtime and works cross-platform against native code (and, via bridges, Java/.NET).

**How to test**
Install (`pip install frida-tools`) and list processes, then get a first look at what's loaded:
```bash
frida-ps -ua                 # running apps (attachable)
frida-trace -n App.exe -i "CryptEncrypt" -i "*ssl*"   # auto-generate stubs for matching exports
```
Enumerate modules and exports interactively with a script attached by name or PID:
```javascript
// enum.js  ->  frida -n App.exe -l enum.js
Process.enumerateModules().forEach(m => console.log(m.name, m.base, m.size));
Module.enumerateExports('libcrypto.dll').forEach(e =>
    console.log(e.type, e.name, e.address));
// find an interesting symbol without a static reference
console.log(Module.getExportByName(null, 'RtlDecryptMemory'));
```
Use `Module.enumerateImports`, `ApiResolver('module')`, and `DebugSymbol.fromAddress()` to correlate addresses back to names when symbols are stripped.

**Framework notes**
Native (C/C++/Rust) and Electron's native layer hook directly. For managed runtimes Frida ships bridges: `Java.perform()` on Android/JVM and `Il2Cpp`/CLR interop for .NET (though dnSpy is usually easier for .NET on Windows). Electron's JS logic is better attacked at the V8/DevTools layer than through Frida.

**Impact**
Full runtime visibility: every exported crypto/auth/network call and its arguments become observable and modifiable.

**Remediation**
You cannot prevent instrumentation of code the user runs; assume the client is hostile territory. Move trust decisions server-side, detect injected agents as a speed bump only, and never treat client-side enforcement as a security boundary.

---

### Frida: hooking functions with Interceptor

**What & why**
`Interceptor.attach` runs your JS on entry/exit of any function, exposing arguments and return values; `Interceptor.replace` swaps the whole implementation. This is the core primitive for logging secrets, tampering with inputs, and forcing outcomes.

**How to test**
Log arguments and tamper with a return value:
```javascript
// hook a comparison-style license check that returns bool
var addr = Module.getExportByName('license.dll', 'ValidateKey');
Interceptor.attach(addr, {
  onEnter(args) { this.key = args[0].readUtf8String(); },
  onLeave(retval) {
    console.log('ValidateKey("' + this.key + '") ->', retval);
    retval.replace(1);          // force success
  }
});
```
Dump buffers passed to crypto to recover plaintext or keys:
```javascript
Interceptor.attach(Module.getExportByName(null, 'EVP_DecryptUpdate'), {
  onEnter(args) { this.out = args[1]; this.len = args[3]; },
  onLeave() { console.log(hexdump(this.out.readByteArray(this.len.toInt32()))); }
});
```
For calling-convention-sensitive or inline targets, hook by resolved address with `ptr('0x...')` plus module base rebasing.

**Framework notes**
Native calls need correct arg indexing per ABI (x64 Windows vs SysV). Java: `Java.use('com.app.Auth').check.implementation = function(){ return true; }`. .NET methods are hookable via the CLR bridge but dnSpy edit-and-continue is often cleaner.

**Impact**
Client-side auth/license/feature gates fall in one line; sensitive buffers are exfiltrated pre-encryption or post-decryption.

**Remediation**
Server-side authorization; sign and verify feature entitlements server-issued; don't branch security decisions on a client-side boolean.

---

### Bypassing client-side checks (license, auth, jailbreak/root, integrity)

**What & why**
Thick clients routinely gate features on local checks: a returned boolean, a string compare against a computed key, a trial-expiry date, or a self-integrity/anti-tamper probe. Because the check and its data live in the same address space as your instrumentation, the branch is yours to flip.

**How to test**
1. Locate the decision with `frida-trace` on likely names (`*valid*`, `*licen*`, `*auth*`, `*trial*`, `*integrity*`) or by tracing string references to error dialogs.
2. Confirm it's the gate by logging arg/return under both pass and fail states.
3. Neutralize: force the return, patch the comparison, or NOP the conditional jump (see debugger patching below).
```javascript
// short-circuit an expiry check that returns days-remaining
Interceptor.replace(daysLeftAddr, new NativeCallback(() => 9999, 'int', []));
```

**Framework notes**
.NET: patch the `if` in dnSpy directly (`brtrue`/`ret true`). Java: override the method to return the happy path. Electron: the gate is usually JS; edit the asar or hook via DevTools. Native: prefer a debugger patch you can persist to disk.

**Impact**
Unlocked premium/enterprise features, bypassed trials, defeated integrity self-checks that other controls depend on.

**Remediation**
Entitlement checks must be server-validated with signed responses bound to a session; obfuscation and anti-tamper raise cost but never make a local check authoritative.

---

### .NET runtime debugging & patching with dnSpy

**What & why**
Managed .NET assemblies decompile to near-original C#/IL. dnSpy (and the maintained `dnSpyEx` fork) lets you set breakpoints, inspect locals, edit methods, and save a patched assembly, making it the most productive tool against Windows desktop .NET (WPF/WinForms) apps.

**How to test**
- Open the assembly (or **Debug > Attach to Process** for a running app), set breakpoints on suspected auth/crypto methods, and read decrypted values and keys from the Locals window at runtime.
- Patch logic with **Edit Method (C#)** or **Edit IL Instructions**, e.g. replace a body with `return true;`, then **File > Save Module**.
- For obfuscated builds, run `de4dot` first to rename and clean, then load into dnSpy.
- Config-based secrets: check `app.config`/`appsettings.json` and embedded resources via the Resources node.

**Framework notes**
Single-file / self-contained .NET and AOT-compiled binaries resist decompilation; extract the bundled managed DLLs first or fall back to native techniques. .NET Framework vs .NET (Core) differ in host layout but dnSpyEx handles both.

**Impact**
Complete recovery of logic, hardcoded keys/connection strings, and trivial in-place patching of any client-side control.

**Remediation**
Don't ship secrets or authoritative logic in client assemblies; use strong-name + signing as tamper-evidence, keep server as source of truth, and treat obfuscation as delay, not defense.

---

### Java agent instrumentation & JVMTI

**What & why**
Java thick clients (Swing/JavaFX, or JAR-packaged tools) can be inspected and rewritten without source via a decompiler plus bytecode instrumentation. Agents attached with `-javaagent` or the Attach API can redefine classes at load or at runtime.

**How to test**
- Decompile with a modern viewer (JD-GUI, Recaf, or CFR: `cfr app.jar --outputdir out`) to read logic and find hardcoded secrets.
- Attach a Byte Buddy / Javassist agent to rewrite methods, or use Recaf to edit bytecode and re-save the JAR.
- Launch with remote debug and attach any JDWP debugger:
```bash
java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -jar app.jar
jdb -attach 5005
```
- Frida's Java bridge also works where the JVM is embedded.

**Framework notes**
Obfuscators (ProGuard/commercial) rename symbols; the logic is still present. Signed/sealed JARs and JPMS modules add friction but bytecode remains editable after unpacking.

**Impact**
Logic recovery, secret extraction, and runtime method replacement to bypass any local gate.

**Remediation**
Keep secrets and trust off the client; sign JARs for integrity; rely on server-side enforcement rather than obfuscation.

---

### Native debuggers: x64dbg, WinDbg, gdb/lldb

**What & why**
For C/C++/Rust binaries a native debugger gives breakpoints, register/memory inspection, and the ability to patch instructions and persist the change. This is how you defeat gates that have no clean symbol to hook.

**How to test**
- **x64dbg (Windows, interactive):** attach or open, break on `CryptDecrypt`/`WinHttpSendRequest`/string-referenced routines, then patch the conditional jump that guards success (toggle `jz`/`jnz` or NOP it) and **Save patched file** to disk.
- **WinDbg (deep/kernel/dumps):** attach with `windbg -pn App.exe`; useful commands: `x app!*valid*` (symbol search), `bp` (breakpoint), `!address`, `s -a 0 L?0x7fffffff "password"` (search memory for a string), `.dump /ma out.dmp` (full dump).
- **gdb/lldb (Linux/macOS):**
```bash
gdb -p $(pgrep app)
(gdb) info functions valid
(gdb) break *0x555555556abc
(gdb) set $rax = 1        # force a return value
```

**Framework notes**
Native only; managed runtimes show JIT stubs, not clean methods (use dnSpy/Java tooling instead). PIE/ASLR means rebase addresses against the module base each run.

**Impact**
Persistent binary patches, live control of execution and return values, and a path to memory dumps.

**Remediation**
Sign binaries and verify at launch (tamper-evidence), but assume any locally patchable check will be patched; enforce server-side.

---

### Hooking auth / license / crypto at runtime

**What & why**
The highest-value hook points are the standard crypto and auth APIs, because plaintext and keys must pass through them regardless of how the app is obfuscated. Instrumenting the boundary between app logic and the crypto provider yields secrets even when the surrounding code is unreadable.

**How to test**
Trace the platform crypto surface and dump the interesting buffers:
```bash
# Windows CNG/CryptoAPI
frida-trace -n App.exe -i "BCryptEncrypt" -i "BCryptDecrypt" -i "CryptProtectData" -i "CryptUnprotectData"
# OpenSSL family (any platform)
frida-trace -n App.exe -i "EVP_*Init*" -i "EVP_*Update" -i "PEM_read*" -i "*_set_key"
```
Log keys handed to key-schedule functions, capture password-based KDF inputs (`PBKDF2`/`bcrypt`/`scrypt` wrappers), and record the pre-TLS plaintext to defeat certificate pinning at the app layer. Correlate captured material with the memory-dump techniques below.

**Framework notes**
.NET wraps CNG under `System.Security.Cryptography` (hook the P/Invoke boundary or breakpoint in dnSpy); Java uses JCA/`Cipher` (override `doFinal`); Electron uses Node `crypto` (hook in-process JS). Native apps hit CNG/CryptoAPI/OpenSSL directly.

**Impact**
Recovery of encryption keys, credentials, and plaintext of "encrypted" local data and traffic.

**Remediation**
Client-side crypto protects data only from other users of the same machine, not from the user; anything the client can decrypt, the operator can too. Bind sensitive operations to server-side keys and sessions.

---

### Process memory dumps

**What & why**
Secrets that are decrypted for use must exist in cleartext in RAM at some point. A full memory dump captures that moment, and unlike a live hook it's a single artifact you can mine offline and re-search.

**How to test**
- **Windows, procdump (Sysinternals):**
```bash
procdump -ma App.exe app.dmp          # full dump by name
procdump -ma <PID> -s 5 -n 3 app      # periodic, to catch transient secrets
```
- **Windows alternatives:** Task Manager > right-click process > *Create dump file*; WinDbg `.dump /ma`.
- **Linux:** `gcore $(pgrep app)`, or read `/proc/<pid>/mem` guided by `/proc/<pid>/maps`.
- **macOS:** `lldb -p <pid>` then `process save-core core.dmp` (SIP/entitlements permitting).
Trigger the dump *after* the app has decrypted/loaded the target secret (post-login, after opening the vault) to maximize what's resident.

**Framework notes**
Managed heaps (.NET/Java) hold strings as objects; string search still works, and for .NET you can load the dump in WinDbg with the SOS extension (`!dumpheap -type String`) for structured extraction. Electron/Chromium processes are large; dump the specific renderer/main PID that holds the data.

**Impact**
Passwords, session tokens, API keys, and decrypted document contents recovered from a single snapshot, often long after they were "used."

**Remediation**
Minimize secret lifetime in memory; zero buffers after use (`SecureZeroMemory`, `Arrays.fill`), prefer `SecureString`/protected memory where meaningful, and accept that a determined local attacker can still catch the window.

---

### Mining a dump for keys, tokens & strings

**What & why**
A dump is just bytes; the skill is knowing what secrets look like. Format-anchored searching turns a multi-gigabyte file into a short list of candidates.

**How to test**
```bash
strings -n 8 app.dmp > s.txt
grep -Ei 'password|passwd|secret|api[_-]?key|token|bearer|authorization' s.txt
# JWTs
grep -Eo 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' app.dmp
# common key/credential markers
grep -aE 'BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|AKIA[0-9A-Z]{16}|xox[baprs]-' app.dmp
```
For binary keys (AES) that won't show in `strings`, carve high-entropy 16/24/32-byte runs, or use the crypto hooks above to grab the key and then confirm its presence in the dump. On Windows, `strings -el` also recovers UTF-16LE, which most .NET/Win32 strings use.

**Framework notes**
.NET/Java = UTF-16/UTF-8 objects (search both encodings; use SOS `!dumpheap`/`!do` for structure). Native = raw C strings and struct blobs. Electron = V8 heap strings, often JSON fragments of tokens.

**Impact**
Turnkey credential and key recovery from an offline artifact, repeatable and grep-able.

**Remediation**
Same as dumps: short secret lifetimes, zeroization, avoid long-lived plaintext tokens in memory, and rotate anything that could have been captured.

---

### Anti-debugging & anti-instrumentation, and bypassing it

**What & why**
Hardened clients try to detect and resist the above: debugger-presence checks, timing checks, Frida/agent detection, and self-integrity probes. These are speed bumps, not walls, because the detection code runs in the process you control.

**How to test**
Recognize common techniques and neutralize each:
- **Windows debugger checks:** `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess(ProcessDebugPort)`, PEB `BeingDebugged` flag. Hook the API to return 0/false, or patch the PEB byte. Tools: ScyllaHide / TitanHide plugins for x64dbg automate most of these.
```javascript
Interceptor.replace(Module.getExportByName('kernel32.dll','IsDebuggerPresent'),
    new NativeCallback(() => 0, 'int', []));
```
- **Timing checks** (`rdtsc`/`GetTickCount` deltas): patch out the branch or single-step past.
- **Frida/agent detection** (scanning maps for `frida`, checking named pipes/ports): use `frida --runtime` stealth options, rename the agent, or hook the detection routine to lie.
- **`ptrace` self-attach (Linux/macOS):** an app calls `ptrace(PTRACE_TRACEME)` so a debugger can't attach; hook/patch `ptrace` to return 0.

**Framework notes**
Native uses OS APIs and CPU instructions (patch/hook). .NET checks `Debugger.IsAttached` (patch in dnSpy). Java may check the JDWP agent list. Electron can detect DevTools via timing on `debugger` statements. Managed checks are usually easier to defeat than native ones.

**Impact**
Anti-debug slows analysis but does not prevent it; once bypassed, all prior techniques apply unchanged.

**Remediation**
Layer anti-tamper for defense-in-depth and to raise attacker cost, but never rely on it as a control; the only durable protection for secrets and decisions is to keep them server-side where the client can't reach.
