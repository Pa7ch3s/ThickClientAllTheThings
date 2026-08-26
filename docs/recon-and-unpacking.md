# Reconnaissance & Unpacking

Before you can attack a desktop application you have to know what it is, how it is built, and where its logic actually lives. Thick clients ship their business logic to the endpoint, which means the bundle on disk is a decompiler's buffet: framework runtimes, packed source, embedded configuration, hardcoded endpoints, and secrets that a web app would have kept server-side. This chapter is about that first pass over an installed application: identifying the framework, prying the container open, and recovering readable code and config from whatever archive, bytecode, or native binary the vendor shipped.

Techniques covered:

- Framework fingerprinting (Electron / Tauri / CEF / WebView2 / .NET / Java / native)
- Unpacking Electron (`asar`, `app.asar` vs `app.asar.unpacked`, main/renderer/preload)
- Decompiling .NET assemblies
- Decompiling Java bytecode
- Reversing native binaries (Ghidra / IDA / radare2 / DIE)
- Extracting embedded resources, config, and secrets
- Installer inspection (MSI / NSIS / Squirrel)

---

### Framework Fingerprinting

- **What & why:** Every subsequent tool choice depends on identifying the runtime. A `.NET` app wants ILSpy; an Electron app wants `asar`; a Qt binary wants Ghidra. Vendors rarely advertise the framework, but the install tree, imported libraries, and embedded strings do. Fingerprint first so you are not running a Java decompiler against a Go binary.
- **How to test:**
  - Start with the install directory layout and file inventory. On Windows the default roots are `%LOCALAPPDATA%\Programs\`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, and per-user `%LOCALAPPDATA%`. On macOS inspect `*.app/Contents/`; on Linux check `/opt`, `/usr/lib`, and AppImage mounts.
  - Enumerate the tree and look for signature files:
    ```bash
    # Linux/macOS
    find "/path/to/App" -maxdepth 3 -type f | sort
    ls -la "/path/to/App.app/Contents/"
    ```
    ```powershell
    # Windows
    Get-ChildItem -Recurse -Depth 3 "C:\Path\To\App" | Select-Object FullName,Length
    ```
  - Inspect the main executable's imports and strings:
    ```bash
    # imported libraries reveal the runtime
    objdump -p app.exe | grep 'DLL Name'        # PE imports
    strings -n 8 app.exe | grep -Ei 'electron|chrome|node|qt|wxwidgets|dotnet|mono|jvm'
    ```
  - Use Detect It Easy (DIE) for a one-shot classification of packer, compiler, and framework:
    ```bash
    diec app.exe          # CLI form of Detect It Easy
    ```
- **Framework notes** (the tells):
  - **Electron:** `resources/app.asar` (or `resources/app/`), a bundled `chrome_100_percent.pak`, `icudtl.dat`, `v8_context_snapshot.bin`, `ffmpeg.dll`/`libffmpeg`, `LICENSES.chromium.html`, and an executable that is really a renamed Electron stub. `strings` shows `node_modules`, `Electron Framework`, Node/Chromium version banners.
  - **Tauri:** a single relatively small native binary (Rust) with **no** bundled Chromium. On Windows it depends on `WebView2Loader.dll` and the Edge WebView2 runtime; on Linux it links `libwebkit2gtk`. `strings` show Rust panic messages, `cargo`, `tao`/`wry` symbols, and no `app.asar`.
  - **CEF (Chromium Embedded Framework):** `libcef.dll`/`libcef.so`/`Chromium Embedded Framework.framework`, `cef.pak`, `cef_100_percent.pak`, `devtools_resources.pak`. Distinct from Electron: no Node runtime and no `app.asar`.
  - **WebView2:** dependence on `Microsoft.Web.WebView2.Core.dll` and the Evergreen runtime (`msedgewebview2.exe` child process). Often a .NET or C++ host, check the host binary separately.
  - **.NET:** presence of `*.dll` managed assemblies, `*.deps.json`, `*.runtimeconfig.json` (.NET Core/5+), or a `mscoree.dll` import (.NET Framework). Self-contained apps ship `coreclr.dll`, `clrjit.dll`, `hostfxr.dll`, `hostpolicy.dll`. Single-file publishes are a native `apphost` with the assemblies embedded.
  - **Java:** `*.jar`/`*.war`, a bundled `jre`/`jdk`/`runtime` directory, `.jnlp`, or a native launcher plus `app/*.cfg` (jpackage/`javafx`). `strings` show `META-INF/MANIFEST.MF`, class names, `JavaVM`.
  - **Native (C/C++/Qt/Delphi):** no managed runtime files. Qt shows `Qt5Core.dll`/`Qt6Core`, `qt.conf`, `platforms/qwindows.dll`. Delphi/C++Builder binaries carry `Borland`/`Embarcadero`/`Delphi` RTTI strings and DFM form resources. Go binaries carry the `go:buildid` string and `runtime.` symbols.
- **Impact:** None directly; this is orientation. But misidentifying the framework wastes the whole engagement.
- **Remediation:** Fingerprinting cannot be prevented and is not a vulnerability. Vendors should assume the framework is known and not rely on obscurity of the runtime.

---

### Unpacking Electron (asar)

- **What & why:** Electron apps package the entire application (main process, renderer, preload scripts, `node_modules`) into an `asar` archive: a simple, unencrypted, concatenated file format with a JSON header. This is source code, not compiled bytecode. Extracting it typically yields the complete JavaScript logic, IPC channel names, `nodeIntegration`/`contextIsolation` settings, and any secrets left in the bundle.
- **How to test:**
  - Locate the archive (usually `resources/app.asar`; sometimes an unpacked `resources/app/` directory instead).
  - Extract with the official `@electron/asar` tool (formerly `asar`):
    ```bash
    npm install -g @electron/asar
    npx @electron/asar list resources/app.asar
    npx @electron/asar extract resources/app.asar ./app_extracted
    ```
  - No Node available? The format is trivial: the header is a JSON pickle at the start of the file. `strings resources/app.asar | less` will already surface file paths, URLs, and inline secrets even without a full extract.
  - After extraction, read `package.json` for `main` (the main-process entrypoint), then trace `BrowserWindow` creation to find `webPreferences` and `preload` paths.
  - Grep the tree for the security-relevant flags and IPC surface:
    ```bash
    grep -rniE 'nodeIntegration|contextIsolation|webSecurity|allowRunningInsecureContent|sandbox' app_extracted/
    grep -rniE "ipcMain\.(on|handle)|ipcRenderer\.(send|invoke)" app_extracted/
    ```
- **Framework notes:**
  - **`app.asar` vs `app.asar.unpacked`:** files that must exist on the real filesystem (native `.node` addons, binaries spawned by the app) are excluded from the archive and shipped in `resources/app.asar.unpacked/`. Always inspect both; native modules there may themselves be reverse-engineering targets.
  - **Fuses / integrity:** newer Electron builds may enable ASAR integrity checking and the `RunAsNode`/`EnableNodeCliInspectArguments` fuses. Integrity is a hash check on the archive; you can still read it, you just cannot trivially repack-and-run without matching the header hash. Check `strings` on the main binary for the fuse wire to read fuse state.
  - **Minified/bundled renderers:** many apps ship webpack/vite output. Use `js-beautify` and any shipped `.map` sourcemaps (`grep -rl sourceMappingURL`) to recover readable source.
  - This technique is Electron-specific. Tauri does **not** use asar; its web assets are compiled into the Rust binary (see native reversing) or served from an embedded store.
- **Impact:** Full recovery of client-side logic; discovery of hardcoded API keys, backend endpoints, unsafe IPC handlers, and misconfigured `webPreferences` that enable RCE from renderer content.
- **Remediation:** Do not treat asar as a security boundary; it is not encrypted. Keep secrets server-side, enable `contextIsolation` and `sandbox`, disable `nodeIntegration`, enable ASAR integrity and relevant Electron fuses, and strip sourcemaps from production builds.

---

### Decompiling .NET Assemblies

- **What & why:** .NET compiles to CIL (MSIL) bytecode carrying rich metadata, so decompilation reconstructs near-original C#/VB source including method bodies, resource names, and string literals. This is one of the highest-yield thick-client targets: config, connection strings, license logic, and crypto keys are frequently recoverable in full.
- **How to test:**
  - Confirm it is managed and read the metadata:
    ```bash
    # ILSpy CLI
    ilspycmd -il App.dll                 # dump IL
    ilspycmd -p -o ./src App.dll         # decompile whole assembly to a C# project
    monodis App.dll | head               # Mono disassembler, if available
    ```
  - GUI decompilers give the best code recovery: **ILSpy** (open source, cross-platform, plus the AvaloniaILSpy build), **dnSpy / dnSpyEx** (decompile **and** live-debug/edit-and-continue on Windows), and JetBrains **dotPeek**.
  - For obfuscated assemblies, identify the obfuscator with DIE or de4dot's detection, and attempt cleanup with **de4dot** before decompiling:
    ```bash
    de4dot App.dll -o App-clean.dll
    ```
  - Hunt strings and resources across all assemblies:
    ```bash
    grep -rniE 'password|secret|apikey|connectionstring|https?://' ./src/
    ```
- **Framework notes:**
  - **.NET Framework vs Core/5+:** Framework assemblies import `mscoree.dll`; Core apps ship `*.deps.json`/`*.runtimeconfig.json`. Both decompile identically.
  - **Single-file publish:** the assemblies are bundled into the native `apphost`. Extract them first with a bundle extractor or dump from memory once running, then decompile the recovered DLLs.
  - **ReadyToRun / AOT:** R2R images still contain the IL; Native AOT compiles straight to native code and must be treated as a native binary (Ghidra/IDA), not decompiled to C#.
  - **Embedded resources:** managed resources live in `.resources` streams; ILSpy/dnSpy expose them, or use `resourcer`/manual `ResourceReader` parsing.
- **Impact:** Recovery of full application logic, hardcoded credentials and connection strings, license/auth bypass insight, and editable assemblies (dnSpy) for runtime tampering during dynamic testing.
- **Remediation:** Never store secrets in managed strings or resources; use a real secret store and server-side validation. Commercial obfuscation (control-flow flattening, string encryption) raises cost but does not stop a determined analyst; treat it as speed-bump, not defense.

---

### Decompiling Java Bytecode

- **What & why:** Like .NET, Java compiles to metadata-rich bytecode that decompiles cleanly back to source. Thick-client Java (Swing/JavaFX/SWT) ships as JARs, often inside a bundled JRE, and commonly contains embedded config, endpoints, and keystores.
- **How to test:**
  - A JAR is a ZIP; list and extract it:
    ```bash
    unzip -l app.jar
    unzip app.jar -d app_extracted/
    cat app_extracted/META-INF/MANIFEST.MF     # Main-Class, classpath
    ```
  - Decompile with a real decompiler. **CFR** and **Procyon** are strong command-line choices; **JD-GUI** and the **Fernflower**-based tools give a GUI:
    ```bash
    java -jar cfr.jar app.jar --outputdir ./cfr_out
    java -jar procyon-decompiler.jar app.jar -o ./procyon_out
    ```
  - Bulk workflows: **jadx** handles JARs (and DEX for Android-style bundles) with `jadx app.jar -d out/` and `jadx-gui`.
  - Inspect a single class or the constant pool without full decompilation:
    ```bash
    javap -c -p -constants com/vendor/App.class
    ```
- **Framework notes:**
  - **jpackage / Java-native launchers:** apps built with `jpackage` ship a native launcher plus `app/*.jar` and an `app/*.cfg` pointing at the main module. Reverse the launcher only to find the JARs; the JARs are the real target.
  - **Fat/shaded JARs and Spring Boot:** dependencies are nested; extract fully and decompile the vendor packages, not the framework libraries.
  - **Obfuscation (ProGuard):** identifiers are stripped/renamed; decompilation still succeeds but naming is lost. Focus on string constants and control flow.
  - **Keystores:** look for `.jks`/`.p12`/`.keystore` in the bundle and inspect with `keytool -list -v -keystore file.jks`.
- **Impact:** Full source recovery, exposed endpoints and credentials, insight into client-side auth/licensing, and extractable signing/TLS keys.
- **Remediation:** Keep secrets out of the bundle, use server-side authorization, and apply obfuscation as a cost-raiser only. Do not ship production keystores with recoverable passwords.

---

### Reversing Native Binaries

- **What & why:** C/C++/Rust/Go/Delphi/Qt binaries have no metadata-rich bytecode, so you get assembly and a decompiler's best-effort pseudocode rather than source. Tauri's web assets, native Electron addons (`.node`), and traditional desktop apps all land here. Yield is lower and slower than managed decompilation but still exposes strings, endpoints, embedded resources, and logic.
- **How to test:**
  - Triage before deep reversing:
    ```bash
    file app.bin
    diec app.bin                 # Detect It Easy: compiler, packer, protector
    strings -n 8 -t x app.bin | grep -Ei 'https?://|api|token|password'
    nm -C app.bin 2>/dev/null    # symbols if not stripped
    objdump -d app.bin | less    # disassembly
    ```
  - Full analysis in a decompiler: **Ghidra** (free, excellent decompiler, batch via `analyzeHeadless`), **IDA Pro/Free**, **Binary Ninja**, or **radare2/rizin + Cutter**:
    ```bash
    # Ghidra headless: auto-analyze into a project
    analyzeHeadless ./proj ProjName -import app.bin

    # radare2 quick pass
    r2 -A app.bin
    # then: afl (list functions), iz (strings in data), ii (imports)
    ```
  - Check for packing (UPX and others) and unpack before analysis:
    ```bash
    upx -t app.bin && upx -d app.bin
    ```
- **Framework notes:**
  - **Tauri:** the Rust binary embeds the frontend web assets and command handlers. `strings` and the decompiler reveal registered `tauri::command` names (the IPC attack surface) and any embedded HTML/JS. Rust symbols are verbose but present unless stripped.
  - **Go:** stripped Go binaries still recover function names via the `pclntab`; use Ghidra scripts or `GoReSym` to restore symbols.
  - **Qt:** signals/slots and translation strings help map UI to logic; embedded `.qml`/resources sit in the Qt Resource System (see next section).
  - **Delphi/C++Builder:** use RTTI-aware helpers (e.g. IDR / Ghidra Delphi scripts) to recover class/form structure and DFM resources.
  - **Native Electron addons:** `.node` files in `app.asar.unpacked` are standard shared objects; reverse them as native binaries.
- **Impact:** Recovery of endpoints, embedded assets, algorithm/crypto logic, and IPC command surfaces; identification of memory-safety bugs for deeper exploitation.
- **Remediation:** Strip symbols, but understand reversing is not preventable. Move trust decisions server-side, validate all IPC/command inputs, and do not embed secrets. Anti-tamper/packing raises cost only.

---

### Extracting Embedded Resources, Config, and Secrets

- **What & why:** Independent of the language, desktop apps carry configuration and assets in the bundle: `.env`-style files, JSON/YAML/XML config, license files, TLS keys, certificate pins, feature flags, and hardcoded backend URLs. This is often the fastest path to impact and should be run in parallel with decompilation.
- **How to test:**
  - Broad content sweep across the extracted/installed tree:
    ```bash
    grep -rniE 'https?://|wss?://|api[_-]?key|secret|password|token|bearer|BEGIN (RSA|EC|PRIVATE)' ./target/
    ```
  - Catalog config and credential-bearing file types:
    ```bash
    find ./target -type f \( -iname '*.json' -o -iname '*.yml' -o -iname '*.yaml' \
      -o -iname '*.xml' -o -iname '*.config' -o -iname '*.ini' -o -iname '*.env' \
      -o -iname '*.pem' -o -iname '*.p12' -o -iname '*.pfx' -o -iname '*.jks' \) -print
    ```
  - **.NET:** read `App.config`/`*.dll.config`, `appsettings.json`, and embedded `.resources`; check `settings` classes in the decompiled source for defaults.
  - **Qt Resource System:** resources compiled into the binary can be carved; look for the `qres`/`.rcc` markers, or extract `.rcc` files with Qt's `rcc`-aware tooling.
  - **Windows PE resources:** dump icons, manifests, version info, and embedded blobs with **Resource Hacker** or `wrestool -x app.exe`.
  - Run a dedicated secret scanner over the whole tree for coverage and entropy detection:
    ```bash
    trufflehog filesystem ./target
    gitleaks detect --no-git --source ./target
    ```
- **Framework notes:** Electron/Java configs are usually plaintext files in the archive; native/Qt configs may be compiled into the binary and must be carved; .NET keeps them in `.config`/`appsettings`/managed resources. Some apps "encrypt" config with a key that is itself in the binary, recover the key via decompilation, then decrypt.
- **Impact:** Exposure of backend endpoints (expands the network attack surface), live API keys and credentials, private keys, and pinning/feature-flag logic that can be bypassed.
- **Remediation:** No secret should live in a distributed binary. Use server-side auth, short-lived tokens fetched at runtime, and OS keystores (DPAPI, Keychain, libsecret) rather than files. Assume anything in the bundle is public.

---

### Installer Inspection (MSI / NSIS / Squirrel)

- **What & why:** Installers ship the same payload you will unpack, and they also encode install-time behavior: custom actions, elevated services, registry keys, scheduled tasks, and update URLs. Inspecting the installer both recovers the payload without running it and surfaces privilege-escalation and supply-chain issues (writable install paths, unsigned updates).
- **How to test:**
  - **MSI (Windows Installer):** MSI is a structured-storage database of tables. Read it without installing:
    ```bash
    # Linux/macOS
    msiinfo tables installer.msi
    msiinfo export installer.msi CustomAction   # inspect custom actions
    msiextract installer.msi                     # extract payload files
    7z l installer.msi                           # 7-Zip also lists/extracts CABs
    ```
    On Windows use **Orca** (MS Windows SDK) or **lessmsi** (`lessmsi x installer.msi`) to browse tables and dump files. Scrutinize the `CustomAction`, `InstallExecuteSequence`, `ServiceInstall`, and `Registry` tables for deferred actions running as SYSTEM.
  - **NSIS:** self-extracting; 7-Zip can list and extract the packaged files, and the script logic is recoverable:
    ```bash
    7z x setup.exe -o./nsis_out
    ```
    For the install script itself, use a maintained NSIS extractor where available; otherwise inspect `strings` for install paths and download URLs.
  - **Squirrel (used by many Electron apps):** the release is a set of NuGet-format `.nupkg` files plus a `RELEASES` manifest, delivered from an update feed. `.nupkg` is a ZIP:
    ```bash
    unzip -l MyApp-1.2.3-full.nupkg
    unzip MyApp-1.2.3-full.nupkg -d squirrel_out/
    cat RELEASES        # SHA1 + filename + size of each package
    ```
    The `lib/net45/` (or app) folder holds the actual Electron/`app.asar` payload. Note the update URL from the app config; unauthenticated/HTTP feeds are a supply-chain finding.
  - **macOS `.pkg`/`.dmg`:** expand flat packages with `pkgutil --expand-full app.pkg out/` and read `Scripts/preinstall`/`postinstall`; mount DMGs and inspect the `.app` bundle.
- **Framework notes:** Squirrel is the Electron-world default and directly exposes the asar payload and update channel. MSI is common for .NET and native enterprise apps and is where SYSTEM-level custom actions live. NSIS wraps everything from games to native apps. Tauri uses its own bundler producing MSI/NSIS on Windows and `.dmg`/`.app` on macOS, so the same tooling applies.
- **Impact:** Payload recovery without execution; discovery of privilege-escalation vectors (weak install-dir ACLs, SYSTEM custom actions, unquoted service paths) and insecure/unsigned update channels enabling supply-chain compromise.
- **Remediation:** Sign installers and every update package, serve update feeds over HTTPS with signature verification, install to protected directories with correct ACLs, minimize and audit elevated custom actions, and never place secrets or writable service binaries in user-writable locations.
