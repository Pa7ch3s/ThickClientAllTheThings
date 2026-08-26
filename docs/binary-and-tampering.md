# Binary Protections & Tampering

A thick client runs on hardware the attacker owns. Every integrity assumption the vendor makes, that the binary on disk is the one they shipped, that a DLL loaded by name is theirs, that a signature means anything at runtime, is a claim to be tested, not trusted. This chapter is about the binary itself: whether it is signed and whether that signature is enforced, whether it can be swapped or side-loaded, and whether its install footprint hands you the machine.

Techniques covered:

- Code signing and runtime enforcement
- DLL search-order hijacking and sideloading
- Anti-tamper and integrity-check bypass
- Writable install and execution paths (local privilege escalation)
- Binary hardening flags (ASLR / DEP / CFG)

---

### Code Signing and Runtime Enforcement

- **What & why:** A signature only matters if something checks it. Many apps are signed at build time but never verify their own or their components' signatures at runtime, so a modified binary or an unsigned dropped module runs unnoticed. Test both halves: is it signed, and is the signature actually enforced.
- **How to test:**
  - Verify the shipped signature and read the chain:
    ```powershell
    # Windows Authenticode
    Get-AuthenticodeSignature "C:\Path\To\App.exe" | Format-List *
    signtool verify /pa /v "C:\Path\To\App.exe"
    ```
    ```bash
    # macOS
    codesign -dv --verbose=4 /Applications/App.app
    spctl -a -vvv /Applications/App.app       # Gatekeeper assessment
    codesign --verify --deep --strict /Applications/App.app
    ```
  - Test enforcement: modify a byte in a non-critical section (or replace a bundled resource/DLL with an unsigned one) on a copy, run it, and see whether the app refuses to start or carries on. If it runs, runtime signature enforcement is absent.
  - Check whether child processes, plugins, and update payloads are signature-checked, not just the main EXE.
- **Framework notes:**
  - **Electron:** the EXE is signed, but the `app.asar` payload is separate; unless ASAR integrity fuses are enabled, swapping asar contents changes behavior with no signature complaint.
  - **.NET:** Authenticode on the host does not cover every managed DLL; strong-naming is not a security boundary (it can be stripped/re-signed). Verify each assembly.
  - **macOS:** notarization plus a hardened runtime is the strong posture; `--deep --strict` reveals unsigned nested code.
- **Impact:** A tampered client runs as the trusted app, enabling backdoors, control bypass, and supply-chain style persistence on the endpoint.
- **Remediation:** Enforce signature validation at runtime for the app and every component it loads or downloads; enable Electron ASAR integrity and fuses; adopt hardened runtime + notarization on macOS. Treat strong-naming as identity, not integrity.

---

### DLL Search-Order Hijacking and Sideloading

- **What & why:** When a program loads a library by name rather than a fully qualified, validated path, Windows walks a search order that often includes the application directory and other writable locations. If you can place a malicious DLL earlier in that order, or supply a DLL the app expects but does not ship (a phantom DLL), your code runs inside the trusted process, frequently with its privileges.
- **How to test:**
  - Watch what the app tries to load and where it fails, with Process Monitor:
    ```
    # ProcMon filters
    Process Name is App.exe
    Operation is CreateFile
    Result is NAME NOT FOUND        # phantom DLLs the app wanted but didn't find
    Path ends with .dll
    ```
  - Identify writable directories in the search path:
    ```powershell
    icacls "C:\Program Files\App"           # look for (M)/(W)/(F) for Users/Authenticated Users
    Get-Acl "C:\Program Files\App" | Format-List
    ```
  - Confirm imports and delay-loads statically:
    ```bash
    dumpbin /dependents App.exe        # or: objdump -p, or the Dependencies GUI tool
    ```
  - Drop a benign proof DLL (one that writes a marker file or pops calc in a lab) matching a missing/hijackable name into a writable search location and confirm it loads. Keep the proof benign and marked.
- **Framework notes:**
  - **Native / .NET:** classic KnownDLLs protections do not cover application-specific DLLs; app-dir planting is the common vector.
  - **Electron:** native `.node` addons and bundled DLLs in `app.asar.unpacked` and the app dir are candidates; the Electron/Chromium runtime loads several platform DLLs.
  - **Installers/updaters** frequently run from `%TEMP%` or `Downloads` and side-load from there, a high-privilege variant if the installer runs elevated.
- **Impact:** Arbitrary code execution in the app's process and privilege context; if the app or its installer/service runs elevated, this is local privilege escalation and a persistence mechanism.
- **Remediation:** Load libraries by full validated path, call `SetDefaultDllDirectories`/`SetDllDirectory` to constrain the search path, ship all dependencies, install to non-user-writable directories with correct ACLs, and verify the signature of every DLL before loading.

---

### Anti-Tamper and Integrity-Check Bypass

- **What & why:** Some clients self-check (hashing their own code, detecting patches or debuggers) to protect license logic or client-side decisions. Because the check runs on the attacker's machine, it can be found and neutralized. Testing it establishes whether integrity is a real control or a speed bump.
- **How to test:**
  - Locate the check by reversing (look for self-reads of the module, hashing routines, calls that abort on mismatch) or dynamically by watching where execution diverges after a patch.
  - Patch statically (edit the binary so the check's branch always passes) or dynamically (hook the check function to return success, see the Runtime & Memory chapter for Frida usage).
  - Re-run the prior tampering tests after the bypass to confirm the integrity gate was the only thing standing between you and a modified client.
- **Framework notes:**
  - **.NET:** dnSpy edits and re-saves assemblies directly; integrity checks that hash a managed DLL are defeated by patching the checker itself.
  - **Native:** packers/protectors (commercial anti-tamper) raise cost and may combine anti-debug; unpack (see recon) before analysis.
  - **Electron:** ASAR integrity is the built-in mechanism; without it there is usually nothing to bypass.
- **Impact:** Removal of the last client-side barrier protecting license checks, feature gates, or tamper detection; enables a fully modified client.
- **Remediation:** Do not rely on client-side integrity to protect security decisions; enforce them server-side. Use anti-tamper only to raise attacker cost and to detect (report server-side), never as the sole control.

---

### Writable Install and Execution Paths (Local Privilege Escalation)

- **What & why:** If an app, its service, or its updater executes binaries from a location a low-privileged user can write to, and runs with higher privilege, a standard user can replace that binary and escalate. Weak install-directory ACLs, unquoted service paths, and writable `%ProgramData%` staging are the usual culprits.
- **How to test:**
  - Audit ACLs on the install dir, any service binaries, and update-staging dirs:
    ```powershell
    icacls "C:\Program Files\App"
    icacls "C:\ProgramData\App"
    Get-CimInstance Win32_Service | Where-Object {$_.PathName -like "*App*"} |
      Select-Object Name,StartName,PathName        # StartName = LocalSystem is the prize
    ```
  - Check for unquoted service paths with spaces (`C:\Program Files\App\svc.exe` unquoted lets `C:\Program.exe` win) and for services whose binary or folder is user-writable.
  - Use PowerUp / winPEAS to enumerate these automatically:
    ```powershell
    powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"
    ```
  - Where a writable path feeding an elevated exec is found, drop a benign proof payload (marker file as the elevated user) to demonstrate, never a real backdoor.
- **Framework notes:** Applies to any framework; the risk lives in the installer/service/updater, not the UI runtime. MSI custom actions and updater helper services running as SYSTEM are common high-value targets (see the recon installer section and the Update Mechanism chapter).
- **Impact:** Local privilege escalation from standard user to SYSTEM/admin; persistent, reliable, and often trivial once a writable elevated path is found.
- **Remediation:** Install to protected directories, set least-privilege ACLs (no write for standard users on anything executed with elevation), quote all service paths, and have elevated helpers validate the signature of anything they execute.

---

### Binary Hardening Flags (ASLR / DEP / CFG)

- **What & why:** Exploit-mitigation flags (ASLR, DEP/NX, Control Flow Guard, stack canaries, safe SEH, CET) do not stop logic bugs but raise the cost of memory-corruption exploitation. Their absence in a native thick client is a real finding and a force-multiplier for any memory bug you find.
- **How to test:**
  - Check Windows PE mitigations:
    ```
    winchecksec App.exe
    # or PowerShell PESecurity: Get-PESecurity -file App.exe
    ```
    Look for `Dynamic Base` (ASLR), `NX` (DEP), `Control Flow Guard`, `SafeSEH`, `GS` (stack cookies), `High Entropy VA`.
  - Check macOS/Linux binaries:
    ```bash
    checksec --file=./app          # RELRO, canary, NX, PIE, fortify
    otool -hv app                  # macOS: PIE flag in the Mach-O header
    ```
  - Note DLLs too; one non-ASLR module can undermine process-wide ASLR.
- **Framework notes:** Most relevant to native/C++/Qt/Delphi and native `.node` addons. Managed (.NET/Java) code is less exposed to classic memory corruption but the native host and any unmanaged dependencies still matter.
- **Impact:** Missing mitigations turn a memory-safety bug from hard-to-exploit into practical code execution; on their own they are a hardening finding.
- **Remediation:** Compile with ASLR/high-entropy, DEP/NX, CFG (or CET where available), stack cookies, and RELRO/PIE on Unix; ensure every shipped module is built with the same flags.
