# Deep Links & Protocol Handlers

A custom URI scheme turns a link into a function call on someone's machine. When a desktop app registers `myapp://`, any web page, chat message, or document can invoke it, and whatever the handler does with the rest of that URI is now reachable from outside the app's trust boundary. This chapter is about finding those handlers, tracing where their input goes, and proving the one-click paths that end in an app action or code execution.

Techniques covered:

- Enumerating registered URI schemes
- Argument and path-traversal injection via handler input
- Command execution through handler sinks
- One-click attack paths
- Electron and Tauri deep-link handling

---

### Enumerating Registered URI Schemes

- **What & why:** You cannot test a handler you have not found. Each OS records custom schemes differently; enumerate them to learn the app's externally reachable entry points and the exact command line the OS runs when the scheme fires.
- **How to test:**
  - **Windows** (schemes live under `HKCR` / `HKCU\Software\Classes` with a `URL Protocol` value; the command is in `shell\open\command`):
    ```powershell
    # find every registered protocol
    Get-ChildItem Registry::HKEY_CLASSES_ROOT |
      Where-Object { $_.GetValue('URL Protocol') -ne $null } | Select-Object Name
    # read the launch command for one scheme
    reg query "HKCR\myapp\shell\open\command"
    ```
    Note the `"%1"` placeholder, that is where the full URI is substituted into the command line.
  - **macOS** (declared in the app's `Info.plist` under `CFBundleURLTypes`):
    ```bash
    /usr/libexec/PlistBuddy -c "Print :CFBundleURLTypes" /Applications/App.app/Contents/Info.plist
    # or query Launch Services for who owns a scheme
    ```
  - **Linux** (`.desktop` files with `MimeType=x-scheme-handler/myapp` and an `Exec=` line):
    ```bash
    grep -rl 'x-scheme-handler/' ~/.local/share/applications /usr/share/applications
    xdg-mime query default x-scheme-handler/myapp
    ```
- **Framework notes:** Electron/Tauri apps register schemes through their own APIs (below) but still land in these OS stores, so enumeration is identical. Watch for multiple schemes per app and for overly generic scheme names that other software might also claim.
- **Impact:** None on its own; this maps the externally reachable surface every later test targets.
- **Remediation:** Register only the schemes you need, with specific non-generic names, and treat every registered scheme as untrusted input.

---

### Argument and Path-Traversal Injection

- **What & why:** The OS substitutes the attacker-controlled URI into a command line or passes it as an argument. If the handler splits, interpolates, or passes that string to a file operation or another program without validation, you can inject extra arguments or traverse paths, before any application-level logic runs.
- **How to test:**
  - Read the launch command (above) and note whether the URI lands in `"%1"` (quoted, one arg) or unquoted. Craft URIs that break out:
    ```
    myapp://open?file=..\..\..\Windows\System32\drivers\etc\hosts
    myapp://action" --extra-flag "injected
    myapp://x%20--debug           # URL-encoded space to smuggle a second token
    ```
  - Trace where the parsed value goes in the decompiled/unpacked handler (see recon): file reads/writes, template strings, spawn calls, loads of local resources.
  - Test path traversal specifically against any parameter used as a filename or path; confirm whether the app will open, read, or write outside its intended directory.
- **Framework notes:**
  - **Electron/Chromium** flag smuggling: historically, a URL that introduced extra `--` tokens could reach the Chromium/Node command line; always test whether handler input can add process flags.
  - **Windows** unquoted `%1` is the classic argument-injection enabler.
- **Impact:** Reading or writing files outside scope, injecting process flags that change the app's security posture, and setting up the command-execution sinks below.
- **Remediation:** Always quote `%1`; parse the URI with a strict URL parser, allowlist schemes/hosts/paths/parameters, canonicalize and reject traversal, and never concatenate handler input into a command line or path.

---

### Command Execution Through Handler Sinks

- **What & why:** The high-severity outcome: handler input reaches a shell, an interpreter, or a spawn call. A single crafted link then runs attacker-chosen commands in the app's context.
- **How to test:**
  - In the handler code, follow the URI value to any sink: `child_process.exec`/`spawn` (Node), `Process.Start`/`ShellExecute` (.NET/Win32), `Runtime.exec` (Java), `system`/`popen`/`CreateProcess` (native), `shell.openExternal`/`shell.openPath` (Electron).
  - Where input reaches a sink, build a proof URI that runs a benign, obviously-yours command (write a marker file, launch calc in a lab), never a destructive or real payload:
    ```
    myapp://run?cmd=... (lab-only, benign marker)
    ```
  - Confirm privilege context of the resulting process and whether any user confirmation is shown.
- **Framework notes:**
  - **Electron:** `shell.openExternal` with attacker-controlled input is a recurring RCE path (it can launch other protocol handlers, including OS ones); `shell.openPath` and `openExternal` on `file:`/`smb:` are dangerous.
  - **Java:** `Runtime.exec` with a composed string is the classic sink.
  - **Native:** unsanitized `system()`/`ShellExecute` on handler input.
- **Impact:** Remote-triggered, one-click code execution in the app's process and privilege level, the top-severity deep-link finding.
- **Remediation:** Never pass handler input to a shell or `openExternal`; use argument arrays (no shell), allowlist the exact actions a scheme may perform, and require explicit user confirmation for anything that launches a process or opens an external target.

---

### One-Click Attack Paths

- **What & why:** Deep-link bugs are dangerous because delivery is trivial: a link in a web page, email, PDF, or chat. Some browsers auto-dispatch known schemes or prompt with a single click. The realistic threat model is "victim clicks a link," so demonstrate the full chain from a hosted page to the app action.
- **How to test:**
  - Host a benign test page in your lab that triggers the scheme and observe the browser/OS prompt behavior:
    ```html
    <a href="myapp://action?param=PROOF">click</a>
    <iframe src="myapp://action?param=PROOF"></iframe>   <!-- test auto-dispatch -->
    <script>location.href = "myapp://action?param=PROOF"</script>
    ```
  - Note how much user interaction is required (silent, one click, or a dialog) and whether the origin of the triggering page is visible or checked by the app.
  - Chain with the injection/command sinks above to show end-to-end impact from a page visit or single click.
- **Framework notes:** Behavior varies by browser and OS version; test the app's actual supported browsers. A handler that trusts input because "it came from our own web app" is wrong, any origin can invoke the scheme.
- **Impact:** Full weaponization of a handler flaw through everyday delivery channels; converts a local parsing bug into a remotely triggered attack.
- **Remediation:** Assume any origin can invoke your scheme; do not tie trust to the assumption that your own site sent the link. Require confirmation for sensitive actions and design handlers to be safe even when the caller is hostile.

---

### Electron and Tauri Deep-Link Handling

- **What & why:** These frameworks add their own registration and dispatch layer on top of the OS scheme, with framework-specific footguns around how the incoming URL reaches the app (fresh launch vs. already-running instance).
- **How to test:**
  - **Electron:** find `app.setAsDefaultProtocolClient('myapp')` and how the URL is received: `open-url` (macOS) and the `second-instance` event plus `process.argv` parsing (Windows/Linux). On Windows the deep link arrives as a command-line argument to a new process, so review the `argv` parsing in the `second-instance`/`requestSingleInstanceLock` handler for the injection issues above.
  - **Tauri:** review the deep-link plugin registration and the handler that receives the opened URL; the URL crosses into Rust command handlers, so trace it into any invoked `#[tauri::command]` (see the IPC chapter).
  - In both, confirm the handler validates scheme, host, and parameters before acting, and that it does not forward the URL to `shell.openExternal`/a shell.
- **Framework notes:** macOS delivers via `open-url` while Windows/Linux deliver via argv, so parsing logic often differs per platform, test each. Single-instance apps parse the URL from the second launch's arguments, a commonly under-validated path.
- **Impact:** Same as the generic cases (injection, traversal, command execution), reached through framework-specific dispatch that is easy to under-secure.
- **Remediation:** Validate the full URL against an allowlist in one place, handle the fresh-launch and already-running paths identically, never pass the URL to a shell or `openExternal`, and keep argv parsing strict on Windows/Linux.
