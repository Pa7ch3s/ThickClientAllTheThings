# The Embedded Web Layer

Many "desktop" applications are a browser wearing a native coat: Electron, Chromium Embedded Framework (CEF), or Microsoft Edge WebView2 rendering HTML/JS inside a process that also holds OS-level privilege. The security of these apps lives or dies at the seam where web content meets native code, so the tester's job is to find every place that seam is thinner than it should be. This chapter is methodology for authorized assessments: read the configuration, map the trust boundary, then prove what crosses it.

Techniques covered:

- Auditing Electron `webPreferences`
- Preload / `contextBridge` over-exposure
- Navigation and window-open handling
- Content-Security-Policy in a desktop context
- The XSS-to-RCE chain
- CEF and WebView2 host-object equivalents

---

### Auditing Electron webPreferences

**What & why**
`webPreferences` on a `BrowserWindow`/`BrowserView` (and `<webview>` tag attributes) decides how much of Node.js and the OS the renderer can touch. Insecure combinations turn an ordinary DOM injection into direct host access. The dangerous flags:

- `nodeIntegration: true` — renderer gets `require`, `process`, and Node built-ins in page context.
- `contextIsolation: false` — preload and page share one JS context, so page script can reach preload internals and prototypes.
- `sandbox: false` — renderer is not confined to the Chromium sandbox; a compromised renderer has far more reach.
- `webSecurity: false` — disables same-origin policy and related protections in that renderer.
- `allowRunningInsecureContent: true` — permits mixed HTTP content on an HTTPS page.
- `nodeIntegrationInSubFrames`, `nodeIntegrationInWorker`, `enableRemoteModule` (legacy `@electron/remote`) — additional exposure surfaces.

**How to test**
1. Get the app source. Unpack `resources/app.asar` with `npx @electron/asar extract app.asar out/` (or `asar extract`). If it is a plain `app/` folder, read it directly.
2. Grep for every window construction and its options: `webPreferences`, `new BrowserWindow`, `new BrowserView`, `<webview`, `nodeIntegration`, `contextIsolation`, `sandbox`, `webSecurity`.
3. Record the resolved value per window, remembering the modern secure defaults (`contextIsolation: true`, `nodeIntegration: false`, `sandbox: true` when the app opts into sandboxing). Flag any window that overrides them, and note the Electron version from `package.json` — old majors shipped weaker defaults.
4. Confirm at runtime. Launch with an inspector where allowed (e.g. `--inspect` / `--remote-debugging-port`) or via the app's own devtools if exposed, and in a controllable renderer evaluate `typeof require`, `typeof process`, `process?.type`. A defined `require` in page context is a finding on its own.

**Framework notes**
This section is Electron-specific. CEF and WebView2 have no Node bridge; their equivalent risk is host-object exposure (below).

**Impact**
`nodeIntegration: true` with any script injection is effectively host code execution. `contextIsolation: false` breaks the guarantee that a wide bridge relies on. `webSecurity: false` re-opens cross-origin data theft and SSRF-like fetches from the app origin.

**Remediation**
Keep the secure defaults: `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`. Never disable `webSecurity`. Do not re-enable `@electron/remote`. Set these per window and treat any exception as a reviewed, documented risk.

---

### Preload / contextBridge over-exposure

**What & why**
With isolation on, the preload script is the sanctioned bridge between page and native. `contextBridge.exposeInMainWorld` publishes an API object to the page. The vulnerability is a *wide* bridge: exposing generic capability instead of narrow, named operations effectively re-opens the boundary that isolation just closed.

Red flags:
- Exposing `ipcRenderer` directly, or an `invoke`/`send` that forwards an arbitrary channel plus arbitrary args to main.
- Exposing methods that take a caller-controlled path, command, URL, or module name (`readFile`, `exec`, `openExternal`, `loadModule`).
- Passing functions or live objects across the bridge in a way the page can weaponize as callbacks.

**How to test**
1. Read every preload file (`webPreferences.preload` paths). Enumerate each `exposeInMainWorld` key and every method it hangs off.
2. For each method, trace the corresponding `ipcMain.handle` / `ipcMain.on` in the main process. Ask: what does the page control, and does main validate it? A handler that does `fs`, `child_process`, shell, or dynamic `require` on page-supplied input is the prize.
3. Check whether the exposed surface is generic (`api.invoke(channel, ...args)`) versus intent-named (`api.getUserProfile()`). Generic forwarding is the classic over-exposure.
4. From a renderer you can drive, enumerate `Object.keys(window.<exposedName>)` and probe each method against a benign, in-scope target to map real reach.

**Framework notes**
CEF: the analogue is registered JS bindings / `CefV8Handler` native functions and the async message-router — audit the router handler for the same "does it act on untrusted args" question. WebView2: `AddHostObjectToScript` and `postMessage` handlers (below).

**Impact**
A single over-broad bridge method can hand the page arbitrary IPC, file, or process access even with `contextIsolation` and `sandbox` fully on. This is the most common real-world thick-client web finding.

**Remediation**
Expose the minimum: specific, named, intent-revealing functions. Validate and allowlist channels and arguments on the main side, never trust the renderer. Do not expose `ipcRenderer` or any raw forwarder. Return plain serializable data.

---

### Navigation and window-open handling

**What & why**
A privileged renderer that navigates to attacker-influenced content inherits that window's privileges. If the app follows links, opens popups, or loads remote URLs into a window with weak `webPreferences`, external content runs with internal trust. The controls are the main-process `webContents` events.

**How to test**
1. Find handlers for `will-navigate`, `will-redirect`, `setWindowOpenHandler` (current API), and the legacy `new-window` event. Confirm each exists and what it allows.
2. Verify `will-navigate` cancels (`event.preventDefault()`) navigations whose origin is not an internal allowlist. Absence of any handler means the window will follow arbitrary links.
3. Verify `setWindowOpenHandler` returns `{ action: 'deny' }` for untrusted URLs and routes legitimate external links to the OS browser via `shell.openExternal` (after its own URL validation, not blindly).
4. Map what content each window loads: local `file://`/`app://` only, or remote HTTPS, or user-supplied HTML. A window that both loads remote content and carries elevated `webPreferences` is a direct finding.
5. Check `webContents.on('did-attach-webview')` for any code that mutates child `webPreferences`.

**Framework notes**
CEF: `CefRequestHandler::OnBeforeBrowse` and life-span/popup handling play the navigation-gating role. WebView2: `NavigationStarting`, `NewWindowRequested`, and `FrameNavigationStarting` events, plus the `Source`/host mapping that determines what "internal" means.

**Impact**
Loading untrusted content into a privileged window collapses the whole model — it is remote content with local capability, the shortest path from a phishing link or a compromised web dependency to host access.

**Remediation**
Deny window-open by default and allowlist. Cancel off-origin navigation. Open external links only in the system browser. Keep any window that touches remote content stripped to browser-only privileges (isolation on, node off, sandbox on).

---

### Content-Security-Policy in a desktop context

**What & why**
CSP is the last line that stops an injected string from becoming executing script, and it matters *more* in a privileged renderer because the blast radius is host access, not cookie theft. Desktop apps frequently ship no CSP, a meta-tag CSP that is trivially bypassed, or one loosened with `unsafe-inline`/`unsafe-eval` to accommodate a framework.

**How to test**
1. Look for CSP set two ways: a `<meta http-equiv="Content-Security-Policy">` in the HTML, and/or a header injected via `session.webRequest.onHeadersReceived`. Note that a `meta` CSP does not cover things a real header does (e.g. it cannot govern the initial document the way a header can) — prefer the header form.
2. Inspect the directives. Flag `script-src` containing `unsafe-inline`, `unsafe-eval`, `*`, remote CDNs, or `data:`. Flag missing `default-src`/`object-src`. `unsafe-eval` is common because bundlers/`eval`-using libs need it — call it out.
3. Confirm the policy actually applies to every window and to child frames/`webview`s, not just the main index.
4. Where authorized, test a benign injection (e.g. an element whose handler writes a sentinel to the DOM) to observe whether inline execution is blocked in practice.

**Framework notes**
CEF and WebView2 render Chromium too, so CSP semantics are identical; deliver it via the host app's response handling (`OnResourceResponse`/interception in CEF, `WebResourceResponseReceived`/host mapping in WebView2) or the served document headers.

**Impact**
A strong CSP can neutralize an XSS bug before it reaches the RCE chain; a missing or `unsafe-*` CSP removes that safety net entirely.

**Remediation**
Ship a strict header-based CSP: no `unsafe-inline`, avoid `unsafe-eval` (refactor the code that needs it), lock `script-src`/`object-src`/`default-src` to `'self'` and known local schemes, apply it to every renderer including child frames.

---

### The XSS-to-RCE chain

**What & why**
In a browser, XSS steals sessions; in a thick client it can reach the host. The chain is: (1) a rendering/injection sink executes attacker-controlled script, (2) that script reaches a native capability — Node globals from `nodeIntegration`, a preload bridge method, or `@electron/remote` — (3) the capability performs a host action (spawn process, write file, load native module). Your assessment demonstrates the whole path, not just step one.

**How to test**
1. Find injection sinks: `innerHTML`/`outerHTML`, `document.write`, `dangerouslySetInnerHTML`, jQuery `.html()`, template rendering without escaping, and any place untrusted data (file contents, chat messages, filenames, URLs, update notes, deep-link params) lands in the DOM.
2. Trace whether attacker data actually reaches a sink unescaped, and whether a framework's default escaping is being bypassed.
3. Establish what the renderer can reach from step one: is `require`/`process` present, or is there a reachable bridge/remote method? Combine the two findings.
4. Prove impact conservatively and in scope: a controlled marker (spawn a benign process that writes a timestamped sentinel file, or read a non-sensitive known path) is sufficient evidence. Do not deploy real payloads.
5. Consider the delivery vector that makes it externally reachable: rendered remote content, protocol/deep-link handlers, opened documents, or a poisoned dependency.

**Framework notes**
Electron is the sharpest because of Node reachability. CEF/WebView2 reach the host only through the app's registered bindings/host objects, so the chain's step two is "reach an exposed host object method" rather than "reach `require`".

**Impact**
Full host code execution in the user's context — the most severe outcome for a desktop app, often wormable through shared/rendered content.

**Remediation**
Fix both ends: eliminate the injection sink (escape/sanitize, prefer safe rendering APIs, use a vetted sanitizer for any HTML that must render), and starve the second stage (isolation on, node off, minimal bridge, strict CSP) so a residual injection has nothing privileged to call.

---

### CEF and WebView2 host-object equivalents

**What & why**
CEF and WebView2 lack a Node bridge, but they offer their own paths from JavaScript to native code, and the same "wide, unvalidated surface" mistakes apply. The assessment questions are identical: what is exposed, and does native trust page-supplied input.

**How to test — WebView2**
1. Search host (C#/C++) code for `AddHostObjectToScript`: every object exposed there is callable from JS as `chrome.webview.hostObjects.<name>`. Audit each method for path/command/URL parameters acted on without validation.
2. Review the `WebMessageReceived` handler (`postMessage` channel) for a generic command dispatcher over page-controlled strings.
3. Check `SetVirtualHostNameToFolderMapping` — a virtual host that maps a folder into the WebView origin. Verify the mapped folder holds only intended assets and the access kind is appropriately restrictive, since content served there is treated as that origin. Confirm `AreHostObjectsAllowed`, and how untrusted navigations are gated (`NavigationStarting`/`NewWindowRequested`).
4. Note whether the app loads remote content into a WebView that also exposes host objects — the WebView2 analogue of a privileged remote window.

**How to test — CEF**
1. Find registered JS bindings via `CefV8Handler`/`CefV8Value::CreateFunction` and window bindings created in `OnContextCreated`; and inspect the async message router (`CefMessageRouterBrowserSide`) handler.
2. Audit each native function/handler for acting on untrusted arguments, exactly as with an Electron IPC handler.
3. Review `OnBeforeBrowse`, resource/scheme handlers, and popup life-span handling for navigation gating and for how untrusted or remote content is confined.

**Framework notes**
Both are Chromium, so CSP and DOM-sink analysis carry over unchanged; only the native-reach mechanism differs (host objects / V8 bindings / message routers instead of Node).

**Impact**
An over-broad host object or message handler yields the same XSS-to-RCE outcome as an over-broad Electron bridge: page script driving native operations.

**Remediation**
Expose only narrow, validated, intent-named host methods; validate every argument native-side. Keep host objects off any WebView/browser that renders untrusted or remote content, restrict virtual host mappings to the minimum folder and access level, and gate navigation to an allowlist.

---

*Scope note: perform this work only against applications you are authorized to assess. Prove impact with benign, controlled indicators; capture the configuration and the reachable path as evidence, and stop short of any action beyond the agreed rules of engagement.*
