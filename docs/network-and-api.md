# Network & API

Thick clients talk to servers, and unlike a browser they do it on their own terms: their own HTTP stack, their own idea of what a valid certificate is, and sometimes their own little web server bound to `127.0.0.1`. This chapter is about getting between the app and the wire, defeating the transport protections it puts in your way (on a target you are authorized to test), and then abusing everything the client wrongly assumes it can trust. The recurring lesson: the client is not a security boundary, no matter how badly it wants to be.

**Techniques**

- Intercepting thick-client traffic (system proxy, mitmproxy, Burp)
- When the app ignores the system proxy (proxifiers, forced routing, hooking)
- Detecting and bypassing TLS certificate pinning
- Certificate validation flaws (disabled / self-signed / any-cert)
- Client-side-only trust (tampering with server responses)
- Local HTTP / WebSocket servers the app stands up

---

### Intercepting Thick-Client Traffic

**What & why**
Before you can test an API you have to see it. Web apps hand you their traffic through the browser's proxy settings; thick clients are inconsistent, and step one of every engagement is establishing a clean man-in-the-middle on a host you control. Everything downstream (auth flaws, IDOR, mass assignment, business-logic abuse) depends on this working.

**How to test**
- Set a system-wide proxy and point it at your interceptor. On Windows: Settings > Network > Proxy, or `netsh winhttp set proxy 127.0.0.1:8080` (WinHTTP-based apps honor this even when the WinINET/IE proxy does not). Install the interceptor CA into the correct store (below).
- **Burp Suite**: Proxy > Options, add an all-interfaces or loopback listener, then drive the app. Use the "Non-proxy-aware clients" invisible-proxy listener plus host redirection when the client speaks TLS straight to a hostname without a `CONNECT`.
- **mitmproxy** for CLI/scriptable work: `mitmproxy -p 8080`, or `mitmweb` for a browser UI. Transparent mode (`mitmproxy --mode transparent`) with OS-level redirection catches apps that never read a proxy setting. `mitmdump -s addon.py` lets you rewrite flows programmatically.
- Confirm capture on plain HTTP first, then HTTPS after the CA is trusted. No traffic at all usually means the app is not proxy-aware (next technique).

**Framework notes**
- **Electron/Chromium**: uses Chromium's network stack; honors system proxy and the `--proxy-server=` switch. Chromium maintains its own root policy but generally consults the OS trust store for user-added CAs on Windows/macOS.
- **.NET (`HttpClient`/`WebClient`)**: `HttpClient` via `SocketsHttpHandler` reads `HttpClient.DefaultProxy`, which on Windows is seeded from WinINET/system settings and from the `HTTP(S)_PROXY` environment variables on modern .NET. Some apps set `Proxy = null` explicitly.
- **Java**: obeys `-Dhttp.proxyHost`/`-Dhttps.proxyHost` and, if the app opts in, `-Djava.net.useSystemProxies=true`. It uses its own `cacerts` truststore, not the OS store.
- **Native (WinHTTP/libcurl/custom)**: WinHTTP honors `netsh winhttp`. Statically linked libcurl or raw sockets may honor nothing.

**Impact**
Full visibility and modification of the client/server conversation; the foundation for testing every server-side and trust flaw.

**Remediation**
Not a client bug per se, but assume traffic is observable and modifiable and enforce all security decisions server-side.

---

### When the App Ignores the System Proxy

**What & why**
Many thick clients read no proxy setting, hardcode a direct connection, or deliberately bypass proxies. You need to force their traffic through your interceptor without their cooperation.

**How to test**
- **Confirm the behavior**: watch connections live. `netstat -bano` (Windows, elevated, shows owning PID/image) or `ss -tnp` / `netstat -tnp` (Linux) while the app runs shows where it is actually connecting. On Windows, Sysinternals **TCPView** or **Process Monitor** give a live per-process view.
- **Proxifiers** force a chosen process through a proxy at the socket layer regardless of app settings: **Proxifier** (commercial) with a rule targeting the app's executable and forwarding to your interceptor; on Linux, **proxychains-ng** (`proxychains4 ./app`) via a SOCKS proxy (mitmproxy exposes one with `--mode socks5`).
- **OS-level redirection / transparent proxy**: redirect outbound 443 to your transparent listener. Linux: `iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080`. This catches apps that ignore proxies entirely.
- **DNS redirection**: point the API hostname at your box via the `hosts` file, terminate TLS locally, and forward upstream. Useful when the app connects by name and pins nothing.
- **Hooking**: when routing alone is not enough, hook the networking functions. **Frida** to intercept `connect`/`send`/TLS calls, or hook the specific HTTP library. For .NET, **Fiddler** with the app forced through it, or hooking `HttpClientHandler`. This overlaps heavily with pinning bypass below.

**Framework notes**
- Env-var-driven stacks (modern .NET, Java with the right flags, libcurl) are easiest: set `HTTPS_PROXY` in the app's environment.
- Chromium/Electron apps almost always route through the system proxy or accept `--proxy-server`, so proxifiers are rarely needed.
- Statically compiled Go binaries honor `HTTPS_PROXY`/`HTTP_PROXY` env vars by default via `net/http`, but ignore OS proxy config; env var first, transparent redirect second.

**Impact**
Restores interception against apps engineered (accidentally or intentionally) to avoid it.

**Remediation**
Bypassing a proxy is not a defense; it only slows an authorized tester and does nothing against a determined attacker on the same host.

---

### Detecting and Bypassing Certificate Pinning

**What & why**
Pinning makes the client reject any certificate except an expected one (a specific cert, public key, or CA), so even with your CA trusted the TLS handshake fails. On your own authorized target you bypass it to continue testing; the exercise also documents how strong (or weak) the pinning actually is.

**How to test — detect**
- Trust your interceptor CA, then connect. If plain-CA MITM works for other apps but this one drops the connection or throws a TLS/handshake error immediately after ClientHello, suspect pinning.
- Inspect the binary/resources for embedded certs or public-key hashes: `strings` on the executable, search app resources for `.cer`/`.pem`/base64 SPKI blobs, and look for pinning library references.

**How to test — bypass**
- **Custom CA install (try first)**: some "pinning" is just normal validation. Install your CA in the right store and retest before assuming real pinning.
- **Frida-based unpinning**: the general-purpose approach. Attach with `frida -f ./app.exe -l unpin.js` (or via `frida-trace`) and hook the validation routine to force success. Target the framework's verify function: schannel/`CertVerifyCertificateChainPolicy` on Windows native, OpenSSL `SSL_CTX_set_verify`/`X509_verify_cert`, .NET `ServerCertificateValidationCallback`, or Java `X509TrustManager.checkServerTrusted`. `frida-trace -i "*verify*"` helps locate the call.
- **Patching**: statically patch the check when hooking is impractical, editing the binary so the validation branch always returns success. Durable but invasive; keep an unmodified copy.
- **Swap the pinned material**: if the pin is a bundled CA/cert file on disk and the app loads it at runtime, replacing that file with your CA can be the least-effort bypass.

**Framework notes**
- **.NET**: pinning is usually in `ServicePointManager.ServerCertificateValidationCallback` or `HttpClientHandler.ServerCertificateCustomValidationCallback` comparing a thumbprint/public key. Hook or patch the callback.
- **Java**: custom `TrustManager`/`HostnameVerifier`, or OkHttp's `CertificatePinner`. Hook `checkServerTrusted` or clear the pinner.
- **Electron/Chromium**: rarely pins in JS; may use Chromium's own mechanisms or a native module. App-layer pins in JS are trivial to patch in the (often unpacked) `app.asar`.
- **Native/OpenSSL/schannel**: hook the C verification functions directly with Frida.

**Impact**
Interception of otherwise-protected traffic; enables full API testing on the authorized target.

**Remediation**
Pin correctly (SPKI pins with backup pins and a rotation plan), but treat pinning as anti-tampering friction, not a trust boundary; still authorize and authenticate server-side.

---

### Certificate Validation Flaws

**What & why**
The opposite failure: the client accepts certificates it should reject. Disabled validation, accepting any/self-signed cert, or ignoring hostname mismatch means a real network attacker (not just an authorized tester with a trusted CA) can MITM the app. This is a genuine vulnerability, not just a test hurdle.

**How to test**
- MITM with a certificate you did **not** add to any trust store: a self-signed cert, a cert for the wrong hostname, and an expired cert. If the app connects anyway, validation is broken.
- mitmproxy/Burp will present their leaf cert; observe whether the client complains. Test each failure mode separately (untrusted issuer vs. hostname mismatch vs. expiry) because apps often check one and not the others.
- Static confirmation: search for tell-tale disabled-validation code (below).

**Framework notes**
- **.NET**: `ServerCertificateValidationCallback = (s, c, ch, e) => true` (or `ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator`) accepts everything. Very common in the wild.
- **Java**: an all-trusting `X509TrustManager` whose `checkServerTrusted` is empty, or `HostnameVerifier` returning `true` unconditionally.
- **Node/Electron**: `rejectUnauthorized: false` on TLS/HTTPS options, or `NODE_TLS_REJECT_UNAUTHORIZED=0` in the environment.
- **Python-based clients**: `verify=False` in `requests`, or an unverified `ssl` context.
- **Native/libcurl**: `CURLOPT_SSL_VERIFYPEER`/`CURLOPT_SSL_VERIFYHOST` set to 0.

**Impact**
Network-position attacker can intercept and modify all traffic, harvest credentials and tokens, and impersonate the server. Especially severe on untrusted networks.

**Remediation**
Use the platform default validation; never disable it. Remove any accept-all callbacks and unverified contexts before shipping. If self-signed certs are genuinely required for an internal deployment, trust the specific CA explicitly rather than disabling checks.

---

### Client-Side-Only Trust (Tampering With Server Responses)

**What & why**
Thick clients frequently enforce restrictions locally based on server responses: a JSON flag like `"isAdmin": false`, `"licensed": true`, a feature list, a price, or an "account locked" state. If the server trusts the client to honor these, rewriting the response in transit unlocks functionality or bypasses controls the server never re-checks.

**How to test**
- With interception established, intercept responses (Burp: Proxy > Options > Intercept Server Responses, or match/replace rules; mitmproxy: a response-editing addon or interactive edit).
- Flip boolean flags (`false`→`true`), change roles/tiers, unhide menu items, alter quantities/prices/limits, and change error/status codes (e.g., turn a `403` auth failure into a `200` success body the client accepts).
- Then perform the privileged action and watch the **next request**. The real question is whether the server re-authorizes it. If the follow-up request succeeds server-side, it is a genuine authorization flaw; if the server rejects it, the client-side unlock is cosmetic (still worth reporting as defense-in-depth, but lower severity).
- Automate with match-and-replace so the unlock persists across the session.

**Framework notes**
- Framework-independent; it is a design flaw in trust placement, not a stack bug. Electron apps make it easiest because UI gating lives in inspectable JS, but the tampering happens on the wire and applies to .NET, Java, and native clients equally.
- Watch for client-side signature/HMAC checks on responses; if present, you may need the signing logic (often recoverable from the binary) or a Frida hook on the verification function.

**Impact**
Privilege escalation, license/paywall bypass, and access to hidden or disabled features whenever the server relies on the client to enforce a restriction it does not re-check.

**Remediation**
Enforce every authorization, entitlement, and business rule on the server for every request. Treat the client purely as presentation. Client-side gating is UX, never security.

---

### Local HTTP / WebSocket Servers the App Stands Up

**What & why**
Many desktop apps run a local server (helper daemon, IPC bridge, auth-callback listener, dev/debug endpoint, updater) bound to `localhost`. If it is unauthenticated, accepts requests from arbitrary origins, or can be reached via DNS rebinding, a malicious web page the user merely visits, or another local process, can drive privileged functionality.

**How to test**
- **Find the listener**: `netstat -bano` (Windows, shows owning process) or `ss -ltnp` / `lsof -iTCP -sTCP:LISTEN -P` (Linux/macOS). Note whether it binds `127.0.0.1`/`::1` (local only) or `0.0.0.0` (exposed to the network, worse). Correlate the PID to the app.
- **Enumerate the API**: browse to `http://127.0.0.1:<port>/`, fuzz paths, and inspect the app's own traffic to learn the routes. For WebSockets, connect with `websocat ws://127.0.0.1:<port>` or a browser console and probe the message protocol.
- **Authentication**: does it require a token/nonce, or will any request work? Replay the app's requests without whatever header/cookie the app sends.
- **CSRF from a browser**: build a page that issues `fetch`/`XMLHttpRequest`/form posts or a `WebSocket` connection to `http://127.0.0.1:<port>` and see whether the browser is allowed through. Check the CORS headers and whether the server validates `Origin`. WebSocket servers frequently do **not** check `Origin`, so any site can open a socket. A `GET` image/script/form can hit endpoints even without CORS if the action is state-changing and unauthenticated.
- **DNS rebinding**: if the server accepts requests based on a `Host`/hostname rather than validating it, an attacker-controlled domain that rebinds to `127.0.0.1` can bypass same-origin protections. Test whether the server rejects unexpected `Host` headers; tools like a rebinding service or a manual short-TTL DNS setup demonstrate it. Servers that only check the source IP is loopback do not stop rebinding.

**Framework notes**
- **Electron/Node**: often an `express`/`ws`/`http` server for OAuth callbacks or IPC. Check for missing `Origin` validation on the `ws` upgrade and permissive CORS (`Access-Control-Allow-Origin: *` with credentials).
- **.NET**: `HttpListener`, Kestrel, or a self-hosted Web API on a loopback port; look for `[EnableCors]` set wide open and absent auth filters.
- **Java**: an embedded Jetty/Netty/gRPC or similar listener; check the bind address and auth interceptors.
- **Native**: a custom socket server; more likely to lack any HTTP niceties and any auth, and to speak a bespoke protocol worth reversing.

**Impact**
Remote-ish attack surface from the local machine: a visited web page or a low-privilege local process invoking privileged app functionality (config changes, file operations, command execution, token theft), often with no user interaction beyond browsing.

**Remediation**
Bind to loopback only; require a per-session secret/token the browser cannot guess or read cross-origin; validate the `Origin` header on both HTTP (CORS) and WebSocket upgrades against an allowlist; validate the `Host` header to defeat DNS rebinding; and authenticate every local endpoint as if it were internet-facing. Do not assume "localhost" means "trusted."
