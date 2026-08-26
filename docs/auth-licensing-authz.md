# Authentication, Licensing & Authorization

Thick clients love to make decisions they have no business making. When the binary on the user's desk decides whether the user is authenticated, licensed, or authorized, the user owns that decision, because the user owns the binary. This chapter is about proving that in an authorized assessment: finding the client-side gates, walking through them, and writing up why the fix is always "move the check server-side."

The through-line: **any control enforced only on the client is bypassable by definition.** The attacker controls the CPU, the memory, the disk, the network, and the clock. Your job is to demonstrate that concretely, not to lecture about it.

**Techniques covered:**

- Client-side vs server-side enforcement (the core distinction)
- License check patching and validation-function hooking
- Offline / replay license validation
- Exposed key-generation and crypto logic
- Trial reset and local state manipulation
- Multi-user separation on a shared host
- In-app privilege boundaries and token/session handling

---

### Mapping the Enforcement Boundary

**What & why.** Before bypassing anything, determine *where* each decision is made. Every auth/license/authz control sits somewhere on a spectrum from "fully local" (a boolean in the binary) to "fully server-authoritative" (client displays a state the server enforces). Client-side-only controls are the vulnerable class; the entire chapter reduces to finding them and proving the point. This mapping step is what turns "I patched a jump" into a finding an engineer can act on.

**How to test.**
- Run the app both online and fully offline (pull the NIC / block it at the host firewall with Windows Defender Firewall or `netsh`). Anything that still "works" while offline is enforced locally.
- Watch the network while exercising login, license activation, and privileged features. Use Wireshark for raw traffic, and an intercepting proxy (Burp Suite, mitmproxy, Fiddler) for HTTP/S. For non-HTTP TLS, consider a transparent proxy or SNI inspection to at least characterize the endpoint.
- Correlate UI state changes with (a) network calls, (b) file/registry writes (Process Monitor / ProcMon), and (c) nothing at all. The third case is a client-only gate.
- For .NET, decompile with dnSpy / ILSpy / dotPeek and read the actual logic. For Java, use JD-GUI / Procyon / CFR. For native, load into Ghidra, IDA, or Binary Ninja and locate the decision points.

**Framework notes.**
- **.NET / Electron / Java** apps frequently ship the *entire* license and auth logic on the client because it is trivially readable, making them the highest-yield targets for this mapping.
- **Native (C/C++)** apps still often reduce a server response to a single local branch; find the branch, and you've found the boundary.

**Impact.** Establishes which findings are "client trusts itself" (high impact, systemic) versus "server checks, client only displays" (usually informational). Drives the severity of everything downstream.

**Remediation.** The client must treat every security decision as advisory UI only. Authentication, entitlement, and authorization must be re-derived on a server the user does not control, on every request, from a session the server issued.

---

### License Check Patching

**What & why.** The classic client-only gate: a function returns "licensed / not licensed," and a conditional branch acts on it. Because the code executes in memory the tester controls, the branch can be inverted, NOP'd, or forced to a constant. This is a demonstration technique, not a deliverable, its purpose is to prove the check is not authoritative.

**How to test.**
- Locate the decision: search the decompiled/disassembled code for license, activation, `IsLicensed`, `IsTrial`, `Validate`, expiry, and strings shown in the "unlicensed" UI.
- In a disassembler (Ghidra/IDA/Binary Ninja), trace the returned boolean to its consuming `test`/`cmp`/`jz`/`jnz` and confirm it is the sole gate.
- Demonstrate in-memory first (non-destructive): set a breakpoint at the return in x64dbg / WinDbg (native) or dnSpy's debugger (.NET) and flip the return value. This proves bypassability without shipping a patched binary.
- Only if the engagement requires a persistent PoC, produce a patched copy in a lab, and document the byte(s) changed. Keep the write-up about *methodology and location*, never a redistributable crack of a specific product.

**Framework notes.**
- **.NET:** dnSpy can edit IL and save the assembly directly; the "modify method body" workflow makes the single-branch fragility obvious. Watch for strong-name / signature checks that re-validate the assembly.
- **Native:** expect anti-tamper (checksums, packers like a UPX-style wrapper, or commercial protectors). Note their presence, unpacking a hardened protector may be out of scope, the *finding* (logic is client-side) usually stands regardless.

**Impact.** Full feature unlock / license bypass with no server interaction. Demonstrates the entitlement model has no server-side authority.

**Remediation.** Entitlements must be enforced server-side per feature invocation. If a feature's data or compute lives server-side and is gated by a server-checked entitlement, a patched client gets an unlocked UI and nothing behind it.

---

### Validation-Function Hooking

**What & why.** Rather than patching bytes on disk, intercept the validation function at runtime and control its inputs/outputs. This is often faster than static patching, survives some integrity checks (the disk file is unchanged), and cleanly demonstrates that the function's result is attacker-controlled.

**How to test.**
- Use Frida to hook the validation routine, log its arguments (activation payloads, server responses, keys), and override its return value. `Interceptor.attach` / `Interceptor.replace` for native; the Java and .NET bridges cover managed targets.
- For Windows API-level license logic (registry, time, hardware IDs), API Monitor or Frida hooks on `RegQueryValueEx`, `GetSystemTime`, `GetVolumeInformation`, etc. reveal what the check reads.
- For .NET, dnSpy's debugger or a Harmony-based instrumentation harness can wrap the target method.
- Capture the real server response (if any) once, then replay/forge it through the hook to see whether the client re-verifies or blindly trusts it.

**Framework notes.**
- **Java:** hook via Frida's Java bridge or a `-javaagent` instrumentation agent; JVM reflection makes even "private" validators reachable.
- **Native with anti-hooking:** some protectors detect Frida (named pipes, memory scans). Note detection; a debugger-based approach (x64dbg) may substitute.

**Impact.** Demonstrates the client cannot protect its own decision logic even without modifying files, and exposes exactly what data the "validation" actually inspects.

**Remediation.** Never let a client-resident function be the arbiter. Bind entitlement to a server session; have the server sign short-lived, feature-scoped grants that the server itself re-checks, so a forged client-side return unlocks nothing real.

---

### Offline / Replay License Validation

**What & why.** Many apps validate a license against a server only once (activation) or accept a cached "last known good" response indefinitely. If the client caches an approval and later trusts it without re-verifying, an attacker can replay the approval or run permanently offline. Weak or absent binding (no nonce, no expiry, no device binding) turns one legitimate approval into unlimited use.

**How to test.**
- Activate legitimately (in an authorized lab) while capturing traffic in Burp/mitmproxy. Identify the activation request/response and any stored token/receipt.
- Go offline and relaunch. Does it still work? For how long? A never-expiring offline grant is the finding.
- Replay the captured "approved" response to the client (proxy match-and-replace, or serve a canned response). If the client accepts a replayed response, it isn't verifying freshness.
- Inspect the stored approval on disk/registry for a nonce, timestamp, server signature, and device fingerprint. Missing freshness/binding = replayable.
- Test clock manipulation in tandem (see Trial Reset), roll the system clock back and see if an "expired" grant revives.

**Framework notes.**
- Applies across .NET/Java/native equally, this is a protocol/state design flaw, not a language flaw.
- Watch for locally cached JWTs or license blobs, decode them (jwt.io offline, or `base64`), and check whether the client validates the signature or merely reads the claims.

**Impact.** Perpetual unlicensed use from a single (or forged) approval; license servers effectively bypassed after first contact.

**Remediation.** Require periodic online re-validation with server-issued, short-lived, signed grants that include a nonce, hard expiry, and device binding. The server must reject replays and stale tokens. Treat "offline grace" as a bounded, server-defined window, not an open door.

---

### Exposed Key-Generation & Crypto Logic

**What & why.** If the client can *verify* a license key locally, it contains the algorithm and often the key material to do so, and where verification lives, forgery frequently follows. Symmetric secrets, hardcoded public/private keys, or a fully local key-derivation scheme let a tester generate accepting inputs. This is assessed to prove the licensing crypto is client-recoverable, not to build or distribute a generator.

**How to test.**
- Decompile and read the verification routine. Identify the scheme: checksum/format check, symmetric MAC with an embedded secret, or public-key signature verification.
- Hunt for embedded secrets: strings, entropy scans (binwalk, `strings`, or a custom entropy pass), and hardcoded keys in resources/config. In .NET/Java these are usually plainly readable.
- If a *private* signing key or a symmetric secret is embedded, that is the whole ballgame, document that keys sufficient to mint valid licenses are recoverable from the client. Do **not** publish working forgeries of a real product; describe the exposure and prove it minimally (e.g., a lab-only self-signed value the app accepts).
- If only a public key is present and the scheme is sound (server holds the private key), note that as the *correct* pattern, then pivot to whether the signature is actually verified (see Hooking / Patching).

**Framework notes.**
- **.NET/Java:** obfuscation (Dotfuscator-class tools, ProGuard) raises effort but rarely changes the conclusion, secrets shipped to the client are recoverable.
- **Native:** whitebox crypto and protectors increase cost; scope accordingly and report the design weakness even if full extraction is deferred.

**Impact.** Attacker can produce inputs the client accepts, unlimited self-service licensing, with no server involvement.

**Remediation.** Only the server should hold signing secrets; the client verifies a signature it cannot forge and, critically, the server re-checks entitlement server-side. Never embed symmetric license secrets or private keys in shipped code. Rotate anything found exposed.

---

### Trial Reset & Local State Manipulation

**What & why.** Time-limited trials and usage counters that live on the client are just editable state: registry keys, files, hidden "phone-home once" flags, or install timestamps. Resetting or forging that state yields an infinite trial. Same class as license patching, different storage.

**How to test.**
- Baseline the clean state, then install/run and diff. Use ProcMon to capture every registry and file write during first launch, activation, and trial countdown. Regshot for before/after registry diffs.
- Look in the obvious and the sneaky places: `HKCU`/`HKLM` under vendor keys, `%APPDATA%`, `%PROGRAMDATA%`, `%LOCALAPPDATA%`, hidden files, alternate data streams (`dir /r`, Streams from Sysinternals), and orphaned keys that survive uninstall.
- Delete/reset the identified state and relaunch, does the trial reset? That's the finding.
- Test the system clock: roll it forward to expire, back to revive. Note whether the app anchors time to a server or trusts the local clock.
- Check for "highest install date ever seen" anti-rollback markers, and whether they too are just local (and thus resettable) state.

**Framework notes.**
- Cross-framework, this is OS-level state. Electron apps additionally stash state in their user-data directory (JSON, LevelDB, `localStorage`), which is trivially editable.
- Watch for state hidden outside the profile specifically to survive uninstall, call this out; it is user-hostile and still bypassable.

**Impact.** Unlimited free use of trial/metered functionality; usage limits are unenforceable.

**Remediation.** Anchor trial/quota state to a server-side account keyed on server-observed time and identity. Local counters and local clocks cannot be trusted. If offline trials are a product requirement, treat any bypass as accepted risk and document it, don't pretend the client enforces it.

---

### Multi-User Separation on a Shared Host

**What & why.** On a shared or multi-session Windows host (fast user switching, RDS/Citrix, kiosk, family PC), a thick client must not let one OS user read another's stored credentials, tokens, cached data, or active session. Apps that store secrets in world-readable locations, cache under machine-wide paths, or reuse a session across OS users leak across the user boundary.

**How to test.**
- Create two OS users. As user A, log in / activate / populate data. As user B, inspect A's artifacts, config files, token caches, saved credentials, SQLite caches, logs, temp files.
- Check ACLs on every storage location the app writes (icacls, AccessEnum from Sysinternals). Flag anything under `%PROGRAMDATA%`, `C:\Temp`, or other shared paths that contains user-specific secrets with permissive DACLs.
- Test credential storage: is it in Windows DPAPI/Credential Manager (per-user protected) or a plaintext/obfuscated file any user can read? Try decrypting A's blob while running as B, DPAPI in user scope should fail; a machine-scope or homebrew scheme may succeed.
- Test session reuse: does A's live token or "remember me" state grant B access without re-auth? Copy tokens across profiles and see if the app accepts them.
- Look at IPC surfaces (named pipes, local sockets, COM) for missing per-user access control that lets B drive A's session.

**Framework notes.**
- **Electron/Java/.NET** all commonly roll their own token caches, prime spots for permissive ACLs or plaintext.
- **DPAPI** is the right primitive on Windows but only when used in *user* scope; machine scope or a shipped key defeats the boundary.

**Impact.** Local privilege/data-boundary break: credential theft, session hijack, and cross-user data disclosure on shared hosts, often achievable by a standard (non-admin) user.

**Remediation.** Store secrets with per-user OS protection (DPAPI user scope, Windows Credential Manager) under per-user paths with correct ACLs. Bind sessions to the OS user and re-authenticate on user switch. Never place user secrets in shared/machine-readable locations.

---

### In-App Privilege Boundaries & Token/Session Handling

**What & why.** Even after legitimate login, thick clients often enforce role/privilege boundaries (admin vs standard user, feature gating, approval workflows) on the client, hiding buttons, disabling menus, filtering views, while the backend accepts the underlying request from anyone. And the session token itself is frequently mishandled: over-broad scope, no expiry, stored in the clear, or accepted without server-side validation. Both collapse to "client says no, server says yes."

**How to test.**
- Enumerate privileged UI (admin panels, disabled controls, hidden features). For each, force-enable it (hook/patch the client) and drive the backend call directly, does the server authorize it based on the caller's actual role, or just the presence of a request?
- Intercept API calls in Burp/mitmproxy and replay a low-privilege user's session against high-privilege endpoints and objects (horizontal and vertical IDOR/BOLA, same discipline as web testing, thick clients are just fatter API clients).
- Inspect the token: decode JWTs and check claims, scope, and expiry; test whether tampering with role/scope claims is detected (bad signature validation, or `alg:none`-style acceptance). Confirm tokens actually expire and can be revoked.
- Test session storage: is the token in memory only, or persisted to a readable file/registry? Can it be lifted and reused from another machine (no device binding)?
- Probe for privilege state held only client-side (a local `isAdmin` flag) and flip it, then observe whether the server cares.

**Framework notes.**
- Cross-framework; the interesting boundary is almost always the client↔backend API, use the same tooling regardless of UI stack.
- For thick clients speaking custom/binary protocols, you may need a protocol-aware proxy or Frida hooks at the send/recv boundary rather than an HTTP proxy.

**Impact.** Vertical privilege escalation (standard user performs admin actions), horizontal access to other users' objects, and session hijack/replay, all despite a "correct-looking" client UI.

**Remediation.** Enforce authorization on the server for every request, per object and per action, from the server-authenticated identity, never from client-supplied role state. Issue short-lived, correctly-scoped, signed, revocable tokens; validate them server-side on every call; bind sessions appropriately. The client UI may *reflect* privileges but must never be the thing that *grants* them.

---

> **Recurring finding, one sentence:** *This control is enforced on the client, which the user fully controls; move the decision to a server the user does not control and re-check it on every request.* If you write that once and cite it throughout the report, you've captured 90% of this chapter.
