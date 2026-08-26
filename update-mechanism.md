# The Update Mechanism

The auto-updater is the one component of a desktop app that is explicitly designed to download code from the internet and run it with the user's privileges. That makes it the highest-value target in the whole binary: break the update channel and you are not exploiting a bug, you are using the vendor's own signed pipe to deliver whatever you want. This chapter is about testing that pipe against your own instance before someone else tests it against production.

Every technique below assumes an authorized-testing posture: your own installed copy, your own MITM proxy, your own malicious update server pointed at a machine you control. Never point a tampered feed at another party's client.

- Update-channel transport (HTTP vs HTTPS, TLS validation)
- MITM of the update check / feed
- Payload signature verification (or its absence)
- Downgrade / rollback to a known-vulnerable version
- Feed / appcast tampering
- Framework-specific quirks (Squirrel, electron-updater, Sparkle/WinSparkle, NSIS)

---

### Update Channel Transport

**What & why.** The first question is whether the update check and the payload download happen over TLS at all, and whether the client actually validates the certificate. A plaintext HTTP update feed is a network-position-to-code-execution primitive. Even an HTTPS feed is worthless if the client disables cert validation, accepts any CA, or pins nothing and trusts a user-installed root.

**How to test.**
- Capture the update traffic with an intercepting proxy (Burp Suite, mitmproxy, Fiddler) or at the packet level with Wireshark. Identify the check URL and the payload URL. Note the scheme of each independently: some clients check over HTTPS but download the package over HTTP.
- Trigger a check on demand (menu "Check for updates", or delete the local "last checked" timestamp / registry value to force one on launch).
- With your proxy's CA trusted by the OS store, see if interception succeeds. Then remove the CA / present a self-signed or hostname-mismatched cert and confirm the client rejects it. A client that connects anyway does not validate TLS.
- Test whether the client honors the system proxy vs. its own network stack. Some Electron/Chromium updaters and some native HTTP libraries bypass the system proxy, so use transparent redirection (hosts-file override to your listener, or DNS spoofing on a lab network) when a proxy alone sees nothing.

**Framework notes.**
- **electron-updater / Squirrel**: feed URLs are configured at build time; Squirrel.Windows historically expects an HTTPS or file/UNC feed. Confirm the shipped URL, not the documented default.
- **Sparkle / WinSparkle**: the appcast URL (`SUFeedURL` in Info.plist, or the WinSparkle-configured URL) may be HTTP in older integrations. Modern Sparkle enforces HTTPS for the appcast by default and will refuse an insecure feed unless the developer explicitly opted out.

**Impact.** Plaintext or unvalidated transport lets a network attacker (same LAN, malicious Wi-Fi, upstream device, compromised CDN) rewrite the feed and/or the payload. Combined with weak signature checking, this is remote code execution as the user, delivered on the next update.

**Remediation.** HTTPS for both the check and the download, with full certificate validation and no opt-out flags shipped in release builds. Consider certificate pinning for the update host. Never fall back to HTTP on TLS failure.

---

### MITM of the Update Check

**What & why.** Even before touching the payload, the check response itself is worth tampering. It tells the client what version exists, where to get it, and (in signed schemes) what the expected hash/signature is. Controlling that response lets you force, suppress, or redirect an update.

**How to test.**
- Proxy the check and capture the exact response format (JSON, XML appcast, `RELEASES` manifest). Replay it with modifications: bump the advertised version, point the download URL at your own server, alter the release notes.
- Confirm what the client does with a redirected download URL. Does it follow cross-origin redirects? Does it re-validate the host? Serve a `302` to an attacker host and watch.
- Test the "no update" path too: can you suppress updates indefinitely by always answering "you're current"? That keeps a victim on a known-vulnerable build (see Downgrade).

**Framework notes.**
- **Squirrel.Windows** consumes a `RELEASES` file listing package filenames and SHA1 hashes plus a base URL. Tampering with `RELEASES` redirects which `.nupkg` is fetched.
- **electron-updater** consumes `latest.yml` / `latest-mac.yml` / `latest-linux.yml` containing version, path, and a `sha512`. That hash is the integrity anchor for updaters that do not verify a code signature themselves.
- **Sparkle** consumes an RSS/XML appcast where each `<item>` carries an `enclosure` with the URL, length, version, and a signature attribute.

**Impact.** Full control of update selection and destination without ever touching the vendor's servers, given a network position.

**Remediation.** Sign the manifest content or bind its integrity to a verified TLS channel plus payload-signature verification, so a rewritten check response cannot by itself cause a bad install.

---

### Payload Signature Verification

**What & why.** This is the crux. If the client verifies a cryptographic signature over the downloaded package against a public key baked into the app, then transport and feed tampering downgrade to denial-of-service. If it verifies only a hash it read from the (attacker-controlled) manifest, or verifies nothing, or verifies but ignores the result, then a served package runs.

**How to test.**
- Stand up your own update server. Reproduce the real feed format and host a tampered package: repackage the installer with a benign marker payload (e.g., a file drop or a callback to a host you own) so you can prove execution without doing damage.
- Serve it to your test instance via the MITM setup and watch whether it installs and runs. If it does, verification is absent or broken.
- Isolate what is actually checked: change one byte of the package and see if it is rejected (hash check present); then also break the signature specifically. A client that accepts a package whose hash matches the manifest but whose signature is invalid is trusting the manifest, not the vendor key.
- On Windows, check whether the installer relies solely on Authenticode. An unsigned or self-signed package that still installs means the updater does not enforce publisher identity.
- Inspect the binary for the embedded public key / expected signer and the verification call so you can reason about what "valid" means to this client.

**Framework notes.**
- **Sparkle / WinSparkle**: modern Sparkle signs the payload with **EdDSA (Ed25519)**; the public key lives in `Info.plist` (`SUPublicEDKey`) and each appcast item carries `sparkle:edSignature`. Legacy Sparkle used **DSA** (`sparkle:dsaSignature` + `SUPublicDSAKeyFile`). Verify which is in force; a project still on DSA-only, or with signature enforcement disabled, is the finding. WinSparkle mirrors this model.
- **electron-updater**: on Windows it can enforce the publisher name from the Authenticode signature via `publisherName` and validates the `sha512` from `latest.yml`. The sha512 is integrity-only, not authenticity, so where code-signing verification is off or the platform doesn't enforce it, the manifest hash is the whole defense, and the manifest is attacker-controlled over a broken channel.
- **Squirrel.Windows**: integrity rests on the `RELEASES` SHA1 and on Authenticode signing of the packaged binaries. Squirrel does not perform an independent vendor-key signature check of the `.nupkg` beyond that, so unsigned or improperly signed contents plus a rewritten `RELEASES` is the classic weakness.
- **NSIS-based updaters**: often just download an `.exe` and execute it. Authenticity depends entirely on whether the app verifies Authenticode (or a custom signature) before launching. Many custom NSIS update stubs verify nothing.

**Impact.** Code execution as the user on next update, from a network position, with no vendor-server compromise. This is the top-severity outcome for the whole app class.

**Remediation.** Verify a cryptographic signature over the payload against a public key embedded in the app, before executing anything. Do not treat a manifest-supplied hash as authenticity. Keep signing keys off the build/distribution host where practical, and rotate if exposure is suspected. Enforce publisher identity on Windows.

---

### Downgrade / Rollback

**What & why.** A client that will install any advertised version, including one older than what is running, can be forced back onto a build with known, patched vulnerabilities. The attacker then exploits the old bug. Even with perfect signature verification, if the vendor's older packages are still validly signed, the updater will happily accept them unless it enforces monotonic versioning.

**How to test.**
- In the check response, advertise a legitimate, still-validly-signed older release. Point the download at the real (or your cached) old signed package. Observe whether the client installs it.
- Note whether the client compares versions at all, and whether it refuses "same or lower". Test edge cases: equal version, pre-release/channel switches, and build-metadata-only differences.
- Verify whether a downgrade is silent or prompts the user, and whether the old build then re-updates forward (a loop you can suppress via the "no update" MITM).

**Framework notes.**
- **electron-updater** exposes `allowDowngrade`; if enabled (or if channel logic permits it), forced rollback is in scope. Confirm the shipped setting rather than assuming the default.
- **Sparkle** compares versions and normally won't offer an older item, but a tampered appcast advertising an old signed enclosure with a spoofed-higher `sparkle:version` while pointing at the old binary is worth testing.
- **Squirrel** selects from `RELEASES`; a curated `RELEASES` listing only an old signed `.nupkg` can pin a victim backward.

**Impact.** Re-introduction of any historically patched vulnerability, reachable remotely on a machine that was fully patched.

**Remediation.** Enforce monotonic version policy: refuse to install a version equal to or lower than the installed one unless an explicit, authenticated rollback is intended. Ship `allowDowngrade` disabled. Consider security-version counters or minimum-version floors so old-but-signed packages stop being accepted after a fixed vuln.

---

### Feed / Appcast Tampering

**What & why.** The manifest is structured, parsed input from the network, so it is both a redirection primitive (covered above) and a parser attack surface in its own right. Injecting content into release-notes rendering, oversized fields, or malformed XML/YAML can yield UI spoofing, XSS-in-a-webview, or parser crashes.

**How to test.**
- Where release notes are rendered, test HTML/script injection. Sparkle renders release notes; if they display in a web context, inject markup and script and see what executes and in which security context. A webview with node/system access rendering attacker-controlled notes is a serious finding.
- Fuzz the manifest: malformed XML/YAML/JSON, huge version strings, unexpected fields, duplicate `<item>`s, signature attributes that are present-but-empty vs. absent (some verifiers fail open when a signature field is missing rather than invalid).
- Specifically test the "missing signature" case: does the client reject an item with no signature, or only reject an item with a wrong one? Fail-open on absence is a common, high-impact bug.

**Framework notes.**
- **Sparkle**: appcast is XML/RSS; release notes may be inline HTML or a linked page. Check the rendering surface and CSP. Confirm behavior when `sparkle:edSignature`/`sparkle:dsaSignature` is absent.
- **electron-updater**: YAML manifest; test YAML edge cases and how a missing/oversized `sha512` or `path` is handled.
- **Squirrel**: line-oriented `RELEASES` text; test malformed lines, unexpected hashes, and path traversal in package filenames.

**Impact.** Ranges from UI spoofing and forged release notes (social-engineering a user into accepting a malicious update) to code execution if release notes render in a privileged webview or if fail-open signature logic accepts unsigned items.

**Remediation.** Treat the manifest as untrusted input: strict schema validation, reject-on-missing-signature (fail closed), render release notes in a sandboxed context with no script and no system bridge, and enforce a strict CSP. Cap field sizes.

---

### Update Delivery Path & Local Tampering

**What & why.** Between download and execution the payload usually lands in a staging directory and is then launched or handed to an elevated helper. If that directory is writable by an unprivileged user, or the elevation helper trusts whatever is staged, a local attacker can swap the payload after verification (a TOCTOU) or plant one directly, turning the updater into a local privilege escalation.

**How to test.**
- Identify the staging path (ProcMon on Windows, `fs_usage`/filesystem monitoring on macOS) and its ACLs. Is it under a user-writable temp location while the installer runs elevated?
- Test the window between signature verification and execution: can you replace the verified file before it is launched? A privileged helper that re-reads the file without re-verifying is vulnerable.
- On macOS, check how the updater relocates/replaces the app bundle and whether a helper tool (installed via the privileged-helper mechanism) validates the caller and the payload.
- Check for DLL/dylib search-order hijacking against the updater or installer stub launched from a writable directory.

**Framework notes.**
- **Squirrel.Windows** stages under a per-user `%LocalAppData%` app directory and runs `Update.exe`; per-user install paths and update stubs are a recurring hijack/tampering surface.
- **Sparkle** uses a privileged installer helper for updates requiring elevation; older Sparkle versions had documented local-tampering / helper-trust issues, so confirm the version and that the helper validates its input.
- **NSIS** stubs frequently run from `%TEMP%`, a prime spot for planted-DLL search-order hijacks.

**Impact.** Local privilege escalation, or persistence via a payload swap, even when the network-facing verification is sound.

**Remediation.** Stage in a location only the privileged process can write; re-verify the signature inside the elevated context immediately before execution; validate the calling process in any helper; avoid launching installer stubs from world-writable directories; use safe library-loading paths.

---

### Methodology Checklist

- Map every URL: check endpoint and payload endpoint, each with its own scheme and host.
- Confirm TLS validation independently on each (trusted-CA intercept, then hostname-mismatch / self-signed).
- Capture and replay the manifest; test version-bump, URL-redirect, downgrade, and missing-signature cases.
- Serve a benign marked package from your own server to your own instance; determine exactly what is verified (nothing / hash-from-manifest / vendor-key signature / Authenticode).
- Test monotonic-version enforcement and the shipped `allowDowngrade`-equivalent setting.
- Inspect the local staging path ACLs and the verify-to-execute window for TOCTOU / LPE.
- Record the framework and its version; map findings to that framework's known signature model (EdDSA/DSA for Sparkle, sha512+Authenticode for electron-updater, RELEASES-SHA1+Authenticode for Squirrel, whatever-the-stub-does for NSIS).
