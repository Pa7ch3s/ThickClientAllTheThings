# Secrets & Data at Rest

Desktop apps have to keep something on the box: session tokens, refresh tokens, API keys, license blobs, cached PII. The interesting question is never "does it store secrets" (it does) but "where, in what state, and who else on the machine can read it." This chapter is about turning an installed app inside-out, on disk and in the registry, to find the material that lets you skip authentication entirely.

Assume local, authenticated access to the machine (your own test box or the client's build) unless the finding is about *cross-user* exposure, which is where the real severity usually lives.

- Hunting hardcoded credentials in unpacked source and binary strings
- Locating token/session stores (%APPDATA%, `~/Library`, `~/.config`, LevelDB, SQLite)
- Judging plaintext vs. "encrypted" storage, and OS keystore use vs. misuse
- Config files and the Windows registry as secret sinks
- Secrets bleeding into logs, crash dumps, and telemetry
- File and registry ACLs that make any of the above readable by other users

---

### Hardcoded credentials in unpacked source & strings

**What & why:** Keys baked into the shipped artifact are recoverable by anyone with the installer. Electron/CEF apps ship readable-ish JS; .NET and Java ship near-source IL/bytecode; native binaries still leak string literals. A hardcoded backend key or symmetric "encryption" key defeats every downstream protection.

**How to test:**
```bash
# Electron: unpack the app archive, then grep the source tree
npx @electron/asar extract resources/app.asar app_src/
rg -n -i '(api[_-]?key|secret|token|passw|bearer|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)' app_src/

# .NET: decompile to source before grepping (ILSpy CLI / dnSpyEx / dotPeek)
ilspycmd -o decomp/ TheApp.exe && rg -n -i 'password|apikey|connectionstring' decomp/

# Java: unzip the jar, decompile classes (CFR / procyon)
unzip app.jar -d jar_src/ && java -jar cfr.jar jar_src/ --outputdir cfr_out/

# Native: pull literals from the binary (both encodings)
strings -n 8 app.exe > s_ascii.txt
strings -n 8 -e l app.exe > s_utf16le.txt   # Windows wide strings

# High-recall secret scanners over the extracted tree / the installer itself
trufflehog filesystem app_src/ --results=verified,unknown
gitleaks detect --no-git --source app_src/
```
Also check embedded resources: .NET `.resources`/`resx`, Qt `.qrc`, Electron `app.asar.unpacked`, and any bundled `.env`, `config.json`, or `appsettings*.json`.

**Framework notes:** Electron ASAR is *not* encryption, just a tar-like container. .NET IL and Java bytecode round-trip to readable source; obfuscation slows reading but string constants survive. Native apps often store keys as static byte arrays, so pivot to entropy scans (below) when `strings` misses.

**Impact:** Full compromise of whatever the key protects, cloned for every user of the app. Symmetric keys used to "encrypt" local data are equivalent to plaintext once extracted.

**Remediation:** No long-lived secrets in the client. Broker sensitive calls server-side; use per-user OAuth/refresh tokens minted at runtime; if a local key is unavoidable, derive it per-user from an OS keystore-protected seed, never a shipped constant.

---

### Entropy scanning for keys, JWTs, and base64 blobs

**What & why:** Renamed variables and obfuscation hide the *word* "key" but not the *shape* of a secret. High-entropy strings, JWT segments, and long base64/hex blobs stand out statistically even when identifiers are meaningless.

**How to test:**
```bash
# Scanners that flag on entropy, not just keywords
trufflehog filesystem app_src/ --results=verified,unknown   # entropy + detectors
detect-secrets scan app_src/ > .secrets.baseline            # Yelp detect-secrets

# JWTs: three base64url segments split by dots
rg -no '\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*' app_src/
# decode/inspect a found token (alg, exp, aud) without a network call
jwt_tool eyJ...           # or: cut -d. -f2 | base64 -d 2>/dev/null

# Long base64 / hex candidates for manual triage
rg -no '[A-Za-z0-9+/]{40,}={0,2}' app_src/ | sort -u
rg -no '\b[0-9a-fA-F]{32,}\b'     app_src/ | sort -u

# Measure entropy of a suspect file/blob
ent suspect.bin
```
Decode base64 candidates and re-scan the output: keys are frequently base64-of-base64 or base64-of-JSON.

**Framework notes:** JWTs found at rest are usually access/refresh tokens; check `exp` and whether the app persists the *refresh* token (long-lived, high value). `alg:none` or symmetric `HS*` with a guessable secret is a separate finding worth flagging.

**Impact:** Recovery of session/refresh tokens enables account takeover without credentials; recovered symmetric keys unlock any locally "encrypted" store.

**Remediation:** Persist only short-lived tokens; store refresh tokens in an OS keystore, not a flat file; rotate on logout.

---

### Locating token & session stores

**What & why:** Before judging protection you have to find every place the app writes. Enumerate the per-user profile, temp dirs, and any custom location from config. Compare a clean install to a logged-in state to see exactly which files hold the session.

**How to test:**
```powershell
# Windows: common roots, sorted by recent writes (catch the file that changed on login)
Get-ChildItem "$env:APPDATA","$env:LOCALAPPDATA","$env:PROGRAMDATA" -Recurse -File -EA SilentlyContinue |
  Sort-Object LastWriteTime -Desc | Select-Object -First 40 FullName,Length,LastWriteTime
```
```bash
# macOS
ls -la ~/Library/"Application Support"/<App>/ ~/Library/Preferences/<bundleid>.plist ~/Library/Caches/<App>/
# Linux
ls -la ~/.config/<App>/ ~/.local/share/<App>/ ~/.cache/<App>/

# Diff approach (any OS): snapshot before login, log in, snapshot after
# Windows live: Sysinternals Procmon, filter Operation=WriteFile, Process Name=app.exe
```
Then classify each hit: Electron LevelDB (`Local Storage/leveldb/`, `IndexedDB/`), SQLite (`*.db`, `*.sqlite`, Chromium `Cookies`, `Login Data`, `Web Data`), JSON/INI/plist, or opaque blobs.

**Framework notes:** Chromium-based (Electron/CEF/WebView2) apps inherit the Chromium profile layout, so token storage often lives in Local Storage LevelDB, IndexedDB, or a `Cookies` SQLite DB. Qt apps default to `QSettings` (INI on Linux, registry on Windows). Java apps often use `java.util.prefs` (registry on Windows, XML under `~/.java/.userPrefs` on *nix).

**Impact:** Foundational; scopes the rest of the assessment.

**Remediation:** N/A (enumeration step), but a tidy, documented storage footprint is itself a hardening win.

---

### Reading Electron/Chromium LevelDB & IndexedDB

**What & why:** Electron apps routinely stash auth state in `localStorage`/`IndexedDB`, which on disk is a Chromium LevelDB. It reads as binary garbage to `strings` but trivially with the right parser, and it's frequently plaintext.

**How to test:**
```bash
# Purpose-built forensic readers for Chromium LevelDB / IndexedDB
python -m ccl_chromium_reader "…/Local Storage/leveldb"       # ccl_chromium_reader
python ccl_leveldb.py "…/Local Storage/leveldb" > ldb_dump.txt # ccl_leveldb

# Quick-and-dirty triage
strings -n 6 "…/Local Storage/leveldb"/*.ldb | rg -i 'token|auth|session|bearer|refresh'
```
```javascript
// If you can run in-app context (DevTools console on a debug build, or ELECTRON dev):
Object.entries(localStorage)   // dump the whole store
```
For `IndexedDB`, the same LevelDB tooling applies; values are often JSON with tokens inline.

**Framework notes:** Chromium may wrap Local Storage/cookie *values* with OS crypto (DPAPI-backed `os_crypt` on Windows, Keychain on macOS) in browser builds, but many Electron apps disable or never wire up that layer, leaving values plaintext. Verify per-value rather than assuming.

**Impact:** Direct session/refresh token theft from a local file; on shared machines, cross-user theft if ACLs are loose.

**Remediation:** Don't put long-lived secrets in renderer-accessible storage; if you must, encrypt with `safeStorage` (Electron) which is keystore-backed, and confirm it's actually enabled on the target OS.

---

### SQLite & flat-file stores (plaintext vs. encrypted)

**What & why:** SQLite is the default local DB for countless thick clients. The failure mode is a token/PII table sitting in the clear, or "encryption" that's really a hardcoded key you already pulled from the binary.

**How to test:**
```bash
sqlite3 app.db '.tables'
sqlite3 app.db '.schema'
sqlite3 app.db "SELECT * FROM tokens;"          # or sessions/users/accounts
strings -n 6 app.db | rg -i 'token|secret|passw'

# Is it plaintext SQLite or an encrypted DB (SQLCipher/other)?
xxd -l 16 app.db      # plaintext SQLite starts with "SQLite format 3\0"
file app.db
# If SQLCipher-encrypted and you recovered the key from the binary:
sqlcipher app.db "PRAGMA key='<recovered-key>'; SELECT * FROM tokens;"
```
For INI/JSON/plist/XML: read directly and check whether "encrypted" values decrypt with a key found earlier or with OS DPAPI (next section).

**Framework notes:** A missing `SQLite format 3` header means an encrypted or non-SQLite DB, commonly SQLCipher. SQLCipher is only as strong as its key management; if the key is a static constant in the app, the DB is effectively plaintext.

**Impact:** Bulk read of tokens, credentials, and PII; if the "encryption" key is shipped, applies to every user.

**Remediation:** Encrypt with a key sealed by the OS keystore and derived per-user; never ship the DB key; scope files to the user (below).

---

### OS secure storage: used correctly vs. not

**What & why:** DPAPI (Windows), Keychain (macOS), and Secret Service/libsecret (Linux) exist precisely so apps don't roll their own crypto. The common findings are (a) not using them at all, (b) using DPAPI at *machine* scope so any local user can decrypt, or (c) storing the keystore item but *also* caching the plaintext elsewhere.

**How to test:**
```powershell
# Windows DPAPI: which scope was used? CurrentUser blobs need the user's key; LocalMachine
# blobs decrypt for ANY user on the box. Test decryptability from a second local account.
# SharpDPAPI enumerates masterkeys, credentials, vaults, and app blobs:
SharpDPAPI.exe blob /target:C:\path\to\blob.bin
SharpDPAPI.exe credentials
# Impacket equivalent for offline masterkey+blob decryption:
dpapi.py masterkey -file <masterkey> -password <pw>
dpapi.py unprotect -file blob.bin -key <decrypted-masterkey>
```
```bash
# macOS Keychain: list and (with authorization) read items
security dump-keychain ~/Library/Keychains/login.keychain-db
security find-generic-password -s "<service>" -g          # prints the secret with a prompt
security find-internet-password -s "<host>" -g

# Linux Secret Service / libsecret
secret-tool search --all service <app>                    # query stored items
busctl --user tree org.freedesktop.secrets                # inspect the Secret Service backend
```
Key checks: is the DPAPI blob `CurrentUser` or `LocalMachine` scope? Is `optionalEntropy` used? Does the Keychain item have a sensible ACL, or is it accessible to any app? On Linux, is libsecret actually backed by an encrypted keyring, or a plaintext fallback when no keyring daemon runs?

**Framework notes:** Electron `safeStorage`, .NET `ProtectedData`, and `CredentialManager`/`Windows.Security.Credentials.PasswordVault` are the sanctioned front-ends. `ProtectedData.Protect(..., DataProtectionScope.LocalMachine)` is the classic cross-user misuse. On Linux, GNOME Keyring/KWallet via libsecret is only protective when a keyring is unlocked; some apps silently fall back to plaintext.

**Impact:** Machine-scope DPAPI or a plaintext libsecret fallback lets *any* local user (or malware in another user's context) decrypt the "protected" secret, negating the control.

**Remediation:** Use CurrentUser/user-scoped protection with per-item entropy; store the secret *only* in the keystore, not also in a cache; on Linux, fail closed if no secure keyring is available rather than writing plaintext.

---

### Config & registry storage of sensitive values

**What & why:** Connection strings, API keys, and "remember me" tokens routinely land in config files or the Windows registry, sometimes base64'd and mistaken for encryption.

**How to test:**
```powershell
# Registry: the app's hive under HKCU/HKLM, recursive value dump
reg query "HKCU\Software\<Vendor>\<App>" /s
Get-ChildItem "HKCU:\Software\<Vendor>" -Recurse |
  ForEach-Object { Get-ItemProperty $_.PSPath } | Format-List *
# Hunt secrets across a hive
reg query HKCU /f "password" /t REG_SZ /s /d
```
```bash
# Config files: read and decode candidates
rg -n -i 'password|apikey|secret|token|connectionstring' <config-dir>/
grep -rhoE '[A-Za-z0-9+/]{20,}={0,2}' <config-dir>/ | while read b; do echo "$b" | base64 -d 2>/dev/null; echo; done
```
Treat base64/hex/ROT as encoding, not encryption. Verify whether "encrypted" registry/config values are DPAPI blobs (decode and test decryption) versus a reversible scheme.

**Framework notes:** .NET `app.config`/`appsettings.json`, Qt `QSettings`, Java `Preferences`, and Electron `electron-store` all serialize to plaintext by default. `electron-store` supports an `encryptionKey`, but that key ships in the app, so it's obfuscation, not confidentiality.

**Impact:** Static recovery of credentials/keys from files or registry, often world- or user-readable.

**Remediation:** Keep secrets out of config/registry; reference a keystore item by handle instead; if a value must persist, seal it with user-scoped OS protection.

---

### Secrets in logs, crash dumps & telemetry

**What & why:** Even when storage is clean, secrets leak through the side channels: verbose logs, unhandled-exception traces, memory dumps, and telemetry/analytics payloads that serialize whole request objects including `Authorization` headers.

**How to test:**
```bash
# Log/crash directories
rg -n -i 'authorization: bearer|password=|token=|set-cookie|api[_-]?key' \
   ~/.config/<App>/logs/ %LOCALAPPDATA%/<App>/logs/ ~/Library/Logs/<App>/
```
```powershell
# Windows crash dumps (WER) and on-demand process dumps
Get-ChildItem "$env:LOCALAPPDATA\CrashDumps","C:\ProgramData\<App>\dumps" -EA SilentlyContinue
procdump -ma <pid> app.dmp        # Sysinternals; then string-scan the dump
strings -n 8 app.dmp | rg -i 'bearer |password|refresh_token'
```
For telemetry, watch what the app *sends*: proxy it (mitmproxy/Burp) and inspect analytics/crash-report POST bodies for tokens, emails, file paths, or full request captures.
```bash
mitmproxy --set listen_port=8080   # then filter analytics/crash-report hosts for secret material
```

**Framework notes:** Electron `crashReporter` and native breakpad/crashpad minidumps can carry heap fragments with tokens. .NET/Java stack traces often log the failing SQL or HTTP call with credentials inline. Third-party crash SDKs may upload dumps off-box, turning a local leak into a vendor-side exposure.

**Impact:** Token/credential disclosure to anyone who can read the logs or dumps, or to a third-party telemetry backend; a local leak can become a supply-chain/data-processor exposure.

**Remediation:** Redact secrets at the logging boundary; scrub minidumps and disable full-memory dumps for sensitive processes; strip auth headers and PII from telemetry; document what crash/analytics SDKs transmit.

---

### File & registry ACLs on stored data

**What & why:** A secret that's "only" in the user profile is fine until the ACL is wrong: world-readable files on a multi-user host, a store under `ProgramData`/`/opt` writable by all, or a registry key with `Everyone:Read`. This is what turns a local finding into cross-user compromise.

**How to test:**
```powershell
# Windows: effective permissions on files and keys
icacls "C:\ProgramData\<App>\tokens.db"
# AccessChk (Sysinternals) shows who really has R/W, including registry
accesschk.exe -q -u "Users" "C:\ProgramData\<App>"
accesschk.exe -q -k -u "Users" "HKLM\Software\<Vendor>\<App>"
Get-Acl "C:\ProgramData\<App>\tokens.db" | Format-List
```
```bash
# macOS/Linux: look for group/other read or write, and inherited ACLs
ls -la ~/.config/<App>/ ; stat -c '%A %U:%G %n' ~/.config/<App>/*
getfacl ~/.config/<App>/tokens.db          # extended ACLs
find /opt/<App> /var/lib/<App> -perm -o+r -o -perm -o+w 2>/dev/null   # world r/w
```
Red flags: secrets under a shared root (`C:\ProgramData`, `/tmp`, `/opt`, `/var`) with `Users`/`Everyone`/`other` read; any secret file group- or world-*writable* (integrity + theft); registry keys granting `NT AUTHORITY\Authenticated Users` read on secret values.

**Framework notes:** Installers frequently create `ProgramData`/`/opt` trees with inherited-permissive ACLs, then drop per-user secrets there. DPAPI CurrentUser scope still protects contents, but plaintext stores in those locations are exposed to every local account.

**Impact:** Cross-user secret theft and, when writable, tampering with the store (e.g., swapping in an attacker token). This is usually the highest-severity variant of an at-rest finding.

**Remediation:** Store per-user secrets under the user profile with owner-only ACLs (`icacls /inheritance:r` then grant only the user; `chmod 600`); never place secrets under world-accessible shared roots; verify installer-set permissions in the test.

---

## Quick triage checklist

- [ ] Unpack/decompile the app; `rg` + `trufflehog`/`gitleaks` over the source tree and installer
- [ ] `strings` (ASCII + UTF-16LE) the binaries; entropy/JWT/base64 sweep
- [ ] Diff the profile before/after login; classify every store (LevelDB/SQLite/config/registry)
- [ ] Read LevelDB/IndexedDB and SQLite directly; confirm plaintext vs. real encryption
- [ ] For each keystore use: check DPAPI scope, Keychain ACL, libsecret plaintext fallback
- [ ] Grep logs and crash dumps; proxy telemetry for secret material
- [ ] Check file/registry ACLs on every store for cross-user read/write
