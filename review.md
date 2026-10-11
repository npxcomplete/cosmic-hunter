# Security review: cosmic-hunter (Bloodborne PC port)

- **Code reviewed:** commit `e076119` ("Online play, Add to Steam (1.6)")
- **Date:** 2026-10-11
- **Scope:** all source in the repository, every vendored component that could be checked against upstream, the built-in game patches, and the full git history.
- **Not covered:** the published release binaries (blocked from this sandbox; see §5) and runtime behaviour (no Windows host or game dump available).

---

## 1. Verdict

**No malware or backdoor was found in the source.** Provenance checks account for almost all of the code:

| Check | Result |
|---|---|
| Delivered repo vs public `Supermedo/bloodborne_pc` (`windows` branch) | **Identical.** Same commit SHA `e076119`, same tree `d5455816`. Every commit exists upstream. The provider did not modify it. |
| `gpu/shadps4` vs shadPS4 `b4e7ae7` (the pin in `gpu/VENDOR.txt`) | 355 files byte-identical. 92 modified and 37 added files are rendering/upscaler work. The lines added to modified files contain only debug env toggles, hash constants, and GPU register handling. |
| Network, NP and shadNet code (103 files) vs `Wozzardman/shadp2p` `main` (`6e97b404`) | **All 103 byte-identical.** |
| cpp-httplib 0.45.0, wepoll, sirit, gcn headers vs the commits shadPS4 pins | Identical (line endings only). |
| `patches/Bloodborne.xml` (60 patches that write code into the game) | All 60 patches appear byte-for-byte in upstream community patch history (`shadps4-emu/ps4_cheats`, `illusion0001/PS4-PS5-Game-Patch`). No `syscall`, `int 2e`, `gs:` PEB/TEB access, or `cpuid` opcodes. |
| Project-written code (`src/`, `gpu/shim`, `gpu/bbnet`, DLSS bridge, launcher, scripts, packaging) | No hidden network endpoints, credentials, persistence, process injection, obfuscation, or encoded payloads. Every network call is a documented feature. |
| Git history | Nothing suspicious added then removed. The only hosts dropped from history are a donation link and a badge service. |

**What remains unverified** is the thing users actually run: the **release zip** (`Bloodborne.exe`, `bb-probe.exe`, the DLLs). Clean source does not prove the binaries were built from it. This is the top open item (§5).

The security risk in this project comes from **vulnerabilities, mostly inherited from upstream, that are much more dangerous in this architecture**, not from planted code. They are ranked below.

---

## 2. Findings, highest risk first

### V1. CRITICAL (with online play on): game network code runs natively with no sandbox, so remote input can lead to code execution

**What:** the PS4 game's own x86-64 code runs inside the host process with the user's full privileges (`src/runtime_*.c`). Guest modules load at **fixed addresses** in the 64 GiB–1 TiB range; high-entropy ASLR is disabled (`gpu/CMakeLists.txt:250–252`), and the Linux build is `-no-pie` (`build.sh:90`). With `BB_ONLINE=1`, data from game servers and **directly from other players** (`gpu/shadps4/core/libraries/network/p2p_sockets.cpp`) is parsed by FromSoftware's 2015 PS4 network code.

**Why it matters:** on a PS4 that code ran inside Sony's sandbox with ASLR. Here, a memory-corruption bug in the game's message, bloodstain, or P2P parsing becomes native code execution on the user's PC, at known addresses, with nothing between it and the Win32 API. FromSoftware's PC online stack has had exactly this class of bug before: Dark Souls III's matchmaking RCE in 2022 (CVE-2022-24126, cited from memory; verify before relying on the number).

**Sources of attacker input:** a malicious or compromised community server (`thehuntersdream.com`), a malicious shadNet server, a MITM (made easy by V3), and any player you are matched with (P2P, reachable from the internet when UPnP opens a port, V5).

**Mitigation in place:** online play is **off by default** (`launcher/bbport_launcher_win.py:174`, `'online': False`).

**Patch steps:**
1. Keep online off by default, and add a clear warning when it's turned on: "other players' data is processed by the game's original code with full access to your PC."
2. Run `bb-probe.exe` with a **restricted token** inside a **Job object** (or an AppContainer). Deny writes outside the game, data, and user folders, and deny child-process creation except for the restart path. The launcher (`run.py`) is the natural place to do this.
3. Add Windows Firewall rules for `bb-probe.exe`: outbound only to the configured servers plus UDP for P2P, and no inbound unless the user opts in.
4. Long term, add size and structure checks in the P2P socket shim (`p2p_sockets.cpp`) for known message types before the data reaches the game.

### V2. HIGH: shadNet account password sent in plaintext over the network

**What:** `gpu/shadps4/shadnet/client.cpp:195–207` builds a `LoginRequest` protobuf containing the **password** and sends it over a raw TCP socket (`client.cpp:293–314`) to `srv.shadps4.net:31313` (the default in `launcher/bbport_launcher_win.py:174`). There is no TLS. The code is identical to upstream shadPS4/shadp2p.

**Impact:** anyone on the network path (public Wi-Fi, the ISP, or a compromised router) can read the account password. Users who reuse passwords are exposed beyond this game.

**Patch steps:**
1. Wrap the shadNet socket in TLS. OpenSSL is already linked for cpp-httplib, so use `SSL_connect` over `m_sock` with hostname verification, and fail closed.
2. Better still, replace password login with a token from an HTTPS login endpoint, so the password never travels on the game protocol.
3. Until this is fixed, warn in the Online page: "use a unique password; it is sent unencrypted."

### V3. HIGH: HTTPS certificate verification is bypassed

**What:** `gpu/shadps4/core/libraries/network/http.cpp:972–986` turns verification off whenever a context called `sceHttpsLoadCert`, which only records the context (`http.cpp:~2010–2028`) and never loads the CA list. `ssl.cpp:852–860` stubs `SSL_connect` to return success. The code is identical to upstream shadPS4. Combined with the host redirect in `run.py:24–25, 46–70` (the game's server becomes `thehuntersdream.com`), the game accepts **any** certificate for those hosts.

**Impact:** a MITM can impersonate the game server and feed arbitrary responses into the game's parsers, which is the input path for V1.

**Patch steps:**
1. Never bypass verification for a host that came from `host_overrides.json`. Those targets (`thehuntersdream.com`, shadNet WebAPI over HTTPS) have publicly trusted certificates, so verify them normally against the system store.
2. Implement `sceHttpsLoadCert`: parse `caList` (DER/PEM) into an `X509_STORE` and pass it with `httplib::Client::set_ca_cert_store`. Verify against that store instead of disabling checks.
3. Only skip verification when the game itself clears `ORBIS_HTTPS_FLAG_SERVER_VERIFY`, and log a warning every time.

### V4. HIGH: self-updater downloads and runs unsigned code

**What:** `launcher/bbport_launcher_win.py:1556–1562` takes the first `.zip` asset of the latest GitHub release. `1379–1420` downloads it, extracts it to `%TEMP%\bbport-update`, and starts `Bloodborne.exe --install-update` from it. That process then overwrites the installation (`1566–1590`). Nothing checks a hash or a signature.

**Impact:** anyone who can publish a release or replace an asset in `Supermedo/bloodborne_pc` (account takeover, a leaked token, or a malicious maintainer) gets code execution on every user who clicks **Update**.

**Patch steps:**
1. Authenticode-sign `Bloodborne.exe`, `bb-probe.exe` and the DLLs in the release pipeline.
2. Before running anything from the download, verify the asset's SHA-256 against the `digest` field the GitHub API returns for release assets (or a signed `SHA256SUMS` in the release). Then call `WinVerifyTrust` on the extracted `Bloodborne.exe` and check that the signer matches a pinned publisher.
3. Extract into a fresh directory created with `tempfile.mkdtemp()` instead of a fixed `%TEMP%` path.

### V5. MEDIUM: UPnP opens a permanent router port by default

**What:** `launcher/bbport_launcher_win.py:175` defaults `online_upnp` to `True`, and `gpu/shim/core/emulator_settings.h:85` defaults `BB_UPNP` on. `net_upnp.cpp:126–127` adds a UDP mapping with **lease `"0"` (no expiry)**. It's only removed on clean shutdown (`:144`), so a crash or a killed process leaves the port open.

**Impact:** the PC stays reachable from the internet on that port after the game exits, which widens V1.

**Patch steps:** default UPnP to off; use a finite lease (for example 3600 s, renewed while running); remove stale `shadPS4` mappings at startup.

### V6. MEDIUM: account password stored in plaintext and passed through the environment

**What:** `online_password` is part of the settings dict saved to `%APPDATA%\bbport-launcher\settings.json` (`launcher/bbport_launcher_win.py:37–38, 175, 393`). It's passed to the game as `BB_SHADNET_PASSWORD` (`:374`, read in `gpu/shim/core/user_manager.h:42`).

**Patch steps:** store it in Windows Credential Manager (`CredWriteW` through ctypes, or `keyring`); give it to the game through an inherited pipe or handle instead of an environment variable; clear it from the settings file on upgrade.

### V7. MEDIUM: third-party XML patches inject native code with no trust check

**What:** `scripts/patches.py:214–225` loads every `*.xml` in the mods patch folder and writes its bytes into the game's executable image (documented in `docs/MODS.md:78–93`). A downloaded "patch pack" is therefore native code running with full user rights (see V1). The built-in set is clean (§1). Asset mods cannot replace `eboot.bin`, `sce_module` or `sce_sys` (`scripts/mods.py:96–97`), which is good.

**Patch steps:** generate a SHA-256 allowlist of known patches from the upstream community repositories (I verified the built-in set this way). Show a blocking warning for any patch outside it, naming the author and listing its writes.

### V8. LOW-MEDIUM: downloaded FSR 4 assets aren't hash-checked

**What:** `tools/fetch_fsr4_assets.sh:29` and `launcher/bbport_launcher_win.py:213, 1111–1130` fetch 60+ SPIR-V and model files from `raw.githubusercontent.com/FireBurn/Q2RTX/<pinned commit>`. The commit is pinned, but nothing checks file hashes. The files are GPU shaders and model blobs, not host code.

**Patch steps:** commit a SHA-256 manifest and verify each file after download; delete any file that fails.

### V9. LOW: `Bloodborne.exe --script <path>` runs any Python file

**What:** `launcher/bbport_launcher_win.py:81–87` passes any path to `runpy.run_path`. The shipped launcher is therefore a general-purpose Python interpreter, useful to an attacker who already has local execution for bypassing application allowlisting.

**Patch steps:** accept only the known script names (`prepare.py`, `link_libc.py`, `link_modules.py`, `content_profile.py`, `patches.py`, `mods.py`) and resolve them under `PORT_DIR / 'scripts'` only.

### V10. LOW: shell injection pattern in desktop-shortcut creation

**What:** `launcher/bbport_launcher_win.py:1446–1452` interpolates `target`, `PORT_DIR`, and `icon` into a PowerShell `-Command` string inside double quotes. An install path containing `"` or `$(...)` executes code. The user has to control the folder name, so the impact is low.

**Patch steps:** pass values through environment variables (`$env:BB_TARGET`) and reference them in a constant script, or create the `.lnk` through COM with ctypes.

### V11. LOW: restart command line comes from an environment variable

**What:** `src/probe.c:350–365` runs `CreateProcessA(NULL, getenv("BB_RESTART_COMMAND"), …)`. Only a same-user process can set this variable, so impact is low.

**Patch steps:** rebuild the restart command from the known executable path and arguments instead of an inherited string.

---

## 3. Corrections to the earlier triage

- **The TLS bypass (now V3) is upstream shadPS4 code**, not something this project added. It's still a real vulnerability.
- **The network code is pinned after all:** all 103 files match shadp2p `6e97b404` exactly. The earlier report called it unverified.
- **`NtCreateThread` in `common/ntapi.cpp`** is unmodified upstream shadPS4. It's benign.
- **The earlier report missed** V1 (native execution plus fixed addresses), V2 (plaintext shadNet login), V5 (permanent UPnP mapping), and V9 (`--script` interpreter).
- **The earlier report rated the updater (now V4) above credential exposure.** V2 and V3 are on by default for every online user, while V4 requires a compromised release, so they rank higher here.

---

## 4. Order of work for patching

1. **V2 and V3** (TLS for shadNet; stop the certificate bypass for overridden hosts). These are the cheapest fixes with the largest exposure reduction, and they close the easiest route into V1.
2. **V4** (signed releases and a verified updater). It protects every user, online or not.
3. **V1 hardening** (restricted token, Job object, firewall rules) and **V5** (UPnP off by default, finite lease).
4. **V6, V7** (credential storage, patch allowlist).
5. **V8–V11** (asset hashes, `--script` allowlist, PowerShell quoting, restart command).

Send V2 and V3 upstream too (shadPS4 and shadp2p), since every fork inherits them.

---

## 5. Open items and what's needed to close them

| Item | Why it's open | What's needed |
|---|---|---|
| **Release binaries** (`Bloodborne.exe`, `bb-probe.exe`, `libbbgpu.dll`, `bbport_dlss.dll`, `nvngx_dlss.dll`) | The proxy blocks `github.com` release downloads (HTTP 403), and the GitHub API refuses repos not attached to this session. | Either allow `github.com` and `objects.githubusercontent.com` in the environment's network settings, or upload the zip. Then: extract the PyInstaller bundle and diff its scripts against source; check Authenticode signatures; compare DLLs with a clean MSYS2 build; run capa and YARA; compare `nvngx_dlss.dll` with NVIDIA's SDK hash. |
| **`half` library** | The shadPS4-pinned fork (`1ddada2`) wasn't found under the name I tried. | The correct upstream URL from shadPS4's `.gitmodules`. Low risk: a header-only math library. |
| **Runtime behaviour** | Nothing was executed. | A Windows VM, a legally obtained game dump, ProcMon/Sysmon, and a sinkholed network (FakeNet-NG) to confirm no unexpected connections, file writes, or child processes. |
| **V1 exploitability** | It depends on bugs in FromSoftware's code. | Fuzz the P2P and server-response parsers through the socket shim. Out of scope for a code review. |
