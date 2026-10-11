# Security review: cosmic-hunter (Bloodborne PC port)

- **Commit reviewed:** `e076119` ("Online play, Add to Steam (1.6)"), branch `claude/elegant-turing-lj6q3t`
- **Date:** 2026-10-11
- **Status:** Initial triage from source reading and pattern scans. This is **not** a complete audit: nothing was built, executed, or diffed against upstream, and the game image was not present.

---

## 1. What this code does (threat model)

The project runs an original PS4 game's x86-64 code natively on Windows (and Linux). It is not an emulator. The relevant trust boundaries are:

| Surface | Why it matters |
|---|---|
| Native host runtime (`src/runtime_*.c`, `gpu/shim`, `gpu/shadps4`) | Executes guest machine code in-process and implements PS4 kernel/library calls. Memory-safety bugs here are reachable from game data. |
| Binary patcher (`scripts/patches.py`, `patches/Bloodborne.xml`, 248 KB) | Writes bytes, including executable patches, into `eboot.bin` at launch. |
| Mods loader (`scripts/mods.py`, `docs/MODS.md`) | Loads third-party XML patches from a mods folder into the game image. |
| Online networking (`gpu/shadps4/core/libraries/network`, `np`, `shadnet`, `gpu/bbnet`, added in the last commit) | Sends the user's account credentials and game traffic to third-party servers over HTTPS. |
| Self-updater (`launcher/bbport_launcher_win.py` ~1379–1420, 1556–1562) | Downloads a zip from GitHub Releases and executes the `Bloodborne.exe` inside it. |
| Windows launcher side effects (Steam `shortcuts.vdf`, PowerShell shortcut creation, `taskkill`-style Steam restarts) | Writes to user-owned config and runs shell commands. |
| Vendored third-party code (`gpu/shadps4` at upstream `b4e7ae7` plus backports, `gpu/third_party`) | Large attack surface; provenance must be verified against upstream. |
| Fetched binary assets (FSR 4 shaders from `FireBurn/Q2RTX`, DLSS `nvngx_dlss.dll`) | Executable code that is not in the repository. |

The game dump (`CUSA03173`, v1.09) is **not** in the repository. It is supplied by the user, so it is an untrusted input in its own right and is out of scope for this repo review but needed for dynamic analysis.

---

## 2. Findings (ranked by triage severity)

Severity is a triage estimate from reading the code. Nothing here has been exploited or reproduced.

### F1. HTTPS certificate verification is disabled for custom-CA contexts (HIGH when online play is on)

- `gpu/shadps4/core/libraries/network/http.cpp:972–986`: when a context has called `sceHttpsLoadCert`, `verify_server` is forced to `false` and the request proceeds without verification.
- `gpu/shadps4/core/libraries/network/http.cpp:~2010–2028` (`sceHttpsLoadCert`): the function only records the context in `contexts_with_loaded_certs`. It never loads the CA list. The code comment says "libSceSsl integration is not implemented", so the bypass is effectively the only behaviour for these contexts.
- `gpu/shadps4/core/libraries/network/ssl.cpp:852–860`: `SSL_connect` and `SSL_connectWithCfgParam` are stubs that return `ORBIS_OK`.
- `run.py:24–25, 46–70` and `launcher/bbport_launcher_win.py:316–328`: `ss4.scej-network.jp:20443` (the game's server) is redirected via `host_overrides.json` to `thehuntersdream.com` (a third-party host) and summons go to a shadNet WebAPI. These redirects rely on certificate checks that the bypass disables.

**Impact:** an on-path attacker (hostile Wi-Fi, a compromised router, or a malicious DNS answer) could impersonate the game server, the community server, or the summon service. They could read or modify sign-in traffic and game messages, or serve altered responses. Whether that reaches the account password depends on the request path, which still needs tracing.

**To verify:** trace which requests run on a `sceHttpsLoadCert` context; confirm the auth/sign-in path; reproduce with a MITM proxy and a self-signed certificate.

### F2. Self-updater executes an unverified zip from GitHub Releases (MEDIUM-HIGH)

- `launcher/bbport_launcher_win.py:1556–1562`: the newest release's first `.zip` asset is taken from the GitHub API and used without a checksum.
- `launcher/bbport_launcher_win.py:1379–1420`: the zip is downloaded, extracted, and `Bloodborne.exe --install-update` is started from the extracted folder. That process then overwrites the installation.
- No SHA-256, Authenticode, or signature check is present (`grep` for `sha256`, `WinVerifyTrust`, `signtool`, and `verify` in `launcher/` finds nothing relevant).

**Impact:** anyone who can publish a release or a malicious asset under `Supermedo/bloodborne_pc` (account takeover, compromised CI, or a release tampered with later) gets code execution on every user who clicks **Update**. The installer runs with the user's full privileges.

**Recommendation:** publish SHA-256 sums and an Authenticode signature with each release; verify both before running anything from the zip.

### F3. Account password stored in plaintext on disk (MEDIUM)

- `launcher/bbport_launcher_win.py:175`: `online_password` is a default key of the app settings.
- `launcher/bbport_launcher_win.py:37–38, 393`: the settings dict is read from and written to `%APPDATA%/bbport-launcher/settings.json`. The password value is part of that dict. (I did not confirm the exact save call; check the writer before relying on this.)
- `launcher/bbport_launcher_win.py:374`: the password is passed to the game as the environment variable `BB_SHADNET_PASSWORD`. Environment variables are visible to other processes running as the same user and can leak into crash dumps and logs.

**Recommendation:** store the credential with Windows Credential Manager / DPAPI, or ask for it on each launch; keep it out of `settings.json`.

### F4. Mods and XML patches inject executable code into the game image (MEDIUM, design risk)

- `scripts/patches.py:214–225` (`external_patches`): reads every `*.xml` in the mods folder, with no signature or allowlist.
- `scripts/mods.py:94`: "executable patches use the existing patch compiler". These compile to machine code written into the game's memory layout.
- `docs/MODS.md:78–93` describes third-party XML patches as a supported feature, with a patch-selection UI in the launcher.

**Impact:** a mod pack is effectively a native code plugin. A user who installs a mod from someone else is trusting that author with full control of the game process.

**Recommendation:** document this clearly as a trust decision; show a warning when enabling an executable patch from an unknown source; consider a hash list for known-good community patches.

### F5. Provenance of vendored code is unverified (MEDIUM, must be closed before the review is complete)

- `gpu/VENDOR.txt`: shadPS4 `b4e7ae776071ceb1dd35004577a8719481e1d258`, with nine backported commits after that point. Local changes are marked `bbport:`, which makes a diff against upstream tractable.
- The **network / NP / shadNet / summon** code (over 100 files added or changed under `gpu/shadps4/core/libraries/{network,np}`, `gpu/shadps4/shadnet`, `gpu/bbnet` and `gpu/shim`, including `gpu/shadps4/core/libraries/network/http.cpp` at 4,443 lines and `np_handler.cpp` at 2,258 lines) was added in the last commit with **no pinned commit or hash**. `gpu/CMakeLists.txt:158–159` and `gpu/shim/core/bloodborne_re.h:1` say it comes from `Wozzardman/shadp2p` (GPL-2.0), but there is no SHA.
- Git history shows two author identities for the same person (`deadinside` / `deadinside28` and `Supermedo`, with two different addresses). Not evidence of wrongdoing by itself, but it makes a history-based attribution check harder.
- **Submodules are not populated**: `gpu/third_party/fsr-vulkan`, `imgui`, `magic_enum`, `miniz`, `xbyak`, `third_party/LibAtrac9`, and `externals/SPIRV-Headers` are empty. That code is not part of what this repo ships, so it cannot be reviewed as-is.

**Recommendation:** for each vendored tree, diff against the pinned upstream commit and list every non-`bbport:` change. For the shadp2p code, pin a commit and diff against it.

### F6. Downloaded assets are pinned by commit but not by hash (LOW-MEDIUM)

- `tools/fetch_fsr4_assets.sh:29`: `curl -fsSL` of 60+ `.spv`/`.bin` files from `raw.githubusercontent.com/FireBurn/Q2RTX/<commit>/...`. The commit is pinned, but no checksum is checked.
- `launcher/bbport_launcher_win.py:213, 1111–1130`: the same files downloaded by the launcher, without a hash.
- These are shader and model blobs executed by the GPU driver through the renderer. They are not native host code, but they are untrusted executable input.

**Recommendation:** commit a SHA-256 manifest and verify each file after download.

### F7. Shell command built from interpolated paths (LOW)

- `launcher/bbport_launcher_win.py:1446–1452`: the desktop shortcut is created by running `powershell -Command` with `TargetPath`, `WorkingDirectory`, and `IconLocation` interpolated inside double quotes. A path containing `"` or `$(...)` breaks out of the string.
- The attacker has to control the install folder name, so impact is limited to the user's own machine. Still, it is an injection pattern, and should be fixed by passing values through environment variables or `-File` with arguments.

### F8. Native code paths worth a closer look (LOW, needs review)

- `gpu/shadps4/common/ntapi.cpp:10, 23`: resolves `NtCreateThread` via `GetProcAddress` on `ntdll`. This is normal for an emulator, but it is an undocumented API and belongs to the same class of code as process-injection techniques. Check how it is used.
- `packaging/bbport-entry.c`: a static program that strips `LD_PRELOAD`, `LD_LIBRARY_PATH` and similar variables before launch. It is intentional and documented, but it removes the usual injection defences on Linux, so it should be reviewed with the rest of the launch path.

---

## 3. Checks that came back clean (or benign)

- **Dynamic code loading in non-vendor code:** no `eval(`, `exec(`, `__import__`, `importlib`, `pickle.load`, or `marshal.loads` outside the test scripts and vendored trees.
- **Hidden Unicode:** the only zero-width or BOM characters are the UTF-8 BOM at the top of two upstream SPDX headers (`gpu/shadps4/common/key_manager.cpp:1`, `gpu/shadps4/core/libraries/videoout/driver.h:1`). Benign.
- **Base64 or packed blobs:** none found outside vendored data (`ffx_a.h` hits are comment rulers).
- **Hard-coded external IPs:** only `1.1.1.1` used as a DNS value in `netctl.cpp:223, 227` and `net_util.cpp:360`. These emulate PS4 network info; they do not beacon.
- **Remote URLs in code:** the set is small and explained in the README (`thehuntersdream.com`, `ss4.scej-network.jp`, `shadnet.shadps4.net`, `srv.shadps4.net`, `api.github.com`, `raw.githubusercontent.com`, Discord, and upstream homepages). The URL scan found no analytics or telemetry endpoints.
- **Persistence:** no registry `Run` keys, scheduled tasks, services, or `LD_PRELOAD` drop-ins are installed by the code I read. The only persistent write is the Steam shortcut, which the user triggers.

---

## 4. Not reviewed (gaps)

1. **Upstream diffs** for `gpu/shadps4` (b4e7ae7 + backports), FSR-Vulkan, ImGui, magic_enum, miniz, xbyak, LibAtrac9, SPIRV-Headers, and shadp2p.
2. **Full read** of the native runtime: `src/runtime_*.c` (~22 files), `gpu/shim/**`, `gpu/bbnet/bbnet_glue.cpp`, the GPU renderer (`gpu/shadps4/video_core`, ~141 files), and the shader recompiler (~122 files). Only sampled.
3. **Built artefacts**: the Windows zip, `bb-probe.exe`, `libbbgpu.dll`, `bbport_dlss.dll`. None are in the repo; they have to be built or downloaded and compared.
4. **Dynamic behaviour**: nothing has been run. Network behaviour, file writes, and process creation need observation in a sandbox.
5. **Game dump handling**: how `eboot.bin` is read and patched. Requires a legally obtained dump, which is not in the repo.

---

## 5. Tools needed

**Source review and provenance**
- `git` with the upstream remotes added, and `git diff --no-index` or difftastic for vendor comparisons.
- Semgrep (community rules for C/C++, Python, bash, and PowerShell).
- CodeQL (C/C++ and Python databases) if the GitHub Advanced Security tooling is available.
- clang-tidy, cppcheck, and the Clang Static Analyzer (`scan-build`).
- Bandit and Ruff for the Python launcher; ShellCheck for the shell scripts.
- Gitleaks or TruffleHog for secrets in the full history (`git log -p`), not just HEAD.
- OSV-Scanner or Syft to map vendored components to known CVEs.

**Build reproduction**
- MSYS2 CLANG64 toolchain (`repo.msys2.org`).
- Visual Studio 2022 Build Tools, for the DLSS bridge.
- Vulkan SDK (`sdk.lunarg.com`), CMake, Ninja, Python 3, PyInstaller.
- Optional: Nix, for the Linux build (`shell.nix`, `packaging/default.nix`).

**Binary analysis (for built artefacts)**
- FLARE **capa**, to list capabilities of the Windows binaries.
- **YARA** with community malware rules.
- **Detect It Easy** and **pefile** / **LIEF** for PE structure, signatures, and section entropy.
- **Ghidra** or **rizin** for targeted decompilation of anything that calls `CreateRemoteThread`, `WriteProcessMemory`, or `NtCreateThread`.
- `signtool` or `sigcheck` to check whether the release binaries are signed at all.

**Dynamic analysis (isolated)**
- A disposable Windows 10/11 VM with snapshots (Hyper-V or QEMU/KVM), **without** a real Steam, PSN, or shadNet account.
- Process Monitor (ProcMon) and Sysmon with a config that logs process creation and network connections.
- Wireshark or `tcpdump` on the VM's virtual NIC, plus **mitmproxy** for HTTPS inspection (requires installing its CA in the VM only).
- **FakeNet-NG** or **INetSim** to answer DNS and HTTP inside the sandbox, so the game gets fake responses and nothing reaches the real servers.
- **Frida** to hook `sceHttpsLoadCert` and the network functions, and to log which hosts and certificates are used.
- Optional: VirusTotal, for hash lookups only. Uploading the actual binaries to a third-party scanner is outward-facing and needs the user's approval first.

---

## 6. Domain and network access needed

Ask for these in the environment's **Network access** settings. Read-only access is enough for everything except the last group.

**Source and provenance (read-only)**
- `github.com`, `api.github.com`: upstream repositories at the pinned commits (shadPS4, FSR-Vulkan, ImGui, magic_enum, miniz, xbyak, LibAtrac9, SPIRV-Headers, Q2RTX, shadp2p, deadinside28/bloodborne_pc) and the release history of `Supermedo/bloodborne_pc`.
- `codeload.github.com`: source tarballs at pinned commits.
- `objects.githubusercontent.com`: release zip contents, so the shipped binaries can be compared with a source build.
- `raw.githubusercontent.com`: FSR4 assets from `FireBurn/Q2RTX` at the pinned commit (to verify hashes).

**Build dependencies (read-only, only if building)**
- `repo.msys2.org`, `sdk.lunarg.com`, `pypi.org`, `files.pythonhosted.org`, `developer.nvidia.com` and `github.com/NVIDIA/DLSS` for the DLSS SDK.

**Vulnerability data (read-only)**
- `api.osv.dev`, `osv.dev`, `nvd.nist.gov` (CVE lookups for vendored components).

**Dynamic analysis (only inside the isolated VM, with DNS sinkholed)**
- `thehuntersdream.com`, `ss4.scej-network.jp`, `shadnet.shadps4.net`, `srv.shadps4.net`: **do not allow real access**. Resolve these to a sinkhole (FakeNet-NG or INetSim) and record what the game sends. Allowing them would send a real account's credentials and game traffic to third parties during analysis.
- `discord.gg`, `store.playstation.com`: not needed for analysis.

**How to enable:** the environment's network policy blocks hosts not on its allow list. Add them under **Allowed domains** in the cloud environment settings, or use a broader access level if that is preferred. Read-only access to the upstream repositories may also require `add_repo` for each repository, because the current session is scoped to `npxcomplete/cosmic-hunter`.

---

## 7. Recommended order of work

1. **Close provenance (F5).** Diff every vendored tree against its pinned upstream. List all non-`bbport:` changes. This is the cheapest way to find injected code, and it covers the shadp2p network code that was added last.
2. **Trace the network trust chain (F1).** Map which requests use `sceHttpsLoadCert` contexts, and what data they carry. Confirm with a MITM test in the sandbox.
3. **Check the release pipeline (F2, F6).** Compare the shipped zip with a clean build from the tagged commit. Check for signatures and whether any hash manifest exists.
4. **Static scans (Section 5)** across non-vendor code, then the vendored code that the diffs flag.
5. **Dynamic run in the sandbox** with sinkholed DNS: launch, observe file and process activity, and check for unexpected network calls.
6. **Fix the medium items:** F3 (password storage), F4 (mods trust warning), F7 (PowerShell quoting).

---

## 8. Open questions for the owner

1. Do you have a legally obtained decrypted dump (`CUSA03173`, v1.09) for dynamic testing? Without one, step 5 cannot run.
2. Is the Windows release built in CI, or by hand? A CI log would show whether the shipped binaries match source.
3. Is online play intended to be on by default for the Windows build? F1 only matters when it is on.
4. Which shadp2p commit was the source of the network code in `e076119`? Without it, F5 cannot be closed.
5. May I add the upstream repositories with `add_repo` (read access), and may I change the sandbox network allow list as described in Section 6?
