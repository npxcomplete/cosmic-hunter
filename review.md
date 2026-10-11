# Security review: cosmic-hunter (Bloodborne Windows/Linux port)

Scope: static triage of the checked-out tree at `e076119` ("Online play, Add to Steam (1.6)"), plus the build scripts. Nothing from the repo was built or executed, and no network access was used.

## Verdict

**No confirmed malware or backdoor found. This is not a clean bill of health.** The review was a first pass and has these gaps:

- All six git submodules are unpopulated, so none of that code was read.
- About 1.2 MB of vendored network and PSN code, added in a single commit, was only spot-checked.
- The shipped artifact (the release zip) cannot be compared to this source.

Risk is concentrated in three places, in this order:

1. The release and update pipeline. The binaries players run are not built from this repo alone.
2. The new online-play stack (1.6), which redirects Sony server traffic and bypasses TLS verification.
3. Unpinned third-party downloads at build or run time.

## What the repo is

- A fork chain: `deadinside28/bloodborne_pc` (Linux port, the original author, 34 commits), then `Supermedo/bloodborne_pc` (Windows port, 16 commits, 2026-10-02 to 2026-10-08).
- It runs a user-supplied, dumped PS4 game via a custom loader (`src/*.c`) and a vendored shadPS4 GPU core (`gpu/`).
- It has a Python/Tk launcher. `launcher/bbport_launcher_win.py` is the Windows launcher that is frozen into `Bloodborne.exe`.
- Commit authorship is consistent with that chain. No commits come from unrelated identities.
- There are no committed executables, DLLs, `.so` files, archives, or opaque blobs. The only binaries are `DejaVuSans.ttf`, one `.png`, and one `.ico`.

## Findings

Severity is my estimate of how much each item warrants attention. It is not a statement that exploitation has been observed.

### 1. Self-updater installs an unverified zip and runs it (High)

`launcher/bbport_launcher_win.py:1371-1420`, `:1554-1590`

- The launcher queries `api.github.com/repos/Supermedo/bloodborne_pc/releases/latest` and takes the first `.zip` asset's `browser_download_url`.
- It downloads and extracts the zip, then executes the extracted `Bloodborne.exe --install-update`. That process copies itself over the install directory.
- There is no hash or signature check, no pinned publisher key, and no code signing check. A compromised maintainer account or release asset would give arbitrary code execution on every launcher that has the update prompt.
- The extracted `Bloodborne.exe` is a PyInstaller bundle, so the code that runs lives in the release asset, not in this source tree.
- `Bloodborne.exe`, `Play Bloodborne.exe`, `bb-probe.exe` and all bundled DLLs come from `packaging/windows/package.sh` run on the maintainer's machine. Nothing here proves a published zip matches this source.

### 2. Game traffic is redirected and TLS verification is bypassed (High, by design but significant)

`run.py:20-70`, `gpu/shadps4/core/libraries/network/http.cpp:336-420`, `:965-985`, `:2010-2035`

- `run.py` writes `host_overrides.json`, mapping Sony's `https://ss4.scej-network.jp:20443` to `https://thehuntersdream.com`. It sets `SHADPS4_HTTP_HOST_OVERRIDES_JSON` so the emulated HTTP stack follows that map.
- Players' game-server requests, including sign-in, therefore go to a third-party server. Its operator is not identified in the repo.
- `http.cpp` disables server certificate verification whenever the game loads custom CAs. The game does so for its private endpoints. The check is `ctx_has_loaded_certs`, and it is skipped because "libSceSsl integration not implemented". The same applies when the game clears `SERVER_VERIFY`.
- Together this allows an on-path attacker, or a malicious override target, to impersonate any server the game talks to.
- `host_overrides.custom.json` and `BB_COMMUNITY_SERVER` allow arbitrary redirects. That is acceptable for user-set values, but they are also an injection point if another local process can write the user directory.

### 3. shadNet client appears to send credentials in cleartext (Medium)

`gpu/shadps4/shadnet/client.cpp:65-200`, `:280-370`

- The client does `getaddrinfo` and a raw `::connect`, then sends a protobuf `Login` request containing the `npid`, `password` and token over plain TCP.
- I found no TLS use in this file. This needs confirming against `server_probe.cpp` and the compiled binary.
- The launcher's "connection test" (`server_check`, `bbport_launcher_win.py:312-335`) also uses plain `http://` to the WebAPI, derived from user input (`webapi_address`).
- `ssl.cpp` and `ssl2.cpp` are 1,600 lines of emulated libSceSsl. They were not reviewed.

### 4. Unpinned and unverified downloads (Medium)

- `tools/fetch_fsr4_assets.sh:10` and `launcher/bbport_launcher_win.py:213,1122` download about 400 files (SPIR-V shaders and neural-net weights) from `raw.githubusercontent.com/FireBurn/Q2RTX/<commit>/...`.
  - The commit is pinned, which is good. The files have no per-file hashes, and they come from a third-party repo that is not the AMD source.
  - They are loaded as GPU shaders and model data (`.spv`, `.bin`). Malformed SPIR-V is a driver attack surface.
  - The Windows launcher downloads them with `urlopen(...).read()` into memory with no size limit, and writes to disk.
- `tools/fsr4cap/build_assets.sh` clones `HansKristian-Work/dxil-spirv` and `GPUOpen-LibrariesAndSDKs/FidelityFX-SDK` at pinned commits, and runs `cmake` and `ninja` on them. Submodules are pulled from branch HEADs recorded in `.gitmodules` (see section 6).
- The Windows `package.sh` runs `pip install pyinstaller` unpinned, with no hash checking. That is a supply-chain path into the frozen `Bloodborne.exe`.
- `packaging/windows/build_dlss.sh` ships NVIDIA's prebuilt `nvngx_dlss.dll` from a user-supplied SDK checkout, plus `bbport_dlss.dll` (a bridge adapted from `IFreemz/shadPS4-Bloodborne-DLSS-FSR`).
  - The bridge source is in `gpu/dlss_bridge/` and looks benign. A prebuilt copy cannot be verified against it.

### 5. Process execution and persistence-adjacent behaviour (Low, reviewed and explained)

All of these have a stated purpose and I found no hidden use.

- PowerShell is invoked only to create a desktop `.lnk` (`:1453`) and to zip or count processes in `package.sh`. The `$s.TargetPath=` string interpolates `PORT_DIR` and `target`, so a path containing `"` or `'` would break out of the quoting. This is local and low impact.
- `bbport_steam.py` edits `Steam\userdata\<id>\config\shortcuts.vdf`. It writes a `.bak` and kills Steam via `steam.exe -shutdown`. This is user-initiated through "Add to Steam".
- `src/probe.c:365` uses `CreateProcessA` to restart itself.
- `tools/bridge_helper/bridge_helper.c` uses `wine_server_fd_to_handle` for a Proton memory-bridge test. It is dev tooling and not packaged.
- `scripts/mods.py` and `scripts/patches.py` apply user mods and `Bloodborne.xml` patches as literal byte writes into game memory. The 248 KB bundled patch file is community-sourced. Each patch is an address and value, with no executable payload format. The patch values were not individually decoded.

### 6. Submodules and vendored code were not reviewable (Gap)

- Submodules (`.gitmodules`):
  - `FireBurn/FSR-Vulkan` (plus 2 local patches, which look benign; I only skimmed them)
  - `ocornut/imgui`
  - `Thealexbarney/LibAtrac9`
  - `Neargye/magic_enum`
  - `richgel999/miniz`
  - `herumi/xbyak`
- `LibAtrac9` is compiled by `build.sh` with `-w` and outside the `-Werror` policy. It decodes untrusted audio from the game.
- The pinned submodule SHAs are in the git tree. They need to be compared against upstream tags.
- `gpu/third_party/httplib/httplib.h` (698 KB) and `wepoll`, `half`, `sirit`, `gcn` are copied in, not submoduled. Each should be diffed against the claimed upstream version.
- `gpu/VENDOR.txt` states shadPS4 commit `b4e7ae776071` with "bbport:" marked local changes. The vendored `gpu/shadps4/` tree should be diffed against that commit to isolate every local change. This is the most useful single check.

### 7. Hardcoded external endpoints

| Endpoint | Where | Purpose |
|---|---|---|
| `api.github.com/repos/Supermedo/bloodborne_pc/releases/latest` | launcher | update check |
| `github.com/Supermedo/bloodborne_pc/releases/*` | launcher | update download |
| `raw.githubusercontent.com/FireBurn/Q2RTX/...` | launcher, `fetch_fsr4_assets.sh` | FSR 4 assets |
| `thehuntersdream.com` (ports 20443, 18671) | `run.py`, launcher | community game server |
| `ss4.scej-network.jp:20443` | `run.py` | Sony server, rewritten away |
| `shadnet.shadps4.net` | docs only | shadNet registration |
| `127.0.0.1:31315` | `run.py` | default shadNet WebAPI |
| user-set shadNet host (31313 / 31315) | launcher | co-op |
| `discord.gg/yTMG8c4Bqm` | README | support |

Not seen: telemetry, analytics, crash upload, or a beacon to any domain outside this list. Online access is gated on `BB_ONLINE=1` per the 1.6 commit message. I did not confirm that gate in `bbnet_glue.cpp` and the runtime.

## Checks that found nothing

- No `eval`, `exec`, `pickle`, `marshal`, `base64` decode-and-run, obfuscated strings, or long hex or base64 blobs in first-party code. `base64` in `scripts/prepare.py` only builds a file id.
- No registry writes beyond reading `HKCU\Software\Valve\Steam\SteamPath`.
- No scheduled tasks, services, or autorun entries.
- No clipboard, keystroke, browser-profile, or wallet access.
- No file reads outside the game directory, user directory, and config.
- `zipfile.extractall` is used on the update archive. Python sanitizes `..` and absolute paths, so no zip-slip.
- CMake uses `find_package` only. There is no `FetchContent`, `file(DOWNLOAD)`, or network-calling `execute_process`.
- No unusual git history: no force-push traces, no history rewrite visible, no added-then-deleted binaries.

## Additional tools and access needed for a comprehensive analysis

### Source and supply chain

| Need | Why |
|---|---|
| `git` with network access to the six submodule repos, then `git submodule status` and diffs against upstream tags | Review pinned SHAs and check for tampering. |
| A clone of upstream shadPS4 at `b4e7ae776071`, plus the backported commits in `VENDOR.txt` | Diff against `gpu/shadps4/`, `gpu/third_party/`. |
| Upstream `shadp2p` (`Wozzardman/shadp2p`) | Diff the 1.6 network, PSN, shadNet and bbnet code, which is claimed to derive from it. |
| Upstream `IFreemz/shadPS4-Bloodborne-DLSS-FSR` and `deadinside28/bloodborne_pc` | Diff the DLSS bridge, and diff the Linux base against the Windows changes. |
| `cpp-httplib`, `wepoll`, `half`, `sirit` upstream releases | Diff against vendored copies. |
| `FireBurn/Q2RTX` at commit `ae8d628f...` | Obtain the 400 FSR 4 asset files, hash them, and validate the SPIR-V. |
| `gh` or GitHub API access to `Supermedo/bloodborne_pc` releases | Download release zips and compare them with a source build. |

### Static and binary analysis

- `semgrep`, `CodeQL` (C/C++ and Python), `cppcheck` or `clang-tidy`, `bandit`, `shellcheck`, and `gitleaks` or `trufflehog` for secrets.
- `spirv-val`, `spirv-dis` and `spirv-opt` for the FSR 4 shaders.
- `ghidra` or `radare2`, `strings`, `binwalk`, `YARA`, `capa`, `pefile` and `die` for the release binaries (`Bloodborne.exe`, `bb-probe.exe`, `bbport_dlss.dll`, `nvngx_dlss.dll`).
- `pyinstxtractor` and `pycdc` or `decompyle3` to unpack the frozen `Bloodborne.exe` and compare its bytecode to `launcher/*.py` and `scripts/*.py`.
- Authenticode and signature check tooling (`osslsigncode`, `sigcheck`) for `nvngx_dlss.dll` and the release binaries.

### Reproducible build and sandbox

- A Windows VM or sandbox, with snapshots, for the MSYS2 CLANG64 toolchain (`clang`, `cmake`, `ninja`, `pkg-config`, SDL3, FFmpeg, OpenSSL, protobuf, miniupnpc), Python 3.10+, and PyInstaller.
- Linux build deps from `shell.nix` (GCC, Vulkan headers and loader, SDL3, glslang, spirv-cross, boost, fmt, and others).
- Package mirrors or allowlists for `msys2.org`, `pypi.org` and `files.pythonhosted.org`, so the toolchain and PyInstaller installs can be hashed.

### Dynamic and network analysis

- `Wireshark`/`tshark`, `mitmproxy` or `Fiddler`, and `Procmon`, `Process Explorer` or `Sysmon`, `API Monitor`, and `Regshot`. Use them to watch network, file, registry and process activity in the sandbox.
- `strace`/`ltrace`, `bpftrace`, `perf`, and `sysdig` or `auditd` for the Linux build.
- Vulkan layers and RenderDoc (to inspect shaders and GPU-side behaviour), `VK_LAYER_KHRONOS_validation`.
- A decoy network environment: `INetSim` or a similar fake-internet setup, plus a DNS sinkhole, so outbound behaviour can be observed without live contact.

### Outbound domains the analysis would need allowed (or captured)

For static and supply-chain work:

- `github.com`, `api.github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `raw.githubusercontent.com`
- `pypi.org`, `files.pythonhosted.org`, `repo.msys2.org`, `mirror.msys2.org`
- `nixos.org` and `cache.nixos.org`
- `developer.nvidia.com`, for the DLSS SDK

For passive reputation lookups (no interaction with the targets):

- `virustotal.com`
- `urlscan.io`
- `crt.sh`
- `whois`, passive DNS, and Shodan or Censys for `thehuntersdream.com`, `shadnet.shadps4.net` and `ss4.scej-network.jp`

Do not contact `thehuntersdream.com` or the shadNet servers from the analysis host with real credentials. Their behaviour should be observed only from the isolated sandbox, with traffic captured.

### Other inputs

- The actual release zip(s) from `Supermedo/bloodborne_pc` releases (1.x), with hashes, to diff against a rebuild.
- A legally obtained, dumped `CUSA03173` game directory, or a stub, to run `bb-probe` end to end. Alternatively, run the repo's `--cpu-only` and test paths (`tests/`) with synthetic input.
- Confirmation from the maintainers of the build environment (toolchain versions, `PATH`, whether `dist/` was built on a clean machine).

## Recommended next steps, in priority order

1. Obtain the published release zip and unpack the PyInstaller bundle. Compare it to this source, and hash every DLL.
2. Populate the submodules and diff them against upstream at the recorded SHAs.
3. Diff `gpu/shadps4/` and `gpu/third_party/httplib` against upstream shadPS4, shadp2p and cpp-httplib.
4. Run `bb-probe.exe` and the launcher in an isolated VM with traffic capture, once with `BB_ONLINE` unset and once set, and compare it to the offline stubs.
5. Establish who operates `thehuntersdream.com` and whether the redirect of Sony's host is acceptable.
6. Recommend hardening: add SHA-256 pinning for the update and FSR 4 downloads, sign the releases, restrict cert-verification bypass to the specific hosts the game needs, move shadNet login to TLS, and pin `pip install pyinstaller` with hashes.
