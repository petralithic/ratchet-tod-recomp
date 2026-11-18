# macOS (Apple Silicon) port: findings and plan

Status: phase 1 (2026-11-17), branch `macos/port-phase1` of the `petralithic` fork. Nothing here
changes the Windows build: every edit is `#ifdef`-limited to non-Windows hosts or goes through
`win32_compat.h`, which is `<windows.h>` on Windows.

Goal: the same game, playable on an M-series Mac, from the **North American disc BCUS98127**
(PARAM.SFO `APP_VER 01.00`, disc `VERSION 02.00`) as well as the EU disc BCES00052 the port targets
today, with the renderer on Vulkan through MoltenVK, as in the
[RACiT macOS work](https://github.com/HighDrexler/RACiT/pull/41).

## 1. How the port is built today (Windows)

**Decrypt.** `src/install/` (C++) and `tools/self2elf.py` (Python, the same steps) turn the disc's
`PS3_GAME/USRDIR/EBOOT.BIN` (an application SELF, key revision 0x0001) into `elf/EBOOT.ELF`: the metadata
info is opened with the public application key (AES-256-CBC), then the section keys (AES-128-CTR), and each
segment is decrypted and inflated. The installer accepts only BCES00052 1.00: it checks PARAM.SFO
(`TITLE_ID`, `APP_VER`) and the SHA-256 of both `EBOOT.BIN` and the resulting ELF
(`kEbootElfSha256 = cd2c3735...` in `src/install/iso.cpp`). It reads disc images that are already
disc-decrypted (ISO 9660), and copies `PS3_GAME` into `game/disc`.

**Lift.** `tools/lift_ppu.ps1` runs ps3recomp's `ppu_loader.py` (function entries from the OPD) and
`ppu_lifter.py` (PowerPC to C++, ~600 MB into `recompiled/`, split into `ppu_recomp_NNN.cpp`), with
`--code-end` from the section headers and two `--hook`s (Lua `luaD_rawrunprotected` and `longjmp`,
made native by `src/stubs/lua_eh.cpp`). `tools/lift_spu.ps1` extracts and lifts the SPURS policy module
(at a fixed guest address), the 21 `C0DEC0DE` job modules (found by scanning) and the two raw-SPU
collision programs (fixed addresses), then `promote_spu_c.py` adds register-promoted twins. Runtime-loaded
SPU overlays are captured while playing and lifted by `tools/lift_dynovl.py` (optional).

**Hook.** The port replaces or wraps game functions by name. `CMakeLists.txt` copies a lifted unit
(`ppu_recomp_000/001/002/003/004/011.cpp`, chosen by file name) and renames
`void func_<EU address>(ppu_context* ctx) {` to `..._lifted`; `src/stubs/*.cpp` then defines
`func_<EU address>` and calls the lifted one (about 30 hooks: aspect ratio, combat log, difficulty lock,
decrypter 60 FPS, UI sync, armor look, collision fast path...). `src/main.cpp`, `src/input/tod_cheat.cpp`
and the stubs also compare return addresses (`ctx->lr == 0x006F1BA0`) and read guest data at fixed
addresses. The ps3recomp fork (`Re-TeRo17/ps3recomp`, branch `tod-1.3`, 476 commits after the runtime
RACiT pins and ~39k lines of ToD changes on top of upstream `93dbfddf`) carries the renderer, SPU fast
paths (skeletal animation, collision) and a shipped pipeline map.

**Renderer.** RSX command stream -> `rsx_dispatch.c` / `cellGcmSys.c` -> **the register-file draw engine**
(`libs/video/rsx_draw_engine.c`, 10.9k lines, API-neutral: decodes NV4097 state, decompiles vertex and
fragment programs to HLSL, caches geometry, textures and surfaces) -> a backend through
`rsx_draw_backend` (46 callbacks, `rsx_draw_engine.h`). Two backends exist in the submodule:

| | `rsx_d3d12_engine.c` | `rsx_vulkan_engine.c` + `rsx_vulkan_encode.inc` |
| --- | --- | --- |
| Size | 8.5k lines | 3.4k lines |
| Callbacks | 44 of 46 | 41 (no `depth_resnap`, `color_copy_rect`, `set_blend_color`, `rt_ao_*`) |
| Shaders | HLSL -> DXBC/DXIL | the same HLSL -> SPIR-V via glslang (`rsx_shader_spirv.cpp`) |
| Platform | Win32 window, DXGI | Win32 window + `vulkan-1.dll` loaded at run time; otherwise plain Vulkan 1.3 (dynamic rendering, timeline semaphores) |
| ToD work since fork | ~12.9k changed lines (FXAA/MSAA present, RT AO via DXR, lazy surface views, pipeline cache) | none (upstream code as of 2026-10-19) |

`rsx_d3d12_backend.c` is the entry point (`rsx_d3d12_backend_init`): it starts the Vulkan engine with
`RSX_BACKEND=vulkan`, else the D3D12 engine. Off Windows, `main.cpp` falls back to the runtime's
null backend. The runtime also has an older Metal backend (`rsx_metal_backend.m`) and the Linux
`rsx_vulkan_backend.c` (a different, pre-draw-engine renderer, the one RACiT's Mac build uses);
neither is used by ToD.

Of the seven 1.3.0 renderer speed-ups, five live in the shared draw engine (`RSX_ZSNAP_KEEP`,
`RSX_ZSNAP_ALT`, `RSX_GOV_MINKB`, `RSX_LANES_ZDEM_ASK`, `RSX_LANES_ZPRESS_PCT`; `ZSNAP_KEEP` needs the
backend's `depth_resnap`), two in the D3D12 engine (`RSX_SURFVIEW_LAZYZOWN`, `RSX_SURFVIEW_LAZYCOLOR`).

**Windows-only parts.**

| Area | Files | macOS status (phase 1) |
| --- | --- | --- |
| Renderer, present, window | `rsx_d3d12_*`, `rsx_vulkan_engine.c` (Win32 surface), `rsx_rt*` (DXR) | null backend; Vulkan engine port is milestone M3 |
| Settings overlay (Dear ImGui on D3D12) | `src/ui/tod_overlay.cpp`, `imgui_impl_dx12` | replaced by `src/ui/tod_overlay_stub.cpp` (no page; menu rows apply through the environment) |
| Keyboard and mouse | `GetAsyncKeyState`, Raw Input in `rsx_host_mouse.c` | VK codes defined, key state hook `tod_host_key_down` (NULL = headless) |
| Controllers | XInput / SDL2 (`PS3RECOMP_PAD_SDL2`), DualSense HID in `tod_dualsense.cpp` | SDL2 is the runtime's default off Windows; DualSense triggers compile, HID path to verify |
| Keycap labels | GDI `TextOutW` in `src/patches/prompts.cpp` | CoreText on macOS |
| Update check | WinHTTP | off (state 0) |
| Research tools | `tod_rwatch.cpp` (vectored exceptions), stall monitor (`tlhelp32`, `dbghelp`) | rwatch stubs; stall monitor already `#ifdef _WIN32` |
| Timers and threads | QPC, waitable timers, `SetThreadDescription` | `win32_compat.h` (+ `CreateWaitableTimerExW` -> fallback) |
| Installer and release | `tod_setup.exe`, `Install.bat`, `Play.bat`, `Update.bat`, PowerShell | to do (M5); `tools/lift_ppu.sh` replaces `lift_ppu.ps1` |
| Discord | named pipe `\\.\pipe\discord-ipc-N` | compiles (Windows code `#ifdef`ed); macOS uses `$TMPDIR/discord-ipc-N` sockets (later) |

## 2. NA disc BCUS98127: what it takes

### 2.1 The executable decrypts and lifts with the existing pipeline

The NA `EBOOT.BIN` (SHA-256 `91e37dad...`) is the same kind of SELF (key revision 0x0001), so
`tools/self2elf.py` decrypts it unchanged: `EBOOT.ELF` SHA-256
`0ee9a8414c8fc182bc19fa2a523e6d050d0be76138b3733ae515798d77d2468c`, 10,923,400 bytes.
`tools/lift_ppu.sh` recognises both releases by that hash and passes each one's Lua hooks.

| | EU BCES00052 1.00 (from the port's docs) | NA BCUS98127 1.00 / disc 02.00 |
| --- | --- | --- |
| `.text` | 0x10280..0x8393A8 | 0x10280..0x839628 (+0x280) |
| import stubs | ..0x83A28C (`--code-end`) | ..0x83A50C (same 0xEE4 bytes) |
| PPU functions (OPD + `bl` targets) | not measured here (no EU copy) | 26,362 |
| Data segment 0x10000000 | PM 0x10053D00, igCollBroadSpu 0x10175180, igcollspu 0x1017BF80 | the same addresses (raw-SPU `DEADDEAD` headers and SPU code found exactly there) |
| WWS job modules | 21 | 21 (`C0DEC0DE`, found by scanning as today) |
| Lua hooks | 0x671A28, 0x8268B4 | 0x671CA8, 0x826B34 (disassembly checked: `L->errorJmp` + setjmp + `bctrl`; register restore from the jmp_buf) |

So the SPU side needs nothing per release: the job modules are found by signature, the policy module and
the raw programs sit at the EU addresses. The PPU side is the same code shifted.

### 2.2 EU -> NA address map (without the EU executable)

The owner has only the NA disc, so the EU code cannot be compared directly. `tools/tod-fnmap`
(Rust, no dependencies) `probe` fits EU addresses onto NA function entries: every NA function start
within ±0x400 of an EU address gives a candidate delta, and a Viterbi pass picks the delta sequence
with the fewest changes. With no constraint, the port's 129 EU function addresses fall into runs of
equal deltas; constrained to those deltas, **126 of 129 sit in runs of 3 or more** of a monotone step
function (the 3 others are comment references, not hooks):

| EU range (`func_` addresses the port names) | NA = EU + | Inserted in NA |
| --- | --- | --- |
| 0x10200 .. 0x26BD0 | 0 | |
| 0x274F8 .. 0x2D2028 | +0x30 | 0x30 bytes between EU 0x26BD0 and 0x274F8 |
| 0x39D400 .. 0x3B7AA8 | +0x230 | 0x200 between 0x2D2028 and 0x39D400 |
| 0x3B8998 .. 0x5AC298 | +0x258 | 0x28 between 0x3B7AA8 and 0x3B8998 |
| 0x5D4040 .. 0x83A28C | +0x280 | 0x28 between 0x5AC298 and 0x5D4040 |

The last step equals the `.text` growth (0x8393A8 -> 0x839628), and the two Lua hooks found by
disassembly agree with it. Four small insertions (0x2D0 bytes in all, about 180 instructions) means
NA and EU are almost the same build; the step boundaries are known only to within the gap between the
nearest port addresses on each side.

What this does **not** prove: that a function at the mapped address is unchanged (the inserted bytes are
code changes somewhere inside those gaps), and where exactly each insertion is. The exact answer is the
RACiT method (`tools/racit_update120_fndiff.py`): hash every function with branch targets and TOC/address
halves masked, then align the two lists. `tod-fnmap sig` produces that list (addresses and 64-bit hashes
only, no code) and `tod-fnmap map` aligns two of them. **Ask the EU maintainer to run
`tod-fnmap sig elf/EBOOT.ELF > BCES00052-1.00.fnsig.tsv`** (seconds, from the ELF they already have); with
it, the number of identical/changed/moved functions and the exact map come out directly.

Still to translate besides the `func_` names:

- **Return-address and code constants**: 65 distinct `0x00XXXXXX` code addresses in `src/`
  (e.g. `ctx->lr == 0x006F1BA0` for the synth tick, which is NA 0x6F1E20); same step function.
- **Guest data addresses**: 52 distinct constants in `src/` (0x10xxxxxx and 0x8xxxxx..). The 0x10000000
  segment lines up (SPU blobs at EU addresses). The 0x840000 segment (OPD, TOC, `.data`) very likely
  lines up too: the entry descriptor the port names for EU ("main TOC (OPD 0x859418)",
  `tod_cheat.cpp`) is exactly the NA ELF's entry point, and the Ratchet object vtable the cheats test
  (0x0084A3F8) holds an OPD pointer (0x866170) in NA, as a vtable should. Each data constant still gets
  checked once against its use (the five in 0x84xxxx..0x8Axxxx first).
- **Lifted-unit file names**: CMake picks `ppu_recomp_002.cpp` etc. by name. The lifter splits units by
  function count, so an NA lift puts the hooked functions in other files. Patch by searching all units for
  the definition instead of by file name.
- The installer's TITLE_ID/APP_VER/hash checks (accept a table of releases).

### 2.3 Plan for NA

1. **Per-release address table**, `versions/<release>.tsv`: hook name -> address (and lr/data constants).
   EU is today's values; NA is generated by `tod-fnmap` (step function now, exact with the EU signature
   file), then each hook's NA function checked by disassembly once (as done for the Lua hooks).
2. **Hooks by symbol, not by EU name**: generate a small header from the table (`TOD_FN_ASPECT_PROJ`,
   `TOD_LR_SYN_TICK`, ...) so `src/` names hooks by role; CMake reads the same table to rename lifted
   definitions (searching every unit). The EU build is byte-for-byte what it is today.
3. **Installer and launcher**: recognise both releases (SFO + ELF hash table), copy or map
   accordingly. Keep EU as the reference release for upstream.
4. Verify on NA (headless, offscreen): boot to title, a level, the hooked features (aspect, combat log,
   difficulty lock, decrypter, menus), then the same for EU when someone with that disc can run it.

### 2.4 Game data

The whole NA disc is decrypted into a folder on this machine (`PS3_GAME/...`, `PS3_DISC.SFB`), which is
the layout the port already runs from: point `PS3_VFS_ROOT` at it (the release default is `game/disc`,
see `src/main.cpp`). No game file is copied into the repository or the build tree; `PS3_HDD0_ROOT`,
saves and caches stay in git-ignored folders. The installer's disc check (`src/install/iso.cpp`) must
accept the NA folder as well (M5); reading straight from an ISO is not planned.

## 3. Renderer for macOS

| | (a) Port RACiT's Vulkan backend | (b) Vulkan engine behind ToD's draw engine (`rsx_vulkan_engine.c`) on MoltenVK | (c) D3D12 -> Vulkan translation (vkd3d-proton) on MoltenVK |
| --- | --- | --- | --- |
| What it is | `rsx_vulkan_backend.c` of RACiT's pinned runtime + its 36k-line patch | the backend that already implements `rsx_draw_backend` in ToD's own runtime, given a non-Win32 surface | run the D3D12 engine unchanged on a D3D12 implementation over Vulkan |
| Fit with ToD | poor: a different, older renderer (pre-draw-engine path) from a runtime 476 commits older; ToD's renderer work (draw engine, surfaces, speed-ups, fog fix) would not apply | direct: same record stream as the D3D12 engine, same draw engine, same HLSL from the same decompilers (SPIR-V via glslang) | in theory none |
| Effort | very high (re-port ToD's renderer fixes into another renderer) | moderate: replace Win32 window/loader/QPC (~150 lines), add the 5 missing callbacks, port the D3D12-only ToD features (FXAA/MSAA present, lazy surface views, `depth_resnap`, `color_copy_rect`) | high and uncertain: vkd3d-proton needs Vulkan features MoltenVK lacks (it targets Linux drivers; bindless/descriptor-heap and DXIL requirements), it is built for Wine; no supported path on macOS |
| Performance | RACiT on M1 Pro: ~80 FPS after a long series of fixes | inherits the RACiT findings below; no extra translation layer beyond MoltenVK | two translation layers (D3D12 -> Vulkan -> Metal) |
| Upstream-friendliness | low: a second renderer to maintain | high: improves the backend already in Re-TeRo17/ps3recomp and helps Windows `RSX_BACKEND=vulkan` users too | low: Windows code stays, Mac needs a heavy external stack |
| Maintenance | two renderers diverge | one engine, two encoders kept side by side (as their headers already intend) | external dependency |

**Recommendation: (b).** ToD already has the right abstraction: the D3D12 and Vulkan engines are two
encoders of one record stream, written to "read side by side". Making the Vulkan engine platform-neutral
(a `VK_EXT_metal_surface` / `VK_KHR_portability_*` surface on macOS, `dlopen` of the Vulkan loader or
MoltenVK, `win32_compat.h` timing, an offscreen mode) gives macOS a renderer that gets every draw-engine
improvement for free, and the same patch is useful on Windows and Linux. It is also the
upstream-friendliest: changes stay inside the runtime fork the port already uses.

Take from RACiT (its Mac log and design notes) the lessons, not the code:

- Run the window/event loop on the process main thread and guest code on a large-stack thread
  (Cocoa requires it); keep an offscreen mode (`PS3RECOMP_VK_WINDOW=0` there) for unattended tests.
- MoltenVK specifics that cost RACiT the most: compensated dot products in the vertex programs (use
  fused multiply-add on Apple GPUs, +116% FPS there), a render-pass barrier fix, safe shader math,
  synchronous pipeline creation to avoid half-drawn passes.
- Per-draw cost on Apple GPUs through MoltenVK is ~5x a native Metal draw of the same shape (RACiT
  `docs/design/gpu-draw-overhead.md`): batch draws that differ only in constants, constants by reference.
  A native Metal encoder behind the same `rsx_draw_backend` stays the long-term option if that gap
  remains; the draw-engine design makes it a third encoder, not a new renderer.
- CPU side: wake the RSX walker on demand instead of sleeping (+24% on Mac), avoid `sched_yield`
  priority depression in spin-waits (macOS `swtch_pri`), NEON SPU lane conversions.

## 4. What phase 1 delivered

- Fork `petralithic/ratchet-tod-recomp`, clone at `~/Projects/tod-recomp` (remote `fork`), branch
  `macos/port-phase1`.
- NA `EBOOT.ELF` decrypted with the existing `self2elf.py`; NA PPU lift with `tools/lift_ppu.sh`
  (results in 5. below).
- `tools/tod-fnmap` (Rust): `sig`, `map`, `probe` (section 2.2).
- Non-renderer port code compiling on macOS arm64: `src/platform/tod_platform.h` (Win32 CRT names, VK
  codes, key-state hook, waitable-timer fallback on top of `win32_compat.h`),
  `src/platform/tod_platform_posix.cpp`, `src/ui/tod_overlay_stub.cpp`, CoreText keycaps, `#ifdef`s in
  `main.cpp`, `host_input.cpp`, `tod_rwatch.cpp`, `update_check.cpp`; `CMakeLists.txt` drops the D3D12
  overlay and links CoreText off Windows. `tools/check_port_posix.sh` compiles every port source to an
  object without a lift (declarations for the referenced lifted functions are generated).
- The ps3recomp runtime library configured and built for macOS arm64 (results in 5. below).

## 5. Phase 1 build results

As of the commit that adds this file:

| Step | Result |
| --- | --- |
| NA `EBOOT.ELF` (self2elf.py) | OK, sha256 `0ee9a841...` |
| `tod-fnmap sig` NA | 26,362 functions |
| `tod-fnmap probe` (port's 129 EU function addresses) | 126 in a 5-step monotone map, 3 comment-only references unmatched |
| NA PPU lift (`tools/lift_ppu.sh`) | OK: 32,170 functions lifted into 12 units (395 MB) |
| ps3recomp runtime library, macOS arm64 | **builds** after M1 (173 arm64 objects, 0 errors; was 153/173). Fixes on `petralithic/ps3recomp` `macos/m1-runtime`, draft upstream PR [Re-TeRo17/ps3recomp#1](https://github.com/Re-TeRo17/ps3recomp/pull/1) |
| Port sources, macOS arm64 (`tools/check_port_posix.sh`) | 36 of 37 compiled to arm64 objects; the last (`_stricmp` in `tod_cheat.cpp`) fixed since |

The 20 runtime units that did not compile on arm64 macOS before M1, by cause (all Windows- or x86-only code, mostly
in the ToD fork's additions; nothing architectural):

| Cause | Units |
| --- | --- |
| MSVC `__declspec(thread)` (C11 `_Thread_local` / `__thread` elsewhere) | `rsx_draw_engine.c`, `anim_ref.h` users: `anim_fx.c`, `anim_hle.c`, `anim_ref.c`, `capture_patch.c` |
| x86 intrinsics: `<intrin.h>`, `<immintrin.h>`, `__rdtsc`, MXCSR round-toward-zero | `spu_channels.c`, `spu_coherency.c`, `sys_timer.c`, `timeline.c`, `cellGcmSys.c` (needs `mach_absolute_time` / `cntvct_el0` and an FPCR rounding-mode path) |
| Win32 types or calls used without `win32_compat.h` (or missing from it: `QueryThreadCycleTime`, `VirtualQuery`, `GetModuleHandleA`, `SUCCEEDED`, `LONGLONG`, `_strnicmp`) | `cellAudio.c`, `cellPad.c`, `cellSpurs.c`, `rsx_dispatch.c`, `spu_raw.c`, `sys_semaphore.c`, `sys_mutex.c` (`lv2_usec_deadline` declared only under `_WIN32`) |
| SEH `__try`/`__except` | `spurs_policy.c` |
| `struct stat::st_mtime` (macOS: `st_mtimespec`) | `cellSaveData.c` |
| DXR ray tracing, D3D12 only | `rsx_rt.c` (exclude off Windows) |

This working branch points `.gitmodules` at `petralithic/ps3recomp` (branch `macos/m1-runtime`) so a clone
fetches the runtime fixes; branches meant for upstream PRs keep the Re-TeRo17 URL until that PR merges.

### M2 status (2026-11-17)

- `versions/addresses.tsv` maps all 166 code addresses the port uses from BCES00052 to BCUS98127.
  `tools/tod-fnmap check` verifies them against the NA ELF and lift:
  - every function entry is a lifted NA function;
  - every return address follows a call to the function the port names;
  - 154 direct calls between mapped functions agree with the map.
- Hooks are named by role (`TOD_HOOK(ROLE)`) and other addresses by EU key (`TOD_FUNC`/`TOD_ADDR`, `src/release/tod_addr.h`).
  `tools/tod_release.cmake` renames each hook in whichever lifted unit holds it.
  For BCES00052 every function name preprocesses to the same token as before.
- NA build on macOS arm64, `-DTOD_RELEASE=BCUS98127`, null renderer, no SPU lift:
  - configure finds all 33 hooks and the hero-update patch;
  - **231 of 233 build steps succeed, including all 12 lifted units**;
  - not yet linked.
- Remaining errors: two boot-scaffold units of the runtime fork use Win32 names without the off-Windows shims, the same kind of fix as M1:
  - `ps3recomp/runtime/ppu/ppu_hle.cpp`: `LARGE_INTEGER`;
  - `ps3recomp/runtime/ppu/ppu_sysprx.cpp`: `QueryThreadCycleTime`.
- Next: include `win32_compat.h`/`win32_diag_compat.h` there under `#ifndef _WIN32`, rebuild, link, then the M2 draft PR (cut from upstream `main`, without the `.gitmodules` change).

## 6. Milestones

Each one is a separate, reviewable change; the EU/Windows build stays identical throughout.

- **M1 Runtime on macOS (library builds; done 2026-11-17).** Fix the 20 units in section 5 (in the ps3recomp fork, Windows unchanged); the runtime builds and passes its own tests on arm64;
  `templates/project` boot smoke runs headless. Fix ToD-fork additions that assume Windows or x86
  (`SPU_RZ_FP_TLS` uses MXCSR round-toward-zero: needs an FPCR path on arm64, as RACiT's NEON work did).
- **M2 Release table and NA hooks.** `versions/` table + generated header; hooks by role; CMake renames by
  search. Exact EU map from the EU maintainer's signature file (or keep the step-function map,
  disassembly-checked per hook). NA game links on macOS with the null renderer.
- **M3 Vulkan engine on macOS.** `rsx_vulkan_engine.c` without Win32: Metal surface via MoltenVK,
  main-thread window, offscreen mode; add `depth_resnap`, `color_copy_rect`, `set_blend_color`;
  RACiT's MoltenVK fixes (fma dot products, barriers). Headless boot to title and into a level,
  frame captures compared with Windows screenshots.
- **M4 Input, overlay, audio.** SDL2 keyboard/mouse into `tod_host_key_down` and the mouse-look path,
  DualSense over SDL/HID, Dear ImGui overlay on the Vulkan present (`imgui_impl_vulkan`), tod.ini writes.
- **M5 Disc and install.** Installer and launcher that recognise EU and NA disc folders (section 2.4); a Mac app bundle (game binary, MoltenVK, SDL2) and launcher flow like RACiT's.
- **M6 Performance.** RACiT's sequence: offscreen benchmark route with guest-frame FPS, then walker
  wake, yield fix, MoltenVK per-draw overhead (batching, constants by reference), SPU NEON paths,
  PGO/hot-code ordering; measure every change against the build before it.
- **M7 Upstream.** One concern per PR to Re-TeRo17 (runtime fork first: Vulkan engine portability;
  then the port's platform layer; then the release table), each stating what was tested on which OS.
