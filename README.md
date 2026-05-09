# wow-client-toolkit

Defensive + analysis toolkit for the World of Warcraft 3.3.5a
client (Wow.exe build 12340, MD5 `5758d89ed392e2190c44c5183a6d23a3`,
size 7,699,456 bytes).

> **AI-driven analysis disclosure.** Every reverse-engineering
> finding, byte-level patch, hook, Ghidra script, and write-up in
> this repository was produced end-to-end by an AI assistant
> (Anthropic Claude). All conclusions should be validated against
> the cited primary sources (TechMecca, stoneharry, Saty, brian8544,
> AzerothCore source) before being relied on for production safety.
> Patches are byte-exact and reproducible; analyses are best-effort.

Three components ship from one workspace, all standalone, all
independent of any private-server project:

| Component | Output | Target | Role |
|---|---|---|---|
| `patcher/` | `wow-exe-patcher` | host | **Static byte patcher** for Wow.exe. Closes the three vectors of the documented RCE chain (`.zdata` no-execute / Warden-loader no-execute / BG-positions loop cap) **plus two newer same-shape sister vulns discovered by `audit/`** (`MSG_GUILD_PERMISSIONS` arithmetic-neutralization, `SMSG_GUILD_ROSTER` MOTD loop-cap). Also bundles tswow-style feature toggles + version/build rewrites. |
| `runtime/` | `wow_rce_watcher.dll` + `wow-rce-watcher.exe` | i686-pc-windows-gnu | **Runtime observer + per-module gate.** Loaded into Wow.exe via DLL injection. Hooks the manual Warden module loader and the BG-positions handler, logs every server-supplied PE buffer + every BG packet's iteration count, dumps the raw module bytes to disk, and pops a synchronous **Yes/No prompt** for every non-canonical Warden module ("Server wants to load XYZ -- allow?"). User clicks Yes -> module runs as if the DLL weren't there; click No -> the loader returns 0 and the bytes never execute. Canonical Blizzard modules are silently allowed; failed-to-display dialogs default to reject. |
| `audit/` | Ghidra Jython scripts | host | **Static audit / re-derivation** scripts. Locate write-primitive call sites, candidate Warden hook points, IAT entries needed for shellcode tracing. Used to validate the patch byte tables and to scout for sister-vulnerabilities to close. |

The three are **complementary**: static patches are bedrock and
survive any RCE attempt; the runtime DLL adds per-module
allow/reject control + forensic visibility (which servers send
which payload, what they import, where they wanted to write);
the audit scripts re-derive everything from the binary so the
patch tables stay verifiable. Recommended deployment is
**patcher first** (safety) **then runtime alongside**
(per-module gate + visibility).

This project bundles the cumulative public knowledge on the 3.3.5a
RCE class (TechMecca's writeup, stoneharry's RCEPatcher, Saty's
PoC2.0, brian8544's PoC1) plus original analysis for Vector 3
(BG-positions loop) which closes the remaining bypass primitive.

---

## The vulnerability — one-page summary

The 3.3.5a Wow.exe contains an RCE chain that has been historically
known to a small set of actors in the WoW emulation scene. Public
disclosure landed via the
[mod-rce](https://github.com/brian8544/mod-rce) AC
module. The chain combines three separate failures in the client:

| # | Name | Where | What it gives the attacker |
|---|---|---|---|
| 1 | `.zdata` RWX section | PE section header (file 0x2A7) | A page-aligned region that's both writable AND executable. Any JMP target deposited here runs immediately under DEP. |
| 2 | Manual Warden PE loader | `FUN_00872350` (file 0x4719D4) | Server-supplied PE module gets per-section `flProtect` straight from the module header — `PAGE_EXECUTE_READWRITE` is honoured. Module entry-point runs attacker code with the client's privileges. |
| 3 | Unbounded BG-positions loop | `FUN_0054B3F0+0x52` (file 0x14A842) | `MSG_BATTLEGROUND_PLAYER_POSITIONS` reads a 32-bit count from the packet, then loops calling `CDataStore::GetInt64(this, *(BEA180+i*8))` — and `GetInt64` despite its name **writes** 8 bytes to its destination argument with no bounds check. Attacker controls count → arbitrary memory write. |

### Why all three patches are needed together

Patches 1 + 2 alone (the original `RCEPatcher`'s coverage) are
**bypassable** because Vector 3 is still active: an attacker can
use the BG-write-primitive to write the *original* bytes back over
patches 1 and 2 in RAM, re-enabling the classic exploit chain.

The bypass sequence:

1. Server sends crafted `MSG_BATTLEGROUND_PLAYER_POSITIONS` with
   `count = (target_addr - 0xBEA180) / 8` (uint32 wrap-around lets
   the loop reach any address)
2. Loop iterates, `GetInt64` writes the original 4 / 6 bytes back
   over the patched location at `0x008725D4` or the `.zdata` PE
   header
3. With patches gone, run the canonical exploit (write shellcode
   to `.zdata`, redirect Warden init to JMP there)

**Patch 3 caps the loop at 80 iterations.** The `i*8 + base` write
target now stays within the legitimate `dword_BEA180` array bounds
(max addr `0xBEA570`). Patches 1 and 2 stay locked in for the
lifetime of the process.

### Vectors 4 + 5 (sister vulnerabilities found by `audit/`)

Tier-1 + tier-2 audit of every `CDataStore::Get*` caller in the
binary (see `docs/rce_vector_inventory.md`) discovered two
**additional** packet handlers with the BG-positions arithmetic
shape, neither covered by the original `RCEPatcher`:

| # | Opcode | Handler | What it gives the attacker |
|---|---|---|---|
| 4 | `0x3FD` `MSG_GUILD_PERMISSIONS` | `FUN_005CB9F0` | `local_c = GetUInt32` from packet, four `GetUInt32` writes per packet to `&DAT_00C21E60 + local_c * 56`. Server picks `local_c` so destination wraps to any 8-byte-aligned address in 32-bit space. |
| 5 | `0x08A` `SMSG_GUILD_ROSTER` | `FUN_005CC5D0` | MOTD-records loop bound `DAT_00C22AB8 = GetUInt32` from packet, per-iteration writes 14 dwords to `&DAT_00C21E64 + i * 56`. Same shape as Patch 3 with a different multiplier. |

Patch 4 neutralises the four `local_c * 7` arithmetic sites in
`FUN_005CB9F0` by replacing each `sub reg, eax` (`2B C8` /
`2B D0`) with `xor reg, reg` (`33 C9` / `33 D2`) -- same byte
length, kills the multiplier so all four `GetUInt32` writes
overlap at fixed addresses.

Patch 5 caps the MOTD loop at 10 iterations -- the value the
in-source post-loop sanity check `if (9 < local_c) goto cleanup`
implies the original developer intended (the check just fires
AFTER the writes, useless as a bounds check).

A third candidate (`SMSG_GUILD_BANK_LIST`, opcode `0x3E8`) is
an out-of-bounds-pointer-class vuln (byte tab-id used as
unchecked array index, fetched pointer becomes write base). The
straightforward in-place patch doesn't fit (the dangerous load
site is referenced from 10+ places in the function); a clean fix
needs a JMP-rel32 trampoline. Tracked in the inventory as Patch 6
deferred.

### Why the static patches and not just a runtime detector?

A runtime DLL detector (e.g. hooking `FUN_00872350` to inspect
modules) is bypassable by the same code that the detector lets
through:

```
1. Server sends Warden module with neutral-looking imports
2. Detector heuristic allows
3. Module entry-point runs:
   a. VirtualProtect(.zdata, RWX)
   b. memcpy(detector_dll_hook_addr, original_5_bytes, 5)  ← un-hook
   c. FreeLibrary(detector_dll)                             ← evict us
4. Subsequent attacks invisible to anything we tried to install
```

In-process defences are only as strong as the lowest-privilege
attacker code that runs at all. **Static byte patches survive any
RCE attempt** because the bytes live on disk and would have to be
re-modified + restart to undo. Per-session safe.

The runtime detector adds value as a **forensic + extra-layer
sensor** on top of the static patches: it records every Warden
module the client sees, can be extended to additional opcodes (BG
packet anomaly detection, etc.), and survives in cases where the
operator can't redistribute a patched binary.

---

## Quick start

### 1. Patch the binary (recommended baseline)

```sh
git clone https://github.com/luebke-dev/wow-client-toolkit
cd wow-client-toolkit
cargo build --release -p wow-exe-patcher
./target/release/wow-exe-patcher patch \
    --input  /path/to/Wow.exe \
    --output /path/to/Wow_safe.exe
```

Default mode applies all three RCE-hardening patches with strict
pre-byte verification and recomputes the PE checksum. The patcher
refuses to write anything if the input doesn't match the canonical
12340 build.

Verify:

```sh
./target/release/wow-exe-patcher verify --input /path/to/Wow_safe.exe
# [OK]   rce.zdata-no-execute @ 0x2a7: applied
# [OK]   rce.warden-loader-no-execute @ 0x4719d4: applied
# [OK]   rce.bg-positions-loop-cap @ 0x14a842: applied
# [OK] all three RCE-hardening patches applied
```

### 2. (Optional) Add the runtime detector for forensic logging

Cross-compile for 32-bit Windows (Wow.exe is 32-bit only):

```sh
# from Linux host, install the mingw32 toolchain once
sudo apt install gcc-mingw-w64-i686    # Debian/Ubuntu
# Fedora:  sudo dnf install mingw32-gcc

rustup target add i686-pc-windows-gnu
cargo build --release --target i686-pc-windows-gnu -p wow-rce-watcher
```

Outputs:
- `target/i686-pc-windows-gnu/release/wow_rce_watcher.dll`
- `target/i686-pc-windows-gnu/release/wow-rce-watcher.exe`

Place both next to your patched Wow.exe and launch:

```sh
# Windows native:
wow-rce-watcher.exe C:\WoW\Wow_safe.exe

# Linux / macOS via Wine:
WINEPREFIX=~/.wine wine wow-rce-watcher.exe drive_c/wow/Wow_safe.exe

# Steam Proton (Launch Options):
#   wine wow-rce-watcher.exe %command%
```

The launcher spawns Wow.exe with `CREATE_SUSPENDED`, injects the
DLL via `CreateRemoteThread + LoadLibraryW`, then resumes the main
thread. The DLL hooks `FUN_00872350` (the Warden module loader) at
`0x00872350` and `.zdata` lockdown via `VirtualProtect`.

Audit log at `%APPDATA%\wow-rce-watcher\events.jsonl`:

```jsonl
{"ts":1714312345,"kind":"hook_installed","target":"0x00872350"}
{"ts":1714312345,"kind":"zdata_locked","addr":"0x00dd1000","old_protection":"0x40","note":"EXECUTE bit cleared on .zdata; Vektor-1 RCE blocked"}
{"ts":1714312399,"kind":"warden_module","action":"allow","md5":"79c0768d657977d697e10bad956cced1","reason":"matches canonical Blizzard 3.3.5a Win module","imports":"...","sections":"..."}
{"ts":1714312410,"kind":"warden_module","action":"block","md5":"deadbeef...","reason":"weaponised import detected: kernel32.dll!CreateProcessA","imports":"...","sections":"..."}
```

---

## Patcher CLI reference

```text
wow-exe-patcher patch  --input <Wow.exe> --output <out.exe> [options]
wow-exe-patcher verify --input <Wow.exe>
wow-exe-patcher probe  --input <Wow.exe>
```

### `patch` flags

| Flag | Default | Effect |
|---|---|---|
| `--rce-hardening` | `true` | Apply all three RCE-hardening patches. Strict pre-byte verified. Pass `--rce-hardening=false` only when you specifically need a vulnerable copy (research). |
| `--version <STRING>` | none | Replace `3.3.5` in `.rdata` with the given string (must fit in the existing slot + trailing NULs). |
| `--build <N>` | none | Replace all occurrences of build number `12340` with `<N>`. |
| `--unlock-signatures` / `--allow-custom-gluexml` | off | Apply the tswow `allow-custom-gluexml` table (TOC.SIG bypass for custom AddOn signatures). |
| `--large-address-aware` | off | Apply the tswow `large-address-aware` patch (4 GB user space). |
| `--view-distance-unlock` | off | Apply the tswow `view-distance-unlock` table. |
| `--item-dbc-disabler` | off | Apply the tswow `item-dbc-disabler` table (server-side item template). |
| `--all-tswow` | off | Shorthand for the four tswow named patches. |
| `--force` | off | Allow `--output` to equal `--input` (in-place patching). |
| `--probe` | off | Print version + build offsets and exit. No write. |

### `verify` exit codes

- `0` — all three RCE-hardening patches applied
- `1` — at least one missing or unrecognised pre-bytes

### `probe`

Prints the version-string offset, all build-number occurrences,
and the bytes currently sitting at each known patch site. No
modification. Useful for forensic analysis of unknown Wow.exe
builds (custom server distributions etc.).

---

## Library usage

```rust
use wow_exe_patcher::{ExeFlags, cmd_patch, verify_rce_hardening};

let flags = ExeFlags {
    rce_hardening: true,
    large_address_aware: true,
    ..Default::default()
};
cmd_patch("Wow.exe".as_ref(), "Wow_safe.exe".as_ref(), None, None, flags)?;

let buf = std::fs::read("Wow_safe.exe")?;
let report = verify_rce_hardening(&buf);
assert!(report.all_applied);
```

---

## Runtime detector — design

```
wow-rce-watcher.exe (launcher)
  └── CreateProcessW(Wow.exe, CREATE_SUSPENDED)
  └── VirtualAllocEx + WriteProcessMemory(L"wow_rce_watcher.dll")
  └── CreateRemoteThread(LoadLibraryW)        -> wow_rce_watcher.dll loaded
  └── ResumeThread

wow_rce_watcher.dll (in Wow.exe address space)
  └── DllMain DLL_PROCESS_ATTACH
        └── side thread:
              ├── install_jmp_hook(0x00872350, hook_entry)
              └── VirtualProtect(.zdata, RW)   ← Vektor-1 mitigation

at runtime, every call to FUN_00872350 triggers:
  └── hook_entry (naked-asm, preserves ECX + EFLAGS)
        ├── pe::parse(module_buffer)
        ├── decision::evaluate(parsed)
        │     ├── MD5 == known Blizzard 79c0768d?  -> Allow
        │     ├── weaponised import (CreateProcess, ShellExecute, ...)?  -> Block
        │     ├── RWX section?                       -> Block
        │     ├── multiple .text sections?           -> Block
        │     └── unknown but clean                  -> Allow + audit log
        ├── log::write_event(verdict)  -> events.jsonl
        └── if Allow: tail-jmp through trampoline (original prologue + JMP back)
            if Block: return 0 (caller handles "module load failed")
```

Key design notes:

- **Naked-asm hook**: `FUN_00872350` has a non-standard ABI (cdecl
  return, but ECX is also read as an OUT-pointer). Neither
  `extern "C"` nor `extern "thiscall"` matches, so the hook entry
  is a `#[unsafe(naked)]` function in inline asm that
  `pushad`+`pushfd`-saves everything before calling the Rust
  inspector, then either tail-jumps to the trampoline or returns 0.
- **Trampoline**: 5-byte JMP-rel32 patch at `0x00872350` redirects
  to `hook_entry`. A heap-allocated trampoline holds the original
  5-byte prologue (`55 8B EC 6A FF` = push ebp; mov ebp, esp;
  push -1) plus a JMP-rel32 back to `0x00872355`, so the original
  function continues normally on the "allow" path.
- **No WASI**: pure cdylib; only Win32 imports. Loads identically
  on native Windows and Wine ≥ 8.0.
- **Audit-friendly**: hand-rolled minimal PE parser (~200 lines),
  no external PE crate. Anyone reading the binary can trace every
  byte we read from the server-supplied buffer.

---

## Audit / Ghidra walkthrough

`audit/scripts/audit_rce.py` is a Ghidra Jython script that walks a
Wow.exe and lists every `VirtualAlloc` / `VirtualProtect` /
`LoadLibrary` call site, suspicious imports, and the manual-PE-loader
decompile. Used to derive and validate the patch byte plan.

```sh
mkdir -p audit/{project,out,input}
cp /path/to/Wow.exe audit/input/Wow.exe

podman run --rm \
  --entrypoint /ghidra/support/analyzeHeadless \
  -v "$PWD/audit/project":/project \
  -v "$PWD/audit/scripts":/scripts \
  -v "$PWD/audit/out":/out \
  -v "$PWD/audit/input":/input:ro \
  docker.io/blacktop/ghidra:latest \
  /project WoW \
  -import /input/Wow.exe \
  -scriptPath /scripts \
  -postScript audit_rce.py
```

First run takes ~4 minutes (Ghidra auto-analysis); subsequent runs
with `-process Wow.exe -noanalysis` are seconds.

---

## Verifying the input binary

The canonical 3.3.5a build 12340 has these properties. The
patcher will refuse anything else (pre-byte verification per
patch).

```
size:    7,699,456 bytes
md5:     5758d89ed392e2190c44c5183a6d23a3
```

Custom-modified Wow.exe distributions from private servers may
have different bytes at the patch sites — 3.3.5a is the terminal
official build, but private servers historically ship their own
forks. In that case, run `probe` to identify the build and
re-derive offsets manually using the audit scripts.

---

## Acknowledgements

- **stoneharry** — original `RCEPatcher`
- **TechMecca** — the public writeup that made this work documentable
- **Saty** — proof-of-concept 2.0 final using Warden
- **brian8544** — proof-of-concept 1.0 + module
- **tswow** — the `ClientPatches.ts` byte tables for the named feature toggles

The third patch (BG-positions loop cap) and the closed-loop
analysis showing why Patches 1+2 alone are bypassable are
contributions of this project.

---

## License

MIT OR Apache-2.0 — pick whichever fits your downstream.
