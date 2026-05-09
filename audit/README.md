# audit/

Ghidra-based static-analysis tooling used to derive + validate the
patch byte plans the patcher applies. Optional — the Rust binary
stands alone; this is here for transparency and for re-deriving
offsets when a custom-server-fork ships a Wow.exe with shifted
addresses (3.3.5a is the terminal build for this codebase, but
private servers historically ship modified copies).

## Contents

| Script | Purpose | Output |
|---|---|---|
| `scripts/audit_rce.py` | Ghidra Jython script. Walks the loaded Wow.exe, lists every `VirtualAlloc` / `VirtualProtect` / `LoadLibrary` / `CreateProcessA` / `ShellExecuteA` call site, dumps the manual-PE-loader (`FUN_00872350`) decompile. Used to derive the Patch 2 byte plan and to spot any new dangerous APIs Wow.exe imports. | `out/audit.md` |
| `scripts/find_write_primitives.py` | Enumerates every caller of the `CDataStore::Get*` write primitives (GetUInt8/16/32/64, GetFloat, GetBytes -- 6 functions in 0x0047B340-0x0047B480) and scores each call site for the BG-positions vuln shape (scaled-index LEA destination + enclosing loop + global loop bound). Used to surface sister write-primitive RCE candidates that need the same loop-cap mitigation as Patch 3. | `out/write_primitives.md` |
| `scripts/identify_handler.py` | Given a `HANDLER_VA` env var, walks back from a function to find direct callers + data references + dispatch-table neighbors. Used to prove a flagged handler IS reachable from a network packet (vs being dead code). Combine with a binary search for the handler's literal address bytes to find the registration call site (`push handler; push opcode; call`). | `out/handler_identity.md` |
| `scripts/find_warden_targets.py` | Locates `FrameScript::Execute`, `push 0x041F` (CMSG_UNUSED5 -- C2 channel candidate), and the Win32 IAT entries we'd hook in the runtime DLL for behavioral tracing of server-pushed shellcode. | `out/warden_targets.md` |
| `scripts/find_pe_loaders.py` | Sweeps the binary for every `cmp word [reg], 0x5A4D` (MZ-magic check) encoding and scores each owning function by `VirtualAlloc` / `VirtualProtect` / section-walk presence. Used to confirm `FUN_00872350` is the only manual PE loader (no sister loaders to bypass Patch 2). | `out/pe_loaders.md` |

## Running

Requires `podman` or `docker`, plus a copy of the canonical Wow.exe.

```sh
mkdir -p project out input
cp /path/to/Wow.exe input/Wow.exe

# First time -- import the binary + run any postScript:
podman run --rm \
  --entrypoint /ghidra/support/analyzeHeadless \
  -v "$PWD/project":/project \
  -v "$PWD/scripts":/scripts \
  -v "$PWD/out":/out \
  -v "$PWD/input":/input:ro \
  docker.io/blacktop/ghidra:latest \
  /project WoW \
  -import /input/Wow.exe \
  -scriptPath /scripts \
  -postScript audit_rce.py

# Subsequent runs (project already imported -- add -process + -noanalysis):
podman run --rm \
  --entrypoint /ghidra/support/analyzeHeadless \
  -v "$PWD/project":/project \
  -v "$PWD/scripts":/scripts \
  -v "$PWD/out":/out \
  -v "$PWD/input":/input:ro \
  docker.io/blacktop/ghidra:latest \
  /project WoW \
  -process Wow.exe -noanalysis \
  -scriptPath /scripts \
  -postScript find_write_primitives.py
```

First import: ~4 minutes (Ghidra auto-analysis pass). Re-runs:
seconds. Pass `-e HANDLER_VA=0x005A4800` etc. to override the
default for `identify_handler.py`.

Output files end up owned by root (the Ghidra container runs as
root). Fix permissions with:

```sh
podman run --rm -v "$PWD/out":/out alpine chmod a+r /out/*.md
```

## Re-deriving offsets

If you have a non-canonical Wow.exe (custom server distribution
etc.), the patcher will refuse to write because pre-bytes don't
match. To derive new offsets:

1. Run the audit on the new binary
2. From the report, locate `FUN_00872350` (manual PE loader) and
   the `MSG_BATTLEGROUND_PLAYER_POSITIONS` handler
3. For each patch site, find the equivalent instruction in the
   new binary
4. Update `RCE_HARDENING_PATCHES` in `patcher/src/lib.rs` with new
   `offset` + `expected` bytes; `new` stays the same

## Why no `apply_patch.py`?

An older revision of this project shipped a Python pure-bytes
patcher as a second source of truth. Removed because the Rust
patcher (`wow-exe-patcher`) is now the single canonical
implementation with strict pre-byte verification, library API,
and tswow-table support that the Python script never had.
