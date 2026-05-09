# audit/

Ghidra-based static-analysis tooling used to derive + validate the
patch byte plans the patcher applies. Optional — the Rust binary
stands alone; this is here for transparency and for re-deriving
offsets when a custom-server-fork ships a Wow.exe with shifted
addresses (3.3.5a is the terminal build for this codebase, but
private servers historically ship modified copies).

## Contents

| File | Purpose |
|---|---|
| `scripts/audit_rce.py` | Ghidra Jython script. Walks the loaded Wow.exe, lists every `VirtualAlloc` / `VirtualProtect` / `LoadLibrary` / `CreateProcessA` / `ShellExecuteA` call site, dumps the manual-PE-loader (`FUN_00872350`) decompile, and writes a markdown report to `audit/out/`. |

## Running

Requires `podman` or `docker`, plus a copy of the canonical Wow.exe.

```sh
mkdir -p project out input
cp /path/to/Wow.exe input/Wow.exe

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
```

First run: ~4 minutes (Ghidra auto-analysis pass).
Subsequent runs: add `-process Wow.exe -noanalysis` → seconds.

Output lands in `out/audit.md`.

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
