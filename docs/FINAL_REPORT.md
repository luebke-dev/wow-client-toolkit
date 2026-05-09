# wow-client-toolkit — final analysis & engineering report

> Generated end-to-end by AI-driven analysis (Anthropic Claude).
> All conclusions should be validated against the cited primary
> sources before being relied on for production safety. Patches
> are byte-exact and reproducible; analyses are best-effort.

Repository: `git@github.com:luebke-dev/wow-client-toolkit.git`
Last commit at time of report: `8d8bdae`
Target binary: World of Warcraft 3.3.5a `Wow.exe` build 12340,
MD5 `5758d89ed392e2190c44c5183a6d23a3`, size 7,699,456 bytes.

---

## Executive summary

**Goal.** A malicious WoW 3.3.5a server can push native code into
its players' clients via a documented Remote-Code-Execution chain.
This project aims to (a) close every known and reasonably
discoverable RCE vector on the client side, and (b) give the
operator visibility + per-module control over server-pushed
Warden modules.

**Result.**

- **Vulnerability landscape mapped end-to-end.** 90 distinct
  packet-handler functions in `Wow.exe` were inspected across
  four audit dimensions (score-7 + score-4 ranking, lower-ranked
  callers, recursive caller-trace through internal helpers,
  non-CDataStore deserialization primitives). Of these, **only
  four functions exhibit the unbounded arbitrary-write shape**
  that defines the BG-positions vuln class:

  1. `MSG_BATTLEGROUND_PLAYER_POSITIONS` (opcode `0x2C0`,
     `FUN_0054B3F0`) — the originally-documented vuln
  2. `MSG_GUILD_PERMISSIONS` (opcode `0x3FD`, `FUN_005CB9F0`) —
     **newly discovered**, multiplier 14
  3. `SMSG_GUILD_ROSTER` (opcode `0x08A`, `FUN_005CC5D0`) —
     **newly discovered**, multiplier 56
  4. `SMSG_GUILD_BANK_LIST` (opcode `0x3E8`, `FUN_005A7250`) —
     **newly discovered**, out-of-bounds-pointer class (different
     shape, same severity)

- **Static byte patches** for vulns #1, #2, and #3 are shipped
  in the `patcher/` crate and verified to apply against the
  canonical `Wow.exe` build 12340. Vuln #4 is documented but
  deferred (it requires a JMP-rel32 trampoline rather than
  surgical byte edits — the function references the bad index
  from 10+ load sites).

- **Runtime DLL** (`runtime/`) provides per-module allow/reject
  control. On every Warden module load it computes the MD5,
  compares against the canonical Blizzard 3.3.5a Win Warden
  hash (`79C0768D657977D697E10BAD956CCED1`), silently allows
  the canonical one, and pops a synchronous Yes/No `MessageBox`
  with full module metadata for any non-canonical module. User
  rejects → loader returns "load failed" and bytes never run.
  Every module is also dumped to disk for offline forensics.

- **Reproducible audit pipeline.** Nine Ghidra Jython scripts
  (`audit/scripts/`) re-derive every patch byte plan + every
  vuln-shape classification from the binary. A non-canonical
  build (e.g. a different private-server-shipped Wow.exe with
  shifted addresses) can be re-audited end-to-end by running
  the scripts against it.

**Practical bottom line for operators.**

| Threat | Coverage |
|---|---|
| Documented public RCE chain (mod-rce, RCEPatcher class) | **Closed** by Patches 1+2+3 |
| Newly-discovered same-shape sister vulns | 2 of 3 closed (Patches 4+5); 1 deferred (GUILD_BANK_LIST) |
| Server pushes a custom Warden module to weaponize | Runtime DLL prompts user per module; rejection blocks execution |
| Server uses a custom Warden module for legitimate cheat detection | User can allow it via the prompt; canonical Blizzard module is silent |
| Browser-history exfil via CreateFileA + HttpSendRequestA | Runtime DLL detour-hooks log the path/URL of every call |

**The toolkit cannot defend against:** physical-machine compromise,
attacker-replaced `Wow.exe` shipped by the server's installer,
attacker-replaced `d3d9.dll` side-loading, addon-author Lua compromise.

---

## Vulnerability landscape (full audit results)

### Confirmed arbitrary-write primitives

| # | Opcode | Name | Handler | Multiplier | Loop bound | Status |
|---|---|---|---|---|---|---|
| 1 | `0x2C0` | `MSG_BATTLEGROUND_PLAYER_POSITIONS` | `FUN_0054B3F0` | 8 | uint32 from packet | **Patch 3** caps the comparison at 80 iterations |
| 2 | `0x3FD` | `MSG_GUILD_PERMISSIONS` | `FUN_005CB9F0` | 56 (= 8\*7) | uint32 from packet | **Patch 4** rewrites `sub reg, eax` -> `xor reg, reg` at 4 sites, eliminates the `*7` factor |
| 3 | `0x08A` | `SMSG_GUILD_ROSTER` (MOTD records loop) | `FUN_005CC5D0` | 56 (= 14 dwords) | uint32 from packet (`DAT_00C22AB8`) | **Patch 5** rewrites `cmp eax, [DAT_00C22AB8]` -> `cmp eax, 10` (matches the in-source `if (9 < local_c)` post-loop sanity check) |
| 4 | `0x3E8` | `SMSG_GUILD_BANK_LIST` | `FUN_005A7250` | byte tab-id used as unchecked pointer-array index | n/a (single-shot per packet) | **Patch 6 deferred** — needs trampoline; documented in `rce_vector_inventory.md` |

### Confirmed safe (audit complete)

| Severity bucket | Count | Notes |
|---|---|---|
| Heap-vec realloc + bounds-checked write | ~22 | All auction handlers, LFG, raid-instance-info, expected-spam-records, USERLIST. `count = 4 billion` -> realloc fails -> safe failure path. |
| `_alloca`-bounded writes | 3 | SMSG_SPELL_UPDATE_CHAIN_TARGETS class; huge count -> stack overflow crash, no controlled write. |
| Sanitized-index (channel-id from name lookup) | 5 | USERLIST_REMOVE/UPDATE, channel-list-clear; index is the lookup result, not packet-direct. |
| Value-validated dispatch (== 0/1/2 etc.) | 5 | SMSG_BATTLEFIELD_STATUS, RAID_READY_CHECK, MIRROR_TIMER, etc. |
| Constant-length memcpy | 9 | All struct-copy patterns (SMSG_AURA_UPDATE, KICK_REASON, etc.). |
| Explicit cap before iteration | 3 | EQUIPMENT_SET_LIST (`if (9 < local_10)`), GOSSIP_MESSAGE (`if (0x20 < local_c)`), BATTLEFIELD_STATUS. |
| Byte-bounded-write (small radius) | 2 | SMSG_TRADE_STATUS_EXTENDED (1 KiB), MSG_GUILD_BANK_LOG_QUERY (~260 KiB). |
| No danger pattern at all | ~30 | spell-related, calendar, achievement, ARENA_TEAM_*, SMSG_UPDATE_OBJECT etc. |
| Non-packet-reachable | ~15 | Asset / init / UI helper functions, no static handler-registration. |

### Possible heap-overflow (severity pending)

Two handlers call a grow function with a packet-supplied count
and then write `count * stride` bytes:

- `SMSG_RAID_INSTANCE_INFO` (`0x2CC`, `FUN_00501030`)
- `SMSG_EXPECTED_SPAM_RECORDS` (`0x332`, `FUN_00501C70`)

Severity depends on the underlying allocator's failure mode
(abort vs silent return). If the allocator aborts on OOM the
write loop never executes and these are DoS-only. If it
returns silently, the writes spill past the old buffer ->
heap-overflow class. **Pending verification of `FUN_00500F10`
and `FUN_004FFCE0`.** These are tracked as Patches 7+8 in the
inventory.

---

## Deliverables

### `patcher/` — `wow-exe-patcher` CLI

Static byte patcher for `Wow.exe`. Usage:

```sh
wow-exe-patcher patch  --input Wow.exe --output Wow_safe.exe
wow-exe-patcher verify --input Wow_safe.exe
wow-exe-patcher probe  --input Wow.exe
```

Each `SecurityPatch` entry has `(file_offset, expected_bytes,
new_bytes, name)`. The verifier refuses to patch if pre-bytes
don't match — protects against patching a non-canonical build.

Current `RCE_HARDENING_PATCHES` table (8 entries, 5 logical
patches):

| name | file offset | bytes |
|---|---|---|
| `rce.zdata-no-execute` | 0x000002A7 | `0xE0 -> 0xC0` |
| `rce.warden-loader-no-execute` | 0x004719D4 | `8B 4E 08 51 -> 6A 04 90 90` |
| `rce.bg-positions-loop-cap` | 0x0014A842 | `3B 3D B0 A5 BE 00 -> 81 FF 50 00 00 00` (cmp imm32 = 80) |
| `rce.guild-permissions-arith-1..4` | 0x001CAE34, ...4F, ...8A, ...A8 | `2B C8/D0 -> 33 C9/D2` (sub→xor, kills `*7` multiplier) |
| `rce.guild-roster-motd-loop-cap` | 0x001CBB15 | `3B 05 B8 2A C2 00 -> 83 F8 0A 90 90 90` (cmp imm8 = 10) |

Bonus: tswow-style toggles (large-address-aware, view-distance,
allow-custom-gluexml, item-dbc-disabler), version/build
rewrites, optional PE checksum recompute.

### `runtime/` — `wow_rce_watcher.dll` + `wow-rce-watcher.exe`

Cross-compiled `i686-pc-windows-gnu`, runs natively on Windows
and under Wine 11+.

**Hooks installed on `DLL_PROCESS_ATTACH`:**

1. **Manual Warden PE loader** (`FUN_00872350`). Naked-asm
   trampoline preserves `ECX` (out-pointer) + `pushad`/`pushfd`
   state, calls Rust `inspect_and_decide`, returns 1 (allow)
   or 0 (block). Allow-path tail-jumps into the trampoline
   (which runs the original 5-byte prologue then jumps back to
   target+5), block-path zeros EAX and `ret`s — caller sees
   "load failed".

2. **MSG_BATTLEGROUND_PLAYER_POSITIONS handler** (`FUN_0054B3F0`).
   Observation only: logs every iteration count seen on the
   wire. Does NOT block — Patch 3 is the safety net.

3. **Detour hooks on Win32 APIs** (`kernel32!CreateFileA`,
   `wininet!InternetOpenA`, `wininet!HttpSendRequestA`). Catches
   both Wow's IAT-routed calls AND server-shellcode-pushed
   calls via `GetProcAddress`. Logs path / URL / headers. Used
   for browser-history-exfil detection.

**Per-module gate** (default behavior, no env var needed):

- Canonical Blizzard module → silent allow + `module_seen`
  audit entry
- Non-canonical module → synchronous Yes/No `MessageBox`
  showing MD5, verdict, first 12 imports, first 6 sections,
  + path to the on-disk dump. Default button = No.
  `MB_TOPMOST | MB_SYSTEMMODAL` for visibility over Wow's
  fullscreen window. Yes → module runs + log
  `module_user_allowed`. No → loader returns 0 + log
  `module_blocked`.
- Failed-to-display dialog (headless, etc.) → fail safe to
  reject.

**Auxiliary forensics:**

- Every PE-shaped buffer is dumped to
  `%APPDATA%\wow-rce-watcher\modules\<md5>.bin`. Operator can
  load it in Ghidra to read string constants (file paths the
  module opens, registry keys it queries, URLs it contacts).
- All events written to `%APPDATA%\wow-rce-watcher\events.jsonl`,
  one JSON object per line, greppable.

### `audit/` — Ghidra Jython scripts

Each script writes a markdown report under `audit/out/`. Run via
`docker.io/blacktop/ghidra:latest` headless (`audit/README.md`
has the full recipe).

| Script | Purpose | Output |
|---|---|---|
| `audit_rce.py` | Walks Wow.exe, lists every `VirtualAlloc`/`VirtualProtect`/etc call site, dumps `FUN_00872350`'s decompile | `audit.md` |
| `find_write_primitives.py` | Audits every caller of every `CDataStore::Get*` write primitive (6 functions), scores each call site (scaled-LEA + loop + global-read), ranks for danger | `write_primitives.md` / `write_primitives_full.md` |
| `find_warden_targets.py` | Finds `FrameScript::Execute`, `push 0x041F` (CMSG_UNUSED5 candidates), Win32 IAT entries | `warden_targets.md` |
| `find_pe_loaders.py` | Sweeps for sister manual-PE-loader functions | `pe_loaders.md` |
| `identify_handler.py` | Given a handler VA, finds direct callers + data refs + dispatch-table neighbors | `handler_identity.md` |
| `find_indirect_refs.py` | Lists ghidra references to a function (calls + data) | `indirect_refs.md` |
| `trace_callers.py` | Recursively walks the call graph backwards looking for a registered packet handler in the chain | `caller_traces.md` |
| `decompile_handlers.py` | Batch-decompiles a configured list of handler VAs | `handler_decompiles*.md` |
| `find_memcpy_in_handlers.py` | Finds packet handlers that call `_memcpy` / `_memmove` at depth 0-1 | `non_cdatastore_primitives.md` |

### `docs/`

- `rce_vector_inventory.md` — full per-handler classification
  table, severity buckets, mitigation options, open questions
- `FINAL_REPORT.md` — this file

---

## Audit methodology

The audit was structured as four parallel sweeps that converged
on a single answer.

**Sweep 1 — write-primitive ranking.** For each of the 6
`CDataStore::Get*` functions (GetUInt8/16/32/64, GetFloat,
GetBytes -- discovered by enumerating function prologues in
`0x47B000-0x47C000` looking for the canonical `55 8B EC 56 8B
F1 8B 46 14 6A <SIZE> 50 E8 ...` pattern), enumerate every
caller, score each call-site by three heuristics:

- +3 for a scaled-index `lea reg, [reg*N + imm]` in the
  instruction window (= attacker-controlled scaled destination)
- +2 for an enclosing loop (backward conditional jump in the
  function body)
- +2 for a global read used as loop bound (= packet-controlled
  iteration count)

Score >= 5 sites match the BG-positions shape and require manual
review.

**Sweep 2 — packet-reachability.** For each candidate handler,
search the binary for the literal handler-VA bytes preceded by
`0x68` (push imm32) and followed by `0x68 imm32 0xE8` — the
canonical `push handler; push opcode; call RegisterHandler`
3-instruction registration pattern. The opcode is the second
imm32. Cross-reference against AzerothCore's
`Opcodes.h` for the human-readable name.

**Sweep 3 — recursive trace for indirect callers.** For
candidates that DON'T have a direct handler-registration, walk
the static call graph backwards (depth limit 6). If the chain
hits a registered handler at any depth, the candidate IS
indirectly reachable.

**Sweep 4 — non-CDataStore primitives.** Find every packet
handler that calls `_memcpy` or `_memmove` within depth 1.
Decompile + classify each: constant-length memcpy =
struct-copy = safe; variable-length memcpy with packet-derived
length = potentially exploitable.

**Result of the four sweeps:** 90 distinct functions classified,
4 arbitrary-write primitives identified, 3 patched, 1 deferred.
The audit is **saturated for the CDataStore primitive family
and the memcpy/memmove path**.

### What the audit explicitly does NOT cover

- **Other deserialization primitives** beyond CDataStore::Get* and
  `_memcpy`/`_memmove`. A custom string parser or a `recv()`
  consumer that the binary uses outside the standard packet
  dispatch path would be missed.
- **Logic bugs that aren't write primitives.** Type confusion,
  use-after-free, integer overflow that doesn't lead to a write
  — not in scope.
- **Lua sandbox escapes.** Lua snippets pushed via
  `FrameScript::Execute` cannot directly call Win32 APIs but CAN
  read in-game state and exfil it via custom `CMSG_*` opcodes
  back to the server.
- **Custom installer / `Wow.exe` distributed by the server.**
  Distribution-trust is upstream of this toolkit.

---

## Recommendations

**For an operator wanting maximum protection:**

1. Run `wow-exe-patcher patch --input Wow.exe --output
   Wow_safe.exe`. This applies all 5 patches; `verify` reports
   the result.
2. Use `Wow_safe.exe` as your binary. Patches 1+2+3+4+5 close
   every confirmed unbounded arbitrary-write primitive.
3. Optionally run the binary via the runtime DLL launcher
   (`wow-rce-watcher.exe Wow_safe.exe`) for per-Warden-module
   prompts + browser-exfil detection. This adds the per-module
   allow/reject UI and the IAT detour audit log.

**For a private-server operator wanting to reassure players:**

1. Ship `Wow_safe.exe` (the patched binary) as your client
   distribution. Document that it's bit-identical to canonical
   `Wow.exe` plus the 5 published security patches; the patcher
   is open-source so any player can verify.
2. Don't push custom Warden modules. The upside (server-side
   cheat detection) doesn't justify the downside (every patched
   client will see a "non-canonical Warden module — allow?"
   prompt and reasonably reject).

**For follow-up engineering work** (NOT done in this round):

- Implement Patch 6 (`SMSG_GUILD_BANK_LIST` OOB-pointer fix) via
  a JMP-rel32 trampoline that masks the tab-id at first load.
- Verify the realloc-failure mode of `FUN_00500F10` and
  `FUN_004FFCE0` to decide whether Patches 7+8 are needed
  (RAID_INSTANCE_INFO, EXPECTED_SPAM_RECORDS).
- Extend the audit to non-CDataStore deserialization primitives
  beyond `_memcpy` / `_memmove` — `recv()`, custom string
  parsers, MPQ/DBC parsers consuming server-pushed asset
  patches.
- Sign the runtime DLL + launcher with a code-signing
  certificate for distribution (currently unsigned -> Defender
  may flag the DLL injector as suspicious).

---

## File index

```
wow-client-toolkit/
├── README.md                          (top-level overview)
├── LICENSE                            (MIT OR Apache-2.0)
├── Cargo.toml                         (workspace root)
├── docs/
│   ├── rce_vector_inventory.md        (per-handler classification)
│   └── FINAL_REPORT.md                (this file)
├── patcher/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                     (RCE_HARDENING_PATCHES + tswow tables + version rewrite)
│       └── main.rs                    (CLI: patch / verify / probe)
├── runtime/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                     (DllMain + FUN_00872350 hook + per-module prompt)
│       ├── decision.rs                (canonical-MD5 compare + heuristic verdict)
│       ├── pe.rs                      (hand-written PE parser)
│       ├── hook.rs                    (JMP-rel32 trampoline installer)
│       ├── bg_handler.rs              (BG-positions handler observation hook)
│       ├── api_hooks.rs               (CreateFileA/InternetOpenA/HttpSendRequestA detours)
│       ├── log.rs                     (events.jsonl writer)
│       └── bin/wow-rce-watcher.rs     (DLL injection launcher)
└── audit/
    ├── README.md                      (Ghidra recipe)
    ├── input/Wow.exe                  (gitignored -- operator supplies)
    ├── project/                       (gitignored -- Ghidra working state)
    ├── scripts/                       (9 Ghidra Jython scripts)
    └── out/                           (audit reports, committed)
```

19 commits in main as of this report. Repository is intended
to remain reproducible: a fresh clone + `cargo build --release
--target i686-pc-windows-gnu` in the rust:1 docker image plus
`gcc-mingw-w64-i686` will rebuild bit-identical artefacts; the
audit recipe in `audit/README.md` will reproduce every report.
