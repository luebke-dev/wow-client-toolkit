# RCE vector inventory -- Wow.exe build 12340

> Status: living document. Edited as analysis progresses.
> Generated end-to-end by AI-driven analysis. Validate every
> claim against primary sources before relying on it.

This document inventories every known + plausible Remote-Code-Execution
attack surface the WoW 3.3.5a client exposes to a malicious server,
and notes whether `wow-client-toolkit` covers it.

The model: **the server controls the bytes, the client trusts them**.
Every place where attacker bytes drive a control-flow decision or a
write target is a vector candidate.

## Status legend

| Symbol | Meaning |
|---|---|
| OK | static patch in `patcher/` closes this on disk |
| OBSERVED | runtime DLL logs but does not block |
| AUDIT | identified as a candidate by `audit/scripts/`; needs manual review |
| OPEN | known to exist, no mitigation in this repo yet |
| OUT-OF-SCOPE | client-side only via Lua (sandboxed by absence of Win32 API access) |

---

## 1. Documented chain (the writeup)

| # | Vector | File offset | VA | Status | Notes |
|---|---|---|---|---|---|
| 1 | `.zdata` section flagged RWX in PE header | 0x000002A7 | section header | OK | patcher rewrites `0xE0` -> `0xC0` (read-write, no execute). Removes the always-executable scratch page that PoCs jump into. |
| 2 | `FUN_00872350` manual PE loader -- maps + executes server-supplied PE bytes | 0x004719D4 | call site | OK | patcher patches the call site to push a forced fail-arg, neutering the loader. Runtime hook observes the buffer for forensics. |
| 3 | `MSG_BATTLEGROUND_PLAYER_POSITIONS` arbitrary write via unbounded loop | 0x0014A842 | `0x0054BA42` | OK | patcher rewrites the global-comparison `cmp edi, [BEA5B0]` into immediate `cmp edi, 80`, capping iterations. Runtime hook observes the count. |

**Closes the public chain.** Patches 1 + 2 + 3 in combination defeat the
documented exploit. Any one alone is bypassable by the other two.

---

## 2. Same-class vectors (write primitives in unbounded loops)

The BG-positions handler bug shape is:

1. Server packet contains a count `N`.
2. Client stores `N` in a global.
3. Client loops `for i in 0..N { CDataStore::GetInt64(&arr_base + i*8) }`.
4. `arr_base` is in the writable part of the binary; `i*8 + base` =
   any address in 4 GiB if `N` is large enough. Result: arbitrary
   write of attacker-supplied bytes.

The same shape can exist in any handler that uses any of the
`CDataStore::GetXxx(this, dst*)` write primitives:

| Function | VA | Writes |
|---|---|---|
| `CDataStore::GetFloat` | `0x0047B330` | 4 bytes |
| `CDataStore::GetInt64` | `0x0047B400` | 8 bytes |
| `CDataStore::GetInt32` | `0x0047B450` | 4 bytes |

`audit/scripts/find_write_primitives.py` enumerates every caller
of all three, scores each call site by:

- presence of scaled-index `lea reg, [reg*N + imm32]` (destination
  arithmetic = bug shape signal)
- enclosing loop (backward conditional jump)
- function reads a global as loop bound (packet-controlled iteration)

See `audit/out/write_primitives.md` for the latest ranked list. Score >= 5
sites are candidates for the same loop-cap mitigation. Status: AUDIT.

### Confirmed sister vulnerabilities (same shape)

The audit script flagged the following call sites at score >= 5.
Manual decompile review classifies each:

| Function | Call site | Verdict | Detail |
|---|---|---|---|
| `FUN_0054b3f0` | `0x0054b41c` | KNOWN (BG-positions) | Patch 3 closes |
| `FUN_0054b3f0` | `0x0054b490` | KNOWN (BG-positions, 2nd inner write) | Patch 3 closes (same outer loop) |
| `FUN_005a4800` | `0x005a4900` | **CONFIRMED VULN** -- opcode `0x03EE` (`MSG_GUILD_BANK_LOG_QUERY`) | Identified by `identify_handler.py` + binary search for the registration call at file offset 0x001a6be4 (`push 0x005A4800; push 0x03EE; call`). Loop bound `local_6` read from packet via `GetInt32(&local_6)` at line 157 of decompile; inner loop writes 40-byte structs to `&DAT_00c0f900 + (local_5*25 + iVar5) * 0x28` with NO bounds check on `local_6`. Server picks count, client writes per-element struct to attacker-controlled address. **No mitigation in this repo yet.** |
| `FUN_00800470` | `0x008004c6` | **CONFIRMED VULN** -- opcode `0x0330` (`SMSG_SPELL_UPDATE_CHAIN_TARGETS`) | Found at file offset 0x0040f64e (`push 0x00800470; push 0x0330; call`). LEA `[EBX*0x8 + 0x0]`. Server-controlled chain-target list; same shape. **No mitigation yet.** |
| `FUN_006d6d20` | `0x006d6d8d` | UNREACHED | No static address reference in the binary. Either dead code or runtime-built vtable. Loop bound is global `0x00c79f98`. Lower attack-surface assumption. |
| `FUN_0080e1b0` | `0x0080e231 + 0x0080e2a4` | UNREACHED | No static address reference; high-VA region. Likely init-time / addon-system code. |

### Mitigation strategy options

For per-site patches (one Patch 4 + Patch 5 + ... per confirmed
vuln) the byte cost grows linearly. A **universal mitigation** is
preferable:

- Patch `CDataStore::GetInt64` (and GetInt32, GetFloat) to range-check
  the destination pointer. If it lies in the writable globals region
  (`0x00800000-0x00E00000`), abort the read instead of writing.
- Cost: ~15 bytes of inserted code per primitive. Requires a 5-byte
  JMP-rel32 trampoline since the original is only 58 bytes (no
  in-place room).
- Risk: legit callers that DO write to globals (per-game state arrays)
  break. Need full caller-classification first.

Status of universal mitigation: **OPEN** -- design + impact study
required before implementation.

---

## 3. Other server-controlled byte streams

| Stream | Entry point | Risk class | Status |
|---|---|---|---|
| Warden module | `FUN_00872350` (covered above) | full RCE | OK + OBSERVED |
| BG-positions packet | `FUN_0054B3F0` (covered above) | arbitrary write | OK + OBSERVED |
| Other opcode handlers (~700) | per-opcode in 0x500000-0x575000 | varies; bug shape #2 above | AUDIT |
| DBC files served via patch-X.MPQ | `DBCStorage::Load` | row-count integer overflow possible if no upper bound; bug class is signed-int * sizeof | OPEN |
| MPQ patch parser | `SFile*` (Blizzard MPQ, not Stormlib) | historical CVEs around block-table parsing | OPEN |
| Realmlist response | `RealmList::Parse` | bounded by SRP6 packet size; low risk | LOW |
| Character enum response | `CharacterEnum::Parse` | bounded; low risk | LOW |
| FrameScript / Lua server-pushed snippets | `FUN_00418c34` (FrameScript::Execute) | Lua-confined; can call client functions if offsets known | OUT-OF-SCOPE for native RCE; IN-SCOPE for data-exfil (see #4) |

---

## 4. Lua-confined data exfiltration (the Warmane-allegation class)

Server-pushed Lua via `FUN_00418c34` cannot directly call Win32
APIs. **But** Lua can:

- Read any in-game state (chat history, open windows, addon-saved
  variables including third-party addon credentials).
- Generate addon messages or whisper-style packets that send
  attacker-readable strings back to the server (covert exfil channel
  via `SendChatMessage` + custom CMSG opcode).
- Trigger UI events that may chain into native code paths.

**More important**: a malicious Warden module (Vector 2 above) is
NOT Lua-confined. It can call any function the client imports plus
anything it resolves via `GetProcAddress`. Wow.exe imports include
(per `audit/out/warden_targets.md`):

- `wininet`: `InternetOpenA`, `HttpOpenRequestA`, `HttpSendRequestA`,
  `InternetCrackUrlA` -- HTTP exfil ready to use
- `kernel32`: `CreateFileA`, `ReadFile`, `WriteFile` -- file IO
- `advapi32`: `RegOpenKeyExA`, `RegQueryValueExA`, `RegSetValueExA`
  -- registry read/write

Combination = a Warden module pushed via the manual loader
(Vector 2) can read `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History`
(SQLite browser-history database) via `CreateFileA` + `ReadFile`,
then send the bytes via `HttpSendRequestA`. **No further Win32
imports needed -- everything's already in the IAT.**

Mitigation: Patches 1 + 2 + 3 close the manual-loader entry point,
so this exfil class is **structurally defeated** when the static
patcher is applied. The runtime DLL OBSERVES this class:

- Every server-pushed PE buffer is dumped to
  `%APPDATA%\wow-rce-watcher\modules\<md5>.bin`.
- Operator can disassemble the dump in Ghidra and read the string
  constants -- file paths, URLs, registry keys -- to confirm intent.

Planned additions:

- IAT hooks on `CreateFileA` / `ReadFile`: log file paths the
  client opens after Warden-module-load. Direct evidence of
  browser-history access.
- IAT hooks on `HttpSendRequestA`: log destination URL of every
  exfil attempt.

---

## 5. Out-of-band vectors

| Vector | Why it matters | Status |
|---|---|---|
| Custom installer / patched Wow.exe distributed by server | Defeats every runtime mitigation | OUT-OF-SCOPE -- distribution-trust is upstream of this toolkit |
| Compromised addon authors | Lua-confined but with full game-state access | OUT-OF-SCOPE |
| DLL-side-loading via attacker-replaced d3d9.dll | Defeats every runtime mitigation | OUT-OF-SCOPE -- file-system trust is upstream |

---

## Open questions

1. Does the writeup's Vector-2 cover the only manual PE loader,
   or are there sister loaders elsewhere in `0x00870000-0x00880000`?
   `audit/scripts/find_warden_targets.py` should be extended to
   sweep for `MZ`-magic-checking code blocks.
2. Are any of the AUDIT-status sites in section 2 actually
   exploitable (LEA + loop + global-bound), or are they all
   safe-by-coincidence (destination = local stack var)? Manual
   review needed for any score>=5 site.
3. DBC parser bounds-checking: AzerothCore + the original Blizzard
   parser both trust the row count from the file header. With
   custom DBC files distributed via `cluster.assets`, does the
   client's load path validate `row_count * row_size <= file_size`?
