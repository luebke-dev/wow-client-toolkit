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
| `CDataStore::GetUInt8`  | `0x0047B340` | 1 byte |
| `CDataStore::GetUInt16` | `0x0047B380` | 2 bytes |
| `CDataStore::GetUInt32` | `0x0047B3C0` | 4 bytes |
| `CDataStore::GetUInt64` | `0x0047B400` | 8 bytes (the writeup-named "GetInt64") |
| `CDataStore::GetFloat`  | `0x0047B440` | 4 bytes |
| `CDataStore::GetBytes`  | `0x0047B480` | variable (`memcpy`-style; bug class is "destination + length both attacker-controlled") |

All 6 share the canonical prologue `55 8B EC 56 8B F1 8B 46 14 6A
<SIZE> 50 E8 ...` -- enumerated by walking function prologues in
`[0x0047B000-0x0047C000]` for the `push <SIZE>` immediate.

`audit/scripts/find_write_primitives.py` enumerates every caller
of all three, scores each call site by:

- presence of scaled-index `lea reg, [reg*N + imm32]` (destination
  arithmetic = bug shape signal)
- enclosing loop (backward conditional jump)
- function reads a global as loop bound (packet-controlled iteration)

See `audit/out/write_primitives.md` for the latest ranked list. Score >= 5
sites are candidates for the same loop-cap mitigation. Status: AUDIT.

### Confirmed packet-reachable sister vulnerabilities

Refined audit (6 write primitives: GetUInt8/16/32/64, GetFloat,
GetBytes -- all the CDataStore::Get* family) plus a binary
search for each candidate handler's literal-address byte sequence
followed by `push handler; push opcode; call RegisterHandler`
identifies the following packet-reachable handlers with the same
audit-shape (scaled-index LEA + loop + global-read) as the
BG-positions vuln.

**Important caveat:** the audit-shape match does NOT mean each
handler is the same severity as BG-positions. To match
BG-positions' "arbitrary write" capability all three of the
following must hold:

1. Loop bound is read via `GetUInt32` (4 bytes, max 4 billion).
   Byte/word bounds limit total iterations.
2. Destination is a **fixed writable-globals base** with the
   counter as offset (`[base_imm + counter*N]`), NOT a heap or
   stack allocation that grows with the count.
3. No pre-loop realloc / capacity check that would either fail
   safely on huge counts or pre-allocate enough room.

Manual byte-level inspection has classified each candidate:

| Opcode | AC name | Handler | Severity |
|---|---|---|---|
| `0x121` | `SMSG_TRADE_STATUS_EXTENDED` | `FUN_00704680` | **bounded**: LEA `[ECX*4 + 0xCA0FF0]` IS a fixed-base write but `ECX` is the zero-extended `local_1` from `GetUInt8` -- only 4 bytes per call * 256 = 1 KiB destination window. Per-call write but small radius. |
| `0x23D` | `SMSG_BATTLEFIELD_LIST` | `FUN_0054e390` | **DoS-only**: capacity-check pattern (cmp local, [global_capacity_store]) -> heap-vec realloc, fails safely on huge counts. |
| `0x2A5` | `SMSG_SET_FORCED_REACTIONS` | `FUN_005d15d0` | **DoS-only**: destination `[edx + esi*8]` where `edx = [0x00C23494]` is a heap-pointer load. Function does pre-loop realloc to grow the vec; with `count=2^32` malloc of 32 GiB fails -> safe failure path. No arbitrary write. |
| `0x330` | `SMSG_SPELL_UPDATE_CHAIN_TARGETS` | `FUN_00800470` | **DoS-only**: destination `[eax + esi*8]` where `eax` is from `_alloca(count*8)` -- stack allocation. Huge count -> stack-overflow crash, no controlled write. |
| `0x34E` | `SMSG_ARENA_TEAM_ROSTER` | `FUN_005a3e10` | **DoS-only**: outer loop bounded `uVar2 < 0xa8 / 0x38 = 3` (max 3 teams). Inner per-member loops write to heap pointer stored in `(&DAT_00c0f84c)[uVar5 * 0xe]` (heap allocation). Can't escape that allocation. |
| `0x35B` | `SMSG_ARENA_TEAM_STATS` | `FUN_005a2d50` | **safe**: 6 GetUInt32 writes to fixed globals `DAT_00c0f860..0xC0F874 + iVar3 * 0x38` where `iVar3` is bounded by outer-loop `uVar2 < 0xa8` -> max 3 iterations. No attacker-controlled scaling. |
| `0x367` | `SMSG_LFG_UPDATE_PLAYER` | `FUN_0055bdc0` | **DoS-only**: capacity-check pattern, heap-vec, fails safely. |
| `0x368` | `SMSG_LFG_UPDATE_PARTY` | `FUN_0055bdc0` | **DoS-only** (same handler shared with 0x367/0x369). |
| `0x369` | `SMSG_LFG_UPDATE_SEARCH` | `FUN_0055bdc0` | **DoS-only** (same handler). |
| `0x3E8` | `SMSG_GUILD_BANK_LIST` | `FUN_005a7250` | **EXPLOITABLE (out-of-bounds pointer-read class)**: tab-id `local_5` is `GetUInt8` (max 255). Destination pointer fetched via `(&DAT_00c1dc40)[(uint)local_5 * 4]` with NO bounds check on `local_5`. Game expects ~8 valid tab-ids; server sending `local_5 = 255` reads garbage from `DAT_00c1dc40 + 0x3FC` and uses that as the heap-pointer base for the per-item writes. Less directly controllable than the BG-positions arithmetic primitive but still an arbitrary-write-via-garbage-pointer. |
| `0x3EE` | `MSG_GUILD_BANK_LOG_QUERY` | `FUN_005a4800` | **bounded**: `local_5` (tab id) and `local_6` (loop count) both `GetUInt8` (max 255). Destination range = `&DAT_00C0F900 .. +260 KiB`. Exploitable for overwriting a global in that window but NOT the unbounded-uint32 shape of BG-positions. |
| `0x3FD` | `MSG_GUILD_PERMISSIONS` | `FUN_005cb9f0` | **EXPLOITABLE (BG-positions class -- NEW)**: `local_c = GetUInt32` from packet (uint32, max 4 billion). Destination = `&DAT_00c21e60 + local_c * 14`. Server picks `local_c` to make the address resolve to ANY 4-byte-aligned address in 32-bit space (modular arithmetic via `local_c = (target - 0xC21E60) / 14`). 8 GetUInt32 writes per packet (4 bytes each, server-controlled value), all at `base + local_c * 14 + offset`. **Identical severity shape to BG-positions.** No mitigation in this repo yet. |
| `0x490` | `SMSG_AUCTION_LIST_PENDING_SALES` | `FUN_0059e880` | **DoS-only**: capacity-check pattern, heap-vec, fails safely. |

**Updated conclusion** (after byte-level scan + Ghidra decompile
of all 13 score-7 candidates AND all 33 score-4 [REVIEW]
candidates):

| Severity | Count | Opcodes |
|---|---|---|
| **Unbounded fixed-base (BG-positions class)** | 3 | `MSG_BATTLEGROUND_PLAYER_POSITIONS` (`0x2C0` -> `FUN_0054b3f0`, **patched** by Patch 3); **NEW: `MSG_GUILD_PERMISSIONS` (`0x3FD` -> `FUN_005cb9f0`, NOT patched, multiplier 14)**; **NEW: `SMSG_GUILD_ROSTER` (`0x08A` -> `FUN_005cc5d0`, NOT patched, multiplier 56 (= 14 dwords)) -- the MOTD-records loop bound `DAT_00c22ab8` is `GetUInt32`, per-iteration writes 14 dwords to `0xC21E64 + i*56`** |
| **Out-of-bounds-pointer class** | 1 | `SMSG_GUILD_BANK_LIST` (`0x3E8`) -- byte tab-id used as unchecked array index |
| **Possible heap-overflow (realloc-failure)** | 2 | `SMSG_RAID_INSTANCE_INFO` (`0x2CC`), `SMSG_EXPECTED_SPAM_RECORDS` (`0x332`) -- both call a grow function with packet-supplied count then write `count * stride` bytes; if the allocator fails silently the writes spill past the old buffer. Severity depends on whether `FUN_00500f10` / `FUN_004ffce0` abort on OOM (likely) or return silently. |
| **Bounded write (byte-counter / small radius)** | 2 | `0x121` (1 KiB window), `0x3EE` (~260 KiB window) |
| **DoS-only (heap-vec / alloca)** | 7 | `0x23D`, `0x2A5`, `0x330`, `0x367`, `0x368`, `0x369`, `0x490` |
| **Safe (explicit cap / bounded index / sanitized lookup)** | 6+ | `0x34E`, `0x35B`, `0x2D4` (cap 1), `0x4BC` (cap 9), `0x3F1`/`0x3F2` (channel-id from name lookup), `0x360` (hash-table lookup) -- plus 11 score-4 handlers with no danger pattern (`0x0A9` SMSG_UPDATE_OBJECT, `0x12A`, `0x179`, `0x23B`, `0x25F`, `0x26F`, `0x3B8`, `0x3BB`, `0x44A`, the 2 shared-dispatchers) |

**Found TWO NEW BG-positions class arbitrary writes**:
`MSG_GUILD_PERMISSIONS` (`0x3FD`, multiplier 14) and
`SMSG_GUILD_ROSTER` (`0x08A`, multiplier 56). Both same shape as
the documented BG vuln. **Patch 3 does not cover either** --
fresh patches are needed.

**Practical implication for the patcher:** Patches 1+2+3 cover
the documented chain but **leave at least two BG-positions class
sister vulns open** (`MSG_GUILD_PERMISSIONS` and
`SMSG_GUILD_ROSTER`) plus one OOB-pointer class
(`SMSG_GUILD_BANK_LIST`) and two possible heap-overflow class
(`SMSG_RAID_INSTANCE_INFO`, `SMSG_EXPECTED_SPAM_RECORDS`,
pending realloc-failure-mode confirmation). Minimal additions:

- **Patch 4** (MSG_GUILD_PERMISSIONS): cap `local_c` after the
  `GetUInt32(&local_c)` in `FUN_005cb9f0` to a small immediate
  (max valid guild-rank is ~10).
- **Patch 5** (SMSG_GUILD_ROSTER): cap `DAT_00c22ab8` after the
  `GetUInt32(&DAT_00c22ab8)` in `FUN_005cc5d0` to a small
  immediate (max MOTD records is 10 per the in-source check
  `if (9 < local_c) goto LAB_005cc773` -- which fires AFTER the
  loop and thus is useless as a bounds check).
- **Patch 6** (SMSG_GUILD_BANK_LIST): cap `local_5` (tab-id)
  after the `GetUInt8(&local_5)` to max 7.
  - **Status: deferred.** The straightforward patch (mask local_5
    immediately after GetUInt8) needs 4 bytes after the call but
    the call is followed immediately by another instruction with no
    NOP padding. The exploit primitive is also referenced from
    multiple load sites (`movzx eax, byte [ebp-1]` + `shl eax, 4`)
    inside a loop body, so a single-site byte-patch leaves the
    inner-loop indexing vulnerable. A clean fix needs either:
    (a) a 5-byte JMP-rel32 trampoline that masks `local_5` and
    returns; (b) per-load-site patching of every `[ebp-1]` read
    in the function (10+ sites); (c) a runtime-DLL-level hook
    that replaces the GetUInt8 destination with a clamped scratch
    slot. None fits the 1-3 byte surgical patch model that
    Patches 1-5 use.
- **Patch 7+8** (RAID_INSTANCE_INFO, EXPECTED_SPAM_RECORDS):
  cap loop counts to AC documented maxima.

**Practical implication for the runtime DLL:** the IAT-detour
hooks on `CreateFileA` / `InternetOpenA` / `HttpSendRequestA`
already added (commit `139f59c`) cover the *post-RCE* class --
even if a server somehow pivots through one of the bounded
write-windows to gain code execution, file-IO + HTTP exfil
gets logged. That layer is correct independent of how many
RCE primitives exist.

Plus the 9 handlers at high-VA (`FUN_006d6d20`, `FUN_0080e1b0`,
`FUN_006d0240`, `FUN_006d0460`, `FUN_006d0ab0`, `FUN_006d53b0`,
`FUN_00755630`, `FUN_00753690`, `FUN_00768760`) which the audit
flagged with score >= 5 but have **no static handler-address
references** in the binary. Tier-2 trace via Ghidra reference-manager
(`audit/scripts/find_indirect_refs.py`) found each is called by
exactly ONE internal helper (e.g. `FUN_006deef0` -> `FUN_006d6d20`),
NOT registered as a packet handler. Two of them aren't even
defined as functions (probably middle-of-instruction false hits).
Treated as **non-packet-reachable** for this audit; if any of
the helper callers is itself reachable from a packet handler,
re-classification needed.

### Mitigation strategy options

For per-site patches the byte cost grows linearly. With **13
confirmed packet-reachable candidates** the per-site approach is
fragile (every patch needs its own pre-byte verification + a
loop-comparison cap byte). A **universal mitigation** is now
clearly the right approach:

- Patch `CDataStore::GetUInt8`, `GetUInt16`, `GetUInt32`,
  `GetUInt64`, `GetFloat`, `GetBytes` (all 6 primitives at
  `0x0047B340-0x0047B480`) with a JMP-rel32 trampoline that
  range-checks the destination pointer. If it lies in writable
  globals (`0x00800000-0x00E00000`), abort the read instead of
  writing.
- Cost: ~15-20 bytes of inserted code per primitive (6 trampolines).
- Risk: legit callers that DO write to globals (per-game state
  arrays, cached UI state, achievement bitfields) break.
  **Need full caller-classification first** (currently 284 callers
  for GetUInt64 alone -- some are arbitrary-write candidates,
  most are legit `lea reg, [ebp - X]` stack-local writes).

The **safer-by-narrower** universal patch:

- Range-check destination only when called from a handler that
  recently called `GetUInt32` and stored the result somewhere
  used as a loop bound. Too contextual for a static patch.

Best practical path likely a **hybrid**:
1. Per-site patches for the 11 confirmed-packet-reachable
   handlers (Patch 4 through Patch 14, one per opcode), each
   capping the loop count at the AC-side documented maximum
   (AC's `MAX_GUILD_BANK_TAB_LOG_EVENTS = 25` etc).
2. A "soft" universal trampoline on the 6 CDataStore primitives
   that LOGS attempted writes to writable globals (observation
   only -- runtime DLL responsibility), so we discover which
   future opcodes need similar caps.

Status: per-site patches **OPEN**; soft observation **OPEN**.

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
   `audit/scripts/find_pe_loaders.py` searches for any code path
   that checks the `MZ` magic via the common encodings. **Latest
   refined search finds 4 PE-checking functions in .text** but
   each is classified after manual decompile inspection:

   | VA | Verdict | Notes |
   |---|---|---|
   | `0x00412237` | SAFE | Tiny header validator (`cmp word [ecx], 0x5A4D / cmp dword [eax + 0x3C], 'PE\0\0' / ret`). Returns 1/0. No mapping. |
   | `0x0077D293` | SAFE | PE-section walker for offset-resolution (no VirtualAlloc / VirtualProtect, just walks section headers to find which section a file offset lives in). |
   | `0x0077E240` | SAFE after follow-up | Validates `MZ` + checks two magic words at `+0x38` (`0xB74F`) and `+0x3A` (`0x2D98`) (Microsoft Rich/DanS-style validator), then walks to PE32/PE32+ optional-header magic. The sub-calls into `0x0077E10D` / `0x0077E18F` are PE-resource-directory walkers (`*0x1C` = 28-byte `IMAGE_RESOURCE_DIRECTORY_ENTRY` stride, no `VirtualAlloc` / `VirtualProtect`). **Validator + resource-table parser**, not a loader. |
   | `0x00993527` | SAFE | MZ check on stack-local + further validation calls; no `VirtualAlloc` / `VirtualProtect` in the visible 256-byte window; structurally a parser/walker, not a loader. |

   **Conclusion: `FUN_00872350` is the only manual PE loader in
   Wow.exe.** Patch 2 closes the entire native-code-execution
   class via Warden / mod-rce style payloads. The remaining RCE
   risk lives in the write-primitive class (section 2 above) plus
   any classes we haven't yet enumerated.
2. Are any of the AUDIT-status sites in section 2 actually
   exploitable (LEA + loop + global-bound), or are they all
   safe-by-coincidence (destination = local stack var)? Manual
   review needed for any score>=5 site.
3. DBC parser bounds-checking: AzerothCore + the original Blizzard
   parser both trust the row count from the file header. With
   custom server-supplied DBC files, does the client's load path
   validate `row_count * row_size <= file_size`?
