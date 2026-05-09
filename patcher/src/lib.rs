//! Static byte patcher for the WoW 3.3.5a `Wow.exe` Windows PE
//! executable (build 12340, MD5 5758d89ed392e2190c44c5183a6d23a3,
//! size 7,699,456 bytes).
//!
//! Bundles every documented Wow.exe patch class under one library +
//! CLI binary:
//!
//! 1. **RCE-hardening** -- three byte patches that close the
//!    documented exploit chain (.zdata RWX section, manual Warden PE
//!    loader, MSG_BATTLEGROUND_PLAYER_POSITIONS unbounded loop). All
//!    three must be applied together; any subset is bypassable.
//!    See `RCE_HARDENING_PATCHES` and the project README for the
//!    full threat model.
//! 2. **Version string** in `.rdata` (`3.3.5` -> e.g. `3.3.5-rg`).
//! 3. **32-bit build number** (`12340` -> `<new>`), all occurrences.
//! 4. **tswow named patch tables** (large-address-aware,
//!    view-distance unlock, allow-custom-gluexml, item-dbc-disabler).
//!    Byte tables sourced verbatim from
//!    `tswow/tswow-scripts/util/ClientPatches.ts`.
//!
//! After any write the PE optional-header `CheckSum` is recomputed
//! (Microsoft's `imagehlp!CheckSumMappedFile` algorithm) so the file
//! still passes signed-loader integrity checks.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use tracing::{info, warn};

const ORIGINAL_VERSION: &[u8] = b"3.3.5";
const ORIGINAL_BUILD_LE: [u8; 4] = [0x34, 0x30, 0x00, 0x00]; // 12340 little-endian

/// One byte-replacement: at `offset`, overwrite with `new`. The patcher
/// records the bytes that were there before and logs them; if the bytes
/// already equal `new`, we skip the write so re-running this on an
/// already-patched exe is a no-op.
struct Patch {
    offset: usize,
    new: &'static [u8],
}

/// `allow-custom-gluexml` from ClientPatches.ts. Same set the legacy
/// `--unlock-signatures` flag now drives.
const TSWOW_ALLOW_CUSTOM_GLUEXML: &[Patch] = &[
    Patch {
        offset: 0x126,
        new: &[0x23],
    },
    Patch {
        offset: 0x1f41bf,
        new: &[0xeb],
    },
    Patch {
        offset: 0x415a25,
        new: &[0xeb],
    },
    Patch {
        offset: 0x415a3f,
        new: &[0x3],
    },
    Patch {
        offset: 0x415a95,
        new: &[0x3],
    },
    Patch {
        offset: 0x415b46,
        new: &[0xeb],
    },
    Patch {
        offset: 0x415b5f,
        new: &[0xb8, 0x03],
    },
    Patch {
        offset: 0x415b61,
        new: &[0x0, 0x0, 0x0, 0xeb, 0xed],
    },
];

const TSWOW_LARGE_ADDRESS_AWARE: &[Patch] = &[Patch {
    offset: 0x000126,
    new: &[0x23],
}];

const TSWOW_VIEW_DISTANCE_UNLOCK: &[Patch] = &[
    Patch {
        offset: 0x014137,
        new: &[0x10, 0x27],
    },
    Patch {
        offset: 0x4c99f0,
        new: &[0x34],
    },
    Patch {
        offset: 0x63cf0c,
        new: &[0x00, 0x40, 0x1c, 0x46, 0x00, 0x40, 0x1c, 0x46],
    },
];

/// `item-dbc-disabler` (kebabstorm port of BenjaminLSR/rajkosto). Lifted
/// verbatim from ClientPatches.ts.
const TSWOW_ITEM_DBC_DISABLER: &[Patch] = &[
    Patch {
        offset: 0x168,
        new: &[0x5a, 0xc5, 0x75],
    },
    Patch {
        offset: 0x11646d,
        new: &[
            0x56, 0x89, 0xe1, 0xe8, 0xdb, 0x1d, 0x24, 0x0, 0x83, 0xc4, 0x4, 0x89, 0xc6, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ],
    },
    Patch {
        offset: 0x1164ac,
        new: &[0x89, 0xf1, 0x90],
    },
    Patch {
        offset: 0x1223f7,
        new: &[
            0x56, 0x89, 0xe1, 0xe8, 0x51, 0x5e, 0x23, 0x0, 0x83, 0xc4, 0x4, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90,
        ],
    },
    Patch {
        offset: 0x122419,
        new: &[0x89, 0xc7, 0x90],
    },
    Patch {
        offset: 0x1a54ef,
        new: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x8d, 0x4d, 0xf4],
    },
    Patch {
        offset: 0x1a54f9,
        new: &[0x53, 0x2d, 0x1b],
    },
    Patch {
        offset: 0x1a5528,
        new: &[0x90, 0x90, 0x90],
    },
    Patch {
        offset: 0x1a552c,
        new: &[0x45, 0xf4],
    },
    Patch {
        offset: 0x1a572e,
        new: &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x89, 0xd9],
    },
    Patch {
        offset: 0x1a5737,
        new: &[0x15, 0x2b, 0x1b],
    },
    Patch {
        offset: 0x1a575c,
        new: &[0x90, 0x90, 0x90],
    },
    Patch {
        offset: 0x1a5760,
        new: &[0x4d, 0xf8],
    },
    Patch {
        offset: 0x1a7cf5,
        new: &[
            0x83, 0xc4, 0x4, 0x56, 0x89, 0xe1, 0xe8, 0xd0, 0x4, 0x1b, 0x0, 0x83, 0xc4, 0x4, 0xeb,
            0x17, 0xcc, 0x89, 0xc3, 0x89, 0xe1, 0xe8, 0x41, 0x5, 0x1b,
        ],
    },
    Patch {
        offset: 0x1a7d0f,
        new: &[
            0x83, 0xc4, 0x4, 0xe9, 0x6b, 0x33, 0x0, 0x0, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x85, 0xc0,
        ],
    },
    Patch {
        offset: 0x1a8c8e,
        new: &[0x89, 0xe1, 0xe8, 0xbb, 0xf5, 0x1a, 0x0, 0x83, 0xc4, 0x4],
    },
    Patch {
        offset: 0x1a8c9c,
        new: &[0x90, 0x90, 0x90],
    },
    Patch {
        offset: 0x1aa6d4,
        new: &[0x89, 0xe1, 0xe8, 0x75, 0xdb, 0x1a, 0x0, 0x83, 0xc4, 0x4],
    },
    Patch {
        offset: 0x1aa6e2,
        new: &[0x90, 0x90, 0x90],
    },
    Patch {
        offset: 0x1aa821,
        new: &[0x90, 0x8d, 0x4d, 0x8, 0xe8, 0xa6, 0xd9, 0x1a],
    },
    Patch {
        offset: 0x1aa82a,
        new: &[0x8b, 0xf8, 0xe9, 0x67, 0xbe, 0x15, 0x0],
    },
    Patch {
        offset: 0x1aa832,
        new: &[0xc0],
    },
    Patch {
        offset: 0x1aa86c,
        new: &[0x90, 0x89, 0xf8],
    },
    Patch {
        offset: 0x1aa8a2,
        new: &[0x89, 0xe1, 0xe8, 0xa7, 0xd9, 0x1a, 0x0, 0x83, 0xc4, 0x4],
    },
    Patch {
        offset: 0x1aa8b0,
        new: &[0x90, 0x90, 0x90],
    },
    Patch {
        offset: 0x1aa9d0,
        new: &[0x89, 0xe1, 0xe8, 0x79, 0xd8, 0x1a, 0x0, 0x83, 0xc4, 0x4],
    },
    Patch {
        offset: 0x1aa9de,
        new: &[0x90, 0x90, 0x90],
    },
    Patch {
        offset: 0x1aaafa,
        new: &[0x89, 0xe1, 0xe8, 0x4f, 0xd7, 0x1a, 0x0, 0x83, 0xc4, 0x4],
    },
    Patch {
        offset: 0x1aab08,
        new: &[0x90, 0x90, 0x90],
    },
    Patch {
        offset: 0x1ab076,
        new: &[
            0x89, 0xe1, 0xe8, 0x53, 0xd1, 0x1a, 0x0, 0xe9, 0x84, 0xcc, 0xff, 0xff,
        ],
    },
    Patch {
        offset: 0x1ab083,
        new: &[0xc0],
    },
    Patch {
        offset: 0x1ab0a9,
        new: &[0x90, 0x90, 0x85, 0xdb],
    },
    Patch {
        offset: 0x1ab316,
        new: &[0x89, 0xe1, 0xe8, 0x33, 0xcf, 0x1a, 0x0, 0x83, 0xc4, 0x4],
    },
    Patch {
        offset: 0x1ab324,
        new: &[0x90, 0x90, 0x90],
    },
    Patch {
        offset: 0x306614,
        new: &[0x8b, 0x41, 0x8, 0x8d, 0x48, 0xc, 0xe9, 0x11, 0x1b, 0x5, 0x0],
    },
    Patch {
        offset: 0x306620,
        new: &[0xeb, 0xf2, 0xcc, 0xcc, 0xcc, 0xcc],
    },
    Patch {
        offset: 0x306650,
        new: &[0xeb, 0x3a, 0xcc, 0xcc, 0xcc, 0xcc],
    },
    Patch {
        offset: 0x306683,
        new: &[0x8d, 0x48],
    },
    Patch {
        offset: 0x306686,
        new: &[
            0xe9, 0x45, 0x1b, 0x5, 0x0, 0xcc, 0x8b, 0x41, 0x8, 0x8d, 0x48, 0xc, 0xe9, 0xe9, 0x1a,
            0x5, 0x0, 0xcc, 0x8d, 0x4d, 0x8, 0xe8, 0xb0, 0x1b, 0x5,
        ],
    },
    Patch {
        offset: 0x3066a0,
        new: &[
            0xe9, 0x8c, 0x41, 0xea, 0xff, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        ],
    },
    Patch {
        offset: 0x306703,
        new: &[0x8d, 0x48],
    },
    Patch {
        offset: 0x306706,
        new: &[
            0xe9, 0x45, 0x1b, 0x5, 0x0, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        ],
    },
    Patch {
        offset: 0x306733,
        new: &[0x8d, 0x48],
    },
    Patch {
        offset: 0x306736,
        new: &[
            0xe9, 0x15, 0x1c, 0x5, 0x0, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
            0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        ],
    },
    Patch {
        offset: 0x309e03,
        new: &[0x8d, 0x48],
    },
    Patch {
        offset: 0x309e06,
        new: &[
            0xe8, 0x45, 0xe4, 0x4, 0x0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ],
    },
    Patch {
        offset: 0x358136,
        new: &[0x56, 0x8b, 0x31, 0x89, 0xf0],
    },
    Patch {
        offset: 0x35813c,
        new: &[
            0x1, 0x99, 0x6a, 0x0, 0x68, 0x70, 0xeb, 0x5e, 0x0, 0x33, 0xc2, 0x8d, 0x4d, 0xf8, 0x51,
            0x2b, 0xc2, 0x50, 0xb9, 0x28, 0xd8, 0xc5, 0x0, 0xc7, 0x45, 0xf8,
        ],
    },
    Patch {
        offset: 0x358157,
        new: &[0x0, 0x0, 0x0, 0xc7, 0x45, 0xfc],
    },
    Patch {
        offset: 0x35815e,
        new: &[
            0x0, 0x0, 0x0, 0xe8, 0xca, 0x3c, 0xf2, 0xff, 0x85, 0xc0, 0x74, 0x8,
        ],
    },
    Patch {
        offset: 0x35816b,
        new: &[
            0x40, 0x4, 0x5e, 0x8b, 0xe5, 0x5d, 0xc3, 0x89, 0xf0, 0x5e, 0x89, 0xec, 0x5d, 0xe9,
            0xa9, 0xe4, 0xfa, 0xff,
        ],
    },
    Patch {
        offset: 0x358186,
        new: &[0x56, 0x8b, 0x31, 0x89, 0xf0],
    },
    Patch {
        offset: 0x35818c,
        new: &[
            0x1, 0x99, 0x6a, 0x0, 0x68, 0x70, 0xeb, 0x5e, 0x0, 0x33, 0xc2, 0x8d, 0x4d, 0xf8, 0x51,
            0x2b, 0xc2, 0x50, 0xb9, 0x28, 0xd8, 0xc5, 0x0, 0xc7, 0x45, 0xf8,
        ],
    },
    Patch {
        offset: 0x3581a7,
        new: &[0x0, 0x0, 0x0, 0xc7, 0x45, 0xfc],
    },
    Patch {
        offset: 0x3581ae,
        new: &[
            0x0, 0x0, 0x0, 0xe8, 0x7a, 0x3c, 0xf2, 0xff, 0x85, 0xc0, 0x74,
        ],
    },
    Patch {
        offset: 0x3581bb,
        new: &[
            0x40, 0x8, 0x5e, 0x8b, 0xe5, 0x5d, 0xc3, 0x89, 0xf0, 0x5e, 0x89, 0xec, 0x5d, 0xe9,
            0x89, 0xe4, 0xfa, 0xff,
        ],
    },
    Patch {
        offset: 0x61be58,
        new: &[0x7c, 0x7c],
    },
];

#[derive(Debug, Clone, Copy, Default)]
pub struct ExeFlags {
    pub probe: bool,
    pub force: bool,
    pub unlock_signatures: bool,
    pub allow_custom_gluexml: bool,
    pub large_address_aware: bool,
    pub view_distance_unlock: bool,
    pub item_dbc_disabler: bool,
    /// Apply the RCE-hardening byte patches (see `RCE_HARDENING_PATCHES`).
    /// On by default in the client-build pipeline so every player who
    /// downloads via our launcher gets a hardened Wow.exe automatically.
    /// Set to `false` only when the operator deliberately wants the
    /// vulnerable client (debugging the exploit chain itself).
    pub rce_hardening: bool,
}

/// One byte-replacement that ALSO verifies the bytes already there
/// match `expected` before writing. Stricter than the tswow-style
/// `Patch` table -- if pre-bytes don't match we refuse to write,
/// because for security patches the wrong build or a previously
/// modified exe could turn a no-op write into a corrupting one.
struct SecurityPatch {
    offset: usize,
    /// Bytes that MUST be at `offset` for the patch to be applied.
    /// Otherwise the input is refused (different build, custom-modified,
    /// etc.). Re-applying after a successful patch is a no-op because
    /// the bytes would equal `new`, not `expected`.
    expected: &'static [u8],
    new: &'static [u8],
    /// Short name for log output.
    name: &'static str,
}

/// RCE-class hardening patches (CVE-equivalent circa 2018).
///
/// 1. `.zdata` section Characteristics top byte 0xE0 → 0xC0:
///    drops `IMAGE_SCN_MEM_EXECUTE` so any JMP into `.zdata` (the
///    canonical final step of every documented 3.3.5a RCE chain)
///    hits DEP/NX. From the original RCEPatcher (stoneharry).
///
/// 2. `FUN_00872350` (manual Warden module loader) at file offset
///    0x4719D4: rewrite the per-section flProtect arg to a constant
///    `PAGE_READWRITE` (0x4). Server-supplied modules can still
///    map their sections, but no section is ever executable -- the
///    module's entry-point JMP traps. Also from RCEPatcher.
///
/// 3. **NEW (added 2026-05-09):** `MSG_BATTLEGROUND_PLAYER_POSITIONS`
///    handler loop bound, FUN_0054B3F0 + 0x52: cap iteration count
///    at 80. Without this the unchecked `dword_BEA5B0` count plus
///    `CDataStore::GetInt64`'s misnamed write semantic gives any
///    server an arbitrary-memory write primitive that can undo
///    patches 1+2 in RAM and re-enable the classic RCE chain.
///    Capping the loop locks patches 1+2 in for the lifetime of
///    the process.
///
/// 4. **NEW (added 2026-05-09):** `MSG_GUILD_PERMISSIONS` handler
///    `FUN_005cb9f0`: neutralize the four `local_c * 7` arithmetic
///    sites that compute `&DAT_00c21e60 + local_c * 56` destinations
///    for `GetUInt32` calls. Each site has a `sub ecx/edx, eax`
///    (`2B C8` / `2B D0`) immediately after `lea ecx/edx, [eax*8 + 0]`
///    -- the sub turns `eax * 8` into `eax * 7`. Replacing each `sub`
///    with `xor reg, reg` (`33 C9` / `33 D2`) zeros the index reg
///    so the LEA computes base + 0 = base. All four GetUInt32
///    writes overlap at fixed addresses; the function still runs
///    but no longer offers an attacker-controlled scaled write.
///    Same severity as Patch 3 but for opcode `0x3FD` instead of
///    `0x2C0`.
///
/// 5. **NEW (added 2026-05-09):** `SMSG_GUILD_ROSTER` MOTD-loop
///    bound cap, FUN_005CC5D0 + 0x145: replace the 6-byte
///    `cmp eax, [0xC22AB8]` (compare against unbounded packet
///    count) with `cmp eax, 10` + 3 NOPs. Caps the loop at 10
///    iterations (matching the in-source post-loop sanity check
///    that the original developer placed AFTER the loop and
///    that thus does not actually bound the writes).
const RCE_HARDENING_PATCHES: &[SecurityPatch] = &[
    SecurityPatch {
        offset: 0x000002A7,
        expected: &[0xE0],
        new: &[0xC0],
        name: "rce.zdata-no-execute",
    },
    SecurityPatch {
        offset: 0x004719D4,
        expected: &[0x8B, 0x4E, 0x08, 0x51],
        new: &[0x6A, 0x04, 0x90, 0x90],
        name: "rce.warden-loader-no-execute",
    },
    SecurityPatch {
        offset: 0x0014A842,
        expected: &[0x3B, 0x3D, 0xB0, 0xA5, 0xBE, 0x00],
        new: &[0x81, 0xFF, 0x50, 0x00, 0x00, 0x00],
        name: "rce.bg-positions-loop-cap",
    },
    SecurityPatch {
        offset: 0x001CAE34,
        expected: &[0x2B, 0xC8],
        new: &[0x33, 0xC9],
        name: "rce.guild-permissions-arith-1",
    },
    SecurityPatch {
        offset: 0x001CAE4F,
        expected: &[0x2B, 0xC8],
        new: &[0x33, 0xC9],
        name: "rce.guild-permissions-arith-2",
    },
    SecurityPatch {
        offset: 0x001CAE8A,
        expected: &[0x2B, 0xD0],
        new: &[0x33, 0xD2],
        name: "rce.guild-permissions-arith-3",
    },
    SecurityPatch {
        offset: 0x001CAEA8,
        expected: &[0x2B, 0xD0],
        new: &[0x33, 0xD2],
        name: "rce.guild-permissions-arith-4",
    },
    // Patch 5: SMSG_GUILD_ROSTER MOTD loop bound cap.
    // Handler FUN_005CC5D0 reads `DAT_00C22AB8` via GetUInt32 and
    // uses it as the upper bound of a do-while loop that writes
    // 14 dwords (56 bytes) per iteration to `&DAT_00C21E64 +
    // local_c * 56`. Server picks the count to make destination
    // wrap modulo 2^32 and target any 8-byte-aligned address.
    // The post-loop sanity check (`if (9 < local_c)`) confirms
    // the intended max is 10 entries -- so we cap the loop
    // comparison at 10.
    //
    // Original (file 0x1CBB15):
    //   3B 05 B8 2A C2 00    cmp eax, [0xC22AB8]   (6 bytes)
    // Replacement:
    //   83 F8 0A             cmp eax, 10            (3 bytes)
    //   90 90 90             nop nop nop            (3 bytes)
    SecurityPatch {
        offset: 0x001CBB15,
        expected: &[0x3B, 0x05, 0xB8, 0x2A, 0xC2, 0x00],
        new: &[0x83, 0xF8, 0x0A, 0x90, 0x90, 0x90],
        name: "rce.guild-roster-motd-loop-cap",
    },
];

pub fn cmd_patch(
    input: &Path,
    output: &Path,
    version: Option<&str>,
    build: Option<u32>,
    flags: ExeFlags,
) -> Result<()> {
    info!(
        input = %input.display(),
        output = %output.display(),
        probe = flags.probe,
        version = ?version,
        build = ?build,
        "exe patch"
    );

    if !flags.probe && input == output && !flags.force {
        bail!(
            "refusing to overwrite input file {:?} without --force",
            input
        );
    }

    let mut buf = std::fs::read(input).with_context(|| format!("reading input {:?}", input))?;
    info!(path = %input.display(), size = buf.len(), "loaded executable");

    let version_offset = find_version_offset(&buf)
        .ok_or_else(|| anyhow!("could not find version string {:?}", ORIGINAL_VERSION))?;
    let padding = count_null_padding(&buf, version_offset + ORIGINAL_VERSION.len());

    let build_offsets = find_build_offsets(&buf, ORIGINAL_BUILD_LE);

    if flags.probe {
        info!(
            offset = format!("0x{:x}", version_offset),
            padding, "version string located"
        );
        for off in &build_offsets {
            info!(
                offset = format!("0x{:x}", off),
                "build number 12340 located"
            );
        }
        println!(
            "version string: offset=0x{:x} length={} trailing_null_padding={}",
            version_offset,
            ORIGINAL_VERSION.len(),
            padding
        );
        println!(
            "build number 0x34 0x30 0x00 0x00 occurrences: {}",
            build_offsets.len()
        );
        for off in &build_offsets {
            println!("  build offset: 0x{:x}", off);
        }
        return Ok(());
    }

    if let Some(new_version) = version {
        replace_version(
            &mut buf,
            version_offset,
            ORIGINAL_VERSION.len(),
            padding,
            new_version,
        )?;
    }

    if let Some(new_build) = build {
        let count = replace_all_build(&mut buf, ORIGINAL_BUILD_LE, new_build);
        if count == 0 {
            bail!("no occurrence of build number 12340 (LE 0x34 0x30 0x00 0x00) found");
        }
        info!(replacements = count, new_build, "build number patched");
    }

    if flags.large_address_aware {
        apply_named_patch(&mut buf, "large-address-aware", TSWOW_LARGE_ADDRESS_AWARE);
    }
    if flags.view_distance_unlock {
        apply_named_patch(&mut buf, "view-distance-unlock", TSWOW_VIEW_DISTANCE_UNLOCK);
    }
    if flags.unlock_signatures || flags.allow_custom_gluexml {
        apply_named_patch(&mut buf, "allow-custom-gluexml", TSWOW_ALLOW_CUSTOM_GLUEXML);
    }
    if flags.item_dbc_disabler {
        apply_named_patch(&mut buf, "item-dbc-disabler", TSWOW_ITEM_DBC_DISABLER);
    }
    if flags.rce_hardening {
        apply_security_patches(&mut buf, RCE_HARDENING_PATCHES)?;
    }

    update_pe_checksum(&mut buf)?;

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    std::fs::write(output, &buf).with_context(|| format!("writing output {:?}", output))?;
    info!(path = %output.display(), "wrote patched executable");
    Ok(())
}

/// Per-patch verification result returned by [`verify_rce_hardening`].
#[derive(Debug)]
pub struct VerifyReport {
    pub all_applied: bool,
    pub lines: Vec<String>,
}

/// Inspect a Wow.exe buffer and report which RCE-hardening patches
/// are applied. Used by the CLI's `verify` subcommand and by anyone
/// embedding the library in a launcher / CI gate.
pub fn verify_rce_hardening(buf: &[u8]) -> VerifyReport {
    let mut lines = Vec::new();
    let mut all_applied = true;
    for entry in RCE_HARDENING_PATCHES {
        let end = entry.offset + entry.expected.len();
        if end > buf.len() {
            lines.push(format!(
                "[FAIL] {} @ 0x{:x}: offset out of range",
                entry.name, entry.offset
            ));
            all_applied = false;
            continue;
        }
        let cur = &buf[entry.offset..end];
        if cur == entry.new {
            lines.push(format!(
                "[OK]   {} @ 0x{:x}: applied",
                entry.name, entry.offset
            ));
        } else if cur == entry.expected {
            lines.push(format!(
                "[MISS] {} @ 0x{:x}: vulnerable (pre-bytes still present)",
                entry.name, entry.offset
            ));
            all_applied = false;
        } else {
            lines.push(format!(
                "[FAIL] {} @ 0x{:x}: unrecognised bytes {:02x?} (expected {:02x?} or {:02x?})",
                entry.name, entry.offset, cur, entry.expected, entry.new
            ));
            all_applied = false;
        }
    }
    VerifyReport { all_applied, lines }
}

/// Apply the RCE-hardening patch table with strict pre-byte
/// verification. Differs from `apply_named_patch` in three ways:
///
/// 1. Each entry carries an `expected` byte slice. The current bytes
///    at `offset` MUST equal it (already-patched is detected
///    separately by comparing against `new`). If neither matches, the
///    file is rejected -- could be a different build, a custom-
///    modified Wow.exe, or a corrupted blob, and silently writing
///    over unknown bytes is dangerous for security patches.
///
/// 2. Per-entry summary logged at INFO so the operator sees each
///    decision (applied / already-patched / rejected).
///
/// 3. Returns `Err` if any entry rejects, so the caller can propagate
///    "I refuse to harden this binary" up to the launcher pipeline.
fn apply_security_patches(buf: &mut [u8], table: &[SecurityPatch]) -> Result<()> {
    for entry in table {
        let end = entry.offset + entry.expected.len();
        if end > buf.len() {
            bail!(
                "security patch {} offset 0x{:x} out of range for this exe ({} bytes)",
                entry.name,
                entry.offset,
                buf.len()
            );
        }
        let current = &buf[entry.offset..end];
        if current == entry.new {
            info!(
                patch = entry.name,
                offset = format!("0x{:x}", entry.offset),
                "already patched -- skipping"
            );
            continue;
        }
        if current != entry.expected {
            bail!(
                "security patch {} pre-byte mismatch at 0x{:x}: \
                 expected {:02x?}, got {:02x?}. \
                 This is not the canonical 3.3.5a build 12340 Wow.exe, \
                 or a previous patch already modified these bytes. \
                 Refusing to overwrite.",
                entry.name,
                entry.offset,
                entry.expected,
                current
            );
        }
        let old: Vec<u8> = current.to_vec();
        buf[entry.offset..end].copy_from_slice(entry.new);
        info!(
            patch = entry.name,
            offset = format!("0x{:x}", entry.offset),
            old = format!("{:02x?}", old),
            new = format!("{:02x?}", entry.new),
            "applied"
        );
    }
    info!(count = table.len(), "rce-hardening patches done");
    Ok(())
}

/// Apply a tswow-style named patch table: at each entry's offset,
/// overwrite the bytes with `entry.new`. If the bytes already match
/// (re-run case), skip the write but still log so the operator sees
/// what happened.
fn apply_named_patch(buf: &mut [u8], name: &str, table: &[Patch]) {
    let mut applied = 0usize;
    let mut already = 0usize;
    let mut out_of_range = 0usize;
    for entry in table {
        let end = entry.offset + entry.new.len();
        if end > buf.len() {
            warn!(
                patch = name,
                offset = format!("0x{:x}", entry.offset),
                len = entry.new.len(),
                "offset out of range for this exe -- skipping"
            );
            out_of_range += 1;
            continue;
        }
        let current = &buf[entry.offset..end];
        if current == entry.new {
            already += 1;
            continue;
        }
        let old: Vec<u8> = current.to_vec();
        buf[entry.offset..end].copy_from_slice(entry.new);
        applied += 1;
        info!(
            patch = name,
            offset = format!("0x{:x}", entry.offset),
            old = format!("{:02x?}", old),
            new = format!("{:02x?}", entry.new),
            "patched"
        );
    }
    info!(
        patch = name,
        applied,
        already_patched = already,
        out_of_range,
        total = table.len(),
        "named patch summary"
    );
    if applied == 0 && already > 0 && out_of_range == 0 {
        info!(patch = name, "no-op (already fully patched)");
    }
}

fn find_version_offset(buf: &[u8]) -> Option<usize> {
    let needle_len = ORIGINAL_VERSION.len();
    buf.windows(needle_len + 1)
        .position(|w| &w[..needle_len] == ORIGINAL_VERSION && w[needle_len] == 0)
}

fn count_null_padding(buf: &[u8], start: usize) -> usize {
    let mut n = 0usize;
    while start + n < buf.len() && buf[start + n] == 0 {
        n += 1;
    }
    n
}

fn find_build_offsets(buf: &[u8], pat: [u8; 4]) -> Vec<usize> {
    let mut out = Vec::new();
    for (i, w) in buf.windows(4).enumerate() {
        if w == pat {
            out.push(i);
        }
    }
    out
}

fn replace_version(
    buf: &mut [u8],
    offset: usize,
    old_len: usize,
    padding: usize,
    new_version: &str,
) -> Result<()> {
    let new_bytes = new_version.as_bytes();
    let slot = old_len + padding;
    if new_bytes.len() + 1 > slot {
        bail!(
            "new version {:?} ({} bytes + NUL) does not fit in slot of {} bytes (old {} + padding {})",
            new_version,
            new_bytes.len(),
            slot,
            old_len,
            padding
        );
    }
    let old_snapshot: Vec<u8> = buf[offset..offset + old_len].to_vec();
    for b in &mut buf[offset..offset + slot] {
        *b = 0;
    }
    buf[offset..offset + new_bytes.len()].copy_from_slice(new_bytes);
    info!(
        offset = format!("0x{:x}", offset),
        old = ?String::from_utf8_lossy(&old_snapshot),
        new = new_version,
        slot,
        "version string replaced"
    );
    Ok(())
}

fn replace_all_build(buf: &mut [u8], pat: [u8; 4], new_build: u32) -> usize {
    let new_le = new_build.to_le_bytes();
    let mut count = 0usize;
    let mut i = 0usize;
    while i + 4 <= buf.len() {
        if buf[i..i + 4] == pat {
            buf[i..i + 4].copy_from_slice(&new_le);
            info!(
                offset = format!("0x{:x}", i),
                old = ?pat,
                new = ?new_le,
                "build number replaced"
            );
            count += 1;
            i += 4;
        } else {
            i += 1;
        }
    }
    count
}

fn update_pe_checksum(buf: &mut [u8]) -> Result<()> {
    let checksum_off = pe_checksum_offset(buf)?;
    buf[checksum_off..checksum_off + 4].copy_from_slice(&[0u8; 4]);
    let sum = compute_pe_checksum(buf);
    buf[checksum_off..checksum_off + 4].copy_from_slice(&sum.to_le_bytes());
    info!(
        offset = format!("0x{:x}", checksum_off),
        checksum = format!("0x{:08x}", sum),
        "PE checksum updated"
    );
    Ok(())
}

fn pe_checksum_offset(buf: &[u8]) -> Result<usize> {
    if buf.len() < 0x40 {
        bail!("file too small for DOS header");
    }
    if &buf[0..2] != b"MZ" {
        bail!("missing MZ signature, not a PE file");
    }
    let e_lfanew = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 24 > buf.len() {
        bail!("e_lfanew out of range");
    }
    if &buf[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        bail!("missing PE\\0\\0 signature");
    }
    Ok(e_lfanew + 4 + 20 + 64)
}

fn compute_pe_checksum(buf: &[u8]) -> u32 {
    let mut sum: u64 = 0;
    let len = buf.len();
    let pairs = len / 2;
    for i in 0..pairs {
        let w = u16::from_le_bytes([buf[2 * i], buf[2 * i + 1]]) as u64;
        sum += w;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if len % 2 == 1 {
        sum += buf[len - 1] as u64;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let folded = (sum & 0xFFFF) as u32;
    folded.wrapping_add(len as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_buf() -> Vec<u8> {
        let mut b = vec![0xAAu8; 32];
        b.extend_from_slice(b"3.3.5");
        b.extend_from_slice(&[0u8; 8]);
        b.extend_from_slice(&[0xBBu8; 16]);
        b.extend_from_slice(&ORIGINAL_BUILD_LE);
        b.extend_from_slice(&[0xCCu8; 8]);
        b.extend_from_slice(&ORIGINAL_BUILD_LE);
        b.extend_from_slice(&[0xDDu8; 16]);
        b
    }

    #[test]
    fn finds_version_offset() {
        let b = synth_buf();
        let off = find_version_offset(&b).expect("found");
        assert_eq!(&b[off..off + 5], b"3.3.5");
    }

    #[test]
    fn replaces_all_build_occurrences() {
        let mut b = synth_buf();
        let n = replace_all_build(&mut b, ORIGINAL_BUILD_LE, 12345);
        assert_eq!(n, 2);
    }

    #[test]
    fn named_patch_idempotent() {
        // Build a buffer big enough that the largest large-address-aware
        // offset (0x126) fits and is initially zero. Apply twice; the
        // second pass should see "already patched".
        let mut b = vec![0u8; 0x200];
        apply_named_patch(&mut b, "test", TSWOW_LARGE_ADDRESS_AWARE);
        assert_eq!(b[0x126], 0x23);
        // Snapshot then re-apply.
        let snap = b.clone();
        apply_named_patch(&mut b, "test", TSWOW_LARGE_ADDRESS_AWARE);
        assert_eq!(snap, b);
    }
}
