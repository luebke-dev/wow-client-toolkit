//! BG-positions handler observation -- pure forensic logging, no
//! patching.
//!
//! `MSG_BATTLEGROUND_PLAYER_POSITIONS` handler at VA 0x0054B3F0
//! in Wow.exe build 12340. We install a 5-byte JMP at offset
//! +0x16 (right after the function's `call CDataStore::GetInt32`
//! returns), so by the time our hook fires, `dword_BEA5B0` is
//! populated with the attacker-controlled count value. We log
//! that count + an optional snapshot of the upcoming shellcode
//! bytes from the CDataStore read cursor, then tail-jmp back into
//! the function.
//!
//! IMPORTANT: this module does NOT apply any patch. The runtime
//! is observation-only. If you want safety + observation, run
//! `wow-exe-patcher patch` against the binary first; static
//! patches plug the hole, this DLL records when the server tried.

use core::arch::naked_asm;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::log;

const BG_COUNT_GLOBAL_VA: usize = 0x00BEA5B0;
/// Hook installation point: right after the function's own
/// `call CDataStore::GetInt32(this, &BEA5B0)` returns. File offset
/// 0x14A806 / VA 0x0054B406.
const BG_HOOK_AFTER_GETINT32_VA: usize = 0x0054B406;

/// Bytes at `BG_HOOK_AFTER_GETINT32_VA` in canonical 12340.
/// `33 DB 33 FF 39` = `xor ebx,ebx; xor edi,edi; cmp` (5 bytes).
/// We replace these with a JMP-rel32 to our hook; the trampoline
/// holds the original 5 bytes + a JMP back to +5.
const BG_HOOK_PROLOGUE: [u8; 5] = [0x33, 0xDB, 0x33, 0xFF, 0x39];

static BG_TRAMPOLINE_PTR: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
pub enum InstallError {
    PrologueMismatch,
    HookFailed(&'static str),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrologueMismatch => {
                write!(f, "BG handler prologue mismatch -- not the expected build")
            }
            Self::HookFailed(s) => write!(f, "hook install failed: {s}"),
        }
    }
}

/// One-shot install: just the observation hook. Refuses if the
/// hook site bytes don't match the canonical build (different
/// build, statically patched, or already hooked).
pub fn install() -> Result<(), InstallError> {
    let hook_site = BG_HOOK_AFTER_GETINT32_VA as *const u8;
    let actual: [u8; 5] = unsafe { std::ptr::read_unaligned(hook_site as *const [u8; 5]) };
    if actual != BG_HOOK_PROLOGUE {
        return Err(InstallError::PrologueMismatch);
    }

    let trampoline = crate::hook::install_jmp_hook_for(
        BG_HOOK_AFTER_GETINT32_VA,
        bg_hook_entry as usize,
        5,
    )
    .map_err(InstallError::HookFailed)?;
    BG_TRAMPOLINE_PTR.store(trampoline, Ordering::Release);
    log::write_event(&log::Event::bg_hook_installed(BG_HOOK_AFTER_GETINT32_VA));
    Ok(())
}

/// Naked-asm hook. Mid-function position so we MUST leave every
/// register and flag exactly as the original code expects -- no
/// caller frame to clean up either.
#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn bg_hook_entry() {
    naked_asm!(
        "pushad",
        "pushfd",
        "mov eax, [{count_global}]",
        "push eax",
        "call {observe}",
        "add esp, 4",
        "popfd",
        "popad",
        "jmp dword ptr [{trampoline}]",
        count_global = sym BG_COUNT_GLOBAL,
        observe = sym observe_bg_call,
        trampoline = sym BG_TRAMPOLINE_PTR,
    );
}

#[unsafe(no_mangle)]
static BG_COUNT_GLOBAL: usize = BG_COUNT_GLOBAL_VA;

extern "C" fn observe_bg_call(count: u32) {
    log::write_event(&log::Event::bg_handler_called(count));
}
