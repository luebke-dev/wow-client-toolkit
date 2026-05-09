//! Minimal 5-byte JMP-rel32 trampoline. Hand-rolled so the DLL has
//! no MinHook / Detours dependency -- a 100-line audit-friendly
//! patch instead of a 5000-line library.
//!
//! Strategy:
//! 1. Disassemble enough of the target's prologue to copy at least
//!    5 bytes of intact instructions into our heap-allocated
//!    trampoline (so a chained `original(...)` call still hits a
//!    valid prologue).
//! 2. Append a `JMP rel32` at the end of the trampoline back to
//!    the target's first instruction past the saved prologue.
//! 3. Make the target page RWX, write `JMP rel32 -> our hook` at
//!    the target entry, restore the page protection.
//!
//! For FUN_00872350 the actual prologue (build 12340) is
//! `55 8B EC 6A FF` (push ebp; mov ebp, esp; push -1) -- 5 bytes
//! covering 3 instructions, ending exactly on a clean boundary.
//! Perfect for our 5-byte JMP-rel32 patch with no instruction
//! split. If we later hook other functions we add a tiny
//! length-decoder.

use windows_sys::Win32::System::Memory::{
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE,
};

/// Default 5-byte prologue (matches FUN_00872350 hook site).
const PROLOGUE_LEN: usize = 5;

/// Install a JMP-rel32 hook at `target` with the default 5-byte
/// prologue (matches the FUN_00872350 hook site). Convenience
/// wrapper around `install_jmp_hook_for`.
pub fn install_jmp_hook(target: usize, hook: usize) -> Result<usize, &'static str> {
    install_jmp_hook_for(target, hook, PROLOGUE_LEN)
}

/// Install a JMP-rel32 hook at `target`, redirecting to `hook`.
/// Each hook site has its own trampoline allocation; passing
/// distinct `target` addresses produces independent hooks. The
/// `prologue_len` argument lets the caller configure how many
/// bytes are copied into the trampoline (must be >= 5 and end on
/// a clean instruction boundary at `target`).
pub fn install_jmp_hook_for(
    target: usize,
    hook: usize,
    prologue_len_arg: usize,
) -> Result<usize, &'static str> {
    let prologue_len = prologue_len_arg;

    // Allocate trampoline page. RWX so we can both write the
    // copied prologue + relative-jump and have the CPU execute it.
    let trampoline_size: usize = prologue_len + 5; // prologue + JMP rel32
    let trampoline = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            trampoline_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if trampoline.is_null() {
        return Err("VirtualAlloc trampoline failed");
    }
    let trampoline = trampoline as usize;

    // Copy the original prologue bytes into the trampoline.
    let target_bytes =
        unsafe { std::slice::from_raw_parts(target as *const u8, prologue_len) };
    let trampoline_slice =
        unsafe { std::slice::from_raw_parts_mut(trampoline as *mut u8, trampoline_size) };
    trampoline_slice[..prologue_len].copy_from_slice(target_bytes);

    // Append `E9 xx xx xx xx` (JMP rel32) back to target+prologue_len.
    let jmp_back_dest = target + prologue_len;
    let jmp_back_origin = trampoline + prologue_len + 5; // after the JMP itself
    let jmp_back_offset = (jmp_back_dest as isize - jmp_back_origin as isize) as i32;
    trampoline_slice[prologue_len] = 0xE9;
    trampoline_slice[prologue_len + 1..prologue_len + 5]
        .copy_from_slice(&jmp_back_offset.to_le_bytes());

    // Patch target with JMP rel32 -> our hook.
    let patch_origin = target + 5;
    let patch_offset = (hook as isize - patch_origin as isize) as i32;
    let mut patch = [0u8; 5];
    patch[0] = 0xE9;
    patch[1..5].copy_from_slice(&patch_offset.to_le_bytes());

    let mut old_prot: PAGE_PROTECTION_FLAGS = 0;
    let ok = unsafe {
        VirtualProtect(
            target as *const _,
            5,
            PAGE_EXECUTE_READWRITE,
            &mut old_prot,
        )
    };
    if ok == 0 {
        return Err("VirtualProtect target -> RWX failed");
    }
    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), target as *mut u8, 5);
    }
    let mut _ignored: PAGE_PROTECTION_FLAGS = 0;
    unsafe {
        VirtualProtect(target as *const _, 5, old_prot, &mut _ignored);
        // Stale icache entries can keep executing the old bytes
        // for a few instructions. Flush.
        windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            target as *const _,
            5,
        );
    }

    Ok(trampoline)
}
