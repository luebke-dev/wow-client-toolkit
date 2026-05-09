//! Per-handler observation hooks for the 3 packet handlers
//! identified by the audit as having BG-positions class arbitrary
//! writes (`MSG_GUILD_PERMISSIONS`, `SMSG_GUILD_ROSTER`,
//! `SMSG_GUILD_BANK_LIST`).
//!
//! Mirrors the `bg_handler.rs` pattern: install a 5+ byte JMP at
//! the spot in each handler RIGHT AFTER the count-reading
//! `CDataStore::Get*` returns, then log the count value + flag
//! anomalies. Static patches 4 + 5 still apply -- this just adds
//! visibility (server sent count=N attempt logged even if patches
//! prevent the actual exploitation).
//!
//! Observation only -- the hook never blocks; it always
//! tail-jumps to its trampoline.

use core::arch::naked_asm;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::log;

// ============================================================
// MSG_GUILD_PERMISSIONS handler -- FUN_005CB9F0
// ============================================================
//
// Hook site: VA 0x005CBA2A, RIGHT AFTER the GetUInt32(&local_c)
// call returns. local_c is at [ebp - 8]; we read it via the
// observer.
//
// 10-byte prologue (mov + LEA = clean instruction boundary):
//   8B 45 F8         mov eax, [ebp - 8]
//   8D 0C C5 00 00 00 00   lea ecx, [eax*8 + 0]
//
// Anomaly threshold: 16 (AC's max guild rank is ~10; anything
// larger = exploit attempt).

const PERM_HOOK_VA: usize = 0x005CBA2A;
const PERM_PROLOGUE: [u8; 10] = [0x8B, 0x45, 0xF8, 0x8D, 0x0C, 0xC5, 0x00, 0x00, 0x00, 0x00];
const PERM_ANOMALY_THRESHOLD: u32 = 16;
static PERM_TRAMPOLINE_PTR: AtomicUsize = AtomicUsize::new(0);

// ============================================================
// SMSG_GUILD_ROSTER MOTD-count handler -- FUN_005CC5D0
// ============================================================
//
// Hook site: VA 0x005CC6B4, RIGHT AFTER GetUInt32(&DAT_00C22AB8)
// for the MOTD-records count. We read DAT_00C22AB8 directly from
// the observer.
//
// 8-byte prologue (xor + cmp = clean):
//   33 C9              xor ecx, ecx
//   39 1D B8 2A C2 00  cmp [0x00C22AB8], ebx
//
// Anomaly threshold: 16 (AC max MOTD records is 10).

const ROSTER_HOOK_VA: usize = 0x005CC6B4;
const ROSTER_PROLOGUE: [u8; 8] = [0x33, 0xC9, 0x39, 0x1D, 0xB8, 0x2A, 0xC2, 0x00];
const ROSTER_COUNT_GLOBAL_VA: usize = 0x00C22AB8;
const ROSTER_ANOMALY_THRESHOLD: u32 = 16;
static ROSTER_TRAMPOLINE_PTR: AtomicUsize = AtomicUsize::new(0);

// ============================================================
// SMSG_GUILD_BANK_LIST tab-id handler -- FUN_005A7250
// ============================================================
//
// Hook site: VA 0x005A7275, RIGHT AFTER the GetUInt8(&local_5)
// (= tab id) returns. local_5 is at [ebp - 1]; we read via the
// observer.
//
// 5-byte prologue (single push imm32 = clean):
//   68 30 DC C1 00     push 0x00C1DC30
//
// Anomaly threshold: 8 (max valid bank tabs is 8 -> indexes 0-7).

const BANKLIST_HOOK_VA: usize = 0x005A7275;
const BANKLIST_PROLOGUE: [u8; 5] = [0x68, 0x30, 0xDC, 0xC1, 0x00];
const BANKLIST_ANOMALY_THRESHOLD: u32 = 8;
static BANKLIST_TRAMPOLINE_PTR: AtomicUsize = AtomicUsize::new(0);

// ============================================================
// Install all three. Each install is independent -- failures are
// logged and skipped so partial coverage is preserved.
// ============================================================

pub fn install_all() {
    install_one(
        PERM_HOOK_VA,
        &PERM_PROLOGUE,
        perm_hook_entry as *const () as usize,
        PERM_PROLOGUE.len(),
        &PERM_TRAMPOLINE_PTR,
        "guild_permissions",
    );
    install_one(
        ROSTER_HOOK_VA,
        &ROSTER_PROLOGUE,
        roster_hook_entry as *const () as usize,
        ROSTER_PROLOGUE.len(),
        &ROSTER_TRAMPOLINE_PTR,
        "guild_roster_motd",
    );
    install_one(
        BANKLIST_HOOK_VA,
        &BANKLIST_PROLOGUE,
        banklist_hook_entry as *const () as usize,
        BANKLIST_PROLOGUE.len(),
        &BANKLIST_TRAMPOLINE_PTR,
        "guild_bank_list_tab",
    );
}

fn install_one(
    site_va: usize,
    expected_prologue: &[u8],
    hook_va: usize,
    prologue_len: usize,
    trampoline_slot: &AtomicUsize,
    name: &'static str,
) {
    let actual = unsafe {
        std::slice::from_raw_parts(site_va as *const u8, prologue_len).to_vec()
    };
    if actual != expected_prologue {
        log::write_event(&log::Event::handler_hook_failed(
            name,
            site_va,
            &format!(
                "prologue mismatch: got {:02x?}, expected {:02x?}",
                actual, expected_prologue
            ),
        ));
        return;
    }
    match crate::hook::install_jmp_hook_for(site_va, hook_va, prologue_len) {
        Ok(tramp) => {
            trampoline_slot.store(tramp, Ordering::Release);
            log::write_event(&log::Event::handler_hook_installed(name, site_va));
        }
        Err(e) => {
            log::write_event(&log::Event::handler_hook_failed(name, site_va, e));
        }
    }
}

// ============================================================
// Naked-asm hook entries. Mid-function position so we MUST leave
// every register and flag exactly as the original code expects.
// Each reads the relevant count value, calls the observer, then
// tail-jumps to its trampoline.
// ============================================================

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn perm_hook_entry() {
    naked_asm!(
        "pushad",
        "pushfd",
        // local_c is at [ebp - 8]. EBP is unchanged inside the
        // hook (we're mid-function; the original frame is intact).
        "mov eax, [ebp - 8]",
        "push eax",
        "call {observe}",
        "add esp, 4",
        "popfd",
        "popad",
        "jmp dword ptr [{tramp}]",
        observe = sym observe_perm_call,
        tramp = sym PERM_TRAMPOLINE_PTR,
    );
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn roster_hook_entry() {
    naked_asm!(
        "pushad",
        "pushfd",
        // MOTD count is in DAT_00C22AB8 (global).
        "mov eax, [{count_global}]",
        "push eax",
        "call {observe}",
        "add esp, 4",
        "popfd",
        "popad",
        "jmp dword ptr [{tramp}]",
        count_global = sym ROSTER_COUNT_GLOBAL,
        observe = sym observe_roster_call,
        tramp = sym ROSTER_TRAMPOLINE_PTR,
    );
}

#[unsafe(no_mangle)]
static ROSTER_COUNT_GLOBAL: usize = ROSTER_COUNT_GLOBAL_VA;

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn banklist_hook_entry() {
    naked_asm!(
        "pushad",
        "pushfd",
        // Tab id is at [ebp - 1] (BYTE). Zero-extend to dword
        // for the observer.
        "movzx eax, byte ptr [ebp - 1]",
        "push eax",
        "call {observe}",
        "add esp, 4",
        "popfd",
        "popad",
        "jmp dword ptr [{tramp}]",
        observe = sym observe_banklist_call,
        tramp = sym BANKLIST_TRAMPOLINE_PTR,
    );
}

// ============================================================
// Observer callbacks -- Rust side, plain extern "C" cdecl.
// Each logs the count + flags an anomaly if it exceeds the
// expected maximum for that opcode.
// ============================================================

extern "C" fn observe_perm_call(count: u32) {
    let anomaly = count > PERM_ANOMALY_THRESHOLD;
    log::write_event(&log::Event::handler_called(
        "MSG_GUILD_PERMISSIONS",
        0x3FD,
        count,
        PERM_ANOMALY_THRESHOLD,
        anomaly,
    ));
}

extern "C" fn observe_roster_call(count: u32) {
    let anomaly = count > ROSTER_ANOMALY_THRESHOLD;
    log::write_event(&log::Event::handler_called(
        "SMSG_GUILD_ROSTER (MOTD count)",
        0x08A,
        count,
        ROSTER_ANOMALY_THRESHOLD,
        anomaly,
    ));
}

extern "C" fn observe_banklist_call(tab_id: u32) {
    let anomaly = tab_id >= BANKLIST_ANOMALY_THRESHOLD;
    log::write_event(&log::Event::handler_called(
        "SMSG_GUILD_BANK_LIST (tab id)",
        0x3E8,
        tab_id,
        BANKLIST_ANOMALY_THRESHOLD,
        anomaly,
    ));
}
