//! Warden Watch -- in-process detector + blocker for the WoW 3.3.5a
//! client's manual PE loader RCE class (CVE-class circa 2018).
//!
//! Loaded into Wow.exe via `wow-rce-watcher launcher` (CreateRemote-
//! Thread + LoadLibraryW). On `DllMain DLL_PROCESS_ATTACH` we
//! install a JMP-trampoline at `0x00872350` (the manual PE loader
//! entry, FUN_00872350 in the standard 12340 build).
//!
//! ## Calling-convention quirk
//!
//! `FUN_00872350` is a custom-ABI function: it takes one buffer
//! pointer on the stack BUT also reads ECX as an OUT-struct
//! pointer (the function writes the loaded module's metadata
//! into `*(ECX)` and `*(ECX+4)`). Yet it ends with a bare `ret`
//! (no callee cleanup). Neither `extern "C"`, `extern "thiscall"`,
//! nor `extern "fastcall"` matches all three properties, so the
//! hook entry is implemented as a `#[naked]` function in inline
//! asm: pushes-everything, calls a Rust inspector with the OUT
//! and IN pointers, and either blocks (return 0) or tail-jumps
//! into the trampoline (which runs the original function with
//! ECX + stack untouched).
//!
//! Decisions are written to `%APPDATA%\wow-rce-watcher\events.jsonl`
//! one JSON object per line so users can audit which modules
//! their client has loaded across sessions.

#![cfg(windows)]

use core::arch::naked_asm;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use windows_sys::Win32::Foundation::{BOOL, HMODULE, TRUE};
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

mod api_hooks;
mod bg_handler;
mod decision;
mod hook;
mod log;
mod pe;

/// `0x00872350` is the entry of the manual PE loader function in
/// Wow.exe build 12340.
const WARDEN_LOADER_ENTRY_RVA: usize = 0x00872350 - 0x00400000;

/// Trampoline address. Set by `install` after VirtualAlloc; read
/// by the naked hook's tail-jump. `static mut` because it's
/// initialised once on the install thread before any hook fires;
/// no other writer ever touches it.
#[unsafe(no_mangle)]
static mut TRAMPOLINE_PTR: usize = 0;

static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(module: HMODULE, reason: u32, _reserved: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe { windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls(module) };
        let _ = std::thread::Builder::new()
            .name("wow-rce-init".into())
            .spawn(|| {
                if let Err(e) = install() {
                    log::write_event(&log::Event::startup_error(&e.to_string()));
                }
            });
    }
    TRUE
}

#[derive(Debug)]
enum InstallError {
    UnexpectedBaseAddress,
    HookFailed(&'static str),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedBaseAddress => write!(f, "Wow.exe not loaded at expected base 0x00400000"),
            Self::HookFailed(s) => write!(f, "hook install failed: {s}"),
        }
    }
}

fn install() -> Result<(), InstallError> {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

    let base = unsafe { GetModuleHandleA(std::ptr::null()) } as usize;
    if base != 0x00400000 {
        return Err(InstallError::UnexpectedBaseAddress);
    }

    let target = base + WARDEN_LOADER_ENTRY_RVA;

    // Sanity: prologue should be `55 8B EC 6A FF` (push ebp; mov
    // ebp, esp; push -1) on build 12340.
    let actual = unsafe { std::ptr::read_unaligned(target as *const [u8; 5]) };
    const EXPECTED_PROLOGUE: [u8; 5] = [0x55, 0x8B, 0xEC, 0x6A, 0xFF];
    if actual != EXPECTED_PROLOGUE {
        return Err(InstallError::HookFailed(
            "loader prologue mismatch -- not the expected Wow.exe build",
        ));
    }

    let trampoline = hook::install_jmp_hook(target, hook_entry as usize)
        .map_err(InstallError::HookFailed)?;
    unsafe {
        TRAMPOLINE_PTR = trampoline;
    }
    HOOK_INSTALLED.store(true, Ordering::Release);

    log::write_event(&log::Event::installed(target));

    // Install the BG-positions handler observation hook. Pure
    // logging -- no patch, no block. If the static patcher hasn't
    // been applied to this Wow.exe and a server sends the exploit
    // count, the loop will run unbounded and the user's client
    // gets compromised. The runtime is OBSERVE-ONLY by design;
    // safety belongs in the static patches.
    if let Err(e) = bg_handler::install() {
        log::write_event(&log::Event::startup_error(&format!(
            "bg-handler hook install failed: {e}"
        )));
    }

    // Install detour-style observe hooks on file-IO + HTTP APIs.
    // Catches both Wow's own IAT-routed calls AND server-pushed
    // shellcode that resolves these APIs via GetProcAddress
    // (the canonical browser-history exfil path).
    api_hooks::install_all();

    Ok(())
}

/// Naked hook entry. Layout-aware asm that:
/// 1. Saves all registers + flags (so the original function sees
///    its caller's state intact even after our inspection).
/// 2. Calls `inspect_and_decide(out_ptr, buf_ptr)` (cdecl) with
///    ECX (the OUT struct ptr the original caller set) as arg1
///    and the first stack arg (the IN buffer) as arg2.
/// 3. On `1` (allow): restore everything, tail-jmp into the
///    trampoline (which runs the original function as if we were
///    never there).
/// 4. On `0` (block): restore everything, set EAX=0, ret -- the
///    caller (FUN_007da610) sees a "module load failed" return.
#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn hook_entry() {
    naked_asm!(
        // Set up our own EBP frame so the inspect call's args are
        // easy to find via [ebp+8].
        "push ebp",
        "mov ebp, esp",
        // [ebp+0]  = saved EBP
        // [ebp+4]  = original caller return-addr (from the call
        //            that landed at 0x00872350; JMP from our patch
        //            preserved it on the stack)
        // [ebp+8]  = stack_arg_1 (the buffer pointer)
        "pushad",
        "pushfd",
        // pushad pushes EAX,ECX,EDX,EBX,ESPorig,EBP,ESI,EDI in
        // that order. After pushfd (4 more bytes pushed), saved
        // ECX is at [esp + 4(eflags) + 4*6(EDI..EDX)] = [esp+28].
        //
        // Push cdecl args for inspect_and_decide(out_ptr, buf):
        "push dword ptr [ebp+8]",       // buf pointer (arg2)
        "push dword ptr [esp+32]",      // saved ECX = out_ptr (arg1) -- 28+4
        "call {inspect}",
        "add esp, 8",                    // cdecl caller cleanup
        // EAX now holds 1 (allow) or 0 (block).
        "test eax, eax",
        "jnz 2f",
        // ----- BLOCK -----
        "popfd",
        "popad",
        "leave",                          // mov esp, ebp; pop ebp
        "xor eax, eax",                   // return 0 to caller
        "ret",
        // ----- ALLOW -----
        "2:",
        "popfd",
        "popad",
        "leave",
        // Tail-jmp into the trampoline. Stack is exactly as it was
        // on entry to FUN_00872350; ECX preserved by popad. The
        // trampoline runs the original 5-byte prologue then jumps
        // back into Wow.exe at 0x00872355, finishing the original
        // function. When that function `ret`s, control returns
        // straight to FUN_00872350's original caller -- our hook
        // is invisible.
        "jmp dword ptr [{trampoline}]",
        inspect = sym inspect_and_decide,
        trampoline = sym TRAMPOLINE_PTR,
    );
}

/// Plain cdecl callback the naked hook invokes. Returns 1 to
/// allow the original loader to map + execute the module, or 0
/// to make the loader fail cleanly (FUN_00872350's caller sees
/// "module load failed" -- no execution happens).
///
/// Canonical Blizzard 3.3.5a Win Warden modules (MD5 `79C0768D
/// 657977D697E10BAD956CCED1`) are always allowed silently. For
/// any non-canonical module a synchronous Yes/No MessageBox is
/// shown describing the module (MD5 + verdict + first imports)
/// and the user decides per-module whether to allow or reject
/// it. Reject -> the loader returns "load failed" and no module
/// code ever runs.
#[unsafe(no_mangle)]
extern "C" fn inspect_and_decide(out_ptr: *const u8, buf_ptr: *const u8) -> u32 {
    let verdict = inspect_buffer(buf_ptr);
    log::write_event(&log::Event::module_seen_with_ctx(&verdict, out_ptr as usize));

    let is_canonical_blizzard = verdict.md5
        == [
            0x79, 0xC0, 0x76, 0x8D, 0x65, 0x79, 0x77, 0xD6, 0x97, 0xE1, 0x0B, 0xAD, 0x95, 0x6C,
            0xCE, 0xD1,
        ];
    let has_payload = verdict.md5 != [0u8; 16]; // [0; 16] = parse failed, not a real MD5
    if has_payload && !is_canonical_blizzard {
        log::write_event(&log::Event::non_canonical_warden(&verdict));

        let allowed = prompt_user_allow_non_canonical(&verdict);
        if !allowed {
            log::write_event(&log::Event::module_blocked(&verdict));
            return 0;
        }
        log::write_event(&log::Event::module_user_allowed(&verdict));
    }

    1
}

/// Pop a SYNCHRONOUS Yes/No MessageBox: "Server wants to load
/// this non-canonical Warden module. Allow?". Returns true if the
/// user clicks Yes (allow), false on No (reject).
///
/// The dialog blocks the FUN_00872350 hook path until the user
/// answers. That stalls Wow.exe's network thread; the server-
/// side may time out and disconnect, which is the expected
/// behavior when a user rejects an unknown module.
///
/// Failures to open the dialog (e.g. running headless under
/// a non-interactive desktop) default to **reject** -- safer to
/// drop a server's payload than to silently allow it when the
/// user can't see the prompt.
fn prompt_user_allow_non_canonical(verdict: &decision::Verdict) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxA, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SYSTEMMODAL, MB_TOPMOST, MB_YESNO,
    };
    let mut hex = String::with_capacity(32);
    for b in &verdict.md5 {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    let imports_preview: String =
        verdict.imports.iter().take(12).cloned().collect::<Vec<_>>().join(", ");
    let sections_preview: String =
        verdict.sections.iter().take(6).cloned().collect::<Vec<_>>().join(", ");
    let body = format!(
        "The server wants Wow.exe to load a NON-CANONICAL Warden module.\n\n\
         MD5: {}\n\
         Verdict: {}\n\n\
         Imports (first 12):\n  {}\n\n\
         Sections (first 6):\n  {}\n\n\
         Canonical Blizzard 3.3.5a Win Warden MD5 is\n\
         79C0768D657977D697E10BAD956CCED1.\n\
         Anything else is a custom module that this server has\n\
         crafted; it will run as native code inside Wow.exe with\n\
         your Windows user's full privileges.\n\n\
         Full module bytes saved to\n\
         %APPDATA%\\wow-rce-watcher\\modules\\{}.bin\n\
         for offline inspection.\n\n\
         ALLOW this module to load?\0",
        hex, verdict.reason, imports_preview, sections_preview, hex
    );
    let title = "wow-client-toolkit: server wants to load Warden module\0";
    let r = unsafe {
        MessageBoxA(
            0,
            body.as_ptr(),
            title.as_ptr(),
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TOPMOST | MB_SYSTEMMODAL,
        )
    };
    if r == 0 {
        // MessageBoxA failed (no interactive desktop, etc.) --
        // fail safe: reject the module.
        return false;
    }
    r == IDYES as i32
}

fn inspect_buffer(buf: *const u8) -> decision::Verdict {
    if buf.is_null() {
        return decision::Verdict {
            action: decision::Action::Allow,
            md5: [0u8; 16],
            reason: "null module buffer (passed through)".into(),
            imports: Vec::new(),
            sections: Vec::new(),
        };
    }
    const MAX_MODULE: usize = 4 * 1024 * 1024;
    let bytes = unsafe { std::slice::from_raw_parts(buf, MAX_MODULE) };

    // Dump every PE-shaped buffer to disk for offline analysis.
    // Lets the operator load suspicious modules in Ghidra and read
    // the actual file paths / API resolutions / network endpoints
    // the server-pushed code embeds as string constants. Safe to
    // call before pe::parse since we're just writing bytes.
    if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
        // PE-bounded size from optional header (best-effort -- if
        // we can't parse SizeOfImage we cap at a reasonable max).
        let sized = pe::guess_size(bytes).unwrap_or(64 * 1024);
        dump_module_bytes(&bytes[..sized.min(bytes.len())]);
    }

    let parsed = match pe::parse(bytes) {
        Ok(p) => p,
        Err(e) => {
            // Snapshot the first 32 bytes so we can figure out
            // what the caller is actually handing us when it's
            // not a raw PE. The audit said "buffer in PE format"
            // but the client may pass a wrapper struct that
            // CONTAINS the PE pointer.
            let dump_len = unsafe {
                let mut n = 0usize;
                let p = buf;
                while n < 32 {
                    // Best-effort byte read; we already promised
                    // 4 MiB readable above, so this is safe for
                    // the buffers FUN_00872350 actually sees.
                    let _ = std::ptr::read_volatile(p.add(n));
                    n += 1;
                }
                n
            };
            let head = unsafe { std::slice::from_raw_parts(buf, dump_len) };
            let hex = head.iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{:02x} ", b);
                s
            });
            return decision::Verdict {
                action: decision::Action::Allow,
                md5: [0u8; 16],
                reason: format!(
                    "not a PE buffer (passed through): {e} | first 32: {}",
                    hex.trim_end()
                ),
                imports: Vec::new(),
                sections: Vec::new(),
            };
        }
    };
    decision::evaluate(&parsed)
}

/// Write the raw bytes of a server-pushed PE module to
/// `%APPDATA%\wow-rce-watcher\modules\<md5>.bin`. Idempotent --
/// re-pushed modules with the same MD5 overwrite themselves.
/// Failures are silently swallowed so a write error never blocks
/// the original Wow.exe code path.
fn dump_module_bytes(bytes: &[u8]) {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(bytes);
    let hash: [u8; 16] = hasher.finalize().into();
    let mut hex = String::with_capacity(32);
    for b in &hash {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }

    let appdata = match std::env::var_os("APPDATA") {
        Some(v) => v,
        None => return,
    };
    let mut path = std::path::PathBuf::from(appdata);
    path.push("wow-rce-watcher");
    path.push("modules");
    let _ = std::fs::create_dir_all(&path);
    path.push(format!("{}.bin", hex));
    if path.exists() {
        return; // already captured
    }
    if let Err(e) = std::fs::write(&path, bytes) {
        log::write_event(&log::Event::startup_error(&format!(
            "module dump write failed for {}: {}",
            hex, e
        )));
    } else {
        log::write_event(&log::Event::module_dumped(&hex, bytes.len()));
    }
}
