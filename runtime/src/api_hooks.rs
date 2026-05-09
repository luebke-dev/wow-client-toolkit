//! Detour-style hooks on a small set of Win32 APIs that are the
//! canonical primitives for the kind of post-RCE behavior a
//! malicious server would do (file IO + HTTP exfil).
//!
//! ## Why detour, not IAT
//!
//! Wow.exe's Import Address Table only catches calls FROM Wow.exe
//! itself. A server-pushed Warden module that resolves API
//! addresses via `GetProcAddress` bypasses the IAT entirely --
//! its `pCreateFileA` already points to the real kernel32 entry.
//! Patching the API entry point itself (5-byte JMP-rel32 detour)
//! intercepts every caller, IAT or shellcode alike.
//!
//! ## Why these specific APIs
//!
//! - `kernel32!CreateFileA` -- every file the process opens. A
//!   browser-history-theft payload calls this with a path like
//!   `C:\Users\X\AppData\Local\Google\Chrome\User Data\Default\History`
//!   (Chrome's SQLite history db). One log line catches the whole
//!   class.
//! - `wininet!InternetOpenA` -- starts an HTTP session. Logs the
//!   user-agent string, often an identifying tag.
//! - `wininet!HttpSendRequestA` -- the actual exfil send. We don't
//!   know the URL at this point but we know a request is going out.
//!
//! ## Observation-only
//!
//! Every hook calls through to the original via the trampoline.
//! Failures in the observation path (e.g. malformed pointer args)
//! are silently swallowed -- we never block the original API.

#![cfg(windows)]

use core::arch::naked_asm;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

use crate::hook;
use crate::log;

/// Hot-patchable Microsoft prologue: `mov edi, edi; push ebp;
/// mov ebp, esp`. Present on every API exported from a
/// Microsoft-compiled system DLL since Windows XP SP2. Wine
/// matches this on its own builds. If we see something else we
/// abort the hook and log -- patching a non-hot-patch prologue
/// risks splitting an instruction.
const HOT_PATCH_PROLOGUE: [u8; 5] = [0x8B, 0xFF, 0x55, 0x8B, 0xEC];

/// Trampoline pointers, set by `install`. Read by each naked hook
/// via `jmp dword ptr [...]`. `static mut` is fine because the
/// install thread is the only writer and runs once before any
/// hook can fire (hooks are armed only after each store).
#[unsafe(no_mangle)]
static mut TRAMP_CREATE_FILE_A: usize = 0;
#[unsafe(no_mangle)]
static mut TRAMP_INTERNET_OPEN_A: usize = 0;
#[unsafe(no_mangle)]
static mut TRAMP_HTTP_SEND_REQUEST_A: usize = 0;
#[unsafe(no_mangle)]
static mut TRAMP_SHELL_EXECUTE_A: usize = 0;
#[unsafe(no_mangle)]
static mut TRAMP_CREATE_PROCESS_A: usize = 0;
#[unsafe(no_mangle)]
static mut TRAMP_LOAD_LIBRARY_A: usize = 0;
#[unsafe(no_mangle)]
static mut TRAMP_REG_OPEN_KEY_EX_A: usize = 0;
#[unsafe(no_mangle)]
static mut TRAMP_REG_SET_VALUE_EX_A: usize = 0;

/// Per-thread reentry guard. The observe callbacks may incidentally
/// trigger more file IO (if logging hits a file the observer also
/// observes -- e.g. our own events.jsonl writer hitting CreateFileA),
/// which would loop. The guard makes the observe a no-op while
/// already inside an observe call on this thread.
thread_local! {
    static IN_OBSERVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn enter_observe<F: FnOnce()>(f: F) {
    IN_OBSERVE.with(|c| {
        if c.get() {
            return;
        }
        c.set(true);
        f();
        c.set(false);
    });
}

/// Try to install all detour hooks. Failures are logged + skipped
/// individually so partial coverage is preserved (e.g. wininet
/// might not be loaded yet -- the hooks for it are skipped, and
/// can be re-attempted later if needed).
pub fn install_all() {
    install_one(
        "kernel32.dll",
        "CreateFileA",
        hook_create_file_a as *const () as usize,
        &raw mut TRAMP_CREATE_FILE_A,
    );
    install_one(
        "wininet.dll",
        "InternetOpenA",
        hook_internet_open_a as *const () as usize,
        &raw mut TRAMP_INTERNET_OPEN_A,
    );
    install_one(
        "wininet.dll",
        "HttpSendRequestA",
        hook_http_send_request_a as *const () as usize,
        &raw mut TRAMP_HTTP_SEND_REQUEST_A,
    );
    install_one(
        "shell32.dll",
        "ShellExecuteA",
        hook_shell_execute_a as *const () as usize,
        &raw mut TRAMP_SHELL_EXECUTE_A,
    );
    install_one(
        "kernel32.dll",
        "CreateProcessA",
        hook_create_process_a as *const () as usize,
        &raw mut TRAMP_CREATE_PROCESS_A,
    );
    install_one(
        "kernel32.dll",
        "LoadLibraryA",
        hook_load_library_a as *const () as usize,
        &raw mut TRAMP_LOAD_LIBRARY_A,
    );
    install_one(
        "advapi32.dll",
        "RegOpenKeyExA",
        hook_reg_open_key_ex_a as *const () as usize,
        &raw mut TRAMP_REG_OPEN_KEY_EX_A,
    );
    install_one(
        "advapi32.dll",
        "RegSetValueExA",
        hook_reg_set_value_ex_a as *const () as usize,
        &raw mut TRAMP_REG_SET_VALUE_EX_A,
    );
}

fn install_one(dll: &str, fn_name: &str, hook_va: usize, tramp_slot: *mut usize) {
    let dll_h = load_module(dll);
    if dll_h == 0 {
        log::write_event(&log::Event::api_hook_failed(dll, fn_name, "module not loaded"));
        return;
    }
    let fn_va = unsafe { GetProcAddress(dll_h as HMODULE, c_str(fn_name).as_ptr() as *const u8) };
    let fn_va = match fn_va {
        Some(p) => p as usize,
        None => {
            log::write_event(&log::Event::api_hook_failed(dll, fn_name, "GetProcAddress null"));
            return;
        }
    };
    let actual = unsafe { std::ptr::read_unaligned(fn_va as *const [u8; 5]) };
    if actual != HOT_PATCH_PROLOGUE {
        log::write_event(&log::Event::api_hook_failed(
            dll,
            fn_name,
            &format!(
                "prologue mismatch: got {:02x?}, expected hot-patch {:02x?}",
                actual, HOT_PATCH_PROLOGUE
            ),
        ));
        return;
    }
    match hook::install_jmp_hook(fn_va, hook_va) {
        Ok(tramp) => {
            unsafe {
                *tramp_slot = tramp;
            }
            log::write_event(&log::Event::api_hook_installed(dll, fn_name, fn_va));
        }
        Err(e) => {
            log::write_event(&log::Event::api_hook_failed(dll, fn_name, e));
        }
    }
}

fn load_module(name: &str) -> usize {
    let cstr = c_str(name);
    let h = unsafe { GetModuleHandleA(cstr.as_ptr() as *const u8) };
    if h != 0 {
        return h as usize;
    }
    // Not loaded yet. Try LoadLibraryA so wininet hooks work even
    // if Wow's main thread hasn't touched HTTP yet.
    let h = unsafe {
        windows_sys::Win32::System::LibraryLoader::LoadLibraryA(cstr.as_ptr() as *const u8)
    };
    h as usize
}

fn c_str(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).expect("nul in string")
}

unsafe fn read_cstr_a(ptr: *const u8, max: usize) -> String {
    if ptr.is_null() {
        return String::from("(null)");
    }
    let mut bytes = Vec::with_capacity(64);
    let mut i = 0;
    while i < max {
        let b = unsafe { std::ptr::read_volatile(ptr.add(i)) };
        if b == 0 {
            break;
        }
        bytes.push(b);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

// ---------------------------------------------------------------
// Observe callbacks. Each takes the relevant args read from the
// stack by the naked entry below.
// ---------------------------------------------------------------

extern "C" fn observe_create_file_a(file_name: *const u8) {
    enter_observe(|| {
        let path = unsafe { read_cstr_a(file_name, 512) };
        log::write_event(&log::Event::api_call("CreateFileA", &[("path", &path)]));
    });
}

extern "C" fn observe_internet_open_a(user_agent: *const u8) {
    enter_observe(|| {
        let ua = unsafe { read_cstr_a(user_agent, 512) };
        log::write_event(&log::Event::api_call("InternetOpenA", &[("user_agent", &ua)]));
    });
}

extern "C" fn observe_http_send_request_a(headers_ptr: *const u8, headers_len: u32) {
    enter_observe(|| {
        let headers = if !headers_ptr.is_null() && headers_len > 0 {
            // Read up to headers_len, capped at 1 KiB.
            let n = (headers_len as usize).min(1024);
            unsafe { read_cstr_a(headers_ptr, n) }
        } else {
            String::new()
        };
        log::write_event(&log::Event::api_call(
            "HttpSendRequestA",
            &[("headers_len", &headers_len.to_string()), ("headers_first_1k", &headers)],
        ));
    });
}

// ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
// Logs lpOperation + lpFile + lpParameters. Wow.exe never calls
// this normally; any call = strong shellcode signal.
extern "C" fn observe_shell_execute_a(
    op: *const u8,
    file: *const u8,
    params: *const u8,
) {
    enter_observe(|| {
        let op = unsafe { read_cstr_a(op, 64) };
        let file = unsafe { read_cstr_a(file, 512) };
        let params = unsafe { read_cstr_a(params, 512) };
        log::write_event(&log::Event::api_call(
            "ShellExecuteA",
            &[("op", &op), ("file", &file), ("params", &params)],
        ));
    });
}

// CreateProcessA(lpApplicationName, lpCommandLine, ...)
// Logs both. Wow.exe never spawns child processes during gameplay.
extern "C" fn observe_create_process_a(app_name: *const u8, cmd_line: *const u8) {
    enter_observe(|| {
        let app = unsafe { read_cstr_a(app_name, 512) };
        let cmd = unsafe { read_cstr_a(cmd_line, 1024) };
        log::write_event(&log::Event::api_call(
            "CreateProcessA",
            &[("app", &app), ("cmd", &cmd)],
        ));
    });
}

// LoadLibraryA(lpLibFileName)
// High call frequency at startup, but should taper after init.
// Server-shellcode resolving extra DLLs would call this.
extern "C" fn observe_load_library_a(lib: *const u8) {
    enter_observe(|| {
        let lib = unsafe { read_cstr_a(lib, 512) };
        log::write_event(&log::Event::api_call(
            "LoadLibraryA",
            &[("lib", &lib)],
        ));
    });
}

// RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult)
// Logs lpSubKey. Wow.exe touches a few well-known keys at startup
// (HKLM\Software\Blizzard, etc.); any other path = persistence /
// recon attempt.
extern "C" fn observe_reg_open_key_ex_a(_hkey: u32, sub_key: *const u8) {
    enter_observe(|| {
        let key = unsafe { read_cstr_a(sub_key, 512) };
        log::write_event(&log::Event::api_call(
            "RegOpenKeyExA",
            &[("sub_key", &key)],
        ));
    });
}

// RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData)
// Logs lpValueName + first bytes of lpData. Wow.exe writes its
// install path / config at most once; persistent malware would
// write run keys.
extern "C" fn observe_reg_set_value_ex_a(
    _hkey: u32,
    value_name: *const u8,
    _reserved: u32,
    dtype: u32,
    data: *const u8,
    cb_data: u32,
) {
    enter_observe(|| {
        let name = unsafe { read_cstr_a(value_name, 512) };
        let data_preview = if !data.is_null() && cb_data > 0 {
            let n = (cb_data as usize).min(256);
            unsafe { read_cstr_a(data, n) }
        } else {
            String::new()
        };
        log::write_event(&log::Event::api_call(
            "RegSetValueExA",
            &[
                ("value_name", &name),
                ("data_type", &dtype.to_string()),
                ("data_size", &cb_data.to_string()),
                ("data_first_256", &data_preview),
            ],
        ));
    });
}

// ---------------------------------------------------------------
// Naked-asm trampoline entries. Each preserves all registers +
// flags, reads the relevant arg(s) from the stdcall arg layout,
// calls the observe callback, then JMPs to the trampoline (which
// runs the original 5-byte prologue then JMPs back to API+5).
//
// Stdcall layout on entry (no own prologue yet, hot-patched at
// API entry, our JMP overwrote the first 5 bytes):
//   [esp+0]  = caller return addr
//   [esp+4]  = arg1
//   [esp+8]  = arg2
//   ...
//
// After pushad (32 bytes) + pushfd (4 bytes) = 36 = 0x24 saved:
//   [esp+0x24] = caller return addr
//   [esp+0x28] = arg1
//   [esp+0x2C] = arg2
//   [esp+0x30] = arg3
// ---------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn hook_create_file_a() {
    naked_asm!(
        "pushad",
        "pushfd",
        "mov eax, [esp + 0x28]",       // arg1 = lpFileName
        "push eax",
        "call {observe}",
        "add esp, 4",
        "popfd",
        "popad",
        "jmp dword ptr [{tramp}]",
        observe = sym observe_create_file_a,
        tramp = sym TRAMP_CREATE_FILE_A,
    );
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn hook_internet_open_a() {
    naked_asm!(
        "pushad",
        "pushfd",
        "mov eax, [esp + 0x28]",       // arg1 = lpszAgent
        "push eax",
        "call {observe}",
        "add esp, 4",
        "popfd",
        "popad",
        "jmp dword ptr [{tramp}]",
        observe = sym observe_internet_open_a,
        tramp = sym TRAMP_INTERNET_OPEN_A,
    );
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn hook_http_send_request_a() {
    naked_asm!(
        "pushad",
        "pushfd",
        // HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength,
        //                  lpOptional, dwOptionalLength)
        // arg2 = lpszHeaders, arg3 = dwHeadersLength
        "mov eax, [esp + 0x2C]",       // arg2 = lpszHeaders
        "mov ecx, [esp + 0x30]",       // arg3 = dwHeadersLength
        "push ecx",
        "push eax",
        "call {observe}",
        "add esp, 8",
        "popfd",
        "popad",
        "jmp dword ptr [{tramp}]",
        observe = sym observe_http_send_request_a,
        tramp = sym TRAMP_HTTP_SEND_REQUEST_A,
    );
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn hook_shell_execute_a() {
    naked_asm!(
        "pushad",
        "pushfd",
        // ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters,
        //               lpDirectory, nShowCmd)
        // args at +0x28 (hwnd), +0x2C, +0x30, +0x34, ...
        "mov eax, [esp + 0x2C]",       // arg2 = lpOperation
        "mov ecx, [esp + 0x30]",       // arg3 = lpFile
        "mov edx, [esp + 0x34]",       // arg4 = lpParameters
        "push edx",
        "push ecx",
        "push eax",
        "call {observe}",
        "add esp, 12",
        "popfd",
        "popad",
        "jmp dword ptr [{tramp}]",
        observe = sym observe_shell_execute_a,
        tramp = sym TRAMP_SHELL_EXECUTE_A,
    );
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn hook_create_process_a() {
    naked_asm!(
        "pushad",
        "pushfd",
        // CreateProcessA(lpApplicationName, lpCommandLine, ...)
        "mov eax, [esp + 0x28]",       // arg1 = lpApplicationName
        "mov ecx, [esp + 0x2C]",       // arg2 = lpCommandLine
        "push ecx",
        "push eax",
        "call {observe}",
        "add esp, 8",
        "popfd",
        "popad",
        "jmp dword ptr [{tramp}]",
        observe = sym observe_create_process_a,
        tramp = sym TRAMP_CREATE_PROCESS_A,
    );
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn hook_load_library_a() {
    naked_asm!(
        "pushad",
        "pushfd",
        // LoadLibraryA(lpLibFileName)
        "mov eax, [esp + 0x28]",       // arg1 = lpLibFileName
        "push eax",
        "call {observe}",
        "add esp, 4",
        "popfd",
        "popad",
        "jmp dword ptr [{tramp}]",
        observe = sym observe_load_library_a,
        tramp = sym TRAMP_LOAD_LIBRARY_A,
    );
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn hook_reg_open_key_ex_a() {
    naked_asm!(
        "pushad",
        "pushfd",
        // RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult)
        "mov eax, [esp + 0x28]",       // arg1 = hKey
        "mov ecx, [esp + 0x2C]",       // arg2 = lpSubKey
        "push ecx",
        "push eax",
        "call {observe}",
        "add esp, 8",
        "popfd",
        "popad",
        "jmp dword ptr [{tramp}]",
        observe = sym observe_reg_open_key_ex_a,
        tramp = sym TRAMP_REG_OPEN_KEY_EX_A,
    );
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
extern "C" fn hook_reg_set_value_ex_a() {
    naked_asm!(
        "pushad",
        "pushfd",
        // RegSetValueExA(hKey, lpValueName, Reserved, dwType,
        //                lpData, cbData)
        "mov eax, [esp + 0x28]",       // arg1 = hKey
        "mov ecx, [esp + 0x2C]",       // arg2 = lpValueName
        "mov edx, [esp + 0x30]",       // arg3 = Reserved
        "mov esi, [esp + 0x34]",       // arg4 = dwType
        "mov edi, [esp + 0x38]",       // arg5 = lpData
        "mov ebx, [esp + 0x3C]",       // arg6 = cbData
        "push ebx",
        "push edi",
        "push esi",
        "push edx",
        "push ecx",
        "push eax",
        "call {observe}",
        "add esp, 24",
        "popfd",
        "popad",
        "jmp dword ptr [{tramp}]",
        observe = sym observe_reg_set_value_ex_a,
        tramp = sym TRAMP_REG_SET_VALUE_EX_A,
    );
}

