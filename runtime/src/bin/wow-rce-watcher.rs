//! Warden Watch launcher.
//!
//! Spawns Wow.exe in a SUSPENDED state, injects the
//! `wow_rce_watcher.dll` via CreateRemoteThread + LoadLibraryW,
//! resumes the main thread. The DLL hooks the manual Warden
//! module loader before the first server packet arrives.
//!
//! Usage:
//!   wow-rce-watcher.exe path\to\Wow.exe [--dll path\to\wow_rce_watcher.dll]
//!
//! The DLL path defaults to `wow_rce_watcher.dll` next to the
//! launcher binary, which is what the bundled installer ships.

#![cfg(windows)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, INFINITE, PROCESS_INFORMATION,
    ResumeThread, STARTUPINFOW, WaitForSingleObject,
};

#[cfg(not(windows))]
fn main() {
    eprintln!("wow-rce-watcher launcher only builds for Windows targets");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    let mut args = std::env::args_os().skip(1);
    let wow_exe = match args.next() {
        Some(a) => PathBuf::from(a),
        None => {
            usage();
            std::process::exit(2);
        }
    };
    let mut dll_path: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        if a == "--dll" {
            dll_path = args.next().map(PathBuf::from);
        }
    }
    let dll_path = dll_path.unwrap_or_else(|| {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("wow-rce-watcher.exe"));
        exe.with_file_name("wow_rce_watcher.dll")
    });

    if !wow_exe.is_file() {
        eprintln!("Wow.exe not found at {}", wow_exe.display());
        std::process::exit(2);
    }
    if !dll_path.is_file() {
        eprintln!("DLL not found at {}", dll_path.display());
        std::process::exit(2);
    }

    if let Err(e) = run(&wow_exe, &dll_path) {
        eprintln!("wow-rce-watcher: {e}");
        std::process::exit(1);
    }
}

fn usage() {
    eprintln!("usage: wow-rce-watcher <Wow.exe> [--dll <wow_rce_watcher.dll>]");
    eprintln!();
    eprintln!("Spawns Wow.exe with the wow-rce-watcher detector DLL injected.");
    eprintln!("Detector logs to %APPDATA%\\wow-rce-watcher\\events.jsonl.");
}

fn run(wow_exe: &Path, dll_path: &Path) -> Result<(), String> {
    let cmdline = to_wide(&format!("\"{}\"", wow_exe.display()));
    let cwd = wow_exe
        .parent()
        .map(|p| to_wide(&p.display().to_string()))
        .unwrap_or_else(|| vec![0]);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessW(
            null_mut(),
            cmdline.as_ptr() as *mut _,
            null_mut(),
            null_mut(),
            FALSE,
            CREATE_SUSPENDED,
            null_mut(),
            cwd.as_ptr(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(format!(
            "CreateProcessW failed (last_error 0x{:X})",
            unsafe { windows_sys::Win32::Foundation::GetLastError() }
        ));
    }

    let result = inject(pi.hProcess, dll_path);
    if let Err(e) = result {
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        return Err(format!("inject failed: {e}"));
    }

    unsafe {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        // Wait so the launcher console stays alive while Wow.exe
        // runs; gives a clean parent for telemetry. Drop this if
        // we ever want the launcher to detach.
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
    }
    Ok(())
}

fn inject(process: HANDLE, dll_path: &Path) -> Result<(), String> {
    let abs = std::fs::canonicalize(dll_path).map_err(|e| format!("canonicalize: {e}"))?;
    let wide_path = to_wide(&abs.display().to_string());
    let bytes_needed = wide_path.len() * 2;

    let remote_buf = unsafe {
        VirtualAllocEx(
            process,
            null_mut(),
            bytes_needed,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_buf.is_null() {
        return Err("VirtualAllocEx".into());
    }
    let mut written = 0usize;
    let ok = unsafe {
        WriteProcessMemory(
            process,
            remote_buf,
            wide_path.as_ptr() as *const _,
            bytes_needed,
            &mut written,
        )
    };
    if ok == 0 || written != bytes_needed {
        unsafe { VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE) };
        return Err("WriteProcessMemory".into());
    }

    // LoadLibraryW lives in kernel32.dll which is always at the
    // same base across processes on the same OS install (ASLR
    // randomises per-boot, not per-process). So our local
    // GetProcAddress(LoadLibraryW) returns the same address the
    // remote process will see.
    let kernel32 = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const _) };
    if kernel32 == 0 {
        return Err("GetModuleHandleA(kernel32) failed".into());
    }
    let load_library_w = unsafe {
        GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr() as *const _)
    };
    if load_library_w.is_none() {
        return Err("GetProcAddress(LoadLibraryW) failed".into());
    }

    let mut tid: u32 = 0;
    let thread = unsafe {
        CreateRemoteThread(
            process,
            null_mut(),
            0,
            Some(std::mem::transmute(load_library_w)),
            remote_buf,
            0,
            &mut tid,
        )
    };
    if thread == 0 {
        unsafe { VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE) };
        return Err("CreateRemoteThread".into());
    }
    unsafe {
        let waited = WaitForSingleObject(thread, 10_000);
        CloseHandle(thread);
        VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        if waited != WAIT_OBJECT_0 {
            return Err("LoadLibraryW remote thread did not finish in 10s".into());
        }
    }
    Ok(())
}

fn to_wide(s: &str) -> Vec<u16> {
    OsString::from(s).encode_wide().chain(Some(0)).collect()
}
