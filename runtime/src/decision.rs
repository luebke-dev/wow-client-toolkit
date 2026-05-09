//! Heuristic engine. Rules ordered roughly by severity (lower
//! = safer; higher = harder fail).
//!
//! Trust anchors:
//! - MD5 of the canonical Blizzard 3.3.5a Win Warden module:
//!     `79C0768D657977D697E10BAD956CCED1`
//!   This hash is bit-identical to what TC + AC ship and what
//!   millions of legit private-server logins have loaded for
//!   years. We treat it as our golden reference.
//!
//! Red flags:
//! - Imports that legit Warden never touches: process spawn,
//!   shell exec, network sockets, file download, GUI apis.
//! - More than one section with EXECUTE bit, or any section with
//!   `IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE` simultaneously.
//! - Bizarre size / section count.
//!
//! Output: a `Verdict` carrying the action + the human-readable
//! reason that gets logged. The blocker action returns 0 to the
//! caller of FUN_00872350 so the loader cleanly fails without a
//! DEP-style crash.

use md5::{Digest, Md5};

use crate::pe::ParsedPe;

#[derive(Debug, Clone, Copy)]
pub enum Action {
    Allow,
    Block,
}

#[derive(Debug)]
pub struct Verdict {
    pub action: Action,
    pub md5: [u8; 16],
    pub reason: String,
    pub imports: Vec<String>,
    pub sections: Vec<String>,
}

const BLIZZARD_WIN_335A_MD5: [u8; 16] = [
    0x79, 0xC0, 0x76, 0x8D, 0x65, 0x79, 0x77, 0xD6, 0x97, 0xE1, 0x0B, 0xAD, 0x95, 0x6C, 0xCE,
    0xD1,
];

/// Imports that the legit Blizzard Warden module is known never
/// to touch. Any of these in a server-supplied module is treated
/// as direct evidence of weaponisation.
const RED_FLAG_IMPORTS: &[&str] = &[
    "CreateProcessA",
    "CreateProcessW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "ShellExecuteExA",
    "ShellExecuteExW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "URLDownloadToCacheFileA",
    "URLDownloadToCacheFileW",
    "InternetOpenA",
    "InternetOpenW",
    "InternetReadFile",
    "WSAStartup",
    "WSASocketA",
    "WSASocketW",
    "socket",
    "connect",
    "send",
    "recv",
    "WriteFile",
    "DeleteFileA",
    "DeleteFileW",
    "MoveFileA",
    "MoveFileW",
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    "WinExec",
    "ExitWindowsEx",
    "InitiateSystemShutdownA",
    "InitiateSystemShutdownW",
];

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

pub fn evaluate(pe: &ParsedPe) -> Verdict {
    let mut hasher = Md5::new();
    hasher.update(pe.raw_bytes_for_hash());
    let hash: [u8; 16] = hasher.finalize().into();

    let import_strings: Vec<String> = pe
        .imports
        .iter()
        .flat_map(|imp| {
            imp.functions
                .iter()
                .map(move |f| format!("{}!{}", imp.dll, f))
        })
        .collect();
    let section_strings: Vec<String> = pe
        .sections
        .iter()
        .map(|s| format!("{} c=0x{:08X} v=0x{:X}", s.name, s.characteristics, s.virtual_size))
        .collect();

    if hash == BLIZZARD_WIN_335A_MD5 {
        return Verdict {
            action: Action::Allow,
            md5: hash,
            reason: "matches canonical Blizzard 3.3.5a Win module".into(),
            imports: import_strings,
            sections: section_strings,
        };
    }

    // Red flag #1: process / shell / network / persistence imports.
    for imp in &pe.imports {
        for fname in &imp.functions {
            if RED_FLAG_IMPORTS.iter().any(|rf| rf == fname) {
                return Verdict {
                    action: Action::Block,
                    md5: hash,
                    reason: format!(
                        "weaponised import detected: {}!{}",
                        imp.dll, fname
                    ),
                    imports: import_strings,
                    sections: section_strings,
                };
            }
        }
    }

    // Red flag #2: writeable + executable section.
    for s in &pe.sections {
        if s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            && s.characteristics & IMAGE_SCN_MEM_WRITE != 0
        {
            return Verdict {
                action: Action::Block,
                md5: hash,
                reason: format!(
                    "section {:?} requests RWX (Characteristics 0x{:08X})",
                    s.name, s.characteristics
                ),
                imports: import_strings,
                sections: section_strings,
            };
        }
    }

    // Red flag #3: more than one executable section. Legit module
    // has exactly one .text-equivalent.
    let exec_count = pe
        .sections
        .iter()
        .filter(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
        .count();
    if exec_count > 1 {
        return Verdict {
            action: Action::Block,
            md5: hash,
            reason: format!(
                "module has {exec_count} executable sections; legit module has 1"
            ),
            imports: import_strings,
            sections: section_strings,
        };
    }

    // No red flag, but unknown hash. Allow with warning so the
    // user can still play on private servers that ship a custom-
    // but-clean module; the event log shows the new hash so they
    // (or we) can promote it to a trusted entry over time.
    Verdict {
        action: Action::Allow,
        md5: hash,
        reason: "unknown module, no red flag (allowed with audit-log entry)".into(),
        imports: import_strings,
        sections: section_strings,
    }
}

impl<'a> ParsedPe<'a> {
    /// We hash only the bytes that fit inside `SizeOfImage` so an
    /// over-allocated buffer doesn't change the MD5.
    fn raw_bytes_for_hash(&self) -> &[u8] {
        let cap = (self.size_of_image as usize).min(self.raw_bytes.len());
        &self.raw_bytes[..cap]
    }
}
