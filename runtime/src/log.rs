//! Append-only JSONL audit log under `%APPDATA%\wow-rce-watcher\events.jsonl`.
//! Format is one self-contained JSON object per line so users can
//! diff / grep across sessions and replay decisions out-of-process.
//!
//! Hand-rolled JSON-ish to avoid pulling in serde inside the
//! injected DLL. Strings are escaped just enough for the fields we
//! actually emit (no newlines, no quotes, no backslashes -- if a
//! malicious module tries to inject control chars via the DLL name
//! we strip them).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::decision::{Action, Verdict};

pub struct Event {
    kind: &'static str,
    fields: Vec<(String, String)>,
}

impl Event {
    pub fn installed(target: usize) -> Self {
        Self {
            kind: "hook_installed",
            fields: vec![("target".into(), format!("0x{:08X}", target))],
        }
    }

    pub fn startup_error(msg: &str) -> Self {
        Self {
            kind: "startup_error",
            fields: vec![("error".into(), sanitize(msg))],
        }
    }

    pub fn bg_hook_installed(addr: usize) -> Self {
        Self {
            kind: "bg_hook_installed",
            fields: vec![
                ("addr".into(), format!("0x{:08x}", addr)),
                (
                    "note".into(),
                    "MSG_BATTLEGROUND_PLAYER_POSITIONS handler observation hook armed".into(),
                ),
            ],
        }
    }

    /// Logged from observe_bg_call -- the `count` value the server
    /// just placed into dword_BEA5B0. Legit packets <= 80; anything
    /// larger is the documented arbitrary-write exploit.
    pub fn bg_handler_called(count: u32) -> Self {
        let kind = if count > 80 {
            "bg_exploit_attempt"
        } else {
            "bg_handler_called"
        };
        let target_addr = 0xBEA180u64.saturating_add((count as u64).saturating_mul(8));
        let note = if count > 80 {
            format!(
                "EXPLOIT: count={count} would reach VA 0x{:08x} via 8*i+0xBEA180 -- runtime is observe-only, attack proceeds; static patcher is the safety net",
                target_addr
            )
        } else {
            format!("legit BG-positions packet, count={count}")
        };
        Self {
            kind,
            fields: vec![
                ("count".into(), count.to_string()),
                ("note".into(), note),
            ],
        }
    }

    /// Logged from `dump_module_bytes` after a server-pushed PE
    /// buffer has been written to disk for offline analysis. The
    /// operator can pull `%APPDATA%\wow-rce-watcher\modules\<md5>.bin`
    /// into Ghidra to read string constants (file paths the module
    /// opens, registry keys it queries, URLs it contacts).
    pub fn module_dumped(md5_hex: &str, size_bytes: usize) -> Self {
        Self {
            kind: "module_dumped",
            fields: vec![
                ("md5".into(), md5_hex.to_string()),
                ("size".into(), size_bytes.to_string()),
                (
                    "note".into(),
                    format!(
                        "raw PE bytes -> %APPDATA%\\wow-rce-watcher\\modules\\{}.bin",
                        md5_hex
                    ),
                ),
            ],
        }
    }

    pub fn zdata_locked(addr: usize, old_prot: u32) -> Self {
        Self {
            kind: "zdata_locked",
            fields: vec![
                ("addr".into(), format!("0x{:08x}", addr)),
                ("old_protection".into(), format!("0x{:08x}", old_prot)),
                (
                    "note".into(),
                    "EXECUTE bit cleared on .zdata; Vektor-1 RCE blocked".into(),
                ),
            ],
        }
    }

    pub fn zdata_lock_failed(addr: usize) -> Self {
        Self {
            kind: "zdata_lock_failed",
            fields: vec![
                ("addr".into(), format!("0x{:08x}", addr)),
                (
                    "note".into(),
                    "VirtualProtect failed; .zdata still RWX -- player still vulnerable to Vektor-1".into(),
                ),
            ],
        }
    }

    pub fn module_seen_with_ctx(verdict: &Verdict, out_ctx: usize) -> Self {
        let mut e = Self::module_seen(verdict);
        e.fields.push(("out_ctx".into(), format!("0x{:08x}", out_ctx)));
        e
    }

    pub fn raw_call(this: usize, p1: usize, p2: usize, p3: usize) -> Self {
        Self {
            kind: "raw_call",
            fields: vec![
                ("this".into(), format!("0x{:08x}", this)),
                ("p1".into(), format!("0x{:08x}", p1)),
                ("p2".into(), format!("0x{:08x}", p2)),
                ("p3".into(), format!("0x{:08x}", p3)),
            ],
        }
    }

    pub fn module_seen(verdict: &Verdict) -> Self {
        let action = match verdict.action {
            Action::Allow => "allow",
            Action::Block => "block",
        };
        let md5 = verdict
            .md5
            .iter()
            .fold(String::new(), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{:02x}", b);
                s
            });
        let imports = verdict
            .imports
            .iter()
            .map(|s| sanitize(s))
            .collect::<Vec<_>>()
            .join(", ");
        let sections = verdict
            .sections
            .iter()
            .map(|s| sanitize(s))
            .collect::<Vec<_>>()
            .join(", ");
        Self {
            kind: "warden_module",
            fields: vec![
                ("action".into(), action.into()),
                ("md5".into(), md5),
                ("reason".into(), sanitize(&verdict.reason)),
                ("imports".into(), imports),
                ("sections".into(), sections),
            ],
        }
    }
}

pub fn write_event(e: &Event) {
    let path = match log_path() {
        Some(p) => p,
        None => return,
    };
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(&path));
    let mut line = String::new();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    line.push_str(&format!(
        "{{\"ts\":{},\"kind\":\"{}\"",
        ts, e.kind
    ));
    for (k, v) in &e.fields {
        line.push_str(&format!(",\"{}\":\"{}\"", k, v));
    }
    line.push_str("}\n");
    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| f.write_all(line.as_bytes()));
}

fn log_path() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    let mut p = PathBuf::from(appdata);
    p.push("wow-rce-watcher");
    p.push("events.jsonl");
    Some(p)
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '"' | '\\' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect()
}
