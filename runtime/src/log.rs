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

    /// Logged after the user clicked **No** on the per-module
    /// allow-or-reject prompt. The loader returns 0 to its
    /// caller, no module bytes are mapped, and the server-side
    /// will likely time out + drop the connection.
    pub fn module_blocked(verdict: &Verdict) -> Self {
        let md5 = verdict
            .md5
            .iter()
            .fold(String::new(), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{:02x}", b);
                s
            });
        Self {
            kind: "module_blocked",
            fields: vec![
                ("md5".into(), md5),
                ("verdict".into(), sanitize(&verdict.reason)),
                (
                    "note".into(),
                    "user rejected the non-canonical Warden module; loader returned 0".into(),
                ),
            ],
        }
    }

    /// Logged after the user clicked **Yes** on the per-module
    /// allow-or-reject prompt. The module proceeds to load + run
    /// as if the DLL were not present.
    pub fn module_user_allowed(verdict: &Verdict) -> Self {
        let md5 = verdict
            .md5
            .iter()
            .fold(String::new(), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{:02x}", b);
                s
            });
        Self {
            kind: "module_user_allowed",
            fields: vec![
                ("md5".into(), md5),
                ("verdict".into(), sanitize(&verdict.reason)),
                (
                    "note".into(),
                    "user explicitly allowed this non-canonical Warden module via prompt".into(),
                ),
            ],
        }
    }

    /// Logged with HIGH PRIORITY whenever a Warden module's MD5
    /// does not match the canonical Blizzard 3.3.5a Win module
    /// (`79C0768D657977D697E10BAD956CCED1`). Greppable for
    /// monitoring; the operator should treat any occurrence as
    /// an immediate "this server is pushing custom bytes into my
    /// process" signal.
    pub fn non_canonical_warden(verdict: &Verdict) -> Self {
        let md5 = verdict
            .md5
            .iter()
            .fold(String::new(), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{:02x}", b);
                s
            });
        let imports_preview = verdict
            .imports
            .iter()
            .take(16)
            .map(|s| sanitize(s))
            .collect::<Vec<_>>()
            .join(", ");
        let sections_preview = verdict
            .sections
            .iter()
            .take(8)
            .map(|s| sanitize(s))
            .collect::<Vec<_>>()
            .join(", ");
        Self {
            kind: "non_canonical_warden",
            fields: vec![
                ("md5".into(), md5),
                ("verdict".into(), sanitize(&verdict.reason)),
                ("imports_first_16".into(), imports_preview),
                ("sections_first_8".into(), sections_preview),
                (
                    "note".into(),
                    "MODULE NOT MATCHING CANONICAL BLIZZARD MD5 (79C0768D657977D697E10BAD956CCED1) -- saved to %APPDATA%\\wow-rce-watcher\\modules\\<md5>.bin for offline analysis".into(),
                ),
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

    /// Logged once per per-handler observation hook install
    /// (handler_observe::install_all).
    pub fn handler_hook_installed(name: &'static str, site_va: usize) -> Self {
        Self {
            kind: "handler_hook_installed",
            fields: vec![
                ("handler".into(), name.into()),
                ("site".into(), format!("0x{:08x}", site_va)),
            ],
        }
    }

    /// Logged when a per-handler hook fails to install (prologue
    /// mismatch, JMP write failed, etc.).
    pub fn handler_hook_failed(
        name: &'static str,
        site_va: usize,
        reason: &str,
    ) -> Self {
        Self {
            kind: "handler_hook_failed",
            fields: vec![
                ("handler".into(), name.into()),
                ("site".into(), format!("0x{:08x}", site_va)),
                ("reason".into(), sanitize(reason)),
            ],
        }
    }

    /// Logged from each per-handler observer callback. `count` is
    /// the value the server just put on the wire for the handler's
    /// list-count / tab-id / similar attacker-controlled field.
    /// `anomaly` indicates the value exceeded the documented AC
    /// maximum for that opcode -- a strong signal the server is
    /// trying to weaponize the vuln.
    pub fn handler_called(
        name: &'static str,
        opcode: u32,
        count: u32,
        threshold: u32,
        anomaly: bool,
    ) -> Self {
        let kind = if anomaly { "handler_anomaly" } else { "handler_called" };
        let note = if anomaly {
            format!(
                "EXPLOIT ATTEMPT: {} sent count={} (> {} expected max). Static patch likely caps the actual write; this is the audit trail.",
                name, count, threshold
            )
        } else {
            format!("legit packet, count={}", count)
        };
        Self {
            kind,
            fields: vec![
                ("handler".into(), name.into()),
                ("opcode".into(), format!("0x{:04X}", opcode)),
                ("count".into(), count.to_string()),
                ("threshold".into(), threshold.to_string()),
                ("note".into(), note),
            ],
        }
    }

    /// Logged once per attempted detour install on a Win32 API.
    pub fn api_hook_installed(dll: &str, fn_name: &str, addr: usize) -> Self {
        Self {
            kind: "api_hook_installed",
            fields: vec![
                ("dll".into(), dll.to_string()),
                ("fn".into(), fn_name.to_string()),
                ("addr".into(), format!("0x{:08x}", addr)),
            ],
        }
    }

    /// Logged when a detour install fails (DLL not loaded,
    /// non-hot-patchable prologue, JMP write failed).
    pub fn api_hook_failed(dll: &str, fn_name: &str, reason: &str) -> Self {
        Self {
            kind: "api_hook_failed",
            fields: vec![
                ("dll".into(), dll.to_string()),
                ("fn".into(), fn_name.to_string()),
                ("reason".into(), sanitize(reason)),
            ],
        }
    }

    /// Logged from each detour observe callback. `kv` is the
    /// per-API set of arg name + stringified value pairs we want
    /// to record (path, URL, headers, etc).
    pub fn api_call(api: &'static str, kv: &[(&str, &str)]) -> Self {
        let mut fields = Vec::with_capacity(kv.len() + 1);
        fields.push(("api".into(), api.into()));
        for (k, v) in kv {
            fields.push(((*k).to_string(), sanitize(v)));
        }
        Self {
            kind: "api_call",
            fields,
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
