//! `wow-exe-patcher` CLI.
//!
//! See `wow-exe-patcher --help` for the full subcommand surface.
//! At a glance:
//!
//! ```text
//! wow-exe-patcher patch  --input Wow.exe --output Wow_safe.exe   # apply patches
//! wow-exe-patcher verify --input Wow.exe                          # check applied state
//! wow-exe-patcher probe  --input Wow.exe                          # diagnostic
//! ```

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use wow_exe_patcher::ExeFlags;

#[derive(Parser)]
#[command(version, about = "WoW 3.3.5a Wow.exe byte patcher (RCE hardening + tswow tables)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Apply patches to a Wow.exe and write the result to <output>.
    /// By default applies the RCE-hardening patches (recommended for
    /// any 3.3.5a client distribution). Additional flags enable
    /// tswow named patch tables.
    Patch {
        /// Source Wow.exe (will not be modified).
        #[arg(long)]
        input: PathBuf,

        /// Destination path. Refuses to overwrite an existing file
        /// unless --force is given. May equal --input only with --force.
        #[arg(long)]
        output: PathBuf,

        /// New version string (e.g. "3.3.5-rg"). Fits inside the
        /// existing slot (original 5 chars + trailing NUL padding).
        #[arg(long)]
        version: Option<String>,

        /// New build number (e.g. 12345). Replaces all occurrences
        /// of 12340 (LE 0x34 0x30 0x00 0x00) in the binary.
        #[arg(long)]
        build: Option<u32>,

        /// Print version + build offsets and exit; no output written.
        #[arg(long, default_value_t = false)]
        probe: bool,

        /// Allow --output to equal --input.
        #[arg(long, default_value_t = false)]
        force: bool,

        /// Disable TOC.SIG verification (alias for --allow-custom-gluexml).
        #[arg(long, default_value_t = false)]
        unlock_signatures: bool,

        /// tswow allow-custom-gluexml table.
        #[arg(long, default_value_t = false)]
        allow_custom_gluexml: bool,

        /// tswow large-address-aware table (4 GB user space).
        #[arg(long, default_value_t = false)]
        large_address_aware: bool,

        /// tswow view-distance unlock table.
        #[arg(long, default_value_t = false)]
        view_distance_unlock: bool,

        /// tswow item-dbc-disabler table (use server-side item template).
        #[arg(long, default_value_t = false)]
        item_dbc_disabler: bool,

        /// Apply all four tswow named patches at once.
        #[arg(long, default_value_t = false)]
        all_tswow: bool,

        /// Apply the RCE-hardening byte patches. ON by default; pass
        /// `--rce-hardening=false` (or `--no-rce-hardening`) to skip.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        rce_hardening: bool,
    },

    /// Inspect a Wow.exe and report which RCE-hardening patches are
    /// applied. Exit 0 = all three applied, exit 1 = at least one
    /// missing or unrecognised pre-bytes.
    Verify {
        #[arg(long)]
        input: PathBuf,
    },

    /// Print the bytes currently sitting at each known patch site
    /// (no modification). Useful for forensic analysis of an unknown
    /// Wow.exe build.
    Probe {
        #[arg(long)]
        input: PathBuf,
    },
}

fn main() -> Result<()> {
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env)
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();
    match cli.command {
        Cmd::Patch {
            input,
            output,
            version,
            build,
            probe,
            force,
            unlock_signatures,
            allow_custom_gluexml,
            large_address_aware,
            view_distance_unlock,
            item_dbc_disabler,
            all_tswow,
            rce_hardening,
        } => {
            let flags = ExeFlags {
                probe,
                force,
                unlock_signatures: unlock_signatures || allow_custom_gluexml || all_tswow,
                allow_custom_gluexml: allow_custom_gluexml || all_tswow,
                large_address_aware: large_address_aware || all_tswow,
                view_distance_unlock: view_distance_unlock || all_tswow,
                item_dbc_disabler: item_dbc_disabler || all_tswow,
                rce_hardening,
            };
            wow_exe_patcher::cmd_patch(&input, &output, version.as_deref(), build, flags)
        }
        Cmd::Verify { input } => {
            let buf = std::fs::read(&input)?;
            let report = wow_exe_patcher::verify_rce_hardening(&buf);
            for line in &report.lines {
                println!("{line}");
            }
            if report.all_applied {
                println!("[OK] all three RCE-hardening patches applied");
                Ok(())
            } else {
                println!("[FAIL] at least one patch missing or unrecognised pre-bytes");
                std::process::exit(1);
            }
        }
        Cmd::Probe { input } => {
            let flags = ExeFlags {
                probe: true,
                force: false,
                unlock_signatures: false,
                allow_custom_gluexml: false,
                large_address_aware: false,
                view_distance_unlock: false,
                item_dbc_disabler: false,
                rce_hardening: false,
            };
            // probe mode in cmd_patch prints + exits; output path
            // is unused but the API requires one, so pass a sentinel.
            wow_exe_patcher::cmd_patch(&input, &input, None, None, flags)
        }
    }
}
