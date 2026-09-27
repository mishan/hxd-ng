//! `hxd-load run <scenario.toml> [--out report.json]` runs a scenario
//! and exits non-zero if any check was violated.
//!
//! `hxd-load accounts <dir> --prefix P --count N --password W [--admin LOGIN]`
//! writes the account files a churn run logs in to, into a server's
//! accounts directory: `P0` up to `P<N-1>`, each allowed to chat and to
//! detach, and optionally one account allowed to disconnect users.

use std::path::PathBuf;
use std::process::ExitCode;

use hxd_load::config::Scenario;

const USAGE: &str = "usage:
  hxd-load run <scenario.toml> [--out <report.json>]
  hxd-load accounts <dir> --prefix <p> --count <n> --password <w> [--admin <login>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("accounts") => accounts(&args[1..]),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("hxd-load: {e}");
            ExitCode::from(2)
        }
    }
}

/// `--flag value`, from anywhere after the positionals.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let path = args.first().ok_or(USAGE)?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let scenario = Scenario::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let report = runtime.block_on(hxd_load::run(scenario))?;
    eprint!("{}", report.summary());
    let json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    match flag(args, "--out") {
        Some(out) => std::fs::write(out, json).map_err(|e| format!("{out}: {e}"))?,
        None => println!("{json}"),
    }
    Ok(if report.violations == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn accounts(args: &[String]) -> Result<ExitCode, String> {
    let dir = PathBuf::from(args.first().ok_or(USAGE)?);
    let prefix = flag(args, "--prefix").ok_or(USAGE)?;
    let count: usize = flag(args, "--count")
        .ok_or(USAGE)?
        .parse()
        .map_err(|e| format!("--count: {e}"))?;
    let password = flag(args, "--password").ok_or(USAGE)?;
    hxd_load::accounts::write(&dir, prefix, count, password, flag(args, "--admin"))?;
    eprintln!("hxd-load: wrote {count} accounts to {}", dir.display());
    Ok(ExitCode::SUCCESS)
}
