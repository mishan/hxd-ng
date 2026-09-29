//! `hlrelay` — put a classic Hotline server where a browser can reach it.
//!
//! ```text
//! hlrelay --upstream 127.0.0.1:5500 [--transfer HOST:PORT | --no-transfers]
//!         [--listen ADDR]... [--name NAME] [--max-connections N]
//!         [--max-pending N] [--max-per-address N]
//!         [--trusted-proxy ADDR[/BITS]]... [--forwarded-header NAME]
//! ```
//!
//! Listens on 127.0.0.1:5700 unless told otherwise — the classic port
//! plus 200, where a client looks first (`docs/hotline-ng-auth.md` §5.1),
//! on loopback, where the TLS-terminating proxy a browser needs reaches
//! it, as hxd-ng's ng listener does by default. `RUST_LOG` sets the log
//! level; `info` by default. `docs/relay.md` describes every flag.

use std::net::IpAddr;
use std::process::ExitCode;

use hlrelay::{Config, ForwardedHeader, TrustedProxies};

const USAGE: &str = "\
usage: hlrelay --upstream HOST:PORT [options]

  --upstream HOST:PORT      the classic server's port (required)
  --transfer HOST:PORT      its transfer port (default: upstream's port plus one)
  --no-transfers            serve no /htxf
  --listen ADDR             where to listen, repeatable (default: 127.0.0.1:5700)
  --name NAME               the server's name in discovery (default: hlrelay)
  --max-connections N       sockets relayed at once (default: 512)
  --max-pending N           connections not yet upgraded (default: 128)
  --max-per-address N       connections per client address, 0 for no limit (default: 16)
  --trusted-proxy ADDR[/BITS]
                            a proxy whose forwarded header is believed, repeatable
  --forwarded-header NAME   x-forwarded-for, forwarded or none (default: x-forwarded-for)
  -h, --help                print this and exit

See docs/relay.md.";

/// What the command line asks for.
enum Invocation {
    Run(Config, Vec<String>),
    Help,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let (cfg, listen) = match parse(std::env::args().skip(1)) {
        Ok(Invocation::Run(cfg, listen)) => (cfg, listen),
        Ok(Invocation::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("hlrelay: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("hlrelay: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async move {
        let mut listeners = Vec::new();
        for addr in &listen {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => listeners.push((addr, l)),
                Err(e) => {
                    eprintln!("hlrelay: {addr}: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        let bound: Vec<IpAddr> = listeners
            .iter()
            .filter_map(|(_, l)| l.local_addr().ok())
            .map(|a| a.ip())
            .collect();
        if let Some(warning) = shared_limit_warning(&cfg, &bound) {
            tracing::warn!("{warning}");
        }
        for (addr, _) in &listeners {
            tracing::info!(
                "relaying {addr} → {} (transfers → {})",
                cfg.upstream,
                cfg.transfer.as_deref().unwrap_or("none")
            );
        }
        // One relay however many addresses it listens on: the limits are
        // shared, not multiplied by the listeners.
        let listeners = listeners.into_iter().map(|(_, l)| l).collect();
        hlrelay::serve_all(listeners, cfg).await;
        ExitCode::SUCCESS
    })
}

/// A relay reachable only on loopback is behind a proxy, which is the
/// deployment `docs/relay.md` documents. With no proxy trusted, every
/// client behind it arrives from loopback and shares one address's
/// limit. Loopback is not trusted by default, since a proxy that does not
/// write the forwarded header passes the client's own straight through;
/// the operator is told instead.
fn shared_limit_warning(cfg: &Config, bound: &[IpAddr]) -> Option<String> {
    let behind_a_proxy =
        !bound.is_empty() && bound.iter().all(|ip| ip.to_canonical().is_loopback());
    if !behind_a_proxy
        || !cfg.trusted_proxies.is_empty()
        || cfg.max_per_address == 0
        || cfg.forwarded_header == ForwardedHeader::None
    {
        return None;
    }
    Some(format!(
        "listening only on loopback with no --trusted-proxy: every client of a \
         proxy in front shares one limit of {} connections; pass \
         --trusted-proxy 127.0.0.1 (or the proxy's address) if the proxy \
         writes {}",
        cfg.max_per_address,
        match cfg.forwarded_header {
            ForwardedHeader::Forwarded => "Forwarded",
            _ => "X-Forwarded-For",
        }
    ))
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Invocation, String> {
    let mut upstream = None;
    let mut transfer = None;
    let mut no_transfers = false;
    let mut listen = Vec::new();
    let mut name = None;
    let mut max = None;
    let mut max_pending = None;
    let mut per_address = None;
    let mut proxies = Vec::new();
    let mut forwarded = None;
    while let Some(a) = args.next() {
        let mut value = || args.next().ok_or(format!("{a} needs a value"));
        let number = |v: String| {
            v.parse::<usize>()
                .map_err(|_| format!("{a}: {v} is not a number"))
        };
        match a.as_str() {
            "--upstream" => upstream = Some(value()?),
            "--transfer" => transfer = Some(value()?),
            "--no-transfers" => no_transfers = true,
            "--listen" => listen.push(value()?),
            "--name" => name = Some(value()?),
            "--max-connections" => max = Some(number(value()?)?),
            "--max-pending" => max_pending = Some(number(value()?)?),
            "--max-per-address" => per_address = Some(number(value()?)?),
            "--trusted-proxy" => proxies.push(value()?),
            "--forwarded-header" => forwarded = Some(ForwardedHeader::parse(&value()?)?),
            "-h" | "--help" => return Ok(Invocation::Help),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let upstream = upstream.ok_or("--upstream is required")?;
    if transfer.is_some() && no_transfers {
        return Err("--transfer and --no-transfers contradict each other".into());
    }
    let mut cfg = Config::new(upstream);
    if let Some(t) = transfer {
        cfg.transfer = Some(t);
    }
    if no_transfers {
        cfg.transfer = None;
    }
    if let Some(n) = name {
        cfg.name = n;
    }
    if let Some(m) = max {
        if m == 0 {
            return Err("--max-connections must be at least 1".into());
        }
        cfg.max_connections = m;
    }
    if let Some(m) = max_pending {
        if m == 0 {
            return Err("--max-pending must be at least 1".into());
        }
        cfg.max_pending = m;
    }
    if let Some(m) = per_address {
        cfg.max_per_address = m;
    }
    cfg.trusted_proxies = TrustedProxies::parse(&proxies)?;
    if let Some(f) = forwarded {
        cfg.forwarded_header = f;
    }
    if listen.is_empty() {
        listen.push("127.0.0.1:5700".into());
    }
    Ok(Invocation::Run(cfg, listen))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Invocation, String> {
        parse(args.iter().map(|a| a.to_string()))
    }

    #[test]
    fn help_is_not_an_error() {
        assert!(matches!(run(&["--help"]), Ok(Invocation::Help)));
        assert!(matches!(run(&["-h"]), Ok(Invocation::Help)));
    }

    #[test]
    fn the_defaults_listen_on_loopback_and_name_no_upstream() {
        let Ok(Invocation::Run(cfg, listen)) = run(&["--upstream", "10.1.2.3:5500"]) else {
            panic!("a bare upstream runs");
        };
        assert_eq!(listen, ["127.0.0.1:5700"]);
        assert_eq!(cfg.name, hlrelay::DEFAULT_NAME);
        assert!(!cfg.name.contains("10.1.2.3"));
        assert!(cfg.trusted_proxies.is_empty());
        assert_eq!(cfg.forwarded_header, ForwardedHeader::XForwardedFor);
    }

    #[test]
    fn a_loopback_relay_with_no_trusted_proxy_is_warned_about() {
        let ips =
            |list: &[&str]| -> Vec<IpAddr> { list.iter().map(|a| a.parse().unwrap()).collect() };
        let cfg = |args: &[&str]| {
            let mut all = vec!["--upstream", "127.0.0.1:5500"];
            all.extend_from_slice(args);
            match run(&all) {
                Ok(Invocation::Run(cfg, _)) => cfg,
                _ => panic!("the flags parse"),
            }
        };
        let plain = cfg(&[]);
        let warning = shared_limit_warning(&plain, &ips(&["127.0.0.1"])).expect("warned");
        assert!(warning.contains("--trusted-proxy"), "{warning}");
        assert!(shared_limit_warning(&plain, &ips(&["::1", "::ffff:127.0.0.1"])).is_some());
        // Reachable from elsewhere, a trusted proxy, or a limit or a header
        // turned off: nothing to say.
        assert!(shared_limit_warning(&plain, &ips(&["127.0.0.1", "0.0.0.0"])).is_none());
        assert!(shared_limit_warning(&plain, &ips(&["192.0.2.1"])).is_none());
        for args in [
            &["--trusted-proxy", "127.0.0.1"][..],
            &["--max-per-address", "0"][..],
            &["--forwarded-header", "none"][..],
        ] {
            assert!(shared_limit_warning(&cfg(args), &ips(&["127.0.0.1"])).is_none());
        }
    }

    #[test]
    fn limits_and_proxies_are_read() {
        let Ok(Invocation::Run(cfg, _)) = run(&[
            "--upstream",
            "127.0.0.1:5500",
            "--max-per-address",
            "0",
            "--max-pending",
            "7",
            "--trusted-proxy",
            "127.0.0.1",
            "--trusted-proxy",
            "10.0.0.0/8",
            "--forwarded-header",
            "forwarded",
        ]) else {
            panic!("the flags parse");
        };
        assert_eq!(cfg.max_per_address, 0);
        assert_eq!(cfg.max_pending, 7);
        assert!(cfg.trusted_proxies.contains("10.9.9.9".parse().unwrap()));
        assert!(cfg.trusted_proxies.contains("127.0.0.1".parse().unwrap()));
        assert_eq!(cfg.forwarded_header, ForwardedHeader::Forwarded);

        assert!(run(&["--upstream", "h:1", "--trusted-proxy", "nope"]).is_err());
        assert!(run(&["--upstream", "h:1", "--forwarded-header", "via"]).is_err());
        assert!(run(&["--upstream", "h:1", "--max-pending", "0"]).is_err());
    }
}
