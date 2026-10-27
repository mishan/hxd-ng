//! The server key handover (`docs/server-key-handover.md` §6): the files
//! the server reads its commitment and its chain from, and `hxd identity
//! successor` and `handover`, which write them. The successor's private
//! key is never among them.

use std::path::{Path, PathBuf};

use hl_identity::handover::{commitment, Handover, MAX_CHAIN};
use hl_identity::{Fingerprint, PublicKey, ServerKey};
use hxd_ng_session::identity::{b64, check_handovers, unb64, Handovers};
use hxd_ng_session::IdentityState;

use crate::{check_config, decode_key, read_key, Config, IdentitySection};

/// What `section` names, as the server serves it.
pub fn load(section: &IdentitySection) -> Result<Handovers, String> {
    let path = &section.handovers;
    let chain = match read(path)? {
        Some(text) => text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| unb64(l).ok_or_else(|| format!("{}: {l:?} is not base64url", path.display())))
            .collect::<Result<_, _>>()?,
        None => Vec::new(),
    };
    Ok(Handovers {
        next: next_key(section)?.map(|k| commitment(&k)),
        chain,
    })
}

/// SIGHUP: serve what the config file's `[identity]` now names, if it
/// checks against the running key. Answers how many handovers are
/// served, and whether a successor is committed to.
pub fn reload(state: &IdentityState, path: &Path) -> Result<(usize, bool), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let config: Config = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    check_config(&config)?;
    let handovers = load(section(&config)?)?;
    let served = (handovers.chain.len(), handovers.next.is_some());
    state.set_handovers(handovers)?;
    Ok(served)
}

/// `hxd identity successor <path>`: a successor's private key written to
/// `path`, and its public key where the server reads it; with `existing`,
/// the successor already at `path`, to restore a commitment whose file
/// was lost. Committing to another key than the one committed to warns
/// each client that remembered it (§5.6), so it takes `replace`.
pub fn successor(
    config: &Config,
    config_path: &Path,
    path: &Path,
    existing: bool,
    replace: bool,
) -> Result<String, String> {
    let section = section(config)?;
    away_from_server(section, config_path, path)?;
    let key = if existing {
        read_key(path)?
    } else {
        ServerKey::generate()
    };
    let chain = load(section)?.chain;
    let last = chain.last().map(|h| Handover::parse(h)).transpose();
    let chained = last.ok().flatten().and_then(|h| h.next);
    // With its file lost, the commitment is still the chain's.
    let committed = next_key(section)?.map(|k| commitment(&k)).or(chained);
    let mine = commitment(&key.public());
    if committed.is_some_and(|c| c != mine) && !replace {
        return Err(
            "the server already commits to another successor; pass --replace only if its \
             private key is lost or exposed, since each client that remembered the \
             commitment then warns once"
                .into(),
        );
    }
    if !existing {
        write_durably(path, &hex(&key), false)?;
    }
    let mut said = vec![format!(
        "successor {}: its private key is at {}, for `hxd identity handover`; \
         keep it where the running server cannot reach it",
        b64(&key.public()),
        path.display()
    )];
    // A chain that does not end at the commitment is not served.
    if !chain.is_empty() && chained != Some(mine) {
        if let Some(aside) = move_aside(&section.handovers, &now().to_string())? {
            said.push(format!(
                "the handovers served until now are moved to {}: they end at another \
                 commitment, so no client could follow them",
                aside.display()
            ));
        }
    }
    write_durably(&section.next_key, &b64(&key.public()), true)?;
    said.push("a running server commits to it on SIGHUP (`systemctl reload`)".into());
    Ok(said.join("\n"))
}

/// `hxd identity handover <successor> [--next <path>]`, with the server
/// stopped: the server key signs over to the successor it commits to,
/// which becomes the server key, committing in turn to a successor made
/// at `next`, or to none.
///
/// Written in the order that leaves every state in between refused at
/// startup: the chain, which then ends at the successor while the server
/// key is still the old one, then the commitment, then the key. Run
/// again after it was cut short, it finishes what the chain records.
pub fn hand_over(
    config: &Config,
    config_path: &Path,
    successor: &Path,
    next: Option<&Path>,
) -> Result<String, String> {
    let section = section(config)?;
    let old = read_key(&section.key)?;
    let new = read_key(successor)?;
    if let Some(out) = next {
        away_from_server(section, config_path, out)?;
    }
    let mut handovers = load(section)?;
    let last = handovers.chain.last().map(|h| Handover::parse(h));
    let last = last
        .transpose()
        .map_err(|e| format!("{}: {e}", section.handovers.display()))?;
    let after = match last.filter(|h| h.old == old.public()) {
        Some(cut) => {
            if cut.new != new.public() {
                return Err(format!(
                    "{} records an unfinished handover to {}, not to {}",
                    section.handovers.display(),
                    b64(&cut.new),
                    successor.display()
                ));
            }
            let after = next.map(read_key).transpose()?;
            if after.as_ref().map(|k| commitment(&k.public())) != cut.next {
                return Err(format!(
                    "the unfinished handover commits to {}: run it again with the same --next",
                    if cut.next.is_some() {
                        "a successor"
                    } else {
                        "none"
                    }
                ));
            }
            handovers.next = cut.next;
            check_handovers(&new.public(), &handovers, now())
                .map_err(|e| format!("{}: {e}", section.handovers.display()))?;
            after
        }
        None => {
            let committed = next_key(section)?.ok_or(
                "the server commits to no successor: make one with `hxd identity successor`, \
                 and hand over to it only once clients have seen the commitment",
            )?;
            if new.public() != committed {
                return Err(format!(
                    "{} is not the successor the server commits to, {}",
                    successor.display(),
                    b64(&committed)
                ));
            }
            if let Some(out) = next.filter(|out| out.exists()) {
                return Err(format!(
                    "{} is already there: if a handover was cut short before it recorded \
                     anything, that is a successor nothing commits to; delete it and run \
                     again",
                    out.display()
                ));
            }
            let after = next.map(|_| ServerKey::generate());
            handovers.next = after.as_ref().map(|k| commitment(&k.public()));
            let signed = Handover {
                old: old.public(),
                new: new.public(),
                next: handovers.next,
                time: now(),
            }
            .sign(&old)
            .map_err(|e| format!("signing the handover: {e}"))?;
            handovers.chain.push(signed);
            let dropped = handovers.chain.len().saturating_sub(MAX_CHAIN);
            handovers.chain.drain(..dropped);
            check_handovers(&new.public(), &handovers, now())
                .map_err(|e| format!("{}: {e}", section.handovers.display()))?;
            if let (Some(out), Some(key)) = (next, &after) {
                write_durably(out, &hex(key), false)?;
            }
            let lines: Vec<String> = handovers.chain.iter().map(|h| b64(h)).collect();
            if let Err(e) = write_durably(&section.handovers, &lines.join("\n"), true) {
                if let Some(out) = next {
                    let _ = std::fs::remove_file(out);
                }
                return Err(e);
            }
            after
        }
    };

    let mut said = Vec::new();
    match (&after, next) {
        (Some(key), Some(out)) => {
            write_durably(&section.next_key, &b64(&key.public()), true)?;
            said.push(format!(
                "the next successor is {}, its private key at {}; keep it where the \
                 running server cannot reach it",
                b64(&key.public()),
                out.display()
            ));
        }
        _ => {
            match std::fs::remove_file(&section.next_key) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!("{}: {e}", section.next_key.display()))
                }
                _ => sync_dir(&section.next_key),
            }
            said.push(
                "no successor is committed, so clients cannot follow the next rotation \
                 until `hxd identity successor` makes one"
                    .into(),
            );
        }
    }
    // Kept before the new key is renamed over it, which leaves no moment
    // with no key, which the server would replace with a random one.
    let retired = aside_path(
        &section.key,
        &format!("old-{}", Fingerprint::of(&old.public()).short()),
    );
    if !retired.exists() {
        write_durably(&retired, &hex(&old), true)?;
    } else if read_key(&retired)?.public() != old.public() {
        return Err(format!("{} holds another key", retired.display()));
    }
    write_durably(&section.key, &hex(&new), true)?;
    said.insert(
        0,
        format!(
            "handed over from {} to {}; the old key is kept at {}\n\
             {} is now a copy of the server key: destroy it",
            b64(&old.public()),
            b64(&new.public()),
            retired.display(),
            successor.display()
        ),
    );
    said.push("start the server to serve the new key".into());
    Ok(said.join("\n"))
}

fn section(config: &Config) -> Result<&IdentitySection, String> {
    config
        .identity
        .as_ref()
        .ok_or_else(|| "no [identity] section: identity is off, so there is no server key".into())
}

fn next_key(section: &IdentitySection) -> Result<Option<PublicKey>, String> {
    let path = &section.next_key;
    read(path)?
        .map(|text| decode_key(&text).map_err(|e| format!("{}: {e}", path.display())))
        .transpose()
}

fn read(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// §6: a successor's private key is kept where the running server cannot
/// reach it, or a thief of the server takes both; beside the config file
/// or the server key, it can.
fn away_from_server(section: &IdentitySection, config: &Path, out: &Path) -> Result<(), String> {
    let dir = |p: &Path| {
        let d = p.parent().filter(|d| !d.as_os_str().is_empty());
        let d = d.unwrap_or(Path::new("."));
        d.canonicalize()
            .map_err(|e| format!("{}: {e}", d.display()))
    };
    let at = dir(out)?;
    for server in [config, section.key.as_path()] {
        let server = dir(server)?;
        if at.starts_with(&server) {
            return Err(format!(
                "{} is under {}, with the server's own files: write a successor's private \
                 key where the running server cannot reach it, such as removable media",
                out.display(),
                server.display()
            ));
        }
    }
    Ok(())
}

/// As `load_key` writes one.
fn hex(key: &ServerKey) -> String {
    key.seed().iter().map(|b| format!("{b:02x}")).collect()
}

/// Owner-only and synced before it counts: in place of what is at `path`
/// with `replace`, through a temporary file renamed over it, or else as a
/// new file, refusing one already there.
fn write_durably(path: &Path, text: &str, replace: bool) -> Result<(), String> {
    use std::io::Write;
    let at = if replace {
        aside_path(path, "tmp")
    } else {
        path.to_path_buf()
    };
    let err = |e: std::io::Error| format!("{}: {e}", at.display());
    if replace {
        match std::fs::remove_file(&at) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(err(e)),
            _ => {}
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&at).map_err(err)?;
    writeln!(f, "{text}")
        .and_then(|()| f.sync_all())
        .map_err(err)?;
    if replace {
        std::fs::rename(&at, path).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    sync_dir(path);
    Ok(())
}

fn sync_dir(path: &Path) {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    let _ = std::fs::File::open(dir.unwrap_or(Path::new("."))).and_then(|d| d.sync_all());
}

fn aside_path(path: &Path, suffix: &str) -> PathBuf {
    let mut aside = path.as_os_str().to_owned();
    aside.push(format!(".{suffix}"));
    PathBuf::from(aside)
}

/// Moved aside rather than deleted: an old chain is the operator's to
/// destroy.
fn move_aside(path: &Path, tag: &str) -> Result<Option<PathBuf>, String> {
    let aside = aside_path(path, &format!("old-{tag}"));
    if aside.exists() {
        return Err(format!("{} is in the way", aside.display()));
    }
    match std::fs::rename(path, &aside) {
        Ok(()) => Ok(Some(aside)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
