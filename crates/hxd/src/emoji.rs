//! `hxd emoji`, the one writer of the server's emoji catalog
//! (`docs/server-emoji.md`). It writes the database the server keeps
//! the catalog in, making each image here with the media pipeline, so a
//! server decodes nothing; a running server serves the edit once SIGHUP
//! has it reread the catalog.

use crate::Config;

/// `hxd emoji …`: `args` are the words after `emoji`.
#[cfg(all(feature = "media", feature = "inbox"))]
pub fn command(config: &Config, args: &[String]) -> Result<String, String> {
    use std::io::Read;
    use std::sync::Arc;
    use std::time::SystemTime;

    use hxd_core::emoji::{EmojiEntry, EmojiStore, EmojiStoreError, NameRefused, NewEmojiName};
    use hxd_core::media::{MediaCodec, MediaReject};

    const USAGE: &str = "usage: hxd emoji list [--removed] | add <name> <file> | \
                         rename <name|'#id'> <new-name> | remove <name|'#id'>";
    // The operator is the only one who hands it a file, and the source's
    // pixels, frames and allocation are bounded whatever its size.
    const MAX_SOURCE_BYTES: usize = 2 << 20;

    let mut removed = false;
    let mut words = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--removed" => removed = true,
            other if other.starts_with('-') => return Err(format!("unknown argument {other:?}")),
            other => words.push(other),
        }
    }
    let known = match words[..] {
        ["list"] => true,
        ["add", _, _] | ["rename", _, _] | ["remove", _] => !removed,
        _ => false,
    };
    if !known {
        return Err(USAGE.into());
    }
    let section = config.emoji.as_ref();
    let policy = section.map_or_else(|| Ok(Default::default()), |e| e.policy())?;
    let path = crate::moderation::db(config).ok_or(
        "[emoji] needs a database: the catalog is kept in the one [inbox], [history] or \
         [news] names",
    )?;
    // Only `add` may make the database, for a catalog set up before the
    // server first starts; anything else names a file that should exist.
    let store = match words[..] {
        ["add", ..] => crate::open_sqlite(&path, hxd_store_sqlite::Synchronous::Normal)?,
        _ if !path.exists() => return Err(format!("{}: no database yet", path.display())),
        ["list"] => Arc::new(
            hxd_store_sqlite::SqliteStore::open_read_only(&path)
                .map_err(|e| format!("{}: {e}", path.display()))?,
        ),
        _ => crate::open_sqlite(&path, hxd_store_sqlite::Synchronous::Normal)?,
    };
    let applied = if section.is_some_and(|e| e.enabled) {
        "a running server applies it on SIGHUP (`systemctl reload`)"
    } else {
        "a server serves it once [emoji] is enabled"
    };
    let name = |n: &str| {
        NewEmojiName::parse(n).map_err(|why| match why {
            NameRefused::Malformed => format!("{n:?}: names are 2 to 32 of a-z, 0-9 and _"),
            NameRefused::Shortcode => format!(
                "{n:?} is a common emoji's shortcode (gemoji's), which clients draw as that \
                 emoji whatever the server holds"
            ),
        })
    };
    let entries = || -> Result<Vec<EmojiEntry>, String> {
        Ok(store.load().map_err(|e| e.to_string())?.entries)
    };
    let find = |what: &str| -> Result<EmojiEntry, String> {
        let mut live = entries()?.into_iter().filter(|e| e.image.is_some());
        match what.strip_prefix('#') {
            Some(n) => {
                let id: u32 = n
                    .parse()
                    .map_err(|_| format!("{what:?} is not an emoji id, such as '#1'"))?;
                live.find(|e| e.id.0 == id)
                    .ok_or(format!("there is no emoji #{id}"))
            }
            None => live
                .find(|e| e.name.as_str() == what)
                .ok_or(format!("there is no emoji :{what}:")),
        }
    };
    let refused = |e: EmojiStoreError| match e {
        EmojiStoreError::CatalogFull => format!(
            "the catalog holds [emoji] max_count = {} emoji already",
            policy.max_count
        ),
        other => other.to_string(),
    };
    let kind = |animated: bool| if animated { "animated GIF" } else { "PNG" };
    match words[..] {
        ["list"] => {
            let lines: Vec<String> = entries()?
                .iter()
                .filter_map(|e| match &e.image {
                    Some(i) => Some(format!(
                        "#{} :{}: {}x{} {}, {} bytes",
                        e.id.0,
                        e.name,
                        i.width,
                        i.height,
                        kind(i.animated),
                        i.bytes.len()
                    )),
                    None => removed.then(|| format!("#{} :{}: removed", e.id.0, e.name)),
                })
                .collect();
            Ok(if lines.is_empty() {
                "no emoji".into()
            } else {
                lines.join("\n")
            })
        }
        ["add", n, file] => {
            let new = name(n)?;
            let n = new.name();
            // Bounded before it is read: the codec would refuse it only after.
            let mut input = Vec::new();
            std::fs::File::open(file)
                .and_then(|f| f.take(MAX_SOURCE_BYTES as u64 + 1).read_to_end(&mut input))
                .map_err(|e| format!("{file}: {e}"))?;
            let image = hxd_media::Codec::new(Default::default())
                .with_max_bytes(MAX_SOURCE_BYTES)
                .emoji(&input, &policy)
                .map_err(|e| match e {
                    MediaReject::Unsupported => {
                        format!("{file}: not an image this server takes: PNG, GIF or JPEG")
                    }
                    MediaReject::TooLarge => format!(
                        "{file}: too small or too large: a source is at most {} MiB and {} \
                         pixels a side, an animation at most [emoji] max_frames = {} frames, \
                         {} seconds and its frames times its pixels within the decode budget, \
                         and the image must fit [emoji] max_bytes = {} once shrunk",
                        MAX_SOURCE_BYTES >> 20,
                        hxd_media::EMOJI_MAX_SOURCE,
                        policy.max_frames,
                        hxd_media::EMOJI_MAX_DURATION_MS / 1000,
                        policy.max_bytes
                    ),
                    other => format!("{file}: {}", other.text()),
                })?;
            store
                .add(&new, &image, SystemTime::now(), policy.max_count)
                .map_err(refused)?;
            // Added already: a failed lookup is no reason to say otherwise.
            let id = find(n.as_str()).map_or("a new id".into(), |e| format!("#{}", e.id.0));
            Ok(format!(
                "added :{n}: as {id}, a {}x{} {} of {} bytes; {applied}",
                image.width,
                image.height,
                kind(image.animated),
                image.bytes.len()
            ))
        }
        ["rename", what, new] => {
            // Its own name again changes nothing, even one the list has
            // gained since the entry was given it.
            let entry = find(what)?;
            if entry.name.as_str() == new {
                return Ok(format!("#{} is :{new}: already", entry.id.0));
            }
            let given = name(new)?;
            store.rename(entry.id, &given).map_err(refused)?;
            Ok(format!(
                "renamed #{} :{}: to :{new}:; {applied}",
                entry.id.0, entry.name
            ))
        }
        ["remove", what] => {
            let entry = find(what)?;
            // As many removed entries are kept as live ones may be.
            store
                .remove(entry.id, SystemTime::now(), policy.max_count)
                .map_err(refused)?;
            Ok(format!(
                "removed :{}: (#{}); {applied}",
                entry.name, entry.id.0
            ))
        }
        _ => Err(USAGE.into()),
    }
}

/// Without the pipeline there is nothing to make an image with, and
/// without SQLite nowhere to keep one.
#[cfg(not(all(feature = "media", feature = "inbox")))]
pub fn command(_config: &Config, _args: &[String]) -> Result<String, String> {
    Err("`hxd emoji` needs a build with the `media` and `inbox` features".into())
}
