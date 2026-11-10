//! Server emoji end to end: a real `[emoji]` config, its catalog in the
//! server's database, and `hxd emoji` run against that database beside
//! the server built from it, which serves an edit once it rereads
//! (SIGHUP).

use std::path::Path;
use std::sync::Arc;

use hxd_core::emoji::EmojiId;
use hxd_core::media::MediaType;

fn configured(dir: &Path, emoji: &str) -> hxd::Config {
    let d = dir.display();
    let path = dir.join("hxd-ng.toml");
    std::fs::write(
        &path,
        format!(
            "[paths]\naccounts = \"{d}/accounts\"\n[inbox]\ndb = \"{d}/hx.db\"\n\
             [emoji]\n{emoji}"
        ),
    )
    .unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    config
}

fn core(config: &hxd::Config) -> Arc<hxd_core::Core> {
    hxd::build_ctx(config, None, None, None, None).unwrap().core
}

fn emoji(config: &hxd::Config, args: &[&str]) -> Result<String, String> {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    hxd::emoji::command(config, &args)
}

fn png_file(dir: &Path, name: &str, w: u32, h: u32) -> String {
    let img = image::RgbaImage::from_fn(w, h, |x, y| image::Rgba([x as u8, y as u8, 0x80, 0xff]));
    saved(dir, name, image::DynamicImage::ImageRgba8(img))
}

/// Opaque pixels nothing compresses.
fn noise_png_file(dir: &Path, name: &str, side: u32) -> String {
    let mut state = 0x2545_f491u32;
    let img = image::RgbImage::from_fn(side, side, |_, _| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let [a, b, c, _] = state.to_le_bytes();
        image::Rgb([a, b, c])
    });
    saved(dir, name, image::DynamicImage::ImageRgb8(img))
}

fn saved(dir: &Path, name: &str, img: image::DynamicImage) -> String {
    let path = dir.join(name);
    img.save(&path).unwrap();
    path.display().to_string()
}

/// A looping GIF of `frames` solid frames, `w` by `h`.
fn gif_bytes(frames: u8, w: u32, h: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut enc = image::codecs::gif::GifEncoder::new(&mut out);
        enc.set_repeat(image::codecs::gif::Repeat::Infinite)
            .unwrap();
        for n in 0..frames {
            let frame =
                image::RgbaImage::from_pixel(w, h, image::Rgba([n.wrapping_mul(15), 0, 0, 255]));
            enc.encode_frame(image::Frame::new(frame)).unwrap();
        }
    }
    out
}

fn saved_bytes(dir: &Path, name: &str, bytes: &[u8]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path.display().to_string()
}

/// `gif` grown to exactly `len` bytes by a comment before its trailer:
/// a valid image whatever its size, and metadata the pipeline drops.
fn gif_of_len(gif: &[u8], len: usize) -> Vec<u8> {
    let (body, trailer) = gif.split_at(gif.len() - 1);
    // The extension's introducer, label and terminator, then sub-blocks
    // of a length byte and up to 255 bytes each.
    let mut left = len - gif.len() - 3;
    let mut comment = vec![0x21, 0xfe];
    while left > 0 {
        let n = match left {
            ..=256 => left - 1,
            // Never leave a single byte, which no sub-block can hold.
            257 => 254,
            _ => 255,
        };
        comment.push(n as u8);
        comment.extend(std::iter::repeat_n(b'.', n));
        left -= n + 1;
    }
    comment.push(0);
    [body, &comment, trailer].concat()
}

#[test]
fn hxd_emoji_edits_the_catalog_a_running_server_serves_once_it_rereads() {
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\n");
    let server = core(&config);
    assert_eq!(server.emoji_revision(), Some(0));
    let big = png_file(td.path(), "big.png", 300, 150);

    let said = emoji(&config, &["add", "party", &big]).unwrap();
    assert!(
        said.starts_with("added :party: as #1, a 128x64 PNG"),
        "{said}"
    );
    assert!(said.contains("SIGHUP"), "{said}");
    assert_eq!(server.emoji_image(EmojiId(1)), None, "not reread yet");
    assert_eq!(server.emoji_reload(), Ok(true));
    let image = server.emoji_image(EmojiId(1)).unwrap();
    assert_eq!(
        (image.mime, image.width, image.height, image.animated),
        (MediaType::Png, 128, 64, false)
    );
    let listed = emoji(&config, &["list"]).unwrap();
    assert!(listed.contains("#1 :party: 128x64 PNG"), "{listed}");

    emoji(&config, &["rename", "#1", "polly"]).unwrap();
    let said = emoji(&config, &["rename", "polly", "polly"]).unwrap();
    assert_eq!(said, "#1 is :polly: already");
    let said = emoji(&config, &["remove", "polly"]).unwrap();
    assert!(said.starts_with("removed :polly: (#1)"), "{said}");
    assert_eq!(emoji(&config, &["list"]).unwrap(), "no emoji");
    let listed = emoji(&config, &["list", "--removed"]).unwrap();
    assert_eq!(listed, "#1 :polly: removed");
    server.emoji_reload().unwrap();
    assert_eq!(server.emoji_image(EmojiId(1)), None);

    let said = emoji(&config, &["add", "polly", &big]).unwrap();
    assert!(
        said.starts_with("added :polly: as #2"),
        "an id never given again: {said}"
    );
    server.emoji_reload().unwrap();
    let revision = server.emoji_revision();
    drop(server);

    let restarted = core(&config);
    assert_eq!(restarted.emoji_revision(), revision);
    assert!(restarted.emoji_image(EmojiId(2)).is_some());
    let listed = restarted.emoji_list(None, None, 10).unwrap();
    let names: Vec<(u32, &str, bool)> = listed
        .entries
        .iter()
        .map(|e| (e.id.0, e.name.as_str(), e.image.is_some()))
        .collect();
    assert_eq!(names, [(1, "polly", false), (2, "polly", true)]);
}

#[test]
fn hxd_emoji_says_why_it_changed_nothing() {
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\nmax_count = 1\n");
    let image = png_file(td.path(), "party.png", 32, 32);
    let image = image.as_str();
    let text = td.path().join("notes.png");
    std::fs::write(&text, "not an image at all ".repeat(8)).unwrap();
    let text = text.display().to_string();
    let text = text.as_str();
    emoji(&config, &["add", "party", image]).unwrap();
    for (args, why) in [
        (vec!["add", "party", image], "already"),
        (vec!["add", "other", image], "max_count"),
        (vec!["add", "other", "missing.png"], "missing.png"),
        (vec!["rename", "#9", "other"], "no emoji #9"),
        (vec!["remove", "nobody"], "no emoji :nobody:"),
        (vec!["list", "--frobnicate"], "unknown argument"),
        (vec!["frobnicate"], "usage"),
    ] {
        let refused = emoji(&config, &args).unwrap_err();
        assert!(refused.contains(why), "{args:?}: {refused}");
    }
    emoji(&config, &["remove", "party"]).unwrap();
    for (args, why) in [
        (vec!["remove", "#1"], "no emoji #1"),
        (vec!["remove", "party"], "no emoji :party:"),
        (vec!["rename", "party", "other"], "no emoji :party:"),
    ] {
        let refused = emoji(&config, &args).unwrap_err();
        assert!(
            refused.contains(why),
            "a removed entry, {args:?}: {refused}"
        );
    }
    let refused = emoji(&config, &["add", "other", text]).unwrap_err();
    assert!(refused.contains("not an image"), "{refused}");
    assert_eq!(emoji(&config, &["list"]).unwrap(), "no emoji");

    let fresh = tempfile::tempdir().unwrap();
    let unstarted = configured(fresh.path(), "enabled = true\n");
    let refused = emoji(&unstarted, &["list"]).unwrap_err();
    assert!(refused.contains("no database yet"), "{refused}");
    assert!(!fresh.path().join("hx.db").exists());
    emoji(&unstarted, &["add", "party", image]).expect("set up before the first start");
    assert!(core(&unstarted).emoji_image(EmojiId(1)).is_some());

    let bare = td.path().join("bare.toml");
    std::fs::write(&bare, "[emoji]\n").unwrap();
    let bare = hxd::Config::load(&bare).unwrap();
    let refused = emoji(&bare, &["list"]).unwrap_err();
    assert!(refused.contains("needs a database"), "{refused}");
}

#[test]
fn a_catalog_turned_off_is_not_served() {
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = false\n");
    assert_eq!(core(&config).emoji_policy(), None);
}

/// What `list` says of each entry, live and removed.
fn listed(config: &hxd::Config) -> Vec<String> {
    let said = emoji(config, &["list", "--removed"]).unwrap();
    match said.as_str() {
        "no emoji" => vec![],
        _ => said
            .lines()
            .map(|l| l.split(' ').take(3).collect::<Vec<_>>().join(" "))
            .collect(),
    }
}

#[test]
fn a_name_is_lowercase_letters_digits_and_underscores_and_live_ones_are_unique() {
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\n");
    let image = png_file(td.path(), "party.png", 32, 32);
    let image = image.as_str();
    for good in ["zz", "a_1", "42"] {
        emoji(&config, &["add", good, image]).unwrap();
    }
    let all = ["#1 :zz: 32x32", "#2 :a_1: 32x32", "#3 :42: 32x32"];
    assert_eq!(listed(&config), all);
    // The rules are `EmojiName`'s; enough to show both verbs hold to them.
    for bad in ["Party", "a", "par-ty"] {
        for args in [vec!["add", bad, image], vec!["rename", "#1", bad]] {
            let refused = emoji(&config, &args).unwrap_err();
            assert!(refused.contains("names are"), "{args:?}: {refused}");
        }
    }
    for args in [vec!["add", "zz", image], vec!["rename", "a_1", "zz"]] {
        let refused = emoji(&config, &args).unwrap_err();
        assert!(refused.contains("already"), "{args:?}: {refused}");
    }
    assert_eq!(listed(&config), all, "nothing refused changed anything");
    emoji(&config, &["remove", "zz"]).unwrap();
    emoji(&config, &["rename", "a_1", "zz"]).expect("a removed entry's name is free");
    emoji(&config, &["add", "a_1", image]).expect("and a renamed one's");
    assert_eq!(
        listed(&config),
        [
            "#1 :zz: removed",
            "#2 :zz: 32x32",
            "#3 :42: 32x32",
            "#4 :a_1: 32x32"
        ]
    );
}

#[test]
fn an_id_is_written_with_its_hash_mark_and_anything_else_is_a_name() {
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\n");
    let image = png_file(td.path(), "party.png", 32, 32);
    emoji(&config, &["add", "party", &image]).unwrap();
    emoji(&config, &["add", "42", &image]).unwrap();
    for (args, why) in [
        (vec!["remove", "1"], "no emoji :1:"),
        (vec!["rename", "2", "other"], "no emoji :2:"),
        (vec!["remove", "#x"], "is not an emoji id"),
        (vec!["remove", "#"], "is not an emoji id"),
        (vec!["remove", "#42"], "no emoji #42"),
    ] {
        let refused = emoji(&config, &args).unwrap_err();
        assert!(refused.contains(why), "{args:?}: {refused}");
    }
    emoji(&config, &["remove", "42"]).unwrap();
    emoji(&config, &["rename", "#1", "hooray"]).unwrap();
    assert_eq!(listed(&config), ["#1 :hooray: 32x32", "#2 :42: removed"]);
}

#[test]
fn every_edit_spends_one_revision_and_a_delta_names_exactly_what_changed() {
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\n");
    let server = core(&config);
    let image = png_file(td.path(), "party.png", 32, 32);
    let image = image.as_str();
    for (args, done, revision) in [
        (vec!["add", "aa", image], true, 1),
        (vec!["add", "bb", image], true, 2),
        (vec!["rename", "aa", "cc"], true, 3),
        (vec!["rename", "cc", "cc"], true, 3),
        (vec!["add", "cc", image], false, 3),
        (vec!["list"], true, 3),
        (vec!["remove", "bb"], true, 4),
        (vec!["remove", "bb"], false, 4),
    ] {
        assert_eq!(emoji(&config, &args).is_ok(), done, "{args:?}");
        server.emoji_reload().unwrap();
        assert_eq!(server.emoji_revision(), Some(revision), "after {args:?}");
    }
    let changed = |since| {
        let listing = server.emoji_list(Some(since), None, 10).unwrap();
        assert!(listing.delta, "from {since}");
        listing
            .entries
            .iter()
            .map(|e| (e.id.0, e.name.to_string(), e.image.is_some()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        changed(1),
        [(1, "cc".to_string(), true), (2, "bb".into(), false)]
    );
    assert_eq!(changed(3), [(2, "bb".to_string(), false)]);
    assert!(changed(4).is_empty());
}

#[test]
fn a_removed_emoji_is_served_by_neither_id_nor_hash() {
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\n");
    let server = core(&config);
    let image = png_file(td.path(), "party.png", 32, 32);
    emoji(&config, &["add", "party", &image]).unwrap();
    emoji(&config, &["add", "other", &image]).unwrap();
    server.emoji_reload().unwrap();
    let party = server.emoji_image(EmojiId(1)).unwrap();
    assert_eq!(
        server.emoji_image(EmojiId(2)).unwrap().hash,
        party.hash,
        "one picture"
    );
    emoji(&config, &["remove", "party"]).unwrap();
    server.emoji_reload().unwrap();
    assert_eq!(server.emoji_image(EmojiId(1)), None);
    assert!(server.emoji_image(EmojiId(2)).is_some());
    assert!(
        server.emoji_by_hash(&party.hash).is_some(),
        "still another entry's picture"
    );
    emoji(&config, &["remove", "other"]).unwrap();
    server.emoji_reload().unwrap();
    assert_eq!(server.emoji_image(EmojiId(2)), None);
    assert_eq!(server.emoji_by_hash(&party.hash), None);
    let kept = server.emoji_list(None, None, 10).unwrap();
    assert!(kept.entries.iter().all(|e| e.image.is_none()));
    assert_eq!(kept.entries.len(), 2, "their ids and names kept");
}

#[test]
fn removed_entries_past_max_count_are_forgotten_oldest_first() {
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\nmax_count = 1\n");
    let server = core(&config);
    let image = png_file(td.path(), "party.png", 32, 32);
    for name in ["aa", "bb"] {
        emoji(&config, &["add", name, &image]).unwrap();
        emoji(&config, &["remove", name]).unwrap();
    }
    assert_eq!(listed(&config), ["#2 :bb: removed"]);
    server.emoji_reload().unwrap();
    let listing = server.emoji_list(Some(1), None, 10).unwrap();
    assert!(
        !listing.delta,
        "a client from before the forgetting is told all"
    );
}

#[test]
fn what_add_makes_follows_the_config_and_the_source() {
    let td = tempfile::tempdir().unwrap();
    let config = configured(
        td.path(),
        "enabled = true\nmax_dimension = 64\nmax_bytes = 3000\nmax_frames = 16\n",
    );
    let wide = png_file(td.path(), "wide.png", 300, 150);
    // Already within max_dimension, so too noisy for max_bytes until
    // it is shrunk.
    let noisy = noise_png_file(td.path(), "noisy.png", 64);
    let animated = saved_bytes(td.path(), "animated.gif", &gif_bytes(2, 100, 50));
    for (name, file, said) in [
        ("wide", &wide, "64x32 PNG"),
        ("noisy", &noisy, "27x27 PNG"),
        ("animated", &animated, "64x32 animated GIF"),
    ] {
        let added = emoji(&config, &["add", name, file]).unwrap();
        assert!(added.contains(&format!(", a {said} of ")), "{added}");
    }
    let listing = emoji(&config, &["list"]).unwrap();
    assert!(
        listing.contains(":animated: 64x32 animated GIF"),
        "{listing}"
    );
    let long = saved_bytes(td.path(), "long.gif", &gif_bytes(17, 16, 16));
    let refused = emoji(&config, &["add", "long", &long]).unwrap_err();
    assert!(refused.contains("max_frames = 16"), "{refused}");
}

#[test]
fn a_source_is_read_up_to_2_mib_and_no_further() {
    const LIMIT: usize = 2 << 20;
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\n");
    let gif = gif_bytes(1, 16, 16);
    let at = saved_bytes(td.path(), "at.gif", &gif_of_len(&gif, LIMIT));
    let past = saved_bytes(td.path(), "past.gif", &gif_of_len(&gif, LIMIT + 1));
    emoji(&config, &["add", "at", &at]).expect("at the limit");
    let refused = emoji(&config, &["add", "past", &past]).unwrap_err();
    assert!(refused.contains("too small or too large"), "{refused}");
}

#[test]
fn the_command_line_waits_out_another_writer() {
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\n");
    let server = core(&config);
    let image = png_file(td.path(), "party.png", 32, 32);
    // A running server mid-write: the file's write lock, held a while.
    let other = rusqlite::Connection::open(td.path().join("hx.db")).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    std::thread::scope(|s| {
        let adding = s.spawn(|| emoji(&config, &["add", "party", &image]));
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!adding.is_finished(), "it waits for the lock");
        other.execute_batch("COMMIT").unwrap();
        adding
            .join()
            .unwrap()
            .expect("written once the other writer is done");
    });
    server.emoji_reload().unwrap();
    assert!(server.emoji_image(EmojiId(1)).is_some());
}

#[test]
#[cfg(unix)]
fn a_source_without_an_end_is_read_only_so_far() {
    use std::io::Write;
    const LIMIT: usize = 2 << 20;
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\n");
    let fifo = td.path().join("endless.png");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let writing = fifo.clone();
    let (done, sent) = std::sync::mpsc::channel();
    // Writes until the reader goes, or well past the limit.
    std::thread::spawn(move || {
        let mut pipe = std::fs::OpenOptions::new()
            .write(true)
            .open(writing)
            .unwrap();
        let chunk = [0u8; 64 << 10];
        let mut sent = 0;
        while sent < 4 * LIMIT && pipe.write_all(&chunk).is_ok() {
            sent += chunk.len();
        }
        done.send(sent).unwrap();
    });
    let refused = emoji(&config, &["add", "party", fifo.to_str().unwrap()]).unwrap_err();
    assert!(refused.contains("too small or too large"), "{refused}");
    let sent = sent
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("the command never opened the pipe");
    assert!(sent < 4 * LIMIT, "read to the writer's end");
    assert!(listed(&config).is_empty());
}

/// The binary itself, killed when the test ends however it ends.
#[cfg(unix)]
struct Binary(std::process::Child);

#[cfg(unix)]
impl Drop for Binary {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The binary on the config in the working directory, logging what an
/// operator's would whatever the test's environment asks.
fn binary() -> std::process::Command {
    let mut hxd = std::process::Command::new(env!("CARGO_BIN_EXE_hxd"));
    hxd.args(["--config", "hxd-ng.toml"])
        .env_remove("RUST_LOG")
        .env_remove("HXD_DEBUG");
    hxd
}

/// `hxd` with `args` beside the config in `dir`: its output, or its error.
fn hxd(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = binary().args(args).current_dir(dir).output().unwrap();
    let said = String::from_utf8_lossy(&out.stdout).trim().to_string();
    match out.status.success() {
        true => Ok(said),
        false => Err(String::from_utf8_lossy(&out.stderr).into_owned()),
    }
}

/// Wait for `log` to say `line`; the log so far if the server exits
/// first.
#[cfg(unix)]
fn said(server: &mut Binary, log: &Path, line: &str) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let said = std::fs::read_to_string(log).unwrap_or_default();
        if said.contains(line) {
            return Ok(());
        }
        if server.0.try_wait().unwrap().is_some() {
            return Err(said);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "never said {line:?}:\n{said}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn a_flag_of_another_command_is_refused_before_emoji() {
    let td = tempfile::tempdir().unwrap();
    let refused = hxd(td.path(), &["--dry-run", "emoji", "list"]).unwrap_err();
    assert!(refused.contains("--dry-run belong"), "{refused}");
}

#[test]
#[cfg(unix)]
fn sighup_has_the_running_binary_reread_what_hxd_emoji_wrote() {
    let td = tempfile::tempdir().unwrap();
    let dir = td.path();
    let log = dir.join("hxd.log");
    // The port is free when picked and bound by the server a moment
    // later, so it is picked again, once, if something took it between.
    let mut server = None;
    for _ in 0..2 {
        let ng = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        std::fs::write(
            dir.join("hxd-ng.toml"),
            format!(
                "[server]\nclassic = false\n[ng]\nbind = \"{ng}\"\n\
                 [paths]\naccounts = \"accounts\"\n[inbox]\ndb = \"hx.db\"\n\
                 [emoji]\nenabled = true\n"
            ),
        )
        .unwrap();
        let out = std::fs::File::create(&log).unwrap();
        let mut started = Binary(
            binary()
                .current_dir(dir)
                .stdout(out.try_clone().unwrap())
                .stderr(out)
                .spawn()
                .unwrap(),
        );
        // Listening, so its SIGHUP handler is installed: it is, before
        // anything binds.
        match said(&mut started, &log, "hotline-ng WebSocket on") {
            Ok(()) => {
                server = Some(started);
                break;
            }
            Err(log) => assert!(log.contains("ng bind"), "hxd exited:\n{log}"),
        }
    }
    let mut server = server.expect("the ng port was taken twice");
    let pid = server.0.id().to_string();
    let hangup = || {
        assert!(std::process::Command::new("kill")
            .args(["-HUP", &pid])
            .status()
            .unwrap()
            .success());
    };

    let image = png_file(dir, "party.png", 32, 32);
    let added = hxd(dir, &["emoji", "add", "party", &image]).unwrap();
    assert!(added.starts_with("added :party: as #1"), "{added}");
    for line in [
        "SIGHUP: emoji catalog now at revision 1",
        "SIGHUP: emoji catalog unchanged at revision 1",
    ] {
        hangup();
        said(&mut server, &log, line).unwrap_or_else(|log| panic!("hxd exited:\n{log}"));
    }
}

#[test]
fn a_common_emojis_shortcode_is_given_to_no_entry() {
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\n");
    let image = png_file(td.path(), "party.png", 32, 32);
    let image = image.as_str();
    emoji(&config, &["add", "party", image]).unwrap();
    for (name, why) in [
        ("thumbsup", "a common emoji's shortcode"),
        ("joy", "a common emoji's shortcode"),
        ("+1", "names are"),
    ] {
        for args in [vec!["add", name, image], vec!["rename", "party", name]] {
            let refused = emoji(&config, &args).unwrap_err();
            assert!(refused.contains(why), "{args:?}: {refused}");
        }
    }
    emoji(&config, &["add", "thumbsup2", image]).expect("a near miss is a name");
    emoji(&config, &["rename", "party", "joy_"]).expect("and so is this one");
    assert_eq!(listed(&config), ["#1 :joy_: 32x32", "#2 :thumbsup2: 32x32"]);
}

#[test]
fn an_entry_named_before_the_list_had_its_name_still_loads_and_serves() {
    use sha2::Digest;
    let td = tempfile::tempdir().unwrap();
    let config = configured(td.path(), "enabled = true\n");
    drop(core(&config));
    // As an older server, whose list lacked the name, would have kept it.
    let bytes = std::fs::read(png_file(td.path(), "joy.png", 32, 32)).unwrap();
    let hash: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    let db = rusqlite::Connection::open(td.path().join("hx.db")).unwrap();
    db.execute(
        "INSERT INTO emoji (name, revision, hash, mime, width, height, animated, bytes, added_at)
         VALUES ('joy', 1, ?1, 'image/png', 32, 32, 0, ?2, 0)",
        rusqlite::params![&hash[..], &bytes],
    )
    .unwrap();
    db.execute("UPDATE emoji_meta SET revision = 1", [])
        .unwrap();
    drop(db);

    let server = core(&config);
    assert_eq!(server.emoji_image(EmojiId(1)).unwrap().hash, hash);
    assert_eq!(server.emoji_by_hash(&hash).unwrap().hash, hash);
    assert_eq!(server.emoji_reload(), Ok(false));
    assert!(server.emoji_image(EmojiId(1)).is_some());
    assert_eq!(listed(&config), ["#1 :joy: 32x32"]);
    assert_eq!(
        emoji(&config, &["rename", "joy", "joy"]),
        Ok("#1 is :joy: already".into()),
        "it keeps its name"
    );
    emoji(&config, &["rename", "joy", "joyful"]).expect("found by its name");
    let refused = emoji(&config, &["rename", "joyful", "joy"]).unwrap_err();
    assert!(refused.contains("a common emoji's shortcode"), "{refused}");
}
