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
    use image::ImageEncoder;
    let img = image::RgbaImage::from_fn(w, h, |x, y| image::Rgba([x as u8, y as u8, 0x80, 0xff]));
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(&mut out)
        .write_image(&img, w, h, image::ExtendedColorType::Rgba8)
        .unwrap();
    let path = dir.join(name);
    std::fs::write(&path, out).unwrap();
    path.display().to_string()
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

    emoji(&config, &["rename", "#1", "parrot"]).unwrap();
    let said = emoji(&config, &["rename", "parrot", "parrot"]).unwrap();
    assert_eq!(said, "#1 is :parrot: already");
    let said = emoji(&config, &["remove", "parrot"]).unwrap();
    assert!(said.starts_with("removed :parrot: (#1)"), "{said}");
    assert_eq!(emoji(&config, &["list"]).unwrap(), "no emoji");
    let listed = emoji(&config, &["list", "--removed"]).unwrap();
    assert_eq!(listed, "#1 :parrot: removed");
    server.emoji_reload().unwrap();
    assert_eq!(server.emoji_image(EmojiId(1)), None);

    let said = emoji(&config, &["add", "parrot", &big]).unwrap();
    assert!(
        said.starts_with("added :parrot: as #2"),
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
    assert_eq!(names, [(1, "parrot", false), (2, "parrot", true)]);
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
        (vec!["add", "Party", image], "names are"),
        (vec!["add", "party", image], "already"),
        (vec!["add", "other", image], "max_count"),
        (vec!["add", "other", "missing.png"], "missing.png"),
        (vec!["rename", "#9", "other"], "no emoji #9"),
        (vec!["rename", "party", "x"], "names are"),
        (vec!["remove", "nobody"], "no emoji :nobody:"),
        (vec!["list", "--frobnicate"], "unknown argument"),
        (vec!["frobnicate"], "usage"),
    ] {
        let refused = emoji(&config, &args).unwrap_err();
        assert!(refused.contains(why), "{args:?}: {refused}");
    }
    emoji(&config, &["remove", "party"]).unwrap();
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
