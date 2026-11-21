//! `hlid init` and the default directory, exercised through the real
//! binary rather than through its internals. What is being checked is a
//! promise made to a *command line* — that hx-ng's identity panel can
//! print `hlid cert --device-pub … --device-enc-pub …` with no `--identity`
//! and have it work — so the test says it the same way a user would.

use std::path::Path;
use std::process::{Command, Output};

fn hlid(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hlid"))
        .env("HLID_HOME", home)
        .args(args)
        .output()
        .expect("hlid did not start")
}

fn ok(home: &Path, args: &[&str]) -> String {
    let out = hlid(home, args);
    assert!(
        out.status.success(),
        "hlid {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fails(home: &Path, args: &[&str]) -> String {
    let out = hlid(home, args);
    assert!(
        !out.status.success(),
        "hlid {args:?} unexpectedly succeeded"
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

const DEVICE_PUB: &str = "aa";
const DEVICE_ENC_PUB: &str = "bb";

fn key_hex(byte: &str) -> String {
    byte.repeat(32)
}

#[test]
fn init_writes_a_whole_identity_and_the_flags_then_fall_back_to_it() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("hlid"); // not pre-created: init makes it
    let stdout = ok(&home, &["init", "--name", "alice"]);
    assert!(stdout.contains("alice"), "{stdout}");

    for f in ["identity.key", "device.key", "cert.bin", "card.bin"] {
        assert!(home.join(f).exists(), "init did not write {f}");
    }

    // The private keys are the user's alone; the certificate and card are
    // public material and are not held to that.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["identity.key", "device.key"] {
            let mode = std::fs::metadata(home.join(f))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "{f} is readable by someone else");
        }
        let mode = std::fs::metadata(&home).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "the directory is readable by someone else");
    }

    // The command hx-ng's panel prints: no --identity, because the
    // browser has no way to know where this machine keeps it.
    let cert = dir.path().join("web.cert");
    ok(
        &home,
        &[
            "cert",
            "--device-pub",
            &key_hex(DEVICE_PUB),
            "--device-enc-pub",
            &key_hex(DEVICE_ENC_PUB),
            "--caps",
            "web",
            "-o",
            cert.to_str().unwrap(),
        ],
    );
    let inspected = ok(&home, &["inspect", cert.to_str().unwrap()]);
    assert!(inspected.contains(&key_hex(DEVICE_PUB)), "{inspected}");
    assert!(inspected.contains("\"caps\": 3"), "{inspected}");

    // The certificate init wrote names the device key it wrote beside it.
    let own = ok(&home, &["inspect", home.join("cert.bin").to_str().unwrap()]);
    assert!(own.contains("\"type\": \"device_cert\""), "{own}");
    let card = ok(&home, &["inspect", home.join("card.bin").to_str().unwrap()]);
    assert!(card.contains("alice"), "{card}");
}

#[test]
fn init_refuses_to_write_over_an_identity_that_is_already_there() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init", "--name", "alice"]);
    let err = fails(dir.path(), &["init", "--name", "bob"]);
    assert!(err.contains("already exists"), "{err}");

    // And the first identity is untouched, rather than half replaced.
    let card = ok(
        dir.path(),
        &["inspect", dir.path().join("card.bin").to_str().unwrap()],
    );
    assert!(card.contains("alice") && !card.contains("bob"), "{card}");
}

#[test]
fn a_missing_default_names_both_the_flag_and_the_file_it_looked_for() {
    let dir = tempfile::tempdir().unwrap();
    // An empty directory, so there is nothing to fall back to.
    let err = fails(dir.path(), &["card", "--name", "alice", "-o", "/dev/null"]);
    assert!(err.contains("--identity"), "{err}");
    assert!(err.contains("identity.key"), "{err}");
    assert!(err.contains("hlid init"), "{err}");

    // A *directory* where the key should be is not a key to fall back
    // to. Taking it would swap this message for "Is a directory" from
    // the read, one layer further from the cause.
    std::fs::create_dir(dir.path().join("identity.key")).unwrap();
    let err = fails(dir.path(), &["card", "--name", "alice", "-o", "/dev/null"]);
    assert!(err.contains("--identity"), "{err}");
    assert!(!err.contains("Is a directory"), "{err}");
}

#[test]
fn with_no_home_at_all_the_error_is_about_the_home_and_not_the_file() {
    // Neither $HLID_HOME nor $HOME. There is no directory to name, so a
    // message shaped "there is no identity.key in <the reason there is
    // no directory>" is nonsense; it should say the one true thing.
    let out = Command::new(env!("CARGO_BIN_EXE_hlid"))
        .env_remove("HLID_HOME")
        .env_remove("HOME")
        .args(["card", "--name", "alice", "-o", "/dev/null"])
        .output()
        .expect("hlid did not start");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("HLID_HOME"), "{err}");
    assert!(
        !err.contains("there is no identity.key in neither"),
        "one error spliced into another: {err}"
    );
}

#[test]
fn the_public_key_form_never_falls_back_to_this_machines_own_device() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init", "--name", "alice"]);

    // Half of the pair is a mistake, not a request to certify whatever
    // device key happens to be lying around: a certificate for the wrong
    // device is one the browser rejects with nothing useful to say.
    let err = fails(
        dir.path(),
        &[
            "cert",
            "--device-pub",
            &key_hex(DEVICE_PUB),
            "-o",
            "/dev/null",
        ],
    );
    assert!(err.contains("--device-enc-pub"), "{err}");

    // And naming both forms at once stays an error rather than one
    // quietly winning.
    let err = fails(
        dir.path(),
        &[
            "cert",
            "--device",
            dir.path().join("device.key").to_str().unwrap(),
            "--device-pub",
            &key_hex(DEVICE_PUB),
            "--device-enc-pub",
            &key_hex(DEVICE_ENC_PUB),
            "-o",
            "/dev/null",
        ],
    );
    assert!(err.contains("alternatives"), "{err}");
}

#[test]
fn bundle_writes_the_certificate_and_card_as_one_thing_to_paste() {
    let dir = tempfile::tempdir().unwrap();
    ok(dir.path(), &["init", "--name", "alice"]);

    let out = dir.path().join("web.bundle");
    ok(
        dir.path(),
        &[
            "cert",
            "--device-pub",
            &key_hex(DEVICE_PUB),
            "--device-enc-pub",
            &key_hex(DEVICE_ENC_PUB),
            "--caps",
            "web",
            "--bundle",
            "-o",
            out.to_str().unwrap(),
        ],
    );

    // `inspect` reads it back as a bundle rather than as an unknown
    // object, which is the whole of what a user can check by hand.
    let seen = ok(dir.path(), &["inspect", out.to_str().unwrap()]);
    assert!(seen.contains("\"type\": \"bundle\""), "{seen}");
    assert!(seen.contains("\"ok\": true"), "{seen}");
    assert!(seen.contains("alice"), "{seen}");
    assert!(seen.contains(&key_hex(DEVICE_PUB)), "{seen}");

    // Without the flag it is still a bare certificate — the paste path
    // that exists today does not change under anyone.
    let plain = dir.path().join("web.cert");
    ok(
        dir.path(),
        &[
            "cert",
            "--device-pub",
            &key_hex(DEVICE_PUB),
            "--device-enc-pub",
            &key_hex(DEVICE_ENC_PUB),
            "-o",
            plain.to_str().unwrap(),
        ],
    );
    let seen = ok(dir.path(), &["inspect", plain.to_str().unwrap()]);
    assert!(seen.contains("\"type\": \"device_cert\""), "{seen}");
}

#[test]
fn a_bundle_will_not_be_built_from_someone_elses_card() {
    let alice = tempfile::tempdir().unwrap();
    let mallory = tempfile::tempdir().unwrap();
    ok(alice.path(), &["init", "--name", "alice"]);
    ok(mallory.path(), &["init", "--name", "mallory"]);

    // Both halves are real and both signatures verify; only the pairing
    // is a lie, which is exactly the case a browser cannot diagnose and
    // would report as a bad paste.
    let err = fails(
        alice.path(),
        &[
            "cert",
            "--device-pub",
            &key_hex(DEVICE_PUB),
            "--device-enc-pub",
            &key_hex(DEVICE_ENC_PUB),
            "--bundle",
            "--card",
            mallory.path().join("card.bin").to_str().unwrap(),
            "-o",
            "/dev/null",
        ],
    );
    assert!(err.contains("card of"), "{err}");
}

#[test]
fn a_certificate_is_minted_at_the_kept_epoch_and_a_long_one_is_warned_of() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("hlid");
    ok(&home, &["init", "--name", "alice"]);
    let seed = std::fs::read_to_string(home.join("identity.key")).unwrap();
    let seed: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&seed.trim()[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    let id = hl_identity::IdentityKey::from_seed(&seed.try_into().unwrap());
    let kept = format!("{{\"{}\": {{\"epoch\": 7}}}}", id.fingerprint());
    std::fs::write(home.join("holder.json"), kept).unwrap();

    let cert = dir.path().join("web.cert");
    let mint = |name: &str| {
        hlid(
            &home,
            &[
                "cert",
                "--device-pub",
                &key_hex(DEVICE_PUB),
                "--device-enc-pub",
                &key_hex(DEVICE_ENC_PUB),
                "--name",
                name,
                "--caps",
                "web",
                "--days",
                "36500",
                "-o",
                cert.to_str().unwrap(),
            ],
        )
    };
    let out = mint("laptop");
    assert!(out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("past the"));
    let c = hl_identity::DeviceCert::parse(&std::fs::read(&cert).unwrap()).unwrap();
    assert_eq!(c.epoch, 7);

    // The longest name there is, at the highest epoch there is, for as
    // long as there is.
    let kept = format!("{{\"{}\": {{\"epoch\": {}}}}}", id.fingerprint(), i64::MAX);
    std::fs::write(home.join("holder.json"), kept).unwrap();
    let out = mint(&"\u{1d538}".repeat(64));
    assert!(out.status.success());
    assert!(std::fs::read(&cert).unwrap().len() > 512);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("past the 512"), "{err}");
}

#[cfg(unix)]
#[test]
fn a_mint_waits_for_whoever_holds_the_holders_lock() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("hlid");
    ok(&home, &["init", "--name", "alice"]);
    let lock = std::fs::File::create(home.join("holder.lock")).unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
    let cert = dir.path().join("web.cert");
    let mut child = Command::new(env!("CARGO_BIN_EXE_hlid"))
        .env("HLID_HOME", &home)
        .args([
            "cert",
            "--device-pub",
            &key_hex(DEVICE_PUB),
            "--device-enc-pub",
        ])
        .args([&key_hex(DEVICE_ENC_PUB), "-o", cert.to_str().unwrap()])
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Unlocked once the child says it is waiting, and not before.
    let mut stderr = std::io::BufReader::new(child.stderr.take().unwrap());
    let (tx, waiting) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        use std::io::BufRead;
        let mut line = String::new();
        while stderr.read_line(&mut line).unwrap_or(0) > 0 {
            if line.contains("waiting for another hlid") {
                let _ = tx.send(());
            }
            line.clear();
        }
    });
    waiting
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("the mint did not wait for the lock");
    assert!(!cert.exists(), "minted under another's lock");
    drop(lock);
    assert!(child.wait().unwrap().success());
    reader.join().unwrap();
    assert!(cert.is_file());
}

#[test]
fn a_certificate_is_minted_with_explicit_paths_and_no_home() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("hlid");
    ok(&home, &["init", "--name", "alice"]);
    let cert = dir.path().join("web.cert");
    let out = Command::new(env!("CARGO_BIN_EXE_hlid"))
        .env_remove("HLID_HOME")
        .env_remove("HOME")
        .args([
            "cert",
            "--identity",
            home.join("identity.key").to_str().unwrap(),
        ])
        .args(["--device-pub", &key_hex(DEVICE_PUB), "--device-enc-pub"])
        .args([&key_hex(DEVICE_ENC_PUB), "-o", cert.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        hl_identity::DeviceCert::parse(&std::fs::read(&cert).unwrap())
            .unwrap()
            .epoch,
        0
    );
}

#[test]
fn devices_renew_renews_this_machines_certificate_at_the_kept_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("hlid");
    ok(&home, &["init", "--name", "alice"]);
    let before =
        hl_identity::DeviceCert::parse(&std::fs::read(home.join("cert.bin")).unwrap()).unwrap();
    let kept = format!(
        "{{\"{}\": {{\"epoch\": 3}}}}",
        hl_identity::Fingerprint::of(&before.identity)
    );
    std::fs::write(home.join("holder.json"), kept).unwrap();
    ok(&home, &["devices", "renew"]);
    let after =
        hl_identity::DeviceCert::parse(&std::fs::read(home.join("cert.bin")).unwrap()).unwrap();
    assert_eq!((after.epoch, after.device), (3, before.device));
}
