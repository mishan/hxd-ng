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
