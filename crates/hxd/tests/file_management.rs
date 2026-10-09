//! File management on both wires against one local file area: New
//! Folder, Delete, rename, Move and comments, each kind of entry under
//! its own access bit, drop boxes out of reach, and a change made on one
//! wire seen on the other.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::{Core, FilePath, FileSource};
use hxd_files::{
    DownloadTokens, EntryLimits, FileService, LocalFileSource, LocalLimits, TransferRegistry,
};
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::{Caps, ServerConfig, ServerCtx};
use hxd_testclient::legacy::{self, Login};
use hxd_testclient::{ng, Error};
use hxproto::messages::tag;
use serde_json::{json, Value};
use tokio::net::TcpListener;

const FILE_LIST: u32 = 0x00c8;
const FILE_GET: u32 = 0x00ca;
const FILE_DELETE: u32 = 0x00cc;
const FILE_MKDIR: u32 = 0x00cd;
const FILE_GET_INFO: u32 = 0x00ce;
const FILE_SET_INFO: u32 = 0x00cf;
const FILE_MOVE: u32 = 0x00d0;
const MAKE_ALIAS: u32 = 0x00d1;
const LIST_ENTRY: u16 = 0x00c8;

const ALL: &str = "create_folders = true\ndelete_files = true\ndelete_folders = true\n\
    rename_files = true\nrename_folders = true\nmove_files = true\nmove_folders = true\n\
    comment_files = true\ncomment_folders = true\nview_drop_boxes = true\n\
    make_aliases = true\n";

/// The accounts every server here has: `admin` may do everything,
/// `keeper` everything but view drop boxes, `filer` everything to files,
/// downloading included, and nothing to folders but make them, `renamer`
/// only rename files, `mover` only move them, and `guest` nothing at all.
const ACCOUNTS: &[(&str, &str)] = &[
    ("admin", ALL),
    (
        "keeper",
        "create_folders = true\ndelete_files = true\ndelete_folders = true\n\
         rename_files = true\nrename_folders = true\nmove_files = true\n\
         move_folders = true\ncomment_files = true\ncomment_folders = true\n",
    ),
    (
        "filer",
        "create_folders = true\ndelete_files = true\nrename_files = true\n\
         move_files = true\ncomment_files = true\ndownload_files = true\n",
    ),
    ("renamer", "rename_files = true\n"),
    ("mover", "move_files = true\n"),
];

struct Running {
    legacy: SocketAddr,
    ng: SocketAddr,
    root: tempfile::TempDir,
    source: Arc<LocalFileSource>,
    _accounts: tempfile::TempDir,
}

impl Running {
    fn path(&self, relative: &str) -> std::path::PathBuf {
        self.root.path().join(relative)
    }

    async fn comment(&self, path: &str) -> Option<String> {
        self.source
            .info(&FilePath::parse(path).unwrap())
            .await
            .unwrap()
            .comment
    }
}

async fn start() -> Running {
    start_with(true).await
}

async fn start_with(writable: bool) -> Running {
    let root = tempfile::tempdir().unwrap();
    let deepest = LocalLimits {
        max_depth: 64,
        ..LocalLimits::default()
    };
    let source = Arc::new(LocalFileSource::open(root.path(), deepest).unwrap());
    let limits = EntryLimits {
        total: 64,
        per_session: 16,
        per_account: 64,
    };
    let service = Arc::new(FileService::new(
        source.clone(),
        writable.then(|| source.clone()),
        Arc::new(TransferRegistry::new(Duration::from_secs(30), limits)),
        Arc::new(DownloadTokens::new(Duration::from_secs(30), limits)),
        Duration::from_secs(5),
    ));

    let accounts = tempfile::tempdir().unwrap();
    std::fs::write(
        accounts.path().join("guest.toml"),
        "name = \"guest\"\n[access]\nread_chat = true\n",
    )
    .unwrap();
    for (login, access) in ACCOUNTS {
        std::fs::write(
            accounts.path().join(format!("{login}.toml")),
            format!("password = \"pw\"\n[access]\nread_chat = true\n{access}"),
        )
        .unwrap();
    }
    let core = Arc::new(Core::new());
    let auth: Arc<dyn hxd_core::AuthBackend> =
        Arc::new(hxd_auth_file::FileAuth::new(accounts.path()));
    let legacy_ctx = ServerCtx {
        core: core.clone(),
        auth: auth.clone(),
        cfg: Arc::new(ServerConfig {
            name: "files".into(),
            version: 185,
            agreement: None,
            login_timeout: Duration::from_secs(5),
            ban_time: Duration::from_secs(60),
            caps: Caps::empty(),
            hope: None,
            mark_cleartext: false,
            trtp_login: hxd_session::TrtpLogin::Verify,
            stamp_queued: true,
            news: Default::default(),
        }),
        files: Some(service.clone()),
        banner: None,
    };
    let ng_ctx = NgCtx {
        core,
        auth,
        cfg: Arc::new(NgConfig {
            server_name: "files".into(),
            caps: vec!["files".into()],
            ..Default::default()
        }),
        registry: Arc::new(Registry::new()),
        identity: None,
        tunnel: None,
        enroll: None,
        files: Some(service),
        registrar: None,
        push: None,
        banner: None,
        metrics: None,
    };
    let legacy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let running = Running {
        legacy: legacy.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
        root,
        source,
        _accounts: accounts,
    };
    tokio::spawn(hxd_session::serve(legacy, legacy_ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    running
}

async fn classic(server: &Running, login: &str) -> legacy::Client {
    legacy::Client::login_at(server.legacy, &Login::account(login, login, "pw"))
        .await
        .unwrap()
}

/// A DIR field naming the folders `path` spells, below the root.
fn dir(path: &[&str]) -> Vec<u8> {
    let mut out = (path.len() as u16).to_be_bytes().to_vec();
    for name in path {
        out.extend_from_slice(&[0, 0, name.len() as u8]);
        out.extend_from_slice(name.as_bytes());
    }
    out
}

fn name(name: &str) -> (u16, Vec<u8>) {
    (tag::FILE_NAME, name.as_bytes().to_vec())
}

fn listed(listing: &legacy::Frame) -> Vec<String> {
    listing
        .all(LIST_ENTRY)
        .into_iter()
        .map(|entry| String::from_utf8(entry[20..].to_vec()).unwrap())
        .collect()
}

/// The task error a refused request answers with.
fn refused(result: hxd_testclient::Result<legacy::Frame>) -> String {
    match result {
        Err(Error::Refused { text, .. }) => text,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn refused_ng(result: hxd_testclient::Result<Value>) -> String {
    match result {
        Err(Error::Refused { code, .. }) => code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[tokio::test]
async fn a_classic_client_keeps_house_and_an_ng_client_sees_it() {
    let server = start().await;
    write(server.root.path(), "notes.txt", b"hello");
    let mut admin = classic(&server, "admin").await;

    // New Folder, in both of mhxd's forms: a name in DIR, and DIR alone.
    admin.call(FILE_MKDIR, &[name("Stuff")]).await.unwrap();
    admin
        .call(FILE_MKDIR, &[(tag::DIR, dir(&["Stuff", "Inner"]))])
        .await
        .unwrap();
    assert!(server.path("Stuff/Inner").is_dir());
    assert_eq!(
        refused(admin.call(FILE_MKDIR, &[name("Stuff")]).await),
        "A file already exists at that path."
    );

    // A comment, then a rename, then a move, each carrying the last.
    admin
        .call(
            FILE_SET_INFO,
            &[name("notes.txt"), (tag::FILE_COMMENT, b"read me".to_vec())],
        )
        .await
        .unwrap();
    admin
        .call(
            FILE_SET_INFO,
            &[
                name("notes.txt"),
                (tag::FILE_RENAME, b"read me.txt".to_vec()),
            ],
        )
        .await
        .unwrap();
    admin
        .call(
            FILE_MOVE,
            &[
                name("read me.txt"),
                (tag::DIR_RENAME, dir(&["Stuff", "Inner"])),
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(server.path("Stuff/Inner/read me.txt")).unwrap(),
        b"hello"
    );
    let info = admin
        .call(
            FILE_GET_INFO,
            &[name("read me.txt"), (tag::DIR, dir(&["Stuff", "Inner"]))],
        )
        .await
        .unwrap();
    assert_eq!(info.bytes(tag::FILE_COMMENT).unwrap(), b"read me");

    // The ng client lists, reads the comment, and then moves the whole
    // folder back to the root under a new name.
    let (mut modern, hello) = ng::Client::account(server.ng, "admin", "pw", "modern")
        .await
        .unwrap();
    assert_eq!(hello["files"]["writable"], true);
    assert_eq!(hello["files"]["may"].as_array().unwrap().len(), 9);
    let info = modern
        .request("files_info", json!({ "path": "Stuff/Inner/read me.txt" }))
        .await
        .unwrap();
    assert_eq!(info["comment"], "read me");
    modern
        .request(
            "files_move",
            json!({ "path": "Stuff/Inner", "to": "Moved" }),
        )
        .await
        .unwrap();
    assert_eq!(
        server.comment("Moved/read me.txt").await.as_deref(),
        Some("read me")
    );

    // Delete, a file and then a folder with everything in it, and what
    // is left is what the classic client lists.
    admin
        .call(
            FILE_DELETE,
            &[name("read me.txt"), (tag::DIR, dir(&["Moved"]))],
        )
        .await
        .unwrap();
    admin.call(FILE_DELETE, &[name("Stuff")]).await.unwrap();
    let listing = admin.call(FILE_LIST, &[]).await.unwrap();
    assert_eq!(listed(&listing), ["Moved"]);
    modern
        .request("files_delete", json!({ "path": "Moved" }))
        .await
        .unwrap();
    let listing = admin.call(FILE_LIST, &[]).await.unwrap();
    assert!(listed(&listing).is_empty());
}

#[tokio::test]
async fn each_kind_of_entry_asks_for_its_own_bit() {
    let server = start().await;
    write(server.root.path(), "file.txt", b"x");
    write(server.root.path(), "Folder/inside.txt", b"x");
    let mut filer = classic(&server, "filer").await;

    // mhxd would let an account that may delete files delete a folder.
    assert_eq!(
        refused(filer.call(FILE_DELETE, &[name("Folder")]).await),
        "You are not allowed to delete folders."
    );
    assert_eq!(
        refused(
            filer
                .call(
                    FILE_SET_INFO,
                    &[name("Folder"), (tag::FILE_RENAME, b"Renamed".to_vec())],
                )
                .await
        ),
        "You are not allowed to rename folders."
    );
    assert_eq!(
        refused(
            filer
                .call(
                    FILE_SET_INFO,
                    &[name("Folder"), (tag::FILE_COMMENT, b"no".to_vec())],
                )
                .await
        ),
        "You are not allowed to comment folders."
    );
    assert_eq!(
        refused(
            filer
                .call(FILE_MOVE, &[name("Folder"), (tag::DIR_RENAME, dir(&[]))])
                .await
        ),
        "You are not allowed to move folders."
    );
    assert!(server.path("Folder/inside.txt").is_file());

    // What it may do to files, it does.
    filer
        .call(
            FILE_MOVE,
            &[name("file.txt"), (tag::DIR_RENAME, dir(&["Folder"]))],
        )
        .await
        .unwrap();
    filer
        .call(
            FILE_DELETE,
            &[name("file.txt"), (tag::DIR, dir(&["Folder"]))],
        )
        .await
        .unwrap();
    assert!(!server.path("Folder/file.txt").exists());

    // The same on the ng wire, where one move is both a rename and a
    // move and asks for both bits.
    let (mut modern, hello) = ng::Client::account(server.ng, "renamer", "pw", "modern")
        .await
        .unwrap();
    assert_eq!(hello["files"]["may"], json!(["rename_files"]));
    modern
        .request(
            "files_move",
            json!({ "path": "Folder/inside.txt", "to": "Folder/renamed.txt" }),
        )
        .await
        .unwrap();
    assert_eq!(
        refused_ng(
            modern
                .request(
                    "files_move",
                    json!({ "path": "Folder/renamed.txt", "to": "moved.txt" }),
                )
                .await
        ),
        "access_denied"
    );
    for (req, params) in [
        ("files_delete", json!({ "path": "Folder/renamed.txt" })),
        ("files_mkdir", json!({ "path": "New" })),
        (
            "files_comment",
            json!({ "path": "Folder/renamed.txt", "comment": "hi" }),
        ),
    ] {
        assert_eq!(
            refused_ng(modern.request(req, params).await),
            "access_denied",
            "{req}"
        );
    }
    assert!(server.path("Folder/renamed.txt").is_file());

    // An account that may do none of an act is refused before the path
    // is looked up, so it cannot learn from the answer what exists.
    let (mut nobody, _) = ng::Client::guest(server.ng, "nobody").await.unwrap();
    for path in ["Folder/renamed.txt", "missing.txt"] {
        assert_eq!(
            refused_ng(
                nobody
                    .request("files_delete", json!({ "path": path }))
                    .await
            ),
            "access_denied",
            "{path}"
        );
    }
}

#[tokio::test]
async fn an_account_with_none_of_an_acts_bits_is_refused_before_the_lookup() {
    let server = start().await;
    write(server.root.path(), "file.txt", b"x");

    // As on mhxd: Move without either move bit, and Set Info without any
    // of the rename and comment bits, are refused before the name is
    // looked up, so a name that is there and one that is not are answered
    // alike, and a Set Info that would change nothing is refused too.
    let mut renamer = classic(&server, "renamer").await;
    let mut mover = classic(&server, "mover").await;
    for held in ["file.txt", "absent.txt"] {
        assert_eq!(
            refused(
                renamer
                    .call(FILE_MOVE, &[name(held), (tag::DIR_RENAME, dir(&[]))])
                    .await
            ),
            "You are not allowed to move files.",
            "{held}"
        );
        for change in [
            (tag::FILE_RENAME, held.as_bytes().to_vec()),
            (tag::FILE_COMMENT, Vec::new()),
            (tag::FILE_RENAME, b"other.txt".to_vec()),
        ] {
            assert_eq!(
                refused(mover.call(FILE_SET_INFO, &[name(held), change]).await),
                "You are not allowed to rename or comment files.",
                "{held}"
            );
        }
    }
    assert!(server.path("file.txt").is_file());
    assert!(!server.path("other.txt").exists());
}

#[tokio::test]
async fn a_folder_holding_a_drop_box_is_kept_from_those_who_cannot_view_it() {
    let server = start().await;
    // One drop box holds a file and the other folders nested past what a
    // delete or move walks; without view_drop_boxes the two are refused
    // alike, so neither the depth nor anything else inside is learned.
    write(server.root.path(), "Shallow/Drop Box/secret.txt", b"x");
    let bottom = vec!["d"; 64].join("/");
    std::fs::create_dir_all(server.path(&format!("Deep/Inner/Drop Box/{bottom}"))).unwrap();
    std::fs::create_dir(server.path("Folder")).unwrap();
    let holds = "That folder holds a drop box.";

    let mut keeper = classic(&server, "keeper").await;
    let (mut modern, _) = ng::Client::account(server.ng, "keeper", "pw", "modern")
        .await
        .unwrap();
    for outer in ["Shallow", "Deep"] {
        assert_eq!(
            refused(keeper.call(FILE_DELETE, &[name(outer)]).await),
            holds,
            "{outer}"
        );
        assert_eq!(
            refused(
                keeper
                    .call(
                        FILE_MOVE,
                        &[name(outer), (tag::DIR_RENAME, dir(&["Folder"]))]
                    )
                    .await
            ),
            holds,
            "{outer}"
        );
        assert_eq!(
            refused(
                keeper
                    .call(
                        FILE_SET_INFO,
                        &[name(outer), (tag::FILE_RENAME, b"Renamed".to_vec())]
                    )
                    .await
            ),
            holds,
            "{outer}"
        );
        for (req, params) in [
            ("files_delete", json!({ "path": outer })),
            (
                "files_move",
                json!({ "path": outer, "to": format!("Folder/{outer}") }),
            ),
        ] {
            assert_eq!(
                refused_ng(modern.request(req, params).await),
                "access_denied",
                "{req} on {outer}"
            );
        }
    }
    assert!(server.path("Shallow/Drop Box/secret.txt").is_file());
    assert!(server
        .path(&format!("Deep/Inner/Drop Box/{bottom}"))
        .is_dir());

    // An account that may view drop boxes moves and deletes such a folder
    // as any other.
    let mut admin = classic(&server, "admin").await;
    admin
        .call(
            FILE_MOVE,
            &[name("Shallow"), (tag::DIR_RENAME, dir(&["Folder"]))],
        )
        .await
        .unwrap();
    assert!(server.path("Folder/Shallow/Drop Box/secret.txt").is_file());
    admin
        .call(
            FILE_DELETE,
            &[name("Shallow"), (tag::DIR, dir(&["Folder"]))],
        )
        .await
        .unwrap();
    assert!(!server.path("Folder/Shallow").exists());
    assert_eq!(
        refused(admin.call(FILE_DELETE, &[name("Deep")]).await),
        "Folders cannot be nested that deeply."
    );

    // And a folder holding none is the keeper's to move.
    keeper
        .call(
            FILE_MOVE,
            &[name("Folder"), (tag::DIR_RENAME, dir(&["Deep"]))],
        )
        .await
        .unwrap();
    assert!(server.path("Deep/Folder").is_dir());
}

#[tokio::test]
async fn set_info_changes_only_what_differs_from_what_was_shown() {
    let server = start().await;
    write(server.root.path(), "file.txt", b"x");
    let mut admin = classic(&server, "admin").await;
    admin
        .call(
            FILE_SET_INFO,
            &[name("file.txt"), (tag::FILE_COMMENT, b"theirs".to_vec())],
        )
        .await
        .unwrap();

    // A Get Info window sends back the name and comment it showed. The
    // comment is unchanged, so an account that may only rename can.
    let mut renamer = classic(&server, "renamer").await;
    renamer
        .call(
            FILE_SET_INFO,
            &[
                name("file.txt"),
                (tag::FILE_RENAME, b"renamed.txt".to_vec()),
                (tag::FILE_COMMENT, b"theirs".to_vec()),
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        server.comment("renamed.txt").await.as_deref(),
        Some("theirs")
    );
    // And changing it is refused before anything is renamed.
    assert_eq!(
        refused(
            renamer
                .call(
                    FILE_SET_INFO,
                    &[
                        name("renamed.txt"),
                        (tag::FILE_RENAME, b"again.txt".to_vec()),
                        (tag::FILE_COMMENT, b"mine".to_vec()),
                    ],
                )
                .await
        ),
        "You are not allowed to comment files."
    );
    assert!(server.path("renamed.txt").is_file());

    // An empty comment clears it; a name that is already taken is not
    // replaced.
    write(server.root.path(), "taken.txt", b"keep");
    admin
        .call(
            FILE_SET_INFO,
            &[name("renamed.txt"), (tag::FILE_COMMENT, Vec::new())],
        )
        .await
        .unwrap();
    assert_eq!(server.comment("renamed.txt").await, None);
    assert_eq!(
        refused(
            admin
                .call(
                    FILE_SET_INFO,
                    &[
                        name("renamed.txt"),
                        (tag::FILE_RENAME, b"taken.txt".to_vec())
                    ],
                )
                .await
        ),
        "A file already exists at that path."
    );
    assert_eq!(std::fs::read(server.path("taken.txt")).unwrap(), b"keep");
    assert_eq!(
        refused(admin.call(FILE_SET_INFO, &[name("renamed.txt")]).await),
        "Nothing to change was supplied."
    );
}

#[tokio::test]
async fn drop_boxes_and_aliases_stay_out_of_reach() {
    let server = start().await;
    write(server.root.path(), "Drop Box/secret.txt", b"x");
    write(server.root.path(), "file.txt", b"x");
    let mut filer = classic(&server, "filer").await;

    // Without view_drop_boxes nothing here names one, as on mhxd.
    assert_eq!(
        refused(filer.call(FILE_MKDIR, &[name("My Drop Box")]).await),
        "You are not allowed to view drop boxes."
    );
    assert_eq!(
        refused(
            filer
                .call(
                    FILE_MOVE,
                    &[name("file.txt"), (tag::DIR_RENAME, dir(&["Drop Box"]))],
                )
                .await
        ),
        "You are not allowed to view drop boxes."
    );
    // A name the drop box holds and one it does not are refused alike,
    // for every request that names one: otherwise "File not found." for
    // the second lists the drop box one guess at a time.
    for held in ["secret.txt", "absent.txt"] {
        let inside = || [name(held), (tag::DIR, dir(&["Drop Box"]))];
        for (ty, extra) in [
            (FILE_DELETE, None),
            (FILE_GET_INFO, None),
            (FILE_GET, None),
            (
                FILE_SET_INFO,
                Some((tag::FILE_RENAME, b"other.txt".to_vec())),
            ),
            (FILE_MOVE, Some((tag::DIR_RENAME, dir(&[])))),
        ] {
            let fields: Vec<_> = inside().into_iter().chain(extra).collect();
            assert_eq!(
                refused(filer.call(ty, &fields).await),
                "You are not allowed to view drop boxes.",
                "{ty:#x} on {held}"
            );
        }
    }
    for folder in [&["Drop Box"][..], &["Drop Box", "absent"]] {
        assert_eq!(
            refused(filer.call(FILE_LIST, &[(tag::DIR, dir(folder))]).await),
            "You are not allowed to view drop boxes.",
            "{folder:?}"
        );
    }
    let (mut modern, _) = ng::Client::account(server.ng, "filer", "pw", "modern")
        .await
        .unwrap();
    assert_eq!(
        refused_ng(
            modern
                .request("files_delete", json!({ "path": "Drop Box/secret.txt" }))
                .await
        ),
        "access_denied"
    );
    for held in ["Drop Box/secret.txt", "Drop Box/absent.txt"] {
        for req in ["files_info", "files_download", "files_delete"] {
            assert_eq!(
                refused_ng(modern.request(req, json!({ "path": held })).await),
                "access_denied",
                "{req} on {held}"
            );
        }
    }
    assert!(server.path("Drop Box/secret.txt").is_file());

    // An alias would be a symlink, which this area never makes, even for
    // an account that may.
    let mut admin = classic(&server, "admin").await;
    assert_eq!(
        refused(
            admin
                .call(
                    MAKE_ALIAS,
                    &[name("file.txt"), (tag::DIR_RENAME, dir(&["Drop Box"]))],
                )
                .await
        ),
        "This server does not make aliases."
    );
}

#[tokio::test]
async fn a_drop_box_behind_a_cut_short_name_is_not_probed() {
    let server = start().await;
    // Named past what a classic wire name holds, so the name a 1.5 client
    // is shown, and sends back, stops short of "Drop Box".
    let long = "Everything sent to the Drop Box";
    let long = format!("Archive of {long}");
    write(server.root.path(), &format!("{long}/secret.txt"), b"x");
    let mut filer = classic(&server, "filer").await;
    let listing = filer.call(FILE_LIST, &[]).await.unwrap();
    let cut = listed(&listing)
        .into_iter()
        .find(|name| long.starts_with(name.as_str()))
        .expect("the drop box is listed in its parent");
    assert!(!cut.to_ascii_lowercase().contains("drop box"), "{cut}");

    assert_eq!(
        refused(filer.call(FILE_LIST, &[(tag::DIR, dir(&[&cut]))]).await),
        "You are not allowed to view drop boxes."
    );
    // What it holds and what it does not are answered alike.
    for ty in [FILE_GET_INFO, FILE_GET, FILE_DELETE] {
        let ask = |held: &str| [name(held), (tag::DIR, dir(&[&cut]))];
        let held = refused(filer.call(ty, &ask("secret.txt")).await);
        let absent = refused(filer.call(ty, &ask("absent.txt")).await);
        assert_eq!(held, absent, "{ty:#x}");
    }
    assert!(server.path(&format!("{long}/secret.txt")).is_file());

    // The name does reach it, for an account that may look.
    let mut admin = classic(&server, "admin").await;
    admin
        .call(
            FILE_GET_INFO,
            &[name("secret.txt"), (tag::DIR, dir(&[&cut]))],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn folders_nested_too_deep_are_refused_on_either_wire() {
    let server = start().await;
    // As deep as a folder may sit, and a tree nested past it behind the
    // server's back.
    let bottom = vec!["d"; 64];
    std::fs::create_dir_all(server.path(&bottom.join("/"))).unwrap();
    std::fs::create_dir_all(server.path(&format!("deep/{}", bottom.join("/")))).unwrap();
    let too_deep = "Folders cannot be nested that deeply.";
    let mut admin = classic(&server, "admin").await;
    assert_eq!(
        refused(
            admin
                .call(FILE_MKDIR, &[name("e"), (tag::DIR, dir(&bottom))])
                .await
        ),
        too_deep
    );
    assert_eq!(
        refused(
            admin
                .call(
                    FILE_SET_INFO,
                    &[name("deep"), (tag::FILE_RENAME, b"deeper".to_vec())]
                )
                .await
        ),
        too_deep
    );

    let (mut modern, _) = ng::Client::account(server.ng, "admin", "pw", "modern")
        .await
        .unwrap();
    assert_eq!(
        refused_ng(
            modern
                .request(
                    "files_mkdir",
                    json!({ "path": format!("{}/e", bottom.join("/")) })
                )
                .await
        ),
        "too_deep"
    );
    assert_eq!(
        refused_ng(
            modern
                .request("files_move", json!({ "path": "deep", "to": "deeper" }))
                .await
        ),
        "too_deep"
    );
    assert!(!server.path(&format!("{}/e", bottom.join("/"))).exists());
    assert!(server.path("deep").is_dir());
    assert!(!server.path("deeper").exists());
}

#[tokio::test]
async fn a_read_only_area_refuses_every_change() {
    let server = start_with(false).await;
    write(server.root.path(), "file.txt", b"x");
    let mut admin = classic(&server, "admin").await;
    assert_eq!(
        refused(admin.call(FILE_DELETE, &[name("file.txt")]).await),
        "This file area is read-only."
    );
    let (mut modern, hello) = ng::Client::account(server.ng, "admin", "pw", "modern")
        .await
        .unwrap();
    assert_eq!(hello["files"], json!({ "writable": false, "may": [] }));
    assert_eq!(
        refused_ng(
            modern
                .request("files_mkdir", json!({ "path": "New" }))
                .await
        ),
        "read_only"
    );
    assert!(server.path("file.txt").is_file());
    assert!(!server.path("New").exists());
}
