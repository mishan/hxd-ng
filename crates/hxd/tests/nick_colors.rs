//! Nick colors (fogWraith's Colored Nicknames) on the classic wire, and
//! as the ng wire sees them: a client that sends a color in User Change
//! is sent everyone's, in user list rows and user changes, and a client
//! that never sent one is sent nothing it would not expect.

use std::net::SocketAddr;
use std::path::Path;

use hxd_testclient::legacy::{self, push, Frame, Login};
use hxd_testclient::ng;
use hxproto::messages::{tag, ClientHdr};

const NO_COLOR: u32 = 0xffff_ffff;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
}

async fn start(dir: &Path) -> Server {
    let d = dir.display();
    let text = format!("[paths]\naccounts = \"{d}/accounts\"\n[ng]\nbind = \"127.0.0.1:0\"\n");
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, &text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    let ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None)
        .unwrap()
        .unwrap();
    let legacy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ng = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        legacy: legacy.local_addr().unwrap(),
        ng: ng.local_addr().unwrap(),
    };
    tokio::spawn(hxd_session::serve(legacy, ctx));
    tokio::spawn(hxd_ng_session::serve(ng, ng_ctx));
    server
}

async fn set_color(c: &mut legacy::Client, color: u32) {
    c.tx.send(
        ClientHdr::UserChange.as_u32(),
        &[(tag::COLOR, color.to_be_bytes().to_vec())],
    )
    .await
    .unwrap();
}

/// The next User Change for `uid` that carries a nick color, and that
/// color.
async fn change_color(c: &mut legacy::Client, uid: u16) -> u32 {
    let f =
        c.rx.recv_where(|f| {
            f.ty == push::USER_CHANGE
                && f.uint(tag::UID) == Some(uid.into())
                && f.chunk(tag::COLOR).is_some()
        })
        .await
        .unwrap();
    f.uint(tag::COLOR).unwrap()
}

/// `uid`'s user list row, raw.
fn row(list: &Frame, uid: u16) -> Vec<u8> {
    list.all(tag::USER_LIST)
        .into_iter()
        .find(|r| r[..2] == uid.to_be_bytes())
        .unwrap()
}

/// What follows the name in a user list row.
fn trailer(row: &[u8]) -> &[u8] {
    let len = u16::from_be_bytes([row[6], row[7]]) as usize;
    &row[8 + len..]
}

#[tokio::test]
async fn a_client_that_sends_a_color_is_sent_everyones() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    let mut ann = legacy::Client::login_at(server.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let mut bob = legacy::Client::login_at(server.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    let mut old = legacy::Client::login_at(server.legacy, &Login::guest("old"))
        .await
        .unwrap();
    let (ann_uid, bob_uid) = (ann.uid.unwrap(), bob.uid.unwrap());

    // Ann has a color before Bob, who already has the user list, says
    // he can show one; saying so tells him hers.
    set_color(&mut ann, 0x00ff_8000).await;
    assert_eq!(change_color(&mut ann, ann_uid).await, 0x00ff_8000);
    bob.call(ClientHdr::UserGetList.as_u32(), &[])
        .await
        .unwrap();
    set_color(&mut bob, 0x0000_80ff).await;
    assert_eq!(change_color(&mut bob, ann_uid).await, 0x00ff_8000);
    assert_eq!(change_color(&mut bob, bob_uid).await, 0x0000_80ff);

    // Rows carry the color after the name, or "none" for a user without.
    let list = bob
        .call(ClientHdr::UserGetList.as_u32(), &[])
        .await
        .unwrap();
    assert_eq!(trailer(&row(&list, ann_uid)), 0x00ff_8000u32.to_be_bytes());
    let old_uid = old.uid.unwrap();
    assert_eq!(trailer(&row(&list, old_uid)), NO_COLOR.to_be_bytes());

    // A cleared color is sent as "none", so it is not left showing.
    set_color(&mut ann, NO_COLOR).await;
    assert_eq!(change_color(&mut bob, ann_uid).await, NO_COLOR);

    // A client that never sent a color gets the rows and changes it
    // always did: nothing after the name, no color field.
    let list = old
        .call(ClientHdr::UserGetList.as_u32(), &[])
        .await
        .unwrap();
    assert!(trailer(&row(&list, bob_uid)).is_empty());
    for f in old.rx.take_backlog() {
        assert!(f.chunk(tag::COLOR).is_none(), "{f:?}");
    }
}

#[tokio::test]
async fn a_client_that_sends_its_color_first_finds_colors_in_the_list() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    let mut ann = legacy::Client::login_at(server.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let ann_uid = ann.uid.unwrap();
    set_color(&mut ann, 0x00ff_8000).await;
    assert_eq!(change_color(&mut ann, ann_uid).await, 0x00ff_8000);

    // As GtkHx does: the color, then the list. Ann is in the rows with
    // her color, and no 301 announces her to Bob ahead of them.
    let mut bob = legacy::Client::login_at(server.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    set_color(&mut bob, 0x0000_80ff).await;
    let list = bob
        .call(ClientHdr::UserGetList.as_u32(), &[])
        .await
        .unwrap();
    assert_eq!(trailer(&row(&list, ann_uid)), 0x00ff_8000u32.to_be_bytes());
    assert!(!bob
        .rx
        .take_backlog()
        .iter()
        .any(|f| f.ty == push::USER_CHANGE && f.uint(tag::UID) == Some(ann_uid.into())));
}

#[tokio::test]
async fn an_ng_client_sees_a_classic_users_color() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    let (mut watcher, _) = ng::Client::guest(server.ng, "watcher").await.unwrap();
    let mut ann = legacy::Client::login_at(server.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let uid = ann.uid.unwrap();
    set_color(&mut ann, 0x00ff_8000).await;
    let changed = watcher
        .event_where("user_changed", |d| d["user"]["uid"] == uid)
        .await
        .unwrap();
    assert_eq!(changed.data["user"]["color"], 0x00ff_8000);
}

#[tokio::test]
async fn a_color_is_masked_to_rgb_and_one_of_the_wrong_size_ignored() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    let (mut watcher, _) = ng::Client::guest(server.ng, "watcher").await.unwrap();
    let mut ann = legacy::Client::login_at(server.legacy, &Login::guest("ann"))
        .await
        .unwrap();
    let mut bob = legacy::Client::login_at(server.legacy, &Login::guest("bob"))
        .await
        .unwrap();
    let (ann_uid, bob_uid) = (ann.uid.unwrap(), bob.uid.unwrap());

    // The reserved high byte never reaches anyone.
    set_color(&mut ann, 0xab00_8000).await;
    assert_eq!(change_color(&mut ann, ann_uid).await, 0x0000_8000);
    let changed = watcher
        .event_where("user_changed", |d| d["user"]["uid"] == ann_uid)
        .await
        .unwrap();
    assert_eq!(changed.data["user"]["color"], 0x0000_8000);

    // Two bytes are no color: Bob is not opted in, and Ann hears of no
    // change to him (past his join, which she has already been sent).
    ann.call(ClientHdr::UserGetList.as_u32(), &[])
        .await
        .unwrap();
    ann.rx.take_backlog();
    bob.tx
        .send(
            ClientHdr::UserChange.as_u32(),
            &[(tag::COLOR, vec![0x12, 0x34])],
        )
        .await
        .unwrap();
    let list = bob
        .call(ClientHdr::UserGetList.as_u32(), &[])
        .await
        .unwrap();
    assert!(trailer(&row(&list, ann_uid)).is_empty());
    ann.call(ClientHdr::UserGetList.as_u32(), &[])
        .await
        .unwrap();
    assert!(!ann
        .rx
        .take_backlog()
        .iter()
        .any(|f| f.ty == push::USER_CHANGE && f.uint(tag::UID) == Some(bob_uid.into())));
}

#[tokio::test]
async fn self_info_and_private_chat_joins_carry_colors_to_a_client_that_sends_them() {
    let td = tempfile::tempdir().unwrap();
    let server = start(td.path()).await;
    let mut bob = legacy::Client::login_at(server.legacy, &Login::guest("bob"))
        .await
        .unwrap();

    // A 1.5 client that logs in without a name finishes with a User
    // Change; one carrying a color is answered with self-info that has
    // the color in a field of its own, where GtkHx reads it.
    let mut ann = legacy::Client::connect(server.legacy).await.unwrap();
    ann.call(
        ClientHdr::Login.as_u32(),
        &[(tag::VERSION, 150u16.to_be_bytes().to_vec())],
    )
    .await
    .unwrap();
    ann.tx
        .send(
            ClientHdr::UserChange.as_u32(),
            &[
                (tag::NAME, b"ann".to_vec()),
                (tag::COLOR, 0x00ff_8000u32.to_be_bytes().to_vec()),
            ],
        )
        .await
        .unwrap();
    let selfinfo = ann.rx.recv_type(push::SELFINFO).await.unwrap();
    assert_eq!(selfinfo.uint(tag::COLOR), Some(0x00ff_8000));

    // Bob, who has no color, joins Ann's private chat: Ann is told so
    // with "none" for his color.
    let created = ann
        .call(
            ClientHdr::ChatCreate.as_u32(),
            &[(tag::UID, bob.uid.unwrap().to_be_bytes().to_vec())],
        )
        .await
        .unwrap();
    let cid = created.bytes(tag::CHAT_ID).unwrap();
    bob.call(ClientHdr::ChatJoin.as_u32(), &[(tag::CHAT_ID, cid)])
        .await
        .unwrap();
    let joined = ann
        .rx
        .recv_where(|f| f.ty == 0x75 && f.uint(tag::UID) == Some(bob.uid.unwrap().into()))
        .await
        .unwrap();
    assert_eq!(joined.uint(tag::COLOR), Some(NO_COLOR));
}
