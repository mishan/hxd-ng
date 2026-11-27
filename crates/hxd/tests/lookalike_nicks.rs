//! A local nick that ends in `[server] bot_suffix`, which the classic wire
//! adds to a bot's nick to say it is one, is shown to classic clients
//! without it, whichever wire set it, at login and on a change; an ng
//! client, which is told who is a bot apart from the name, sees the nick
//! as it was set. (`@tag` under `[link] show_tags`, the cuts and what
//! draws as nothing are `hxd_session::names`' tests.)

use std::net::SocketAddr;
use std::path::Path;

use hxd_testclient::legacy::{self, push, Login};
use hxd_testclient::ng;
use hxproto::messages::{tag, ClientHdr};
use serde_json::json;

struct Server {
    legacy: SocketAddr,
    ng: SocketAddr,
}

async fn start(dir: &Path) -> Server {
    let d = dir.display();
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n[server]\nbot_suffix = \" [bot]\"\n\
         [ng]\nbind = \"127.0.0.1:0\"\n"
    );
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

async fn nicks(c: &mut legacy::Client) -> Vec<String> {
    let mut nicks: Vec<String> = c
        .user_list()
        .await
        .unwrap()
        .into_iter()
        .map(|row| String::from_utf8(row.nick).unwrap())
        .collect();
    nicks.sort();
    nicks
}

#[tokio::test]
async fn a_nick_ending_in_the_bot_suffix_is_shown_without_it_from_either_wire() {
    let dir = tempfile::tempdir().unwrap();
    let s = start(dir.path()).await;
    let mut classic = legacy::Client::login_at(s.legacy, &Login::guest("alice [bot]"))
        .await
        .unwrap();
    let (mut mobile, hello) = ng::Client::guest(s.ng, "bob [bot]").await.unwrap();
    assert_eq!(hello["self"]["nick"], "bob [bot]");
    assert_eq!(nicks(&mut classic).await, ["alice", "bob"]);

    classic
        .tx
        .send(
            ClientHdr::UserChange.as_u32(),
            &[(tag::NAME, b"carol [bot]".to_vec())],
        )
        .await
        .unwrap();
    mobile
        .request("nick", json!({ "nick": "dave [bot]" }))
        .await
        .unwrap();
    assert_eq!(nicks(&mut classic).await, ["carol", "dave"]);
    let (_, later) = ng::Client::guest(s.ng, "eve").await.unwrap();
    let mut seen: Vec<&str> = later["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["nick"].as_str().unwrap())
        .collect();
    seen.sort();
    assert_eq!(seen, ["carol [bot]", "dave [bot]", "eve"]);

    // A line and a private message from her: the classic reader is sent
    // her name without it, in the line's name column and the message.
    mobile.chat("hello").await.unwrap();
    let line = classic.rx.recv_where(|f| f.ty == push::CHAT).await.unwrap();
    let body = String::from_utf8(line.bytes(tag::BODY).unwrap()).unwrap();
    assert!(body.ends_with(" dave:  hello"), "{body:?}");
    let to = classic.uid.unwrap();
    mobile
        .request("msg", json!({ "to": to, "text": "psst" }))
        .await
        .unwrap();
    let msg = classic.rx.recv_where(|f| f.ty == push::MSG).await.unwrap();
    assert_eq!(msg.bytes(tag::NAME).unwrap(), b"dave");
}
