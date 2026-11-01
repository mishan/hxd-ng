//! Portable friendships on the classic wire
//! (`docs/proposals/portable-friends.md` §4, §7): servers built from a
//! real config, each with an ng port, an identity and a SQLite store, and
//! classic clients that hold their own device keys, prove them with Prove
//! Device and sign offers, acceptances and withdrawals with hl-identity's
//! own API. The requests are built and the replies read by `hxproto`, as
//! GtkHx builds and reads them. A friendship made with an ng client or
//! another classic one is in place on the next server once both present
//! it, a withdrawal on one ends it on the other, a rotation's records are
//! fetched, and a session that did not negotiate bit 15, and a period
//! client beside it all, see nothing new.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use hl_identity::friendship::Pair;
use hl_identity::{
    cert, Acceptance, Card, DeviceCert, DeviceKey, DeviceProof, Fingerprint, Friendship,
    IdentityKey, LoginProof, Offer, Rotation, ServerChallenge, Withdrawal,
};
use hxd_testclient::device::{get_device_challenge, prove_device};
use hxd_testclient::legacy::{push, Client, Frame, Login};
use hxd_testclient::messaging::{self as im, reason};
use hxd_testclient::ng;
use hxproto::messages::{tag, ClientHdr, ServerHdr};
use hxproto::messaging::{
    parse_entry, parse_friendships, parse_present_friendships, parse_roster, FriendshipAnswer,
    FriendshipQuery, Presentation, ReasonCode, RosterEntry, RosterState, Who, CAP_DEVICE_PROOF,
    CAP_FRIENDSHIPS, CAP_IDENTITY, CAP_MESSAGING,
};
use hxproto::parse::capabilities_decode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const DAY: u64 = 24 * 3600;
/// Everything a classic client that makes portable friendships offers.
const FRIENDS: u64 = CAP_MESSAGING | CAP_IDENTITY | CAP_DEVICE_PROOF | CAP_FRIENDSHIPS;
const NOT_PROVED: &str = "This session has not proved a device that may make friendships.";

struct Server {
    plain: SocketAddr,
    ng: SocketAddr,
}

/// An identity with two devices, each certified.
struct Person {
    id: IdentityKey,
    devices: Vec<(DeviceKey, Vec<u8>)>,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn person(seed: u8) -> Person {
    let id = IdentityKey::from_seed(&[seed; 32]);
    let devices = (0..2)
        .map(|n| {
            let dev = DeviceKey::from_seed(&[seed.wrapping_mul(16).wrapping_add(n + 1); 32]);
            let cert = DeviceCert::for_device(&id, &dev, now() - 3600, cert::RECOMMENDED_LIFETIME)
                .unwrap()
                .sign(&id);
            (dev, cert)
        })
        .collect();
    Person { id, devices }
}

fn alice() -> Person {
    person(1)
}
fn bob() -> Person {
    person(2)
}
fn carol() -> Person {
    person(3)
}
/// Alice's successor, to whom her card commits.
fn successor() -> Person {
    person(4)
}

fn fp(p: &Person) -> Fingerprint {
    Fingerprint::of(&p.id.public())
}

fn card(who: &Person, name: &str) -> Vec<u8> {
    Card::new(&who.id, name, now())
        .sign(&who.id, vec![])
        .unwrap()
}

/// A server whose `alice`, `bob` and `carol` link those identities, with
/// `erin` a password account beside them, all taking part in messaging.
async fn start(dir: &Path) -> Server {
    let accounts = dir.join("accounts");
    hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
    let member = "read_chat = true\nsend_chat = true\nsend_msgs = true\nmessaging = true\n";
    for (login, link) in [
        ("alice", Some(fp(&alice()))),
        ("bob", Some(fp(&bob()))),
        ("carol", Some(fp(&carol()))),
        ("erin", None),
    ] {
        let link = link.map_or_else(String::new, |f| {
            format!("[identity]\nfingerprint = \"{f}\"\n")
        });
        std::fs::write(
            accounts.join(format!("{login}.toml")),
            format!("name = \"{login}\"\npassword = \"pw\"\n[access]\n{member}{link}"),
        )
        .unwrap();
    }
    let plain = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ngl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (p, n) = (plain.local_addr().unwrap(), ngl.local_addr().unwrap());
    let allowed: Vec<String> = [alice(), bob(), carol(), successor()]
        .iter()
        .map(|p| format!("\"{}\"", fp(p)))
        .collect();
    // A case logs one account in more often than a person would, and an
    // identity guest sends at once.
    let text = format!(
        "[paths]\naccounts = \"{d}/accounts\"\n\
         [limits]\nconnections_per_account = 0\nreconnect_seconds = 0\n\
         [inbox]\ndb = \"{d}/hx.db\"\n\
         [messaging]\nenabled = true\n\
         [ng]\nbind = \"{n}\"\n\
         [identity]\nkey = \"{d}/identity.key\"\nnext_key = \"{d}/identity.next\"\n\
         handovers = \"{d}/identity.handovers\"\nsuccessors = \"{d}/identity.successors\"\n\
         newcomer_delay = 0\nhosts = [\"{n}\"]\nclassic_hosts = [\"{p}\"]\nallow_list = [{}]\n",
        allowed.join(", "),
        d = dir.display(),
    );
    let path = dir.join("hxd-ng.toml");
    std::fs::write(&path, text).unwrap();
    let config = hxd::Config::load(&path).unwrap();
    hxd::check_config(&config).unwrap();
    // As the binary builds them.
    let mut ctx = hxd::build_ctx(&config, None, None, None, None).unwrap();
    let ng_ctx = hxd::build_ng_ctx(&config, &ctx, None, None, None).unwrap();
    ctx.device_proof = hxd::device::prover(ng_ctx.as_ref());
    tokio::spawn(hxd::presence_flusher(ctx.core.clone()));
    tokio::spawn(hxd_session::serve(plain, ctx));
    tokio::spawn(hxd_ng_session::serve(ngl, ng_ctx.unwrap()));
    Server { plain: p, ng: n }
}

fn login(account: &str, caps: u64) -> Login {
    Login {
        caps: Some(caps as u16),
        ..Login::account(account, account, "pw")
    }
}

fn confirmed(reply: &Frame) -> u64 {
    reply
        .chunk(tag::CAPABILITIES)
        .map_or(0, |c| capabilities_decode(c.data))
}

/// Get Device Challenge and Prove Device with `who`'s device `dev`.
async fn prove(c: &mut Client, s: &Server, who: &Person, dev: usize) {
    let host = s.plain.to_string();
    let reply = ask(
        c,
        ClientHdr::GetDeviceChallenge,
        get_device_challenge(&host),
    )
    .await;
    let ch = ServerChallenge::parse_trtp(&reply.bytes(tag::SERVER_CHALLENGE).unwrap()).unwrap();
    let (key, cert) = &who.devices[dev];
    let proof =
        DeviceProof::sign(key, &ch.challenge, &ch.server_key, &ch.host, now(), None).unwrap();
    let chunks = prove_device(&proof, cert, Some(&card(who, "friend")));
    ok(c, ClientHdr::ProveDevice, chunks).await;
}

/// A classic session of `account` that negotiated bit 15, proved `who`'s
/// device `dev` before it joined, and joined.
async fn classic_device(s: &Server, account: &str, who: &Person, dev: usize) -> Client {
    let mut c = Client::connect(s.plain).await.unwrap();
    let l = login(account, FRIENDS);
    let reply = c.login_unannounced(&l).await.unwrap();
    assert_eq!(confirmed(&reply) & CAP_FRIENDSHIPS, CAP_FRIENDSHIPS);
    prove(&mut c, s, who, dev).await;
    c.join(&l).await.unwrap();
    c
}

/// A classic session of `account` offering `caps`, joined.
async fn classic(s: &Server, account: &str, caps: u64) -> (Client, Frame) {
    let mut c = Client::connect(s.plain).await.unwrap();
    let reply = c.login(&login(account, caps)).await.unwrap();
    (c, reply)
}

/// One HTTP/1.1 request, closed after its answer: the JSON body.
async fn http_json(addr: SocketAddr, path: &str, body: &[u8]) -> Value {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(5), s.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    serde_json::from_slice(&raw[split + 4..]).unwrap()
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn unb64(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

/// An ng session of `who`'s device 0 with `card`, `extra` beside the
/// challenge binding, speaking the friend family and its portable part.
async fn ng_device(s: &Server, who: &Person, card: &[u8], extra: Value) -> ng::Client {
    let mut c = ng_socket(s, who, card, extra).await;
    let hello = c
        .login(json!({ "messaging": true, "friendships": true }))
        .await
        .unwrap();
    assert!(
        hello["caps"]
            .as_array()
            .unwrap()
            .contains(&json!("friendships")),
        "{hello}"
    );
    c
}

/// An ng socket authenticated with `who`'s device 0, not yet logged in.
async fn ng_socket(s: &Server, who: &Person, card: &[u8], extra: Value) -> ng::Client {
    let ch = http_json(s.ng, "/identity/challenge", b"").await;
    let challenge: [u8; 32] = unb64(ch["challenge"].as_str().unwrap()).try_into().unwrap();
    let key: [u8; 32] = unb64(ch["server_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    let (dk, cert) = &who.devices[0];
    let proof = LoginProof::sign(dk, &challenge, &key, &s.ng.to_string(), now()).unwrap();
    let mut body = json!({ "card": b64(card), "device_cert": b64(cert), "proof": b64(&proof) });
    for (k, v) in extra.as_object().into_iter().flatten() {
        body[k] = v.clone();
    }
    let auth = http_json(s.ng, "/identity/auth", body.to_string().as_bytes()).await;
    let token = auth["token"].as_str().unwrap_or_else(|| panic!("{auth}"));
    let tcp = TcpStream::connect(s.ng).await.unwrap();
    ng::Client::over(Box::new(tcp), &format!("ws://{}/ng?token={token}", s.ng))
        .await
        .unwrap()
}

async fn ask(c: &mut Client, hdr: ClientHdr, chunks: im::Chunks) -> Frame {
    c.ask(hdr, &chunks)
        .await
        .unwrap_or_else(|e| panic!("{hdr:?}: {e}"))
}

async fn ok(c: &mut Client, hdr: ClientHdr, chunks: im::Chunks) -> Frame {
    let f = ask(c, hdr, chunks).await;
    assert!(!f.is_error(), "{hdr:?}: {:?}", f.error_text());
    f
}

/// A failure, and its reason code.
async fn refused(c: &mut Client, hdr: ClientHdr, chunks: im::Chunks) -> Option<ReasonCode> {
    let f = ask(c, hdr, chunks).await;
    assert!(f.is_error(), "{hdr:?} was not refused");
    reason(&f)
}

fn entry(f: &Frame) -> RosterEntry<'_> {
    parse_entry(f.wire(), f.wire().len()).unwrap()
}

/// The first notification of type `ty` about `login` that `pred` takes.
async fn told(
    c: &mut Client,
    ty: ServerHdr,
    login: &str,
    pred: impl Fn(&RosterEntry<'_>) -> bool,
) -> Frame {
    c.recv_where(|f| {
        f.ty == ty.as_u32() && f.trans == 0 && {
            let e = entry(f);
            e.login == login.as_bytes() && pred(&e)
        }
    })
    .await
    .unwrap_or_else(|e| panic!("no {ty:?} about {login}: {e}"))
}

fn state(s: RosterState) -> impl Fn(&RosterEntry<'_>) -> bool {
    move |e| e.state == Some(s.wire())
}

async fn ng_event(c: &mut ng::Client, ev: &str, pred: impl Fn(&Value) -> bool) -> Value {
    c.event_where(ev, pred)
        .await
        .unwrap_or_else(|e| panic!("no {ev}: {e:?}"))
        .data
}

fn offer(from: &Person, dev: usize, to: &Person, time: u64) -> Vec<u8> {
    let (key, cert) = &from.devices[dev];
    Offer {
        from: from.id.public(),
        to: fp(to),
        time,
        expires: time + DAY,
        id: [time as u8; 16],
        cert: cert.clone(),
    }
    .sign(key)
    .unwrap()
}

fn accept(offer: &[u8], by: &Person, dev: usize, time: u64) -> Vec<u8> {
    let (key, cert) = &by.devices[dev];
    let acceptance = Acceptance {
        offer: Sha256::digest(offer).into(),
        from: by.id.public(),
        time,
        cert: cert.clone(),
    }
    .sign(key)
    .unwrap();
    Friendship::encode(offer, &acceptance)
}

fn withdraw(by: &Person, dev: usize, other: &Person, before: u64, time: u64) -> Vec<u8> {
    let (key, cert) = &by.devices[dev];
    Withdrawal {
        from: by.id.public(),
        pair: Pair::new(fp(by), fp(other)).hash(),
        party: None,
        before,
        time,
        cert: cert.clone(),
    }
    .sign(key)
    .unwrap()
}

fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn hashes(e: &RosterEntry<'_>) -> Vec<[u8; 32]> {
    e.friendship_hashes.iter().flatten().map(|h| **h).collect()
}

type Outcome = ([u8; 32], Option<ReasonCode>, Option<Vec<u8>>);

/// A Present Friendships reply's groups: each hash, its reason, and the
/// withdrawal beside a `Withdrawn`.
fn outcomes(f: &Frame) -> Vec<Outcome> {
    parse_present_friendships(f.wire(), f.wire().len())
        .unwrap()
        .outcomes()
        .map(|o| (*o.hash, o.reason_code(), o.withdrawal.map(<[u8]>::to_vec)))
        .collect()
}

async fn present(c: &mut Client, objects: &[Presentation<'_>]) -> Frame {
    ok(
        c,
        ClientHdr::PresentFriendships,
        im::present_friendships(objects),
    )
    .await
}

/// Alice, on a classic session, offers Bob a friendship, which he sees on
/// his own classic session and accepts: the friendship's bytes.
async fn befriend_classic(a: &mut Client, b: &mut Client, alice: &Person, bob: &Person) -> Vec<u8> {
    let o = offer(alice, 0, bob, now() - 60);
    let asked = ok(a, ClientHdr::AddFriend, im::add_friend_offering(b"bob", &o)).await;
    assert_eq!(
        asked.uint(tag::ROSTER_STATE),
        Some(RosterState::PendingOut.wire().into())
    );
    let req = told(b, ServerHdr::FriendRequest, "alice", |_| true).await;
    let e = entry(&req);
    assert_eq!(
        e.offer,
        Some(o.as_slice()),
        "the offer, to a session of bit 15"
    );
    assert_eq!(e.identity, Some(&fp(alice).0));
    let f = accept(&o, bob, 0, now() - 60);
    ok(
        b,
        ClientHdr::FriendResponse,
        im::friend_response_with(b"alice", &f),
    )
    .await;
    let done = told(
        a,
        ServerHdr::RosterEntry,
        "bob",
        state(RosterState::Accepted),
    )
    .await;
    assert_eq!(hashes(&entry(&done)), vec![hash(&f)]);
    f
}

#[tokio::test]
async fn a_friendship_made_with_an_ng_client_is_in_place_on_the_next_server() {
    let (alice, bob) = (alice(), bob());
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let s1 = start(d1.path()).await;
    let s2 = start(d2.path()).await;

    let mut alice1 = classic_device(&s1, "alice", &alice, 0).await;
    let mut bob1 = ng_device(&s1, &bob, &card(&bob, "bob"), json!({})).await;
    let found = ok(&mut alice1, ClientHdr::FindUser, im::find_user(b"bob")).await;
    let roster = parse_roster(found.wire(), found.wire().len()).unwrap();
    let them = roster.entries().next().unwrap();
    assert_eq!(them.identity, Some(&fp(&bob).0));

    let o = offer(&alice, 0, &bob, now() - 60);
    ok(
        &mut alice1,
        ClientHdr::AddFriend,
        im::add_friend_offering(b"bob", &o),
    )
    .await;
    let req = ng_event(&mut bob1, "friend_request", |d| d["login"] == "alice").await;
    assert_eq!(req["offer"], b64(&o));
    let f = accept(&o, &bob, 0, now() - 60);
    bob1.request(
        "friend_respond",
        json!({ "login": "alice", "accept": true, "friendship": b64(&f) }),
    )
    .await
    .unwrap();
    let made = told(
        &mut alice1,
        ServerHdr::RosterEntry,
        "bob",
        state(RosterState::Accepted),
    )
    .await;
    let e = entry(&made);
    assert_eq!(hashes(&e), vec![hash(&f)]);
    assert_eq!(e.identity, Some(&fp(&bob).0));

    // The second server, where neither has been: no request, and friends
    // once both have presented it.
    let mut alice2 = classic_device(&s2, "alice", &alice, 1).await;
    let mut bob2 = classic_device(&s2, "bob", &bob, 1).await;
    let found = ok(
        &mut alice2,
        ClientHdr::FindUser,
        im::find_user_by(Who::Identity(&fp(&bob).0)),
    )
    .await;
    let roster = parse_roster(found.wire(), found.wire().len()).unwrap();
    assert_eq!(roster.entries().next().unwrap().login, b"bob");
    for c in [&mut alice2, &mut bob2] {
        let reply = present(c, &[Presentation::Friendship(&f)]).await;
        assert_eq!(
            outcomes(&reply),
            vec![(hash(&f), Some(ReasonCode::Ok), None)]
        );
    }
    let active = told(
        &mut alice2,
        ServerHdr::RosterEntry,
        "bob",
        state(RosterState::Accepted),
    )
    .await;
    assert_eq!(hashes(&entry(&active)), vec![hash(&f)]);
    let listed = ok(&mut bob2, ClientHdr::GetRoster, Vec::new()).await;
    let roster = parse_roster(listed.wire(), listed.wire().len()).unwrap();
    let alice_row = roster.entries().find(|e| e.login == b"alice").unwrap();
    assert_eq!(hashes(&alice_row), vec![hash(&f)]);

    let unknown = [7; 32];
    let fetched = ok(
        &mut bob2,
        ClientHdr::GetFriendships,
        im::get_friendships(&[
            FriendshipQuery::Hash(&hash(&f)),
            FriendshipQuery::Hash(&unknown),
        ]),
    )
    .await;
    let answers: Vec<_> = parse_friendships(fetched.wire(), fetched.wire().len())
        .unwrap()
        .answers()
        .map(|a| match a {
            FriendshipAnswer::Friendship { hash, friendship } => {
                (*hash, friendship.map(<[u8]>::to_vec))
            }
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        answers,
        vec![(hash(&f), Some(f.clone())), (unknown, None)],
        "a hash no friend's entry carried tells nothing"
    );
}

#[tokio::test]
async fn a_withdrawal_on_one_server_ends_a_classic_friendship_on_the_other() {
    let (alice, bob) = (alice(), bob());
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let s1 = start(d1.path()).await;
    let s2 = start(d2.path()).await;
    let mut alice1 = classic_device(&s1, "alice", &alice, 0).await;
    let mut bob1 = classic_device(&s1, "bob", &bob, 0).await;
    let f = befriend_classic(&mut alice1, &mut bob1, &alice, &bob).await;
    let mut alice2 = classic_device(&s2, "alice", &alice, 1).await;
    let mut bob2 = classic_device(&s2, "bob", &bob, 1).await;
    present(&mut alice2, &[Presentation::Friendship(&f)]).await;
    present(&mut bob2, &[Presentation::Friendship(&f)]).await;
    told(
        &mut bob2,
        ServerHdr::RosterEntry,
        "alice",
        state(RosterState::Accepted),
    )
    .await;

    let before = now();
    let w = withdraw(&alice, 1, &bob, before, now());
    let removed = ok(
        &mut alice2,
        ClientHdr::RemoveFriend,
        im::remove_friend_with(Who::Login(b"bob"), None, Some(&w)),
    )
    .await;
    assert_eq!(reason(&removed), Some(ReasonCode::Ok));
    let gone = told(
        &mut bob2,
        ServerHdr::RosterEntry,
        "alice",
        state(RosterState::Removed),
    )
    .await;
    assert_eq!(entry(&gone).withdrawal, Some(w.as_slice()));

    // Alice's other device brings the same cutoff, signed afresh, to the
    // first server.
    let again = withdraw(&alice, 0, &bob, before, now());
    let taken = present(&mut alice1, &[Presentation::Withdrawal(&again)]).await;
    let pair = Pair::new(fp(&alice), fp(&bob)).hash();
    assert_eq!(outcomes(&taken), vec![(pair, Some(ReasonCode::Ok), None)]);
    let gone = told(
        &mut bob1,
        ServerHdr::RosterEntry,
        "alice",
        state(RosterState::Removed),
    )
    .await;
    assert_eq!(entry(&gone).withdrawal, Some(again.as_slice()));
    let refused = present(&mut bob1, &[Presentation::Friendship(&f)]).await;
    assert_eq!(
        outcomes(&refused),
        vec![(hash(&f), Some(ReasonCode::Withdrawn), Some(again))]
    );
}

#[tokio::test]
async fn a_half_out_of_time_or_withdrawn_is_answered_by_its_code() {
    let (alice, bob, carol) = (alice(), bob(), carol());
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path()).await;
    let mut a = classic_device(&s, "alice", &alice, 0).await;
    let mut b = classic_device(&s, "bob", &bob, 0).await;
    let mut c = classic_device(&s, "carol", &carol, 0).await;
    let (hour_ago, t) = (now() - 3600, now());

    let stale = offer(&alice, 0, &bob, hour_ago);
    assert_eq!(
        refused(
            &mut a,
            ClientHdr::AddFriend,
            im::add_friend_offering(b"bob", &stale)
        )
        .await,
        Some(ReasonCode::Stale),
        "802 with an offer an hour old"
    );
    let o = offer(&alice, 0, &bob, t);
    ok(
        &mut a,
        ClientHdr::AddFriend,
        im::add_friend_offering(b"bob", &o),
    )
    .await;
    let late = accept(&o, &bob, 0, t + 3600);
    assert_eq!(
        refused(
            &mut b,
            ClientHdr::FriendResponse,
            im::friend_response_with(b"alice", &late)
        )
        .await,
        Some(ReasonCode::Stale),
        "805 with an acceptance an hour ahead"
    );
    ok(
        &mut b,
        ClientHdr::FriendResponse,
        im::friend_response_with(b"alice", &accept(&o, &bob, 0, t)),
    )
    .await;

    // A stale withdrawal still removes the friend here, under a
    // withdrawal of the server's own, and is answered so.
    let old = withdraw(&alice, 0, &bob, hour_ago, hour_ago);
    assert_eq!(
        refused(
            &mut a,
            ClientHdr::RemoveFriend,
            im::remove_friend_with(Who::Login(b"bob"), None, Some(&old))
        )
        .await,
        Some(ReasonCode::Stale),
        "803 with a withdrawal an hour old"
    );
    told(
        &mut b,
        ServerHdr::RosterEntry,
        "alice",
        state(RosterState::Removed),
    )
    .await;
    // That withdrawal ends an offer Alice made before it.
    let cut = offer(&alice, 0, &bob, t - 60);
    assert_eq!(
        refused(
            &mut a,
            ClientHdr::AddFriend,
            im::add_friend_offering(b"bob", &cut)
        )
        .await,
        Some(ReasonCode::Withdrawn),
        "802 with a half the server's withdrawal ends"
    );

    // Friends again, and a block that stands whatever becomes of its
    // withdrawal.
    let later = now() + 5;
    let o = offer(&alice, 0, &bob, later);
    ok(
        &mut a,
        ClientHdr::AddFriend,
        im::add_friend_offering(b"bob", &o),
    )
    .await;
    ok(
        &mut b,
        ClientHdr::FriendResponse,
        im::friend_response_with(b"alice", &accept(&o, &bob, 0, later)),
    )
    .await;
    told(
        &mut a,
        ServerHdr::RosterEntry,
        "bob",
        state(RosterState::Accepted),
    )
    .await;
    assert_eq!(
        refused(
            &mut a,
            ClientHdr::BlockUser,
            im::block_withdrawing(b"bob", &old)
        )
        .await,
        Some(ReasonCode::Stale),
        "806 with a withdrawal an hour old"
    );
    let listed = ok(&mut a, ClientHdr::GetRoster, Vec::new()).await;
    let roster = parse_roster(listed.wire(), listed.wire().len()).unwrap();
    let row = roster.entries().find(|e| e.login == b"bob").unwrap();
    assert_eq!(
        row.roster_state(),
        Some(RosterState::Blocked),
        "the block stands"
    );

    // Carol withdrew from Alice before they were ever friends here; her
    // acceptance from before it is refused.
    let cutoff = withdraw(&carol, 0, &alice, t, t);
    present(&mut c, &[Presentation::Withdrawal(&cutoff)]).await;
    let o = offer(&alice, 0, &carol, t - 120);
    ok(
        &mut a,
        ClientHdr::AddFriend,
        im::add_friend_offering(b"carol", &o),
    )
    .await;
    let before_it = accept(&o, &carol, 0, t - 60);
    assert_eq!(
        refused(
            &mut c,
            ClientHdr::FriendResponse,
            im::friend_response_with(b"alice", &before_it)
        )
        .await,
        Some(ReasonCode::Withdrawn),
        "805 with a half a withdrawal held here ends"
    );
}

#[tokio::test]
async fn get_friendships_answers_a_rotation_in_chain_order() {
    let (alice, bob, next) = (alice(), bob(), successor());
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path()).await;
    // Alice's card commits to her successor, so this server anchors it.
    let mut committed = Card::new(&alice.id, "alice", now());
    committed.successor = Some(fp(&next).0);
    let committed = committed.sign(&alice.id, vec![]).unwrap();
    let mut alice0 = ng_device(&s, &alice, &committed, json!({})).await;
    let mut bob0 = classic_device(&s, "bob", &bob, 0).await;
    let o = offer(&alice, 0, &bob, now() - 60);
    alice0
        .request("friend_add", json!({ "login": "bob", "offer": b64(&o) }))
        .await
        .unwrap();
    told(&mut bob0, ServerHdr::FriendRequest, "alice", |e| {
        e.offer == Some(o.as_slice())
    })
    .await;
    let f = accept(&o, &bob, 0, now() - 60);
    ok(
        &mut bob0,
        ClientHdr::FriendResponse,
        im::friend_response_with(b"alice", &f),
    )
    .await;

    let record = Rotation {
        identity: alice.id.public(),
        successor: next.id.public(),
        time: now(),
    }
    .sign(&alice.id, &next.id)
    .unwrap();
    ng_device(
        &s,
        &next,
        &card(&next, "alice"),
        json!({ "rotation": b64(&record) }),
    )
    .await;

    let unknown = [7; 32];
    let fetched = ok(
        &mut bob0,
        ClientHdr::GetFriendships,
        im::get_friendships(&[
            FriendshipQuery::Hash(&hash(&f)),
            FriendshipQuery::Hash(&unknown),
            FriendshipQuery::Identity(&fp(&next).0),
        ]),
    )
    .await;
    let answers: Vec<(Vec<u8>, Vec<Vec<u8>>)> =
        parse_friendships(fetched.wire(), fetched.wire().len())
            .unwrap()
            .answers()
            .map(|a| match a {
                FriendshipAnswer::Friendship { hash, friendship } => (
                    hash.to_vec(),
                    friendship.into_iter().map(<[u8]>::to_vec).collect(),
                ),
                FriendshipAnswer::Rotations { identity, records } => {
                    (identity.to_vec(), records.map(<[u8]>::to_vec).collect())
                }
            })
            .collect();
    assert_eq!(
        answers,
        vec![
            (hash(&f).to_vec(), vec![f.clone()]),
            (unknown.to_vec(), vec![]),
            (fp(&next).0.to_vec(), vec![record]),
        ]
    );
}

#[tokio::test]
async fn bit_15_is_confirmed_only_beside_bits_6_and_13_where_a_device_can_be_proved() {
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path()).await;
    for (name, offered, want) in [
        ("everything", FRIENDS, CAP_FRIENDSHIPS),
        ("without bit 13", FRIENDS & !CAP_IDENTITY, 0),
        ("without bit 14", FRIENDS & !CAP_DEVICE_PROOF, 0),
        ("without bit 6", FRIENDS & !CAP_MESSAGING, 0),
    ] {
        let (_c, reply) = classic(&s, "alice", offered).await;
        assert_eq!(
            confirmed(&reply) & (CAP_IDENTITY | CAP_FRIENDSHIPS),
            want,
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_session_without_bit_15_and_a_period_client_see_nothing_new() {
    let (alice, bob) = (alice(), bob());
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path()).await;
    // A period client of Bob's own account, whose friends' traffic would
    // reach it were the family told to a session that never asked.
    let mut period = Client::login_at(s.plain, &Login::account("bob", "bob", "pw"))
        .await
        .unwrap();
    period.user_list().await.unwrap();
    let (mut plain_bob, reply) = classic(&s, "bob", CAP_MESSAGING | CAP_DEVICE_PROOF).await;
    assert_eq!(confirmed(&reply) & CAP_FRIENDSHIPS, 0);
    prove(&mut plain_bob, &s, &bob, 1).await;
    ok(&mut plain_bob, ClientHdr::GetRoster, Vec::new()).await;
    let mut alice0 = classic_device(&s, "alice", &alice, 0).await;
    let mut bob0 = ng_device(&s, &bob, &card(&bob, "bob"), json!({})).await;

    let o = offer(&alice, 0, &bob, now() - 60);
    ok(
        &mut alice0,
        ClientHdr::AddFriend,
        im::add_friend_offering(b"bob", &o),
    )
    .await;
    let req = told(&mut plain_bob, ServerHdr::FriendRequest, "alice", |_| true).await;
    let e = entry(&req);
    assert_eq!((e.offer, e.identity), (None, None), "a plain request");
    ng_event(&mut bob0, "friend_request", |d| d["login"] == "alice").await;
    bob0.request(
        "friend_respond",
        json!({ "login": "alice", "accept": true, "friendship": b64(&accept(&o, &bob, 0, now())) }),
    )
    .await
    .unwrap();
    let made = told(
        &mut plain_bob,
        ServerHdr::RosterEntry,
        "alice",
        state(RosterState::Accepted),
    )
    .await;
    let e = entry(&made);
    assert_eq!((hashes(&e), e.identity), (vec![], None), "a plain entry");
    let listed = ok(&mut plain_bob, ClientHdr::GetRoster, Vec::new()).await;
    let roster = parse_roster(listed.wire(), listed.wire().len()).unwrap();
    let row = roster.entries().find(|e| e.login == b"alice").unwrap();
    assert_eq!((hashes(&row), row.identity), (vec![], None));
    let found = ok(&mut plain_bob, ClientHdr::FindUser, im::find_user(b"alice")).await;
    assert!(found.chunk(tag::FRIEND_IDENTITY).is_none());

    // What only bit 15 opens is not there, and its fields are ignored.
    let refused = ask(
        &mut plain_bob,
        ClientHdr::PresentFriendships,
        im::present_friendships(&[Presentation::Friendship(b"f")]),
    )
    .await;
    assert_eq!(refused.error_text().as_deref(), Some("Not implemented."));
    let ignored = ok(
        &mut plain_bob,
        ClientHdr::AddFriend,
        im::add_friend_offering(b"carol", b"not an offer"),
    )
    .await;
    assert_eq!(
        ignored.uint(tag::ROSTER_STATE),
        Some(RosterState::PendingOut.wire().into())
    );

    period.chat(b"still here").await.unwrap();
    period.recv_where(|f| f.ty == push::CHAT).await.unwrap();
    let stray: Vec<u32> = period
        .rx
        .take_backlog()
        .iter()
        .map(|f| f.ty)
        .filter(|ty| ![push::CHAT, push::USER_CHANGE, push::SELFINFO].contains(ty))
        .collect();
    assert!(
        stray.is_empty(),
        "a period client hears none of it: {stray:x?}"
    );
}

#[tokio::test]
async fn a_session_that_proved_no_device_makes_no_friendship_act() {
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path()).await;
    let (mut c, reply) = classic(&s, "alice", FRIENDS).await;
    assert_eq!(confirmed(&reply) & CAP_FRIENDSHIPS, CAP_FRIENDSHIPS);
    let o = offer(&alice(), 0, &bob(), now());
    let junk: Vec<Vec<u8>> = (0..32u8).map(|n| vec![n; 64]).collect();
    let objects: Vec<Presentation<'_>> = junk.iter().map(|j| Presentation::Friendship(j)).collect();
    for (hdr, chunks) in [
        (ClientHdr::AddFriend, im::add_friend_offering(b"bob", &o)),
        (
            ClientHdr::PresentFriendships,
            im::present_friendships(&objects),
        ),
        (
            ClientHdr::GetFriendships,
            im::get_friendships(&[FriendshipQuery::Hash(&hash(&o))]),
        ),
    ] {
        for _ in 0..3 {
            let f = ask(&mut c, hdr, chunks.clone()).await;
            assert_eq!(f.error_text().as_deref(), Some(NOT_PROVED), "{hdr:?}");
            assert_eq!(reason(&f), None, "{hdr:?}");
        }
    }
    // What was refused spent its requests' own weight alone, not its
    // objects', of which three full presentations would leave no room.
    let mut proved = classic_device(&s, "alice", &alice(), 0).await;
    present(&mut proved, &objects).await;

    // But a run of empty requests is paced, proved or not.
    let (mut erin, reply) = classic(&s, "erin", FRIENDS).await;
    assert_eq!(confirmed(&reply) & CAP_FRIENDSHIPS, CAP_FRIENDSHIPS);
    let mut paced = false;
    for _ in 0..100 {
        let f = ask(&mut erin, ClientHdr::GetFriendships, Vec::new()).await;
        if reason(&f) == Some(ReasonCode::RateLimited) {
            paced = true;
            break;
        }
        assert_eq!(f.error_text().as_deref(), Some(NOT_PROVED));
    }
    assert!(paced, "a run of unproved 834s is paced");
}

#[tokio::test]
async fn presenting_is_paced_per_account_and_never_kicked_for() {
    let (alice, bob) = (alice(), bob());
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path()).await;
    let mut a = classic_device(&s, "alice", &alice, 0).await;
    let junk: Vec<Vec<u8>> = (0..33u8).map(|n| vec![n; 64]).collect();
    // Past the bound, refused before anything is spent.
    let too_many: im::Chunks = junk.iter().map(|j| (tag::FRIENDSHIP, j.clone())).collect();
    for _ in 0..3 {
        let f = ask(&mut a, ClientHdr::PresentFriendships, too_many.clone()).await;
        assert_eq!((f.is_error(), reason(&f)), (true, None));
    }
    let junk = &junk[..32];
    let objects: Vec<Presentation<'_>> = junk.iter().map(|j| Presentation::Friendship(j)).collect();
    for _ in 0..2 {
        let reply = present(&mut a, &objects).await;
        let got = outcomes(&reply);
        assert_eq!(got.len(), 32);
        assert!(got
            .iter()
            .all(|(_, r, _)| *r == Some(ReasonCode::BadSignature)));
    }
    assert_eq!(
        refused(
            &mut a,
            ClientHdr::PresentFriendships,
            im::present_friendships(&objects)
        )
        .await,
        Some(ReasonCode::RateLimited)
    );
    // A block is never held up by pacing: its withdrawal is taken, and
    // the block made, whatever is left.
    let w = withdraw(&alice, 0, &bob, now(), now());
    let blocked = ok(
        &mut a,
        ClientHdr::BlockUser,
        im::block_withdrawing(b"bob", &w),
    )
    .await;
    assert_eq!(reason(&blocked), Some(ReasonCode::Ok));
    let listed = ok(&mut a, ClientHdr::GetRoster, Vec::new()).await;
    let roster = parse_roster(listed.wire(), listed.wire().len()).unwrap();
    let row = roster.entries().find(|e| e.login == b"bob").unwrap();
    assert_eq!(row.roster_state(), Some(RosterState::Blocked));
    // Counted by the account, so reconnecting buys nothing.
    let junk_hashes: Vec<[u8; 32]> = junk.iter().map(|j| hash(j)).collect();
    let asked: Vec<FriendshipQuery<'_>> = junk_hashes.iter().map(FriendshipQuery::Hash).collect();
    let mut again = classic_device(&s, "alice", &alice, 1).await;
    assert_eq!(
        refused(
            &mut again,
            ClientHdr::GetFriendships,
            im::get_friendships(&asked)
        )
        .await,
        Some(ReasonCode::RateLimited)
    );
    // Paced, not kicked, and another account not held to it.
    ok(&mut a, ClientHdr::GetRoster, Vec::new()).await;
    let mut b = classic_device(&s, "bob", &bob, 0).await;
    ok(
        &mut b,
        ClientHdr::GetFriendships,
        im::get_friendships(&asked),
    )
    .await;
    // An empty request weighs something too.
    let mut paced = false;
    for _ in 0..100 {
        let f = ask(&mut b, ClientHdr::GetFriendships, Vec::new()).await;
        if reason(&f) == Some(ReasonCode::RateLimited) {
            paced = true;
            break;
        }
        assert!(!f.is_error(), "{:?}", f.error_text());
    }
    assert!(paced, "a run of empty 834s is paced");
}

#[tokio::test]
async fn a_block_withdrawing_says_nothing_of_whom_it_names() {
    let (alice, bob) = (alice(), bob());
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path()).await;
    let mut a = classic_device(&s, "alice", &alice, 0).await;
    let hour_ago = now() - 3600;
    // Nobody holds `nobody`; `erin` links no identity; `carol` is no
    // friend of Alice's.
    for (name, w, want) in [
        (
            "malformed",
            b"not a withdrawal".to_vec(),
            ReasonCode::BadSignature,
        ),
        (
            "an hour old",
            withdraw(&alice, 0, &bob, hour_ago, hour_ago),
            ReasonCode::Stale,
        ),
        (
            "for another pair",
            withdraw(&alice, 0, &bob, now(), now()),
            ReasonCode::Ok,
        ),
    ] {
        for who in ["nobody", "erin", "carol"] {
            let f = ask(
                &mut a,
                ClientHdr::BlockUser,
                im::block_withdrawing(who.as_bytes(), &w),
            )
            .await;
            assert_eq!(reason(&f), Some(want), "{name}, to {who}");
        }
    }
}

#[tokio::test]
async fn an_upgrade_offer_reaches_bit_15_sessions_alone_and_is_canceled_alone() {
    let (alice, bob, carol) = (alice(), bob(), carol());
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path()).await;
    let mut alice0 = classic_device(&s, "alice", &alice, 0).await;
    let mut bob0 = classic_device(&s, "bob", &bob, 0).await;
    let (mut plain_bob, _) = classic(&s, "bob", CAP_MESSAGING).await;
    ok(&mut plain_bob, ClientHdr::GetRoster, Vec::new()).await;
    befriend_classic(&mut alice0, &mut bob0, &alice, &bob).await;

    let up = offer(&alice, 0, &bob, now());
    let asked = ok(
        &mut alice0,
        ClientHdr::AddFriend,
        im::add_friend_offering(b"bob", &up),
    )
    .await;
    assert_eq!(
        (reason(&asked), asked.uint(tag::ROSTER_STATE)),
        (
            Some(ReasonCode::Ok),
            Some(RosterState::Accepted.wire().into())
        ),
        "an upgrade offer is not AlreadyFriends"
    );
    told(&mut bob0, ServerHdr::FriendRequest, "alice", |e| {
        e.offer == Some(up.as_slice())
    })
    .await;
    // Waiting, it goes after the roster's reply, the friend still a
    // friend.
    let mut bob1 = classic_device(&s, "bob", &bob, 1).await;
    let listed = ok(&mut bob1, ClientHdr::GetRoster, Vec::new()).await;
    let roster = parse_roster(listed.wire(), listed.wire().len()).unwrap();
    let row = roster.entries().find(|e| e.login == b"alice").unwrap();
    assert_eq!(row.roster_state(), Some(RosterState::Accepted));
    told(&mut bob1, ServerHdr::FriendRequest, "alice", |e| {
        e.offer == Some(up.as_slice())
    })
    .await;

    // Canceled, the offer alone goes.
    let canceled = ok(
        &mut alice0,
        ClientHdr::RemoveFriend,
        im::remove_friend_with(Who::Login(b"bob"), Some(&up), None),
    )
    .await;
    assert_eq!(reason(&canceled), Some(ReasonCode::Ok));
    let mut bob2 = classic_device(&s, "bob", &bob, 1).await;
    let listed = ok(&mut bob2, ClientHdr::GetRoster, Vec::new()).await;
    let roster = parse_roster(listed.wire(), listed.wire().len()).unwrap();
    let row = roster.entries().find(|e| e.login == b"alice").unwrap();
    assert_eq!(row.roster_state(), Some(RosterState::Accepted));
    ok(&mut bob2, ClientHdr::FindUser, im::find_user(b"alice")).await;
    assert!(
        !bob2
            .rx
            .take_backlog()
            .iter()
            .any(|f| f.ty == ServerHdr::FriendRequest.as_u32()),
        "no offer waits once canceled"
    );
    ok(&mut plain_bob, ClientHdr::FindUser, im::find_user(b"alice")).await;
    let requests: Vec<Frame> = plain_bob
        .rx
        .take_backlog()
        .into_iter()
        .filter(|f| f.ty == ServerHdr::FriendRequest.as_u32())
        .collect();
    assert_eq!(
        requests.len(),
        1,
        "the first request alone, not the upgrade"
    );
    assert_eq!(entry(&requests[0]).offer, None);

    // 803 may name its party by fingerprint, answered alike whether or
    // not there was anything to drop.
    for (who, ends) in [(fp(&carol), false), (fp(&bob), true)] {
        let f = ok(
            &mut alice0,
            ClientHdr::RemoveFriend,
            im::remove_friend_with(Who::Identity(&who.0), None, None),
        )
        .await;
        assert_eq!(reason(&f), Some(ReasonCode::Ok), "{who}");
        if ends {
            told(
                &mut bob0,
                ServerHdr::RosterEntry,
                "alice",
                state(RosterState::Removed),
            )
            .await;
        }
    }
}

#[tokio::test]
async fn an_identity_guest_is_listed_and_answered_only_where_it_can_be_named() {
    use hxproto::messaging::{parse_message_requests, Presence, RequestAction};
    let (bob, next) = (bob(), successor());
    let d = tempfile::tempdir().unwrap();
    let s = start(d.path()).await;
    let erin_ng = |naming: bool| async move {
        let mut c = ng::Client::connect(s.ng).await.unwrap();
        let hello = c
            .login(
                json!({ "login": "erin", "password": "pw", "messaging": true,
                           "guest_identities": naming }),
            )
            .await
            .unwrap();
        let caps = hello["caps"].as_array().unwrap().clone();
        assert_eq!(caps.contains(&json!("guest_identities")), naming, "{hello}");
        c
    };
    let (mut erin, mut erin_plain) = (erin_ng(true).await, erin_ng(false).await);
    erin.request("presence", json!({ "takes_requests": true }))
        .await
        .unwrap();
    let mut bob15 = classic_device(&s, "bob", &bob, 0).await;
    let (mut bob6, _) = classic(&s, "bob", CAP_MESSAGING).await;
    let takes = im::set_presence(&Presence {
        state: None,
        status_text: None,
        discoverable: None,
        takes_requests: Some(true),
    });
    ok(&mut bob15, ClientHdr::SetPresence, takes).await;

    let mut plain = ng::Client::connect(s.ng).await.unwrap();
    plain.login(json!({ "nick": "visitor" })).await.unwrap();
    let mut guest = ng_socket(&s, &next, &card(&next, "next"), json!({})).await;
    guest.login(json!({})).await.unwrap();
    for to in ["erin", "bob"] {
        for c in [&mut plain, &mut guest] {
            let sent = c
                .request("msg", json!({ "to_login": to, "text": "hi" }))
                .await
                .unwrap();
            assert_eq!(sent["requested"], true, "{to}");
        }
    }

    // On the ng wire, by the capability.
    let key = fp(&next).to_string();
    let named = |listed: &Value| -> Vec<Value> {
        listed["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g.get("fingerprint").cloned().unwrap_or(Value::Null))
            .collect()
    };
    let listed = erin.request("requests", json!({})).await.unwrap();
    assert_eq!(named(&listed), [Value::Null, json!(key)]);
    let listed = erin_plain.request("requests", json!({})).await.unwrap();
    assert_eq!(named(&listed), [Value::Null]);
    let answer = json!({ "fingerprint": key, "action": "approve" });
    match erin_plain.request("request_answer", answer.clone()).await {
        Err(hxd_testclient::Error::Refused { code, .. }) => assert_eq!(code, "no_such_request"),
        other => panic!("{other:?}"),
    }
    erin.request("request_answer", answer).await.unwrap();
    let listed = erin.request("requests", json!({})).await.unwrap();
    assert_eq!(
        listed["approvals"],
        json!([{ "login": "guest", "fingerprint": key }])
    );
    guest
        .request("msg", json!({ "to_login": "erin", "text": "let in" }))
        .await
        .unwrap();
    ng_event(&mut erin, "msg", |d| d["text"] == "let in").await;

    // On the classic wire, by bit 15.
    let groups = |f: &Frame| -> Vec<Option<[u8; 32]>> {
        parse_message_requests(f.wire(), f.wire().len())
            .unwrap()
            .groups()
            .map(|g| g.identity.copied())
            .collect()
    };
    let listed = ok(&mut bob15, ClientHdr::GetMessageRequests, Vec::new()).await;
    assert_eq!(groups(&listed), [None, Some(fp(&next).0)]);
    let listed = ok(&mut bob6, ClientHdr::GetMessageRequests, Vec::new()).await;
    assert_eq!(groups(&listed), [None]);
    let delete = RequestAction::Delete.wire().to_be_bytes().to_vec();
    // Without bit 15 the identity is no field of its, and `guest` names
    // the plain guests as it always did.
    let answer = vec![
        (tag::FRIEND_LOGIN, b"guest".to_vec()),
        (tag::FRIEND_IDENTITY, fp(&next).0.to_vec()),
        (tag::REQUEST_ACTION, delete.clone()),
    ];
    ok(&mut bob6, ClientHdr::AnswerMessageRequest, answer).await;
    let listed = ok(&mut bob15, ClientHdr::GetMessageRequests, Vec::new()).await;
    assert_eq!(groups(&listed), [Some(fp(&next).0)]);
    let answer = vec![
        (tag::FRIEND_IDENTITY, fp(&next).0.to_vec()),
        (tag::REQUEST_ACTION, delete),
    ];
    ok(&mut bob15, ClientHdr::AnswerMessageRequest, answer).await;
    let listed = ok(&mut bob15, ClientHdr::GetMessageRequests, Vec::new()).await;
    assert!(groups(&listed).is_empty());
}
