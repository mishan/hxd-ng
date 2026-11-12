//! A whole classic connection from its first byte: the TRTP hello, the
//! login, and every transaction after it dispatched against a real core.
#![no_main]

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use hxd_core::{
    AuthBackend, Core, HistoryPolicy, InboxPolicy, MemoryLog, MemoryStore, ReactionPolicy,
};
use hxd_session::{cap, run_session, Caps, ServerConfig, ServerCtx};
use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Env {
    rt: tokio::runtime::Runtime,
    auth: Arc<hxd_auth_file::FileAuth>,
    cfg: Arc<ServerConfig>,
    _dir: tempfile::TempDir,
}

fn env() -> &'static Env {
    static ENV: OnceLock<Env> = OnceLock::new();
    ENV.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let accounts = dir.path().join("accounts");
        hxd_auth_file::FileAuth::bootstrap(&accounts).unwrap();
        // An account that may react and answer mail, which a guest may not.
        std::fs::write(
            accounts.join("fuzz.toml"),
            "name = \"fuzz\"\npassword = \"fuzz\"\n[access]\nread_chat = true\nsend_chat = true\n\
             send_msgs = true\n",
        )
        .unwrap();
        Env {
            rt: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap(),
            auth: Arc::new(hxd_auth_file::FileAuth::new(accounts)),
            cfg: Arc::new(ServerConfig {
                agreement: Some("agreement".into()),
                caps: Caps::empty()
                    .with(cap::TEXT_ENCODING)
                    .with(cap::CHAT_HISTORY)
                    .with(cap::STRUCTURED_CHAT)
                    .with(cap::REPLIES)
                    .with(cap::REACTIONS),
                ..ServerConfig::default()
            }),
            _dir: dir,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let env = env();
    env.rt.block_on(async {
        // A core per input, so no ban or flood count carries between them,
        // with a log for its lines to be reacted to on and an inbox for
        // its messages to be answered by.
        let core = Core::new()
            .with_history(Arc::new(MemoryLog::default()), HistoryPolicy::default())
            .with_reactions(ReactionPolicy::default())
            .with_inbox(
                Arc::new(MemoryStore::new()),
                env.auth.clone(),
                InboxPolicy::default(),
            );
        let ctx = ServerCtx {
            core: Arc::new(core),
            auth: env.auth.clone() as Arc<dyn AuthBackend>,
            cfg: env.cfg.clone(),
            files: None,
            banner: None,
            device_proof: None,
        };
        let peer = SocketAddr::from(([127, 0, 0, 1], 5500));
        let place = ctx.core.admit_connection(peer.ip()).unwrap();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let session = tokio::spawn(run_session(
            server,
            peer,
            ctx,
            Default::default(),
            Default::default(),
            place,
        ));
        let (mut rd, mut wr) = tokio::io::split(client);
        let drain = tokio::spawn(async move { rd.read_to_end(&mut Vec::new()).await });
        let _ = wr.write_all(data).await;
        let _ = wr.shutdown().await;
        session.await.unwrap();
        let _ = drain.await.unwrap();
    });
});
