//! The Hotline-ng wire: JSON requests and replies, seq-stamped events,
//! login, resume and sync, over a WebSocket.
//!
//! Every event's seq is checked as it arrives. The protocol promises a
//! gapless, monotonic stream per session, across resumes; a violation is
//! recorded in [`Receiver::seq_faults`] rather than raised, so a load run
//! can count them and a test can assert there are none.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::{Error, Result, DEFAULT_TIMEOUT};

/// Anything a WebSocket can run over.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type Ws = WebSocketStream<Box<dyn Io>>;

/// One event, as the server stamped it.
#[derive(Debug, Clone)]
pub struct Event {
    pub seq: u64,
    pub ev: String,
    pub data: Value,
}

/// A seq that was not the one after the last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqFault {
    pub expected: u64,
    pub got: u64,
}

/// How a resume went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resumed {
    /// The gap was replayed: this many events follow the reply.
    Replayed(u64),
    /// The gap is gone; the client must `sync` before it trusts its view.
    ResyncRequired,
}

/// The sending half of a connection.
pub struct Sender {
    sink: SplitSink<Ws, Message>,
    next_id: u64,
    /// How long one send may take: a server that has stopped reading
    /// must not hold a sender forever.
    pub timeout: Duration,
}

impl Sender {
    /// Send a request without waiting for its reply; returns its id.
    pub async fn send(&mut self, method: &str, params: Value) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let mut req = json!({ "id": id, "req": method });
        if !params.is_null() {
            req["params"] = params;
        }
        timeout(self.timeout, self.sink.send(Message::Text(req.to_string())))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(ws_error)?;
        Ok(id)
    }

    /// Send a close frame.
    pub async fn close(&mut self) -> Result<()> {
        self.sink.close().await.map_err(ws_error)
    }
}

/// The receiving half. It checks every event's seq as it arrives and
/// keeps what the caller has not asked for yet, oldest first.
pub struct Receiver {
    stream: SplitStream<Ws>,
    backlog: VecDeque<Event>,
    pub timeout: Duration,
    /// The last seq accounted for.
    pub last_seq: u64,
    pub seq_faults: Vec<SeqFault>,
    /// The server has said the gap since `last_seq` is gone (a resume
    /// answered `resync_required`): the next event may jump ahead, once,
    /// until a `sync` accounts for it.
    pub gap_expected: bool,
}

impl Receiver {
    /// The next thing off the socket, reply or event, backlog first.
    pub async fn next(&mut self) -> Result<Incoming> {
        if let Some(e) = self.backlog.pop_front() {
            return Ok(Incoming::Event(e));
        }
        timeout(self.timeout, self.read())
            .await
            .map_err(|_| Error::Timeout)?
    }

    /// The same with no timeout at all: for a reader that waits as long
    /// as the run does.
    pub async fn next_forever(&mut self) -> Result<Incoming> {
        if let Some(e) = self.backlog.pop_front() {
            return Ok(Incoming::Event(e));
        }
        self.read().await
    }

    /// The reply to `id`; events meanwhile go to the backlog, and an
    /// error reply is `Err(Refused)`.
    pub async fn reply(&mut self, id: u64) -> Result<Value> {
        // For the whole wait: steady events must not stretch it.
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            let got = tokio::time::timeout_at(deadline, self.read())
                .await
                .map_err(|_| Error::Timeout)??;
            match got {
                Incoming::Reply(v) if v["reply"].as_u64() == Some(id) => return reply_value(v),
                Incoming::Reply(v) => {
                    return Err(Error::Protocol(format!("reply to another request: {v}")));
                }
                Incoming::Event(e) => self.backlog.push_back(e),
            }
        }
    }

    /// The first event named `ev` for which `pred` holds; the rest stay
    /// in the backlog in order.
    pub async fn event_where(&mut self, ev: &str, pred: impl Fn(&Value) -> bool) -> Result<Event> {
        if let Some(i) = self
            .backlog
            .iter()
            .position(|e| e.ev == ev && pred(&e.data))
        {
            return Ok(self.backlog.remove(i).expect("position is in range"));
        }
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            let got = tokio::time::timeout_at(deadline, self.read())
                .await
                .map_err(|_| Error::Timeout)??;
            match got {
                Incoming::Event(e) if e.ev == ev && pred(&e.data) => return Ok(e),
                Incoming::Event(e) => self.backlog.push_back(e),
                Incoming::Reply(v) => {
                    return Err(Error::Protocol(format!("unexpected reply: {v}")));
                }
            }
        }
    }

    pub async fn event(&mut self, ev: &str) -> Result<Event> {
        self.event_where(ev, |_| true).await
    }

    pub fn take_backlog(&mut self) -> Vec<Event> {
        self.backlog.drain(..).collect()
    }

    async fn read(&mut self) -> Result<Incoming> {
        loop {
            let msg = self
                .stream
                .next()
                .await
                .ok_or(Error::Closed)?
                .map_err(ws_error)?;
            let text = match msg {
                Message::Text(t) => t,
                Message::Close(_) => return Err(Error::Closed),
                _ => continue,
            };
            let v: Value = serde_json::from_str(&text)
                .map_err(|e| Error::Protocol(format!("not JSON: {e}")))?;
            if v.get("reply").is_some() {
                return Ok(Incoming::Reply(v));
            }
            let (Some(seq), Some(ev)) = (v["seq"].as_u64(), v["ev"].as_str()) else {
                return Err(Error::Protocol(format!("neither reply nor event: {v}")));
            };
            let jumped = self.gap_expected && seq > self.last_seq;
            self.gap_expected = false;
            if seq != self.last_seq + 1 && !jumped {
                self.seq_faults.push(SeqFault {
                    expected: self.last_seq + 1,
                    got: seq,
                });
            }
            self.last_seq = self.last_seq.max(seq);
            return Ok(Incoming::Event(Event {
                seq,
                ev: ev.to_owned(),
                data: v["data"].clone(),
            }));
        }
    }
}

fn reply_value(v: Value) -> Result<Value> {
    if let Some(err) = v.get("error") {
        return Err(Error::Refused {
            code: err["code"].as_str().unwrap_or_default().to_owned(),
            text: err["text"].as_str().unwrap_or_default().to_owned(),
        });
    }
    Ok(v["ok"].clone())
}

/// A scripted ng client: a [`Sender`] and a [`Receiver`] over one
/// socket, which [`Client::split`] hands out separately.
pub struct Client {
    pub tx: Sender,
    pub rx: Receiver,
    /// `(session, token)`, once logged in: what a resume presents.
    pub session: Option<(String, String)>,
    /// The uid the server gave this session.
    pub uid: Option<u64>,
}

impl Client {
    /// `ws://addr/ng`.
    pub async fn connect(addr: SocketAddr) -> Result<Client> {
        let tcp = timeout(DEFAULT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| Error::Timeout)??;
        tcp.set_nodelay(true)?;
        Client::over(Box::new(tcp), &format!("ws://{addr}/ng")).await
    }

    /// `wss://host/ng` through TLS at `addr` — a reverse proxy, since the
    /// ng listener itself speaks plain HTTP.
    pub async fn connect_tls(
        addr: SocketAddr,
        host: &str,
        config: Arc<ClientConfig>,
    ) -> Result<Client> {
        let name = ServerName::try_from(host.to_owned())
            .map_err(|e| Error::Protocol(format!("server name: {e}")))?;
        let tls = timeout(DEFAULT_TIMEOUT, async {
            let tcp = TcpStream::connect(addr).await?;
            tcp.set_nodelay(true)?;
            TlsConnector::from(config).connect(name, tcp).await
        })
        .await
        .map_err(|_| Error::Timeout)??;
        Client::over(Box::new(tls), &format!("wss://{host}/ng")).await
    }

    /// Upgrade a stream the caller opened, at `url`.
    pub async fn over(stream: Box<dyn Io>, url: &str) -> Result<Client> {
        let (ws, _) = timeout(
            DEFAULT_TIMEOUT,
            tokio_tungstenite::client_async(url, stream),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|e| Error::Protocol(format!("upgrade: {e}")))?;
        let (sink, stream) = ws.split();
        Ok(Client {
            tx: Sender {
                sink,
                next_id: 1,
                timeout: DEFAULT_TIMEOUT,
            },
            rx: Receiver {
                stream,
                backlog: VecDeque::new(),
                timeout: DEFAULT_TIMEOUT,
                last_seq: 0,
                seq_faults: Vec::new(),
                gap_expected: false,
            },
            session: None,
            uid: None,
        })
    }

    /// Connect and log in as a guest.
    pub async fn guest(addr: SocketAddr, nick: &str) -> Result<(Client, Value)> {
        let mut c = Client::connect(addr).await?;
        let hello = c.login(json!({ "nick": nick })).await?;
        Ok((c, hello))
    }

    /// Connect and log in to an account.
    pub async fn account(
        addr: SocketAddr,
        login: &str,
        password: &str,
        nick: &str,
    ) -> Result<(Client, Value)> {
        let mut c = Client::connect(addr).await?;
        let hello = c
            .login(json!({ "login": login, "password": password, "nick": nick }))
            .await?;
        Ok((c, hello))
    }

    /// `login` with these params; the reply's `ok` on success.
    pub async fn login(&mut self, params: Value) -> Result<Value> {
        let ok = self.request("login", params).await?;
        self.rx.last_seq = ok["seq"].as_u64().unwrap_or(0);
        self.uid = ok["self"]["uid"].as_u64();
        if let (Some(s), Some(t)) = (ok["session"].as_str(), ok["token"].as_str()) {
            self.session = Some((s.to_owned(), t.to_owned()));
        }
        Ok(ok)
    }

    /// Open a new connection and resume the session `session` names,
    /// from `last_seq`, carrying `faults` over so a run's seq record
    /// spans its reconnects.
    pub async fn resume(
        addr: SocketAddr,
        session: (String, String),
        last_seq: u64,
        faults: Vec<SeqFault>,
    ) -> Result<(Client, Resumed)> {
        let mut c = Client::connect(addr).await?;
        c.rx.last_seq = last_seq;
        c.rx.seq_faults = faults;
        c.session = Some(session.clone());
        let params = json!({ "session": session.0, "token": session.1, "last_seq": last_seq });
        match c.request("resume", params).await {
            Ok(ok) => {
                c.uid = ok["self"]["uid"].as_u64();
                let n = ok["replay"].as_u64().unwrap_or(0);
                Ok((c, Resumed::Replayed(n)))
            }
            Err(Error::Refused { code, .. }) if code == "resync_required" => {
                c.rx.gap_expected = true;
                Ok((c, Resumed::ResyncRequired))
            }
            Err(e) => Err(e),
        }
    }

    /// `sync`: the server's view, and the seq it is current to, which
    /// becomes this client's.
    pub async fn sync(&mut self) -> Result<Value> {
        let ok = self.request("sync", Value::Null).await?;
        if let Some(seq) = ok["seq"].as_u64() {
            self.rx.last_seq = self.rx.last_seq.max(seq);
        }
        // Whatever gap a resync left is accounted for now.
        self.rx.gap_expected = false;
        Ok(ok)
    }

    /// Send a request and wait for its reply.
    pub async fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.tx.send(method, params).await?;
        self.rx.reply(id).await
    }

    pub async fn next(&mut self) -> Result<Incoming> {
        self.rx.next().await
    }

    /// The next event, backlog first; a stray reply is an error.
    pub async fn next_event(&mut self) -> Result<Event> {
        match self.rx.next().await? {
            Incoming::Event(e) => Ok(e),
            Incoming::Reply(v) => Err(Error::Protocol(format!("unexpected reply: {v}"))),
        }
    }

    pub async fn event_where(&mut self, ev: &str, pred: impl Fn(&Value) -> bool) -> Result<Event> {
        self.rx.event_where(ev, pred).await
    }

    pub async fn event(&mut self, ev: &str) -> Result<Event> {
        self.rx.event(ev).await
    }

    /// Send a public chat line.
    pub async fn chat(&mut self, text: &str) -> Result<Value> {
        self.request("chat", json!({ "text": text })).await
    }

    /// Log out cleanly: the session ends, and it will not detach.
    pub async fn logout(mut self) -> Result<()> {
        self.request("logout", Value::Null).await?;
        let _ = self.tx.close().await;
        Ok(())
    }

    /// Close the socket with a close frame: the connection is lost, and
    /// a session that may detach does.
    pub async fn close(mut self) -> Result<()> {
        self.tx.close().await
    }

    pub fn split(self) -> (Sender, Receiver) {
        (self.tx, self.rx)
    }
}

/// What came off the socket.
#[derive(Debug)]
pub enum Incoming {
    Reply(Value),
    Event(Event),
}

fn ws_error(e: tokio_tungstenite::tungstenite::Error) -> Error {
    use tokio_tungstenite::tungstenite::Error as E;
    match e {
        E::ConnectionClosed | E::AlreadyClosed => Error::Closed,
        E::Io(io) => Error::from(io),
        other => Error::Protocol(other.to_string()),
    }
}
