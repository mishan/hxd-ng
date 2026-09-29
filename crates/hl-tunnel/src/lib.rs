//! The TRTP-over-WebSocket transport (`docs/hotline-ng-auth.md` §7.3):
//! a WebSocket whose binary frames, concatenated, are the byte stream a
//! TCP connection to the legacy port would carry. This adapter presents
//! such a socket as `AsyncRead + AsyncWrite`, so that whatever sits on
//! the far side of it — hxd-ng's legacy frontend, or `hlrelay`'s copy to
//! a classic server's TCP port (§10.2) — runs without knowing it isn't
//! on TCP.
//!
//! Frame boundaries carry no meaning: reads drain whatever frame arrived,
//! writes send each `poll_write` buffer as one frame. Text frames are a
//! protocol error and end the stream; a close frame is EOF.
//!
//! A write is queued in the WebSocket sink until a flush; `poll_write`
//! tries one opportunistically, but a writer that stops after a write
//! and never flushes can leave the last frame sitting there. The legacy
//! frontend flushes after every write for exactly this reason, and
//! `tokio::io::copy` flushes whenever its reader has nothing more.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll, Waker};
use std::time::Duration;

use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{interval_at, Instant, Interval, MissedTickBehavior};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// How often the server pings a quiet tunnel — the same clock the JSON
/// path uses, for the same reasons.
const PING_EVERY: Duration = Duration::from_secs(30);

/// How many ping periods of silence end the stream. A ping with no
/// deadline behind it asks a question and accepts no answer: the peer
/// that went away is exactly the case it is for, and without this the
/// tunnel lives until TCP gives up. Three periods so one lost ping, or
/// one tick delayed behind a busy socket, is not a disconnection.
const SILENT_PERIODS: u32 = 3;

pub struct WsByteStream<S> {
    ws: WebSocketStream<S>,
    /// Unread tail of the last binary frame.
    pending: Vec<u8>,
    pending_at: usize,
    eof: bool,
    /// Server-initiated keep-alive, driven from the read side.
    ping: Interval,
    /// A tick found the socket too busy to take a ping; the next write
    /// or flush that finds it ready sends one.
    ping_owed: bool,
    /// How long the peer may be silent before the keep-alive counts as
    /// unanswered, and when it last showed any sign of life: a frame
    /// from it, or a write it drained (`Stall`).
    silence: Duration,
    heard: Instant,
    stall: Stall,
    /// The task last parked on a write, which a sink call made from the
    /// read side can rob of its wake-up (`wake_writer`).
    writer: Option<Waker>,
}

/// Which of the sink's calls last had to wait for the peer to drain.
/// One that then completes is the peer reading what it was sent, which
/// is as much a sign of life as a frame from it: a download's client
/// says nothing after its request, and on a link the transfer fills,
/// its pongs arrive behind the data or its pings wait for room, so the
/// frames it sends alone would call it gone mid-file.
///
/// Only a completion that had to wait counts. A write the socket takes
/// at once proves nothing, since a peer that has gone away still has
/// buffers to fill; once they are full, a peer that is gone never lets
/// another write through, and the deadline ends it as before. And
/// `poll_ready` counts only its own waits, as it answers from a flag,
/// without touching the socket, while a flush is still under way.
#[derive(Default)]
struct Stall {
    ready: bool,
    flush: bool,
}

impl<S> WsByteStream<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self::with_ping_period(ws, PING_EVERY)
    }

    /// The same, with the keep-alive period named — for tests, which
    /// cannot wait half a minute to see one.
    pub(crate) fn with_ping_period(ws: WebSocketStream<S>, every: Duration) -> Self {
        // `interval_at`, not `interval`: the latter's first tick is
        // immediate, and a ping before the client has said anything is
        // noise on every connection.
        let mut ping = interval_at(Instant::now() + every, every);
        ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
        WsByteStream {
            ws,
            pending: Vec::new(),
            pending_at: 0,
            eof: false,
            ping,
            ping_owed: false,
            silence: every * SILENT_PERIODS,
            heard: Instant::now(),
            stall: Stall::default(),
            writer: None,
        }
    }
}

impl<S> WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// The sink's `poll_ready`, noting a wait and the drain that ends it.
    fn sink_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let p = Pin::new(&mut self.ws).poll_ready(cx).map_err(ws_err);
        match p {
            Poll::Pending => self.stall.ready = true,
            Poll::Ready(Ok(())) if self.stall.ready => {
                self.stall.ready = false;
                self.heard = Instant::now();
            }
            Poll::Ready(_) => {}
        }
        p
    }

    /// The sink's `poll_flush`, the same way. A flush that completes has
    /// written everything queued, whichever call had been waiting.
    fn sink_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let p = Pin::new(&mut self.ws).poll_flush(cx).map_err(ws_err);
        match p {
            Poll::Pending => self.stall.flush = true,
            Poll::Ready(Ok(())) => {
                if self.stall.flush || self.stall.ready {
                    self.heard = Instant::now();
                }
                self.stall = Stall::default();
            }
            Poll::Ready(Err(_)) => {}
        }
        p
    }

    /// Queue a ping if the sink will take one now, and push it out if the
    /// socket will; otherwise it stays owed. Called only once the sink
    /// has said it is ready.
    fn send_ping(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        Pin::new(&mut self.ws)
            .start_send(Message::Ping(Vec::new()))
            .map_err(ws_err)?;
        self.ping_owed = false;
        if let Poll::Ready(Err(e)) = self.sink_flush(cx) {
            return Err(e);
        }
        Ok(())
    }

    /// Remember the task a write parks, for `wake_writer`.
    fn note_writer(&mut self, cx: &Context<'_>) {
        match &self.writer {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => self.writer = Some(cx.waker().clone()),
        }
    }

    /// The sink keeps one waker for writes, so a sink call from the read
    /// side of a `tokio::io::split` replaces the write side's, and a
    /// writer parked on a full socket would never hear that it drained.
    /// Wake it, so that it polls again and registers itself afresh.
    fn wake_writer(&self, cx: &Context<'_>) {
        if let Some(w) = &self.writer {
            if !w.will_wake(cx.waker()) {
                w.wake_by_ref();
            }
        }
    }
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::other(e)
}

impl<S> AsyncRead for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pending_at < this.pending.len() {
                let n = (this.pending.len() - this.pending_at).min(buf.remaining());
                let at = this.pending_at;
                buf.put_slice(&this.pending[at..at + n]);
                this.pending_at += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            // Keep-alive. A tunnelled session can be silent for hours —
            // a classic client watching chat sends nothing — and nothing
            // else on this path would notice a peer that went away or a
            // NAT that dropped the mapping; the JSON path has pinged
            // every 30 s since it was written. It goes out from here
            // because the read side is the task that is otherwise
            // parked, and because polling the stream is what registers
            // the timer's wake-up. The halves of a `tokio::io::split`
            // take turns, so the writer cannot be mid-frame while this
            // runs.
            if this.ping.poll_tick(cx).is_ready() {
                // Nothing at all since the last few pings: the peer is
                // gone. Any frame counts as an answer — tungstenite
                // hands pongs up, and a client that is talking is not
                // the case this is about — and so does a write it
                // drained (`Stall`). A peer that neither talks nor
                // reads is dropped here, however much is queued for it.
                if this.heard.elapsed() >= this.silence {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "tunnel silent past the pong deadline",
                    )));
                }
                // Not ready to send is not an error: the socket is
                // busy, which is the thing a ping is asking about. The
                // ping is owed instead, and the write side sends it as
                // soon as the socket has room.
                let sent = match this.sink_ready(cx) {
                    Poll::Ready(Ok(())) => this.send_ping(cx),
                    Poll::Ready(Err(e)) => Err(e),
                    Poll::Pending => {
                        this.ping_owed = true;
                        Ok(())
                    }
                };
                this.wake_writer(cx);
                sent?;
                // Register for the *next* tick before parking. A ready
                // tick consumed the timer's wake-up, and the only other
                // one on this task belongs to the WebSocket — so without
                // this, a peer that says nothing never wakes this task
                // again and the deadline above is never reached.
                // `while`, not `if`: `MissedTickBehavior::Delay` cannot
                // hand back two ready ticks in a row today, and this does
                // not depend on that staying true.
                while this.ping.poll_tick(cx).is_ready() {}
            }
            let frame = ready!(Pin::new(&mut this.ws).poll_next(cx));
            this.heard = Instant::now();
            match frame {
                Some(Ok(Message::Binary(data))) => {
                    this.pending = data;
                    this.pending_at = 0;
                }
                // tungstenite answers pings itself; pongs and frames
                // carrying nothing are just skipped.
                Some(Ok(Message::Ping(_)))
                | Some(Ok(Message::Pong(_)))
                | Some(Ok(Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "text frame on a TRTP tunnel",
                    )));
                }
                Some(Err(e)) => return Poll::Ready(Err(ws_err(e))),
            }
        }
    }
}

impl<S> AsyncWrite for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.note_writer(cx);
        ready!(this.sink_ready(cx))?;
        // A ping the read side could not send goes ahead of the data,
        // which then waits for the sink to be ready again, as the sink
        // requires of every send.
        if this.ping_owed {
            this.send_ping(cx)?;
            ready!(this.sink_ready(cx))?;
        }
        Pin::new(&mut this.ws)
            .start_send(Message::Binary(buf.to_vec()))
            .map_err(ws_err)?;
        // Push it out now if the socket will take it; if not, the data is
        // accepted and the caller's flush finishes the job.
        if let Poll::Ready(Err(e)) = this.sink_flush(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.note_writer(cx);
        if this.ping_owed {
            ready!(this.sink_ready(cx))?;
            this.send_ping(cx)?;
        }
        this.sink_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.note_writer(cx);
        Pin::new(&mut self.ws).poll_close(cx).map_err(ws_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::protocol::Role;

    #[tokio::test]
    async fn frames_become_bytes_and_back() {
        let (a, b) = tokio::io::duplex(4096);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(b, Role::Client, None).await;
        let mut stream = WsByteStream::new(server);

        // Two frames read as one contiguous byte run, across a small buffer.
        client.send(Message::Binary(b"hel".to_vec())).await.unwrap();
        client
            .send(Message::Binary(b"lo world".to_vec()))
            .await
            .unwrap();
        let mut got = [0u8; 11];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello world");

        // A write goes out as a binary frame.
        stream.write_all(b"reply").await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            Message::Binary(b"reply".to_vec())
        );

        // Text is a protocol error.
        client.send(Message::Text("nope".into())).await.unwrap();
        assert_eq!(
            stream.read(&mut [0u8; 4]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn a_quiet_tunnel_is_pinged() {
        // The legacy frontend's reader task is parked on a read for as
        // long as the client says nothing, which on this wire can be
        // hours. Without this the server would never notice a peer that
        // went away, and a NAT in between would drop the mapping.
        let (a, b) = tokio::io::duplex(4096);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(b, Role::Client, None).await;
        let mut stream = WsByteStream::with_ping_period(server, Duration::from_millis(20));

        // Nobody is writing; the read is what drives the clock.
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 8];
            let n = stream.read(&mut buf).await.unwrap();
            (stream, n)
        });
        let first = tokio::time::timeout(Duration::from_secs(5), client.next())
            .await
            .expect("a ping should arrive on a quiet tunnel")
            .unwrap()
            .unwrap();
        assert_eq!(first, Message::Ping(Vec::new()));
        // And it keeps happening, rather than being a one-off.
        let second = tokio::time::timeout(Duration::from_secs(5), client.next())
            .await
            .expect("and another")
            .unwrap()
            .unwrap();
        assert_eq!(second, Message::Ping(Vec::new()));

        // Bytes still arrive through all of it.
        client
            .send(Message::Binary(b"hello".to_vec()))
            .await
            .unwrap();
        let (_stream, n) = tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("the read completes")
            .unwrap();
        assert_eq!(n, 5);
    }

    #[tokio::test]
    async fn a_peer_that_never_answers_ends_the_stream() {
        // The other half of the keep-alive: without a deadline the ping
        // asks a question and accepts no answer, and a tunnel whose peer
        // vanished lives until TCP gives up — minutes, or on a path that
        // silently blackholes, never.
        let (a, b) = tokio::io::duplex(4096);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, None).await;
        // The client is never polled, so it never pongs and never
        // closes: a peer that stopped reading.
        let _client = WebSocketStream::from_raw_socket(b, Role::Client, None).await;
        let mut stream = WsByteStream::with_ping_period(server, Duration::from_millis(20));
        let err = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0u8; 8]))
            .await
            .expect("the read must end on its own")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// The frames a server wrote, read off the raw socket: `(opcode,
    /// payload length)` for each whole one in `raw`. Server frames are
    /// never masked.
    fn frames(raw: &[u8]) -> Vec<(u8, usize)> {
        frame_payloads(raw)
            .iter()
            .map(|(op, payload)| (*op, payload.len()))
            .collect()
    }

    /// The same, with each frame's payload.
    fn frame_payloads(raw: &[u8]) -> Vec<(u8, &[u8])> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 2 <= raw.len() {
            let op = raw[at] & 0x0f;
            let (len, head) = match raw[at + 1] & 0x7f {
                126 if at + 4 <= raw.len() => {
                    (u16::from_be_bytes([raw[at + 2], raw[at + 3]]) as usize, 4)
                }
                127 if at + 10 <= raw.len() => {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(&raw[at + 2..at + 10]);
                    (u64::from_be_bytes(b) as usize, 10)
                }
                126 | 127 => break,
                n => (n as usize, 2),
            };
            if at + head + len > raw.len() {
                break;
            }
            out.push((op, &raw[at + head..at + head + len]));
            at += head + len;
        }
        out
    }

    #[tokio::test]
    async fn a_peer_that_drains_but_never_speaks_is_alive() {
        // A download over `/htxf`: after its request the client sends
        // nothing, and on a link the transfer fills the pings wait for
        // room and the pongs queue behind the data. The peer reading what
        // it is sent is its sign of life, and the transfer outlasts many
        // pong deadlines.
        // A period long enough that a stall of a CI runner does not make
        // the reader's deadline and the peer's next read ready together.
        const PERIOD: Duration = Duration::from_millis(250);
        const CHUNK: usize = 1024;
        const CHUNKS: usize = 120;
        let (a, mut b) = tokio::io::duplex(256);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, None).await;
        let stream = WsByteStream::with_ping_period(server, PERIOD);
        // Split, as the legacy frontend does, so the keep-alive runs on
        // the reader's task while the writer's is parked on a full socket.
        let (mut rd, mut wr) = tokio::io::split(stream);
        let reader = tokio::spawn(async move { rd.read(&mut [0u8; 8]).await });
        let writer = tokio::spawn(async move {
            for _ in 0..CHUNKS {
                wr.write_all(&[7u8; CHUNK]).await?;
                wr.flush().await?;
            }
            io::Result::Ok(wr)
        });

        // The peer: reads the raw socket slowly, never writes a byte, so
        // it answers no ping.
        let started = Instant::now();
        let mut raw = Vec::new();
        let mut buf = [0u8; 512];
        let data = |raw: &[u8]| -> usize {
            frames(raw)
                .iter()
                .filter(|(op, _)| *op == 0x2)
                .map(|(_, len)| len)
                .sum()
        };
        while data(&raw) < CHUNK * CHUNKS {
            let n = tokio::time::timeout(Duration::from_secs(5), b.read(&mut buf))
                .await
                .expect("the transfer keeps moving")
                .unwrap();
            assert!(n > 0, "the tunnel closed mid-transfer");
            raw.extend_from_slice(&buf[..n]);
            assert!(!reader.is_finished(), "{:?}", reader.await);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            started.elapsed() > PERIOD * SILENT_PERIODS * 2,
            "the transfer should outlast the deadline to show anything"
        );
        let _wr = tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .expect("the writer finishes")
            .unwrap()
            .unwrap();
        assert!(!reader.is_finished(), "{:?}", reader.await);
        // And pings went out through all of it, not skipped for want of
        // a moment the socket was idle.
        assert!(
            frames(&raw).iter().any(|(op, _)| *op == 0x9),
            "no ping was sent during the transfer"
        );
    }

    #[tokio::test]
    async fn a_ping_owed_to_a_full_socket_goes_ahead_of_the_next_write() {
        // A tick that finds the socket full cannot send its ping, and
        // owes it instead: the write that next finds room sends it first.
        // The sink only reports itself full once tungstenite's own buffer
        // is past its write_buffer_size (128 KiB), so the writer here
        // queues well past that without flushing, into a socket its peer
        // is not yet reading.
        const PERIOD: Duration = Duration::from_millis(250);
        const CHUNK: usize = 8 * 1024;
        const CHUNKS: usize = 64;
        let (a, mut b) = tokio::io::duplex(4096);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, None).await;
        let stream = WsByteStream::with_ping_period(server, PERIOD);
        let (mut rd, mut wr) = tokio::io::split(stream);
        let reader = tokio::spawn(async move { rd.read(&mut [0u8; 8]).await });
        let writer = tokio::spawn(async move {
            for i in 0..CHUNKS {
                wr.write_all(&[i as u8; CHUNK]).await?;
            }
            wr.flush().await?;
            io::Result::Ok(wr)
        });

        // One tick passes while the socket is full, well inside the
        // deadline, and then the peer reads everything as fast as it can.
        tokio::time::sleep(PERIOD * 3 / 2).await;
        assert!(!writer.is_finished(), "the writer should be parked");
        let mut raw = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        let data = |raw: &[u8]| -> usize {
            frames(raw)
                .iter()
                .filter(|(op, _)| *op == 0x2)
                .map(|(_, len)| len)
                .sum()
        };
        while data(&raw) < CHUNK * CHUNKS {
            let n = tokio::time::timeout(Duration::from_secs(5), b.read(&mut buf))
                .await
                .expect("the transfer keeps moving")
                .unwrap();
            assert!(n > 0, "the tunnel closed mid-transfer");
            raw.extend_from_slice(&buf[..n]);
        }
        let _wr = tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .expect("the writer finishes")
            .unwrap()
            .unwrap();
        assert!(!reader.is_finished(), "{:?}", reader.await);

        let sent = frame_payloads(&raw);
        let ping = sent
            .iter()
            .position(|(op, _)| *op == 0x9)
            .expect("the owed ping was never sent");
        assert!(
            sent[..ping].iter().any(|(op, _)| *op == 0x2)
                && sent[ping + 1..].iter().any(|(op, _)| *op == 0x2),
            "the ping should go between the data queued before the stall \
             and the write that waited for room"
        );
        // And the data is all there, in the order it was written.
        let got: Vec<u8> = sent
            .iter()
            .filter(|(op, _)| *op == 0x2)
            .flat_map(|(_, payload)| payload.iter().copied())
            .collect();
        let want: Vec<u8> = (0..CHUNKS).flat_map(|i| vec![i as u8; CHUNK]).collect();
        assert!(got == want, "the data arrived damaged or out of order");
    }

    #[tokio::test]
    async fn a_peer_that_neither_speaks_nor_drains_ends_the_stream() {
        // The other half: a write parked on a peer that has stopped
        // reading is no sign of life, and the deadline still ends it.
        let (a, _b) = tokio::io::duplex(256);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, None).await;
        let stream = WsByteStream::with_ping_period(server, Duration::from_millis(20));
        let (mut rd, mut wr) = tokio::io::split(stream);
        let _writer = tokio::spawn(async move {
            loop {
                if wr.write_all(&[7u8; 1024]).await.is_err() || wr.flush().await.is_err() {
                    return;
                }
            }
        });
        let err = tokio::time::timeout(Duration::from_secs(5), rd.read(&mut [0u8; 8]))
            .await
            .expect("the read must end on its own")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn close_is_eof() {
        let (a, b) = tokio::io::duplex(4096);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(b, Role::Client, None).await;
        let mut stream = WsByteStream::new(server);
        client.close(None).await.unwrap();
        assert_eq!(stream.read(&mut [0u8; 4]).await.unwrap(), 0);
    }
}
