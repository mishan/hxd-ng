//! The TRTP-over-WebSocket transport (`docs/hotline-ng-identity.md` §6.3):
//! a WebSocket whose binary frames, concatenated, are the byte stream a
//! TCP connection to the legacy port would carry. This adapter presents
//! such a socket as `AsyncRead + AsyncWrite` so the legacy frontend can
//! run on it without knowing it isn't on TCP.
//!
//! Frame boundaries carry no meaning: reads drain whatever frame arrived,
//! writes send each `poll_write` buffer as one frame. Text frames are a
//! protocol error and end the stream; a close frame is EOF.
//!
//! A write is queued in the WebSocket sink until a flush; `poll_write`
//! tries one opportunistically, but a writer that stops after a write
//! and never flushes can leave the last frame sitting there. The legacy
//! frontend flushes after every write for exactly this reason.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{interval_at, Instant, Interval, MissedTickBehavior};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// How often the server pings a quiet tunnel — the same clock the JSON
/// path uses, for the same reasons.
const PING_EVERY: Duration = Duration::from_secs(30);

pub struct WsByteStream<S> {
    ws: WebSocketStream<S>,
    /// Unread tail of the last binary frame.
    pending: Vec<u8>,
    pending_at: usize,
    eof: bool,
    /// Server-initiated keep-alive, driven from the read side.
    ping: Interval,
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
                // Not ready to send is not an error: the socket is
                // busy, which is the thing a ping is asking about.
                if let Poll::Ready(Ok(())) = Pin::new(&mut this.ws).poll_ready(cx) {
                    Pin::new(&mut this.ws)
                        .start_send(Message::Ping(Vec::new()))
                        .map_err(ws_err)?;
                    if let Poll::Ready(Err(e)) = Pin::new(&mut this.ws).poll_flush(cx) {
                        return Poll::Ready(Err(ws_err(e)));
                    }
                }
            }
            match ready!(Pin::new(&mut this.ws).poll_next(cx)) {
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
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(Pin::new(&mut self.ws).poll_ready(cx)).map_err(ws_err)?;
        Pin::new(&mut self.ws)
            .start_send(Message::Binary(buf.to_vec()))
            .map_err(ws_err)?;
        // Push it out now if the socket will take it; if not, the data is
        // accepted and the caller's flush finishes the job.
        if let Poll::Ready(Err(e)) = Pin::new(&mut self.ws).poll_flush(cx) {
            return Poll::Ready(Err(ws_err(e)));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws).poll_flush(cx).map_err(ws_err)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
    async fn close_is_eof() {
        let (a, b) = tokio::io::duplex(4096);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(b, Role::Client, None).await;
        let mut stream = WsByteStream::new(server);
        client.close(None).await.unwrap();
        assert_eq!(stream.read(&mut [0u8; 4]).await.unwrap(), 0);
    }
}
