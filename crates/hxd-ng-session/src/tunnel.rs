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

use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

pub struct WsByteStream<S> {
    ws: WebSocketStream<S>,
    /// Unread tail of the last binary frame.
    pending: Vec<u8>,
    pending_at: usize,
    eof: bool,
}

impl<S> WsByteStream<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        WsByteStream {
            ws,
            pending: Vec::new(),
            pending_at: 0,
            eof: false,
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
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.pending_at < self.pending.len() {
                let n = (self.pending.len() - self.pending_at).min(buf.remaining());
                let at = self.pending_at;
                buf.put_slice(&self.pending[at..at + n]);
                self.pending_at += n;
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => {
                    self.pending = data;
                    self.pending_at = 0;
                }
                // tungstenite answers pings itself; pongs and frames
                // carrying nothing are just skipped.
                Some(Ok(Message::Ping(_)))
                | Some(Ok(Message::Pong(_)))
                | Some(Ok(Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    self.eof = true;
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
    async fn close_is_eof() {
        let (a, b) = tokio::io::duplex(4096);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, None).await;
        let mut client = WebSocketStream::from_raw_socket(b, Role::Client, None).await;
        let mut stream = WsByteStream::new(server);
        client.close(None).await.unwrap();
        assert_eq!(stream.read(&mut [0u8; 4]).await.unwrap(), 0);
    }
}
