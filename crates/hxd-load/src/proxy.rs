//! `linkproxy`: a TCP proxy between a linked server's dialer and its peer,
//! which a scenario cuts and restores on its own schedule
//! (`docs/load-testing.md` §8.2). It copies bytes and never looks at
//! them, so a key-mode link's TLS runs through it untouched.
//!
//! Cut, it closes every connection it carries, and accepts and at once
//! closes every new one, which each side sees as the link dropping and
//! the dialer as a TLS handshake that failed, not a partition that
//! leaves its connects to time out; restored, it carries connections
//! again.
//!
//! Stalled, it stops reading what the peer sends the dialer, while what
//! the dialer sends still goes through: the peer hears from the dialer
//! as ever, and its writes back up as they would behind a dialer that
//! stopped reading, until the peer gives up on it or the stall ends.

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Clone, Copy, Default)]
struct State {
    open: bool,
    /// How many cuts there have been: a connection ends at the first cut
    /// after it was accepted, even one restored before its task looked.
    cuts: u64,
    stalled: bool,
}

pub struct Proxy {
    state: watch::Sender<State>,
    task: JoinHandle<()>,
}

impl Proxy {
    pub async fn start(listen: SocketAddr, upstream: SocketAddr) -> Result<Proxy, String> {
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| format!("proxy {listen}: {e}"))?;
        let (state, rx) = watch::channel(State {
            open: true,
            ..State::default()
        });
        let task = tokio::spawn(serve(listener, upstream, rx));
        Ok(Proxy { state, task })
    }

    pub fn cut(&self) {
        self.state.send_modify(|s| {
            s.open = false;
            s.cuts += 1;
        });
    }

    pub fn restore(&self) {
        self.state.send_modify(|s| s.open = true);
    }

    pub fn stall(&self) {
        self.state.send_modify(|s| s.stalled = true);
    }

    pub fn unstall(&self) {
        self.state.send_modify(|s| s.stalled = false);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.cut();
        self.task.abort();
    }
}

async fn serve(listener: TcpListener, upstream: SocketAddr, state: watch::Receiver<State>) {
    loop {
        // An error accepting one connection (out of descriptors, say) is
        // that connection's, not the proxy's.
        let Ok((client, _)) = listener.accept().await else {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            continue;
        };
        let now = *state.borrow();
        if !now.open {
            continue;
        }
        let mut cut = state.clone();
        let stall = state.clone();
        tokio::spawn(async move {
            let Ok(server) = connect(upstream).await else {
                return;
            };
            let (client_rd, client_wr) = client.into_split();
            let (server_rd, server_wr) = server.into_split();
            // An end's half-close is passed on as one, so a peer's Close
            // is still read before the socket goes; a reset or a failed
            // write ends both directions, even one stalled, so the dialer
            // learns its peer gave up as it would behind a stopped server.
            let up = pipe(client_rd, server_wr, None);
            let down = pipe(server_rd, client_wr, Some(stall));
            tokio::pin!(up, down);
            let (mut up_open, mut down_open) = (true, true);
            while up_open || down_open {
                tokio::select! {
                    r = &mut up, if up_open => match r {
                        Ok(()) => up_open = false,
                        Err(()) => break,
                    },
                    r = &mut down, if down_open => match r {
                        Ok(()) => down_open = false,
                        Err(()) => break,
                    },
                    _ = cut.wait_for(|s| s.cuts != now.cuts) => break,
                }
            }
        });
    }
}

/// The proxy's own receive buffer toward the peer, small: stalled, the
/// proxy is a dialer that stopped reading, and its kernel should take no
/// more off the peer than such a dialer's would before the peer's
/// writes back up. Loopback's autotuned buffers hold megabytes.
const UPSTREAM_RECV_BUFFER: u32 = 64 * 1024;

async fn connect(upstream: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
    let socket = match upstream {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_recv_buffer_size(UPSTREAM_RECV_BUFFER)?;
    socket.connect(upstream).await
}

/// Copy one direction, reading nothing while `stall` says so: `Ok` once
/// its reader closed and its writer was closed in turn, `Err` on a
/// reset or a failed write.
async fn pipe(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    mut stall: Option<watch::Receiver<State>>,
) -> Result<(), ()> {
    let mut buf = vec![0; 16 * 1024];
    loop {
        if let Some(s) = stall.as_mut() {
            s.wait_for(|s| !s.stalled).await.map_err(|_| ())?;
        }
        match from.read(&mut buf).await.map_err(|_| ())? {
            0 => return to.shutdown().await.map_err(|_| ()),
            n => to.write_all(&buf[..n]).await.map_err(|_| ())?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn echo() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    async fn round_trip(addr: SocketAddr) -> std::io::Result<Vec<u8>> {
        let mut s = TcpStream::connect(addr).await?;
        s.write_all(b"ping").await?;
        let mut got = vec![0; 4];
        s.read_exact(&mut got).await?;
        Ok(got)
    }

    #[tokio::test]
    async fn a_cut_ends_what_it_carries_and_refuses_more_until_restored() {
        let listen = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let proxy = Proxy::start(listen, echo().await).await.unwrap();
        let mut carried = TcpStream::connect(listen).await.unwrap();
        carried.write_all(b"ping").await.unwrap();
        let mut got = [0; 4];
        carried.read_exact(&mut got).await.unwrap();

        proxy.cut();
        let mut rest = Vec::new();
        assert_eq!(carried.read_to_end(&mut rest).await.unwrap_or(0), 0);
        assert!(round_trip(listen).await.is_err());

        proxy.restore();
        assert_eq!(round_trip(listen).await.unwrap(), b"ping");
    }

    #[tokio::test]
    async fn a_peer_that_gives_up_during_a_stall_is_passed_on_to_the_dialer() {
        let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = peer.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept, then give up on the dialer at once.
            let _ = peer.accept().await;
        });
        let listen = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let proxy = Proxy::start(listen, upstream).await.unwrap();
        proxy.stall();
        let mut s = TcpStream::connect(listen).await.unwrap();
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if s.write_all(b"ping").await.is_err() {
                    return;
                }
                let mut b = [0; 1];
                match tokio::time::timeout(std::time::Duration::from_millis(50), s.read(&mut b))
                    .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) => return,
                    _ => {}
                }
            }
        });
        assert!(
            ended.await.is_ok(),
            "the dialer never learned its peer gave up"
        );
    }

    #[tokio::test]
    async fn a_stall_holds_back_what_the_peer_sends_until_it_ends() {
        let listen = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let proxy = Proxy::start(listen, echo().await).await.unwrap();
        let mut s = TcpStream::connect(listen).await.unwrap();
        proxy.stall();
        s.write_all(b"ping").await.unwrap();
        let mut got = [0; 4];
        let held = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            s.read_exact(&mut got),
        );
        assert!(held.await.is_err(), "the echo came back through a stall");
        proxy.unstall();
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }
}
