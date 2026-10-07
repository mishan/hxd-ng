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

use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub struct Proxy {
    /// Whether it carries connections, and how many cuts there have been:
    /// a connection ends at the first cut after it was accepted, even one
    /// restored before its task looked.
    state: watch::Sender<(bool, u64)>,
    task: JoinHandle<()>,
}

impl Proxy {
    pub async fn start(listen: SocketAddr, upstream: SocketAddr) -> Result<Proxy, String> {
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| format!("proxy {listen}: {e}"))?;
        let (state, rx) = watch::channel((true, 0));
        let task = tokio::spawn(serve(listener, upstream, rx));
        Ok(Proxy { state, task })
    }

    pub fn cut(&self) {
        self.state.send_modify(|(open, cuts)| {
            *open = false;
            *cuts += 1;
        });
    }

    pub fn restore(&self) {
        self.state.send_modify(|(open, _)| *open = true);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.cut();
        self.task.abort();
    }
}

async fn serve(listener: TcpListener, upstream: SocketAddr, state: watch::Receiver<(bool, u64)>) {
    loop {
        // An error accepting one connection (out of descriptors, say) is
        // that connection's, not the proxy's.
        let Ok((mut client, _)) = listener.accept().await else {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            continue;
        };
        let (open, at) = *state.borrow();
        if !open {
            continue;
        }
        let mut state = state.clone();
        tokio::spawn(async move {
            let Ok(mut server) = TcpStream::connect(upstream).await else {
                return;
            };
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                _ = state.wait_for(|(_, cuts)| *cuts != at) => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
}
