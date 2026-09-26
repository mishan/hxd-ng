//! Scripted Hotline clients for hxd-ng's own tests: the e2e suites in
//! `crates/hxd/tests/` and the load harness, `hxd-load`.
//!
//! [`legacy::Client`] speaks the classic wire, over plain TCP or TLS, and
//! frames with the pinned `hxproto` rather than with the server's framer.
//! [`ng::Client`] speaks the Hotline-ng JSON wire over a WebSocket. Both
//! keep whatever arrives while they wait for something in particular, so
//! nothing a caller has not looked at is ever silently dropped — the
//! load harness counts every chat line and every seq, and a helper that
//! discarded "unrelated" traffic would hide exactly what it is looking
//! for.
//!
//! Everything returns a [`Result`]. A test that wants to fail loudly
//! unwraps; the harness counts the error and carries on.

pub mod legacy;
pub mod ng;
pub mod tls;

use std::fmt;
use std::time::Duration;

/// How long a client waits for anything before it gives up, unless told
/// otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a client call failed.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// Nothing arrived in time.
    Timeout,
    /// The server closed the connection.
    Closed,
    /// Something arrived that the protocol does not allow.
    Protocol(String),
    /// The server answered, and the answer was no. On the legacy wire
    /// `code` is empty and `text` is the task error; on ng both are the
    /// error body's.
    Refused {
        code: String,
        text: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o: {e}"),
            Error::Timeout => write!(f, "timed out"),
            Error::Closed => write!(f, "connection closed"),
            Error::Protocol(why) => write!(f, "protocol: {why}"),
            Error::Refused { code, text } if code.is_empty() => write!(f, "refused: {text}"),
            Error::Refused { code, text } => write!(f, "refused ({code}): {text}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::UnexpectedEof => Error::Closed,
            _ => Error::Io(e),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
