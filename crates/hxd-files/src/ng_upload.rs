//! Uploads on the ng wire (`docs/ng-uploads.md`): FilePut's rules over the
//! local area's partials, the bytes arriving in pieces over HTTP, each
//! appended to the partial at its length, the last publishing it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hxd_core::{Core, FileError, FilePath, FilePrincipal};
use hxfiles_xfer::resume_digest;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncSeekExt};

use crate::local::PartialKey;
use crate::transfer::{copy_exact, on_disk};
use crate::{FileService, Liveness, UploadQuote};

/// The most one piece carries.
pub const PIECE: u64 = 8 << 20;

/// Uploads one session may have under way at once, and everyone.
const PER_SESSION: usize = 8;
const TOTAL: usize = 1024;

pub struct NgUploadRequest {
    pub principal: FilePrincipal,
    /// Whose partials these are: the account's login, as a classic
    /// upload's are, so either wire may finish what the other began.
    pub owner: String,
    /// Whose transfer places a piece holds (`Core::transfer_person`).
    pub person: String,
    pub path: FilePath,
    pub size: u64,
    /// Into a drop box its uploader may not view: see
    /// [`crate::UploadTransfer::blind`].
    pub blind: bool,
    /// Starts over rather than being quoted the partial.
    pub fresh: bool,
    pub comment: Option<String>,
}

/// What `files_upload` answers.
#[derive(Debug)]
pub struct NgUploadTicket {
    pub token: String,
    pub offset: u64,
    pub piece: u64,
    /// The partial's resume digest, which the first piece echoes.
    pub digest: Option<[u8; resume_digest::ENCODED_LEN]>,
}

/// One piece's place in the file, from its `Content-Range`.
#[derive(Debug, Clone, Copy)]
pub struct Piece {
    pub start: u64,
    pub len: u64,
    pub total: u64,
}

#[derive(Debug)]
pub enum PieceOutcome {
    /// Written; the next starts here.
    Accepted(u64),
    /// The last: the file is published at this path.
    Published(FilePath),
}

#[derive(Debug)]
pub enum PieceError {
    /// No such upload, or not this session's any longer.
    Gone,
    /// Not where the partial is, or not this file, or another piece is
    /// under way, or the echoed digest is not the partial's: the client
    /// asks where to carry on from rather than guess.
    Conflict(u64),
    TooLong,
    File(FileError),
}

impl From<FileError> for PieceError {
    fn from(error: FileError) -> Self {
        PieceError::File(error)
    }
}

struct Grant {
    principal: FilePrincipal,
    person: String,
    path: FilePath,
    size: u64,
    /// As the sidecar keeps it: Mac Roman, capped.
    comment: Vec<u8>,
    key: PartialKey,
    /// The partial as quoted, until a first piece has proved it holds the
    /// same bytes.
    quote: Option<UploadQuote>,
    /// The partial's generation once a piece has written to it, so a
    /// partial another upload replaced is not appended to.
    generation: Option<[u8; 16]>,
    offset: u64,
    busy: bool,
    expires: Instant,
}

impl Grant {
    fn piece(&self) -> u64 {
        // A blind upload's partial lasts only while one request writes it.
        if self.key.blind {
            self.size
        } else {
            PIECE
        }
    }
}

pub struct NgUploads {
    ttl: Duration,
    grants: Mutex<HashMap<[u8; 32], Grant>>,
}

impl NgUploads {
    /// An upload lasts `ttl` from its issue and from each piece.
    pub fn new(ttl: Duration) -> Self {
        NgUploads {
            ttl,
            grants: Mutex::new(HashMap::new()),
        }
    }
}

/// Lets the next piece in however this one ends: a client that drops its
/// connection mid-piece ends the request without its outcome being
/// recorded. What it wrote the next piece finds, as it would any partial
/// that is not where the upload left it.
struct Release<'a> {
    uploads: &'a NgUploads,
    key: [u8; 32],
}

impl Drop for Release<'_> {
    fn drop(&mut self) {
        if let Some(grant) = self.uploads.grants.lock().unwrap().get_mut(&self.key) {
            grant.busy = false;
        }
    }
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

impl FileService {
    /// Checks an upload as FilePut would, quotes the partial it may resume,
    /// and issues the token its pieces are sent to.
    pub async fn ng_upload_begin(
        &self,
        request: NgUploadRequest,
    ) -> Result<NgUploadTicket, FileError> {
        let source = self
            .uploads
            .clone()
            .ok_or_else(|| FileError::Unavailable("read-only file area".into()))?;
        let key = if request.blind {
            PartialKey::blind(&request.owner)?
        } else {
            PartialKey::resumable(&request.owner, &request.path)
        };
        let (quote_key, path, size) = (key.clone(), request.path.clone(), request.size);
        let resume = !request.fresh;
        let quote = on_disk(&source, move |source| {
            source.prepare_upload(&quote_key, &path, Some(size), true, resume)
        })
        .await?
        // A partial longer than the file is another file's.
        .filter(|quote| quote.data_offset < size);
        let now = Instant::now();
        let mut grants = self.ng_uploads.grants.lock().unwrap();
        grants.retain(|_, grant| grant.expires > now || grant.busy);
        let mine = grants
            .values()
            .filter(|grant| grant.principal == request.principal)
            .count();
        if mine >= PER_SESSION || grants.len() >= TOTAL {
            return Err(FileError::Busy);
        }
        let mut raw = [0; 32];
        getrandom::getrandom(&mut raw)
            .map_err(|e| FileError::Unavailable(format!("upload token: {e}")))?;
        let token = URL_SAFE_NO_PAD.encode(raw);
        let ticket = NgUploadTicket {
            token: token.clone(),
            offset: quote.as_ref().map_or(0, |quote| quote.data_offset),
            piece: if key.blind { request.size } else { PIECE },
            digest: quote.as_ref().and_then(|quote| quote.digest),
        };
        grants.insert(
            digest(&token),
            Grant {
                principal: request.principal,
                person: request.person,
                path: request.path,
                size: request.size,
                comment: request
                    .comment
                    .map(|comment| {
                        let mut stored = hxproto::text::from_utf8(&comment);
                        stored.truncate(hxhfs::hfs::MAX_COMMENT);
                        stored
                    })
                    .unwrap_or_default(),
                key,
                offset: ticket.offset,
                quote,
                generation: None,
                busy: false,
                expires: now + self.ng_uploads.ttl,
            },
        );
        Ok(ticket)
    }

    /// Writes one piece of the upload `token` names, read from `body`, and
    /// publishes the file when it is the last. `echo` is the client's
    /// resume digest, which the first piece after a quote must carry.
    pub async fn ng_upload_piece(
        &self,
        core: &Arc<Core>,
        token: &str,
        piece: Piece,
        echo: Option<[u8; resume_digest::ENCODED_LEN]>,
        body: &mut (impl AsyncRead + Unpin),
    ) -> Result<PieceOutcome, PieceError> {
        let source = self.uploads.clone().ok_or(PieceError::Gone)?;
        let key = digest(token);
        let (principal, person, path, size, comment, partial, quote, generation) = {
            let mut grants = self.ng_uploads.grants.lock().unwrap();
            let grant = grants.get_mut(&key).ok_or(PieceError::Gone)?;
            let live = core.session_serial(grant.principal.uid) == Some(grant.principal.serial);
            if !live || (grant.expires <= Instant::now() && !grant.busy) {
                grants.remove(&key);
                return Err(PieceError::Gone);
            }
            if grant.busy || piece.total != grant.size || piece.start != grant.offset {
                return Err(PieceError::Conflict(grant.offset));
            }
            let last = piece.start + piece.len == grant.size;
            if piece.len > grant.piece() || piece.start + piece.len > grant.size {
                return Err(PieceError::TooLong);
            }
            // Nothing past the quote is written until the client shows it
            // holds what the partial does.
            if let Some(quote) = &grant.quote {
                let echoed = echo.as_ref().zip(quote.digest.as_ref());
                if !echoed.is_some_and(|(echo, quoted)| resume_digest::matches(quoted, echo)) {
                    return Err(PieceError::Conflict(grant.offset));
                }
            }
            // A piece that adds nothing and does not finish the file is
            // nothing to do.
            if piece.len == 0 && !last {
                return Err(PieceError::Conflict(grant.offset));
            }
            grant.busy = true;
            (
                grant.principal,
                grant.person.clone(),
                grant.path.clone(),
                grant.size,
                grant.comment.clone(),
                grant.key.clone(),
                grant.quote.clone(),
                grant.generation,
            )
        };
        let _release = Release {
            uploads: &self.ng_uploads,
            key,
        };
        let written = self
            .write_piece(
                core, &source, principal, &person, &path, size, comment, &partial, quote,
                generation, piece, body,
            )
            .await;
        let mut grants = self.ng_uploads.grants.lock().unwrap();
        match written {
            Ok((offset, generation, None)) => {
                if let Some(grant) = grants.get_mut(&key) {
                    grant.offset = offset;
                    grant.generation = Some(generation);
                    grant.quote = None;
                    grant.busy = false;
                    grant.expires = Instant::now() + self.ng_uploads.ttl;
                }
                Ok(PieceOutcome::Accepted(offset))
            }
            Ok((_, _, Some(published))) => {
                grants.remove(&key);
                Ok(PieceOutcome::Published(published))
            }
            Err((error, offset)) => {
                // A partial another upload replaced cannot be carried on,
                // nor one this piece left part-written, whose generation the
                // grant never learned: the client asks again and is quoted
                // what is there. One the piece did not touch can be tried
                // again as it was. A blind partial went with the request
                // that wrote it.
                let replaced = matches!(error, FileError::OriginChanged);
                let untouched = offset == Some(piece.start) && !partial.blind && !replaced;
                match grants.get_mut(&key) {
                    Some(grant) if untouched => grant.busy = false,
                    _ => {
                        grants.remove(&key);
                    }
                }
                Err(match replaced {
                    true => PieceError::Gone,
                    false => error.into(),
                })
            }
        }
    }

    /// The piece onto the partial, then the partial published if that was
    /// the last: the partial's length and generation after, and where it
    /// was published. A failure says how long the partial now is, when it
    /// can be resumed at all.
    #[allow(clippy::too_many_arguments)]
    async fn write_piece(
        &self,
        core: &Arc<Core>,
        source: &Arc<crate::LocalFileSource>,
        principal: FilePrincipal,
        person: &str,
        path: &FilePath,
        size: u64,
        comment: Vec<u8>,
        partial: &PartialKey,
        quote: Option<UploadQuote>,
        generation: Option<[u8; 16]>,
        piece: Piece,
        body: &mut (impl AsyncRead + Unpin),
    ) -> Result<(u64, [u8; 16], Option<FilePath>), (FileError, Option<u64>)> {
        let running = self
            .transfers
            .run_upload(principal, person)
            .map_err(|e| (e, Some(piece.start)))?;
        let alive = Liveness::new(core.clone(), principal).ended_by(Some(running.cancel()));
        let fresh = piece.start == 0 && quote.is_none() && generation.is_none();
        let (key, upload_path) = (partial.clone(), path.clone());
        let files = on_disk(source, move |source| {
            let files = source.begin_upload(&key, &upload_path, fresh, size)?;
            let expected = match (quote, generation) {
                (Some(quote), _) => Some(quote),
                (None, Some(generation)) => Some(UploadQuote {
                    data_offset: piece.start,
                    resource_offset: 0,
                    generation,
                    digest: None,
                }),
                (None, None) => None,
            };
            if let Some(expected) = expected {
                source.recheck_resume(&files, &expected)?;
            }
            Ok(files)
        })
        .await
        .map_err(|e| (e, Some(piece.start)))?;
        let mut output = tokio::fs::File::from_std(
            files
                .data
                .try_clone()
                .map_err(|e| (FileError::Unavailable(e.to_string()), Some(piece.start)))?,
        );
        let copied = async {
            output
                .seek(std::io::SeekFrom::Start(piece.start))
                .await
                .map_err(|e| FileError::Unavailable(e.to_string()))?;
            copy_exact(body, &mut output, piece.len, source, &alive).await
        }
        .await;
        let length = files.data.metadata().map(|m| m.len()).ok();
        if let Err(error) = copied {
            return Err((error, length));
        }
        let generation = source.upload_generation(&files).map_err(|e| (e, length))?;
        let offset = piece.start + piece.len;
        if offset < size {
            return Ok((offset, generation, None));
        }
        // Nothing is published for a session that ended while its bytes
        // were arriving.
        alive.check().map_err(|e| (e, length))?;
        let tree = source.lock_tree().await;
        let path = path.clone();
        let published = on_disk(source, move |source| {
            let hfs = hxhfs::HfsInfo {
                comment,
                ..Default::default()
            };
            source.publish_upload(&tree, &path, &files, &hfs)
        })
        .await
        .map_err(|e| (e, None))?;
        Ok((offset, generation, Some(published)))
    }
}
