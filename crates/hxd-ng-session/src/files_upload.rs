//! `PUT /files/upload/<token>`: one piece of an upload `files_upload`
//! began (`docs/ng-uploads.md` §2).

use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, BodyStream, Full};
use hxd_core::FileError;
use hxd_files::{Piece, PieceError, PieceOutcome};
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, CONTENT_RANGE, RETRY_AFTER};
use hyper::{Request, Response, StatusCode};
use serde_json::json;

use crate::media::json_resp;
use crate::NgCtx;

type Resp = Response<Full<Bytes>>;

/// Where a client carries on from.
const UPLOAD_OFFSET: &str = "upload-offset";
/// Its resume digest, on the first piece after a quote.
const UPLOAD_DIGEST: &str = "upload-digest";

pub async fn piece(token: &str, req: Request<Incoming>, ctx: &NgCtx) -> Resp {
    let Some(service) = ctx.files.as_ref() else {
        return status(StatusCode::NOT_FOUND);
    };
    let headers = req.headers();
    let length = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    // An empty file is the one upload with no range to send.
    let piece = match headers
        .get(CONTENT_RANGE)
        .map(|v| v.to_str().ok().and_then(range))
    {
        Some(Some(piece)) => piece,
        None if length == Some(0) => Piece {
            start: 0,
            len: 0,
            total: 0,
        },
        _ => return status(StatusCode::BAD_REQUEST),
    };
    // The body is the range, which hyper then holds it to.
    if length != Some(piece.len) {
        return status(StatusCode::BAD_REQUEST);
    }
    let echo = match headers
        .get(UPLOAD_DIGEST)
        .map(|v| v.to_str().ok().and_then(hex))
    {
        Some(None) => return status(StatusCode::BAD_REQUEST),
        Some(Some(echo)) => Some(echo),
        None => None,
    };
    let timeout = match service.uploads.as_ref() {
        Some(source) => source.limits().upload_timeout,
        None => return status(StatusCode::NOT_FOUND),
    };
    let body = BodyStream::new(req.into_body().map_err(std::io::Error::other))
        .try_filter_map(|frame| futures_util::future::ready(Ok(frame.into_data().ok())));
    let mut body = tokio_util::io::StreamReader::new(body);
    let written = tokio::time::timeout(
        timeout,
        service.ng_upload_piece(&ctx.core, token, piece, echo, &mut body),
    )
    .await
    .unwrap_or_else(|_| {
        Err(PieceError::File(FileError::Unavailable(
            "piece exceeded its time limit".into(),
        )))
    });
    match written {
        Ok(PieceOutcome::Accepted(offset)) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(UPLOAD_OFFSET, offset.to_string())
            .body(Full::new(Bytes::new()))
            .unwrap(),
        Ok(PieceOutcome::Published(path)) => {
            json_resp(StatusCode::CREATED, json!({ "path": path.as_slash_path() }))
        }
        Err(PieceError::Gone) => status(StatusCode::NOT_FOUND),
        Err(PieceError::Conflict(offset)) => Response::builder()
            .status(StatusCode::CONFLICT)
            .header(UPLOAD_OFFSET, offset.to_string())
            .body(Full::new(Bytes::new()))
            .unwrap(),
        Err(PieceError::TooLong) => status(StatusCode::PAYLOAD_TOO_LARGE),
        Err(PieceError::File(error)) => {
            let (code, text) = crate::files::error_code(&error);
            let mut resp = json_resp(
                match error {
                    FileError::Busy | FileError::TooManyTransfers | FileError::Unavailable(_) => {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                    FileError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
                    _ => StatusCode::UNPROCESSABLE_ENTITY,
                },
                json!({ "error": { "code": code, "text": text } }),
            );
            if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
                resp.headers_mut()
                    .insert(RETRY_AFTER, hyper::header::HeaderValue::from_static("5"));
            }
            resp
        }
    }
}

fn status(code: StatusCode) -> Resp {
    Response::builder()
        .status(code)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// `bytes <first>-<last>/<total>`, a piece of at least one byte.
fn range(value: &str) -> Option<Piece> {
    let (span, total) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (first, last) = span.split_once('-')?;
    let number = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u64>().ok())
            .flatten()
    };
    let (first, last, total) = (number(first)?, number(last)?, number(total)?);
    (first <= last && last < total).then(|| Piece {
        start: first,
        len: last - first + 1,
        total,
    })
}

fn hex(value: &str) -> Option<[u8; hxd_files::RESUME_DIGEST_LEN]> {
    let mut out = [0; hxd_files::RESUME_DIGEST_LEN];
    if value.len() != out.len() * 2 {
        return None;
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(value.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::range;

    #[test]
    fn a_piece_is_one_range_inside_its_total() {
        let piece = range("bytes 8-15/20").unwrap();
        assert_eq!((piece.start, piece.len, piece.total), (8, 8, 20));
        for refused in [
            "bytes 8-15/15",
            "bytes 9-8/20",
            "bytes 8-/20",
            "bytes */20",
            "bytes +8-15/20",
            "items 8-15/20",
            "bytes 0-1,4-5/20",
        ] {
            assert!(range(refused).is_none(), "{refused}");
        }
    }
}
