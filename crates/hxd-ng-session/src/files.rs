//! Hotline-ng Files requests and HTTP download authorization.

use hxd_core::access::bit;
use hxd_core::{FileError, FileKind, FilePath, FilePrincipal};
use serde_json::{json, Value};

use crate::conn::SessState;
use crate::proto::{FilesDownloadParams, FilesPathParams, ReqEnvelope};
use crate::NgCtx;

pub(crate) async fn handle(ctx: &NgCtx, state: &SessState, req: &ReqEnvelope) -> String {
    if !state.access.has(bit::DOWNLOAD_FILES) {
        return crate::proto::reply_err(
            req.id,
            "access_denied",
            "You are not allowed to read files.",
        );
    }
    let Some(service) = ctx.files.as_ref() else {
        return crate::proto::reply_err(req.id, "not_available", "Files are not available.");
    };
    match req.req.as_str() {
        "files_list" => {
            let params = if req.params.is_null() {
                Ok(FilesPathParams::default())
            } else {
                serde_json::from_value::<FilesPathParams>(req.params.clone())
            };
            let Ok(params) = params else {
                return crate::proto::reply_err(req.id, "bad_request", "Malformed files_list.");
            };
            let path = match FilePath::parse(&params.path) {
                Ok(path) => path,
                Err(error) => return error_reply(req.id, error),
            };
            match service.source.list(&path).await {
                Ok(entries) => crate::proto::reply_ok(
                    req.id,
                    json!({
                        "path": path.as_slash_path(),
                        "entries": entries.into_iter().map(|entry| {
                            json!({
                                "name": entry.name,
                                "kind": kind(entry.kind),
                                "size": entry.size.to_string(),
                                "media_type": entry.media_type,
                                "modified": entry.modified,
                            })
                        }).collect::<Vec<_>>()
                    }),
                ),
                Err(error) => error_reply(req.id, error),
            }
        }
        "files_info" => {
            let params = serde_json::from_value::<FilesPathParams>(req.params.clone());
            let Ok(params) = params else {
                return crate::proto::reply_err(req.id, "bad_request", "Malformed files_info.");
            };
            let path = match FilePath::parse(&params.path) {
                Ok(path) if !path.is_root() => path,
                _ => return crate::proto::reply_err(req.id, "bad_request", "Malformed file path."),
            };
            match service.source.info(&path).await {
                Ok(info) => crate::proto::reply_ok(req.id, info_json(info)),
                Err(error) => error_reply(req.id, error),
            }
        }
        "files_download" => {
            let params = serde_json::from_value::<FilesDownloadParams>(req.params.clone());
            let Ok(params) = params else {
                return crate::proto::reply_err(req.id, "bad_request", "Malformed files_download.");
            };
            let path = match FilePath::parse(&params.path) {
                Ok(path) if !path.is_root() => path,
                _ => return crate::proto::reply_err(req.id, "bad_request", "Malformed file path."),
            };
            let info = match service.source.info(&path).await {
                Ok(info) if info.kind == FileKind::File => info,
                Ok(_) => return crate::proto::reply_err(req.id, "not_file", "Path is not a file."),
                Err(error) => return error_reply(req.id, error),
            };
            let Some(serial) = ctx.core.session_serial(state.uid) else {
                return crate::proto::reply_err(req.id, "not_authorized", "Session ended.");
            };
            match service.downloads.issue(
                FilePrincipal {
                    uid: state.uid,
                    serial,
                },
                path,
            ) {
                Ok(token) => crate::proto::reply_ok(
                    req.id,
                    json!({
                        "url": format!("/files/{token}"),
                        "size": info.size.to_string(),
                        "media_type": info.media_type,
                    }),
                ),
                Err(error) => error_reply(req.id, error),
            }
        }
        _ => crate::proto::reply_err(req.id, "unknown_method", "Unknown request."),
    }
}

fn kind(kind: FileKind) -> &'static str {
    match kind {
        FileKind::File => "file",
        FileKind::Folder => "folder",
    }
}

fn info_json(info: hxd_core::FileInfo) -> Value {
    json!({
        "path": info.path.as_slash_path(),
        "name": info.path.name(),
        "kind": kind(info.kind),
        "size": info.size.to_string(),
        "media_type": info.media_type,
        "created": info.created,
        "modified": info.modified,
        "comment": info.comment,
    })
}

fn error_reply(id: u64, error: FileError) -> String {
    let (code, message) = match error {
        FileError::InvalidPath => ("bad_request", "Malformed file path."),
        FileError::NotFound => ("not_found", "File not found."),
        FileError::NotFolder => ("not_folder", "Path is not a folder."),
        FileError::NotFile => ("not_file", "Path is not a file."),
        FileError::AlreadyExists => ("already_exists", "A file already exists at that path."),
        FileError::RangeUnsupported => ("range_unsupported", "This file cannot be resumed."),
        FileError::RangeInvalid => ("range_invalid", "Invalid file range."),
        FileError::OriginChanged => ("origin_changed", "The file changed at its origin."),
        FileError::TooLarge => ("too_large", "File exceeds the server limit."),
        FileError::Busy => ("busy", "The file service is busy."),
        FileError::Unavailable(_) => ("not_available", "The file service is unavailable."),
    };
    crate::proto::reply_err(id, code, message)
}
