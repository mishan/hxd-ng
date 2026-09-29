//! Hotline-ng Files requests and HTTP download authorization.

use hxd_core::access::{bit, AccessBits};
use hxd_core::{FileError, FileKind, FilePath, FilePrincipal};
use hxd_files::FileService;
use serde_json::{json, Value};
use tracing::info;

use crate::conn::SessState;
use crate::proto::{
    FilesCommentParams, FilesDownloadParams, FilesMoveParams, FilesPathParams, ReqEnvelope,
};
use crate::NgCtx;

/// Every act of file management, by the name the login block's `may`
/// lists it under, and the access bit it needs.
const ACTS: [(&str, u8); 9] = [
    ("create_folders", bit::CREATE_FOLDERS),
    ("delete_files", bit::DELETE_FILES),
    ("delete_folders", bit::DELETE_FOLDERS),
    ("rename_files", bit::RENAME_FILES),
    ("rename_folders", bit::RENAME_FOLDERS),
    ("move_files", bit::MOVE_FILES),
    ("move_folders", bit::MOVE_FOLDERS),
    ("comment_files", bit::COMMENT_FILES),
    ("comment_folders", bit::COMMENT_FOLDERS),
];

/// The login reply's `files` block, present exactly when the `files` cap
/// is: whether the area can change at all, and which of its changes this
/// session may make, so a client can leave out a Delete it would only be
/// refused.
pub fn login_json(service: &FileService, access: AccessBits) -> Value {
    let writable = service.uploads.is_some();
    json!({
        "writable": writable,
        "may": ACTS
            .iter()
            .filter(|(_, b)| writable && access.has(*b))
            .map(|(name, _)| *name)
            .collect::<Vec<_>>(),
    })
}

pub(crate) async fn handle(ctx: &NgCtx, state: &SessState, req: &ReqEnvelope) -> String {
    let Some(service) = ctx.files.as_ref() else {
        return crate::proto::reply_err(req.id, "not_available", "Files are not available.");
    };
    // Listing and info are the account's `[extra] file_list` and
    // `file_getinfo`, and a drop box's listing also `view_drop_boxes`, as
    // on the legacy wire; only a download asks for the `download_files`
    // bit.
    match req.req.as_str() {
        "files_list" => {
            if !state.file_list {
                return crate::proto::reply_err(
                    req.id,
                    "access_denied",
                    "You are not allowed to list files.",
                );
            }
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
            if let Some(refusal) = drop_box_refusal(req.id, state, &path) {
                return refusal;
            }
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
            if !state.file_getinfo {
                return crate::proto::reply_err(
                    req.id,
                    "access_denied",
                    "You are not allowed to get file info.",
                );
            }
            let params = serde_json::from_value::<FilesPathParams>(req.params.clone());
            let Ok(params) = params else {
                return crate::proto::reply_err(req.id, "bad_request", "Malformed files_info.");
            };
            let path = match FilePath::parse(&params.path) {
                Ok(path) if !path.is_root() => path,
                _ => return crate::proto::reply_err(req.id, "bad_request", "Malformed file path."),
            };
            // Before the lookup, as on the legacy wire: what a drop box
            // holds, or whether it holds a name, is not this session's to
            // learn.
            if let Some(refusal) = drop_box_refusal(req.id, state, &path) {
                return refusal;
            }
            match service.source.info(&path).await {
                Ok(info) => crate::proto::reply_ok(req.id, info_json(info)),
                Err(error) => error_reply(req.id, error),
            }
        }
        "files_download" => {
            if !state.access.has(bit::DOWNLOAD_FILES) {
                return crate::proto::reply_err(
                    req.id,
                    "access_denied",
                    "You are not allowed to download files.",
                );
            }
            let params = serde_json::from_value::<FilesDownloadParams>(req.params.clone());
            let Ok(params) = params else {
                return crate::proto::reply_err(req.id, "bad_request", "Malformed files_download.");
            };
            let path = match FilePath::parse(&params.path) {
                Ok(path) if !path.is_root() => path,
                _ => return crate::proto::reply_err(req.id, "bad_request", "Malformed file path."),
            };
            if let Some(refusal) = drop_box_refusal(req.id, state, &path) {
                return refusal;
            }
            let info = match service.source.info(&path).await {
                Ok(info) if info.kind == FileKind::File => info,
                Ok(_) => return crate::proto::reply_err(req.id, "not_file", "Path is not a file."),
                Err(error) => return error_reply(req.id, error),
            };
            let (Some(serial), Some(details)) = (
                ctx.core.session_serial(state.uid),
                ctx.core.user_details(state.uid),
            ) else {
                return crate::proto::reply_err(req.id, "not_authorized", "Session ended.");
            };
            match service.downloads.issue(
                FilePrincipal {
                    uid: state.uid,
                    serial,
                },
                &details.login,
                path.clone(),
                service.source.supports_ranges(&path),
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
        "files_mkdir" | "files_delete" | "files_move" | "files_comment" => {
            match manage(service, state, req).await {
                Ok(()) => crate::proto::reply_ok(req.id, json!({})),
                Err(Refusal::Denied(message)) => {
                    crate::proto::reply_err(req.id, "access_denied", message)
                }
                Err(Refusal::Malformed) => crate::proto::reply_err(
                    req.id,
                    "bad_request",
                    &format!("Malformed {}.", req.req),
                ),
                Err(Refusal::ReadOnly) => {
                    crate::proto::reply_err(req.id, "read_only", "This file area is read-only.")
                }
                Err(Refusal::File(error)) => error_reply(req.id, error),
            }
        }
        _ => crate::proto::reply_err(req.id, "unknown_method", "Unknown request."),
    }
}

enum Refusal {
    Denied(&'static str),
    Malformed,
    ReadOnly,
    File(FileError),
}

impl From<FileError> for Refusal {
    fn from(error: FileError) -> Self {
        Refusal::File(error)
    }
}

/// A path to act on: never the root, which no act here may touch.
fn entry_path(path: &str) -> Result<FilePath, Refusal> {
    match FilePath::parse(path) {
        Ok(path) if !path.is_root() => Ok(path),
        _ => Err(Refusal::Malformed),
    }
}

/// File management, by the legacy wire's rules (`hxd-session`'s
/// `file_manage`): each act needs the bit for the kind of entry it acts
/// on, and a path naming a drop box needs `view_drop_boxes` besides.
async fn manage(
    service: &FileService,
    state: &SessState,
    req: &ReqEnvelope,
) -> Result<(), Refusal> {
    let source = service.uploads.as_deref().ok_or(Refusal::ReadOnly)?;
    let may = |b: u8| state.access.has(b);
    let reach = |path: &FilePath| {
        if path.is_drop_box() && !may(bit::VIEW_DROP_BOXES) {
            Err(Refusal::Denied("You are not allowed to view drop boxes."))
        } else {
            Ok(())
        }
    };
    let uid = state.uid;
    // Before any lookup, so an account that may do none of an act cannot
    // learn from it what exists: what the entry is then says which of
    // the pair it needs.
    let any = |bits: &[u8]| bits.iter().any(|b| may(*b));
    let allowed = match req.req.as_str() {
        "files_delete" => any(&[bit::DELETE_FILES, bit::DELETE_FOLDERS]),
        "files_comment" => any(&[bit::COMMENT_FILES, bit::COMMENT_FOLDERS]),
        "files_move" => any(&[
            bit::RENAME_FILES,
            bit::RENAME_FOLDERS,
            bit::MOVE_FILES,
            bit::MOVE_FOLDERS,
        ]),
        _ => true,
    };
    if !allowed {
        return Err(Refusal::Denied("You are not allowed to change that."));
    }
    match req.req.as_str() {
        "files_mkdir" => {
            let params = serde_json::from_value::<FilesDownloadParams>(req.params.clone())
                .map_err(|_| Refusal::Malformed)?;
            let path = entry_path(&params.path)?;
            if !may(bit::CREATE_FOLDERS) {
                return Err(Refusal::Denied("You are not allowed to create folders."));
            }
            reach(&path)?;
            source.make_folder(&path).await?;
            info!(uid, %path, "folder created");
        }
        "files_delete" => {
            let params = serde_json::from_value::<FilesDownloadParams>(req.params.clone())
                .map_err(|_| Refusal::Malformed)?;
            let path = entry_path(&params.path)?;
            reach(&path)?;
            let kind = service.source.info(&path).await?.kind;
            let (needed, denied) = match kind {
                FileKind::File => (bit::DELETE_FILES, "You are not allowed to delete files."),
                FileKind::Folder => (
                    bit::DELETE_FOLDERS,
                    "You are not allowed to delete folders.",
                ),
            };
            if !may(needed) {
                return Err(Refusal::Denied(denied));
            }
            source
                .delete(&path, kind, may(bit::VIEW_DROP_BOXES))
                .await?;
            info!(uid, %path, "deleted");
        }
        "files_move" => {
            let params = serde_json::from_value::<FilesMoveParams>(req.params.clone())
                .map_err(|_| Refusal::Malformed)?;
            let (path, to) = (entry_path(&params.path)?, entry_path(&params.to)?);
            reach(&path)?;
            reach(&to)?;
            let kind = service.source.info(&path).await?.kind;
            let folder = kind == FileKind::Folder;
            // One request is both of the legacy wire's: a new name asks
            // what Set Info's rename does, and a new folder what Move does.
            if path.name() != to.name()
                && !may(if folder {
                    bit::RENAME_FOLDERS
                } else {
                    bit::RENAME_FILES
                })
            {
                return Err(Refusal::Denied(if folder {
                    "You are not allowed to rename folders."
                } else {
                    "You are not allowed to rename files."
                }));
            }
            if path.parent() != to.parent()
                && !may(if folder {
                    bit::MOVE_FOLDERS
                } else {
                    bit::MOVE_FILES
                })
            {
                return Err(Refusal::Denied(if folder {
                    "You are not allowed to move folders."
                } else {
                    "You are not allowed to move files."
                }));
            }
            source
                .rename(&path, &to, kind, may(bit::VIEW_DROP_BOXES))
                .await?;
            info!(uid, from = %path, %to, "moved");
        }
        _ => {
            let params = serde_json::from_value::<FilesCommentParams>(req.params.clone())
                .map_err(|_| Refusal::Malformed)?;
            let path = entry_path(&params.path)?;
            reach(&path)?;
            let kind = service.source.info(&path).await?.kind;
            let (needed, denied) = match kind {
                FileKind::File => (bit::COMMENT_FILES, "You are not allowed to comment files."),
                FileKind::Folder => (
                    bit::COMMENT_FOLDERS,
                    "You are not allowed to comment folders.",
                ),
            };
            if !may(needed) {
                return Err(Refusal::Denied(denied));
            }
            source.set_comment(&path, kind, &params.comment).await?;
            info!(uid, %path, "comment set");
        }
    }
    Ok(())
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

/// mhxd's `check_dropbox`: a path naming a drop box, in any case, is for
/// accounts that may view drop boxes, to list, inspect or download.
fn drop_box_refusal(id: u64, state: &SessState, path: &FilePath) -> Option<String> {
    (path.is_drop_box() && !state.access.has(bit::VIEW_DROP_BOXES)).then(|| {
        crate::proto::reply_err(
            id,
            "access_denied",
            "You are not allowed to view drop boxes.",
        )
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
        FileError::CrossesFilesystems => (
            "cross_filesystem",
            "That cannot be moved across filesystems.",
        ),
        FileError::TooDeep => ("too_deep", "Folders cannot be nested that deeply."),
        FileError::HoldsDropBox => ("access_denied", "That folder holds a drop box."),
        FileError::Busy => ("busy", "The file service is busy."),
        FileError::Unavailable(_) => ("not_available", "The file service is unavailable."),
    };
    crate::proto::reply_err(id, code, message)
}
