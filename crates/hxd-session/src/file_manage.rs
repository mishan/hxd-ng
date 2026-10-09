//! File management on the legacy wire: Delete (204), New Folder (205),
//! Set Info (207: rename and comment), Move (208), and Make Alias (209),
//! which this file area refuses.
//!
//! mhxd is the reference for what each request carries and what each
//! needs (`files.c`, `rcv.c`), with one deliberate difference: mhxd lets
//! an account with either Delete or Move bit act on files and folders
//! alike, and here each kind asks for its own bit, as the bitmap names
//! them. An entry is named by the name this connection was listed, byte
//! for byte, so the connection's encoding runs through here as it does
//! through listing.

use hxd_core::access::bit;
use hxd_core::{Account, FileError, FileKind, FilePath};
use hxd_files::{FileService, LocalFileSource};
use hxproto::messages::{tag, ClientHdr};
use tracing::info;

use crate::encoding::TextEncoding;
use crate::files;

/// Make File Alias, which `hxproto` has no name for.
pub(crate) const MAKE_ALIAS: u32 = 0x00d1;

/// The transactions answered here.
pub(crate) fn handles(ty: u32) -> bool {
    ty == MAKE_ALIAS
        || [
            ClientHdr::FileDelete,
            ClientHdr::FileMkdir,
            ClientHdr::FileSetInfo,
            ClientHdr::FileMove,
        ]
        .iter()
        .any(|hdr| hdr.as_u32() == ty)
}

/// Why a request was refused: a task error of its own, or the file
/// area's.
pub(crate) enum Refusal {
    Text(&'static str),
    File(FileError),
}

impl From<FileError> for Refusal {
    fn from(error: FileError) -> Self {
        Refusal::File(error)
    }
}

/// Who is asking, in the terms the answer turns on.
pub(crate) struct Asker<'a> {
    pub account: &'a Account,
    pub enc: TextEncoding,
    pub large: bool,
    pub core: &'a hxd_core::Core,
    pub uid: hxd_core::Uid,
}

impl Asker<'_> {
    fn can(&self, b: u8) -> bool {
        self.account.access.has(b)
    }

    fn drop_boxes(&self) -> bool {
        self.can(bit::VIEW_DROP_BOXES)
    }

    /// mhxd's `check_dropbox`: a path naming a drop box is out of reach
    /// without the bit that views them, for every act here.
    fn reach(&self, path: &FilePath) -> Result<(), Refusal> {
        if path.is_drop_box() && !self.drop_boxes() {
            return Err(DROP_BOX);
        }
        Ok(())
    }

    /// [`reach`](Self::reach) asked of the path as the client spelled it,
    /// before anything is looked up: a lookup first would answer "File
    /// not found." for a name a drop box does not hold and this refusal
    /// for one it does, which is a listing of the drop box one guess at a
    /// time. The check on the resolved path still follows, for a name
    /// that reaches a drop box without spelling one.
    fn reach_spelled(&self, dir: Option<&[u8]>, name: Option<&[u8]>) -> Result<(), Refusal> {
        if files::spells_drop_box(self.enc, dir, name) && !self.drop_boxes() {
            return Err(DROP_BOX);
        }
        Ok(())
    }
}

const DROP_BOX: Refusal = Refusal::Text("You are not allowed to view drop boxes.");

/// Answers one of the transactions [`handles`] names; the reply to a
/// success carries nothing, as mhxd's does.
pub(crate) async fn transaction(
    service: Option<&FileService>,
    who: Asker<'_>,
    ty: u32,
    fields: &[(u16, &[u8])],
) -> Result<(), Refusal> {
    let field = |tag: u16| {
        fields
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, data)| *data)
    };
    // An alias would be a symlink, and this file area neither follows nor
    // shows one: it was made for exactly that.
    if ty == MAKE_ALIAS {
        return Err(Refusal::Text("This server does not make aliases."));
    }
    let service = service.ok_or(Refusal::Text("Files are not available on this server."))?;
    let source: &LocalFileSource = service
        .uploads
        .as_deref()
        .ok_or(Refusal::Text("This file area is read-only."))?;
    let listed = service.source.as_ref();
    let dir = field(tag::DIR);
    let name = field(tag::FILE_NAME);
    let login = &who.account.login;

    if ty == ClientHdr::FileMkdir.as_u32() {
        if !who.can(bit::CREATE_FOLDERS) {
            return Err(Refusal::Text("You are not allowed to create folders."));
        }
        who.reach_spelled(dir, name)?;
        let (components, name) = files::named(dir, name)?;
        let parent =
            files::resolve_folders(listed, &components, who.large, who.enc, who.drop_boxes())
                .await?;
        let path = files::new_name(&parent, &name, who.enc)?;
        who.reach(&path)?;
        // A folder costs no spam points beyond its transaction's, so what
        // one account may make is held to [limits] folders.
        if who.core.folder_reserve(who.uid).is_err() {
            return Err(Refusal::Text(
                "You are making folders too fast. Try again in a little while.",
            ));
        }
        if let Err(error) = source.make_folder(&path).await {
            who.core.folder_refund(who.uid);
            return Err(error.into());
        }
        info!(%login, %path, "folder created");
        return Ok(());
    }

    if ty == ClientHdr::FileDelete.as_u32() {
        if !who.can(bit::DELETE_FILES) && !who.can(bit::DELETE_FOLDERS) {
            return Err(Refusal::Text("You are not allowed to delete files."));
        }
        who.reach_spelled(dir, name)?;
        let (components, name) = files::named(dir, name)?;
        let (path, entry, _) = files::resolve_in(
            listed,
            &components,
            &name,
            who.large,
            who.enc,
            who.drop_boxes(),
        )
        .await?;
        who.reach(&path)?;
        match entry.kind {
            FileKind::File if !who.can(bit::DELETE_FILES) => {
                return Err(Refusal::Text("You are not allowed to delete files."));
            }
            FileKind::Folder if !who.can(bit::DELETE_FOLDERS) => {
                return Err(Refusal::Text("You are not allowed to delete folders."));
            }
            _ => {}
        }
        source.delete(&path, entry.kind, who.drop_boxes()).await?;
        info!(%login, %path, "deleted");
        return Ok(());
    }

    // Before any lookup, as mhxd refuses them (`rcv.c`): an account that
    // may do none of what a request asks learns nothing from it of what
    // exists, and what the entry turns out to be then says which of its
    // bits it needs.
    if ty == ClientHdr::FileMove.as_u32()
        && !who.can(bit::MOVE_FILES)
        && !who.can(bit::MOVE_FOLDERS)
    {
        return Err(Refusal::Text("You are not allowed to move files."));
    }
    if ty == ClientHdr::FileSetInfo.as_u32()
        && ![
            bit::RENAME_FILES,
            bit::RENAME_FOLDERS,
            bit::COMMENT_FILES,
            bit::COMMENT_FOLDERS,
        ]
        .iter()
        .any(|b| who.can(*b))
    {
        return Err(Refusal::Text(
            "You are not allowed to rename or comment files.",
        ));
    }

    // Set Info and Move name the entry the way Get Info does. mhxd also
    // takes a Move with DIR alone, which moves DIR's folder to wherever
    // DIR_RENAME names; no client sends it, and here it is refused.
    let name = name
        .filter(|name| !name.is_empty())
        .ok_or(Refusal::Text("No file name was supplied."))?;
    who.reach_spelled(dir, Some(name))?;
    let to_dir = field(tag::DIR_RENAME);
    if ty == ClientHdr::FileMove.as_u32() {
        who.reach_spelled(to_dir, None)?;
    }
    let components = match dir {
        Some(bytes) => files::parse_dir(bytes)?,
        None => Vec::new(),
    };
    let (path, entry, wire_name) = files::resolve_in(
        listed,
        &components,
        name,
        who.large,
        who.enc,
        who.drop_boxes(),
    )
    .await?;
    who.reach(&path)?;
    let folder = entry.kind == FileKind::Folder;

    if ty == ClientHdr::FileMove.as_u32() {
        let to_dir = to_dir.ok_or(Refusal::Text("No destination was supplied."))?;
        if !who.can(if folder {
            bit::MOVE_FOLDERS
        } else {
            bit::MOVE_FILES
        }) {
            return Err(Refusal::Text(if folder {
                "You are not allowed to move folders."
            } else {
                "You are not allowed to move files."
            }));
        }
        let parent =
            files::resolve_dir(listed, Some(to_dir), who.large, who.enc, who.drop_boxes()).await?;
        let to = parent.join(path.name().ok_or(FileError::InvalidPath)?)?;
        who.reach(&to)?;
        source
            .rename(&path, &to, entry.kind, who.drop_boxes())
            .await?;
        info!(%login, from = %path, %to, "moved");
        return Ok(());
    }

    // Set Info. A client sends back what its Get Info window shows, so a
    // field is a change only when it differs from what this connection
    // was shown: renaming a file asks nothing of the comment bits, and
    // commenting nothing of the rename ones.
    let rename = field(tag::FILE_RENAME).filter(|new| !new.is_empty() && *new != wire_name);
    let comment = field(tag::FILE_COMMENT).filter(|comment| {
        *comment
            != who
                .enc
                .body_capped(entry.comment.as_deref().unwrap_or_default(), 255)
    });
    if field(tag::FILE_RENAME).is_none() && field(tag::FILE_COMMENT).is_none() {
        return Err(Refusal::Text("Nothing to change was supplied."));
    }
    if comment.is_some()
        && !who.can(if folder {
            bit::COMMENT_FOLDERS
        } else {
            bit::COMMENT_FILES
        })
    {
        return Err(Refusal::Text(if folder {
            "You are not allowed to comment folders."
        } else {
            "You are not allowed to comment files."
        }));
    }
    let to = match rename {
        None => None,
        Some(new) => {
            if !who.can(if folder {
                bit::RENAME_FOLDERS
            } else {
                bit::RENAME_FILES
            }) {
                return Err(Refusal::Text(if folder {
                    "You are not allowed to rename folders."
                } else {
                    "You are not allowed to rename files."
                }));
            }
            let parent = path.parent().ok_or(FileError::InvalidPath)?;
            let to = files::new_name(&parent, new, who.enc)?;
            who.reach(&to)?;
            Some(to)
        }
    };
    // Comment first, then the name, as mhxd orders them: the sidecar the
    // comment is written to moves with the entry.
    if let Some(comment) = comment {
        source
            .set_comment(&path, entry.kind, &who.enc.decode(comment))
            .await?;
        info!(%login, %path, "comment set");
    }
    if let Some(to) = to {
        source
            .rename(&path, &to, entry.kind, who.drop_boxes())
            .await?;
        info!(%login, from = %path, %to, "renamed");
    }
    Ok(())
}
