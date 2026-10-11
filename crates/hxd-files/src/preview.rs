//! What a client is shown of a file before it downloads one
//! (`docs/hotline-ng.md` §7.2): an image this server has decoded and drawn
//! again, smaller, or the start of a text in UTF-8. Never the file's own
//! bytes, so a preview is nothing a browser has to be trusted to parse.

use std::sync::Arc;

use hxd_core::{FileError, FileInfo, MediaCodec, MediaReject};
use tokio::io::AsyncReadExt;

use crate::FileService;

/// How much of a text a preview shows.
pub const TEXT_BYTES: u64 = 256 * 1024;

/// The pipeline image previews are made with, and its bounds.
#[derive(Clone)]
pub struct ImagePreviews {
    pub codec: Arc<dyn MediaCodec>,
    /// The largest file read for one; the codec refuses larger itself.
    pub max_bytes: u64,
    /// What a preview is fitted to, on its longer side.
    pub max_dimension: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewKind {
    Image,
    Text,
}

pub struct Preview {
    pub kind: PreviewKind,
    pub media_type: &'static str,
    pub bytes: Vec<u8>,
    /// A text longer than [`TEXT_BYTES`], shown only in part.
    pub truncated: bool,
    /// An image's, as drawn.
    pub dimensions: Option<(u32, u32)>,
}

impl std::fmt::Debug for Preview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Preview")
            .field("kind", &self.kind)
            .field("len", &self.bytes.len())
            .field("truncated", &self.truncated)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum PreviewError {
    File(FileError),
    /// Neither an image the pipeline takes nor text.
    Unsupported,
    TooLarge,
    Busy,
}

impl From<FileError> for PreviewError {
    fn from(error: FileError) -> Self {
        PreviewError::File(error)
    }
}

pub async fn make(service: &FileService, info: &FileInfo) -> Result<Preview, PreviewError> {
    let mut body = service.source.open(&info.path, 0).await?;
    let mut head = Vec::new();
    read(
        &mut body.reader,
        TEXT_BYTES.min(info.size),
        &mut head,
        service,
    )
    .await?;
    if is_image(&head) {
        let Some(images) = service.image_previews.as_ref() else {
            return Err(PreviewError::Unsupported);
        };
        if info.size > images.max_bytes {
            return Err(PreviewError::TooLarge);
        }
        read(
            &mut body.reader,
            info.size - head.len() as u64,
            &mut head,
            service,
        )
        .await?;
        let (codec, max) = (images.codec.clone(), images.max_dimension);
        let drawn = crate::spawn_blocking("preview", move || codec.preview(&head, max))
            .await
            .map_err(|e| FileError::Unavailable(e.to_string()))?
            .map_err(|e| match e {
                MediaReject::TooLarge => PreviewError::TooLarge,
                MediaReject::Busy => PreviewError::Busy,
                _ => PreviewError::Unsupported,
            })?;
        return Ok(Preview {
            kind: PreviewKind::Image,
            media_type: drawn.mime.mime(),
            dimensions: Some((drawn.width, drawn.height)),
            bytes: drawn.bytes,
            truncated: false,
        });
    }
    let truncated = info.size > head.len() as u64;
    let declared = info.type_code == Some(*b"TEXT")
        || info
            .media_type
            .as_deref()
            .is_some_and(|m| m.starts_with("text/"));
    let text = text(&head, truncated, declared).ok_or(PreviewError::Unsupported)?;
    Ok(Preview {
        kind: PreviewKind::Text,
        media_type: "text/plain; charset=utf-8",
        bytes: text.into_bytes(),
        truncated,
        dimensions: None,
    })
}

/// Up to `len` more bytes of `reader` onto `into`, within the service's
/// idle timeout.
async fn read(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    len: u64,
    into: &mut Vec<u8>,
    service: &FileService,
) -> Result<(), FileError> {
    tokio::time::timeout(service.idle_timeout, reader.take(len).read_to_end(into))
        .await
        .map_err(|_| FileError::Unavailable("preview read stalled".into()))?
        .map_err(|e| FileError::Unavailable(e.to_string()))?;
    Ok(())
}

/// The three formats the pipeline takes, by their magic.
fn is_image(head: &[u8]) -> bool {
    head.starts_with(&[0xff, 0xd8, 0xff])
        || head.starts_with(b"\x89PNG\r\n\x1a\n")
        || head.starts_with(b"GIF87a")
        || head.starts_with(b"GIF89a")
}

/// `head` as text with LF line endings, or `None` for what is not text: a
/// NUL anywhere, or bytes that are not UTF-8 in a file that does not say
/// it is text, which is then read as Mac Roman. A `truncated` head may
/// end partway through a character, which is left off.
fn text(head: &[u8], truncated: bool, declared: bool) -> Option<String> {
    if head.contains(&0) {
        return None;
    }
    let text = match std::str::from_utf8(head) {
        Ok(text) => text.to_owned(),
        Err(e) if truncated && e.error_len().is_none() => {
            String::from_utf8_lossy(&head[..e.valid_up_to()]).into_owned()
        }
        Err(_) if declared => hxproto::text::mac_roman_to_utf8(head),
        Err(_) => return None,
    };
    Some(text.replace("\r\n", "\n").replace('\r', "\n"))
}

#[cfg(test)]
mod tests {
    use super::text;

    #[test]
    fn text_is_utf8_or_declared_mac_roman_with_lf_endings() {
        let cases: [(&[u8], bool, bool, Option<&str>); 7] = [
            (
                b"one\r\ntwo\rthree\n",
                false,
                false,
                Some("one\ntwo\nthree\n"),
            ),
            ("caf\u{e9}".as_bytes(), false, false, Some("caf\u{e9}")),
            (b"caf\x8e", false, true, Some("caf\u{e9}")),
            (b"caf\x8e", false, false, None),
            (b"caf\xc3", true, false, Some("caf")),
            (b"caf\xc3", false, false, None),
            (b"text\0more", false, true, None),
        ];
        for (head, truncated, declared, expected) in cases {
            assert_eq!(
                text(head, truncated, declared).as_deref(),
                expected,
                "{head:?} truncated={truncated} declared={declared}"
            );
        }
    }
}
