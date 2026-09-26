//! The server banner, as mhxd serves it (`rcv.c`): `HTLS_HDR_BANNER` after
//! a client's AGREEMENTAGREE, carrying the banner's type and URL, and —
//! for a banner this server holds — `HTLC_HDR_DOWNLOAD_BANNER` answered
//! with an HTXF reference the client redeems for the image's bytes.
//!
//! Two shapes, told apart by the type: `"URL "` sends the client to fetch
//! the image itself, and anything else names the format of an image to be
//! downloaded here, with the URL, when there is one, as where a click on
//! it goes.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use hxd_files::TransferRegistry;
use hxproto::messages::tag;

/// The largest banner file served. A classic banner is a 468×60 JPEG of a
/// few kilobytes; this is GtkHx's own ceiling, so no banner this server
/// accepts is one that client refuses.
pub const MAX_BANNER_BYTES: usize = 1024 * 1024;

/// The type of a banner the client fetches from its URL.
const TYPE_URL: [u8; 4] = *b"URL ";

/// The banner a server shows every 1.5+ client after its agreement.
pub struct Banner {
    url: Option<String>,
    file: Option<BannerFile>,
}

struct BannerFile {
    path: PathBuf,
    transfers: Arc<TransferRegistry>,
    current: RwLock<Image>,
}

/// A banner image as loaded: its type code and its bytes.
#[derive(Clone)]
pub(crate) struct Image {
    pub kind: [u8; 4],
    pub bytes: Arc<[u8]>,
}

impl Banner {
    /// A banner the client fetches from `url` itself.
    pub fn url(url: String) -> Self {
        Banner {
            url: Some(url),
            file: None,
        }
    }

    /// A banner held here, read from `path` now and on every [`reload`],
    /// and fetched over HTXF through `transfers`. `url`, if any, is where
    /// a click on it goes.
    ///
    /// [`reload`]: Banner::reload
    pub fn file(
        path: &Path,
        url: Option<String>,
        transfers: Arc<TransferRegistry>,
    ) -> Result<Self, String> {
        let image = load(path)?;
        Ok(Banner {
            url,
            file: Some(BannerFile {
                path: path.to_path_buf(),
                transfers,
                current: RwLock::new(image),
            }),
        })
    }

    /// Re-read the banner file from the path it was loaded from. A file
    /// that no longer loads leaves the banner in use as it was. Nothing to
    /// do for a banner that is only a URL.
    pub fn reload(&self) -> Result<(), String> {
        if let Some(file) = &self.file {
            let image = load(&file.path)?;
            *file.current.write().unwrap() = image;
        }
        Ok(())
    }

    /// The type code clients are sent: `"URL "`, or the image's format.
    pub fn kind(&self) -> [u8; 4] {
        match &self.file {
            Some(file) => file.current.read().unwrap().kind,
            None => TYPE_URL,
        }
    }

    /// The size of the banner held here, when there is one.
    pub fn image_len(&self) -> Option<usize> {
        self.image().map(|(image, _)| image.bytes.len())
    }

    /// The `HTLS_HDR_BANNER` payload: the type always, the URL when there
    /// is one, which is what mhxd sends.
    pub(crate) fn push_chunks(&self) -> Vec<(u16, Vec<u8>)> {
        let mut chunks = vec![(tag::BANNER_TYPE, self.kind().to_vec())];
        if let Some(url) = &self.url {
            chunks.push((tag::BANNER_URL, url.as_bytes().to_vec()));
        }
        chunks
    }

    /// The image held here and the registry its transfers are issued from.
    pub(crate) fn image(&self) -> Option<(Image, &TransferRegistry)> {
        self.file.as_ref().map(|file| {
            (
                file.current.read().unwrap().clone(),
                file.transfers.as_ref(),
            )
        })
    }
}

/// Read a banner file, refusing one too large to serve or in a format no
/// client is told how to show.
fn load(path: &Path) -> Result<Image, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_BANNER_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() > MAX_BANNER_BYTES {
        return Err(format!(
            "{}: a banner is at most {} KiB",
            path.display(),
            MAX_BANNER_BYTES / 1024
        ));
    }
    let kind = sniff(&bytes).ok_or_else(|| {
        format!(
            "{}: a banner must be a JPEG, GIF or PNG image",
            path.display()
        )
    })?;
    Ok(Image {
        kind,
        bytes: bytes.into(),
    })
}

/// The Mac OS type code for an image, from its magic bytes. JPEG and GIF
/// are what a classic client can show; PNG is for the later clients that
/// decode it.
fn sniff(bytes: &[u8]) -> Option<[u8; 4]> {
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some(*b"JPEG")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some(*b"GIFf")
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(*b"PNGf")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hxd_files::EntryLimits;
    use std::time::Duration;

    fn registry() -> Arc<TransferRegistry> {
        Arc::new(TransferRegistry::new(
            Duration::from_secs(60),
            EntryLimits {
                total: 4,
                per_session: 1,
                per_account: 1,
            },
        ))
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hxd-banner-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn formats_are_named_by_their_magic_not_their_extension() {
        assert_eq!(sniff(&[0xff, 0xd8, 0xff, 0xe0, 0]), Some(*b"JPEG"));
        assert_eq!(sniff(b"GIF89a\x01\x00"), Some(*b"GIFf"));
        assert_eq!(sniff(b"GIF87a\x01\x00"), Some(*b"GIFf"));
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n\0\0"), Some(*b"PNGf"));
        assert_eq!(sniff(b"BM\0\0"), None);
        assert_eq!(sniff(b""), None);
    }

    #[test]
    fn a_url_banner_sends_its_type_and_url() {
        let banner = Banner::url("https://hl.example/b.jpg".into());
        assert_eq!(
            banner.push_chunks(),
            vec![
                (tag::BANNER_TYPE, b"URL ".to_vec()),
                (tag::BANNER_URL, b"https://hl.example/b.jpg".to_vec()),
            ]
        );
        assert!(banner.image().is_none());
        banner.reload().unwrap();
    }

    #[test]
    fn a_file_banner_is_typed_by_its_image_and_keeps_its_link() {
        let path = scratch("link.gif");
        std::fs::write(&path, b"GIF89a-body").unwrap();
        let banner = Banner::file(&path, Some("https://hl.example/".into()), registry()).unwrap();
        assert_eq!(
            banner.push_chunks(),
            vec![
                (tag::BANNER_TYPE, b"GIFf".to_vec()),
                (tag::BANNER_URL, b"https://hl.example/".to_vec()),
            ]
        );
        assert_eq!(&*banner.image().unwrap().0.bytes, b"GIF89a-body");

        let bare = Banner::file(&path, None, registry()).unwrap();
        assert_eq!(
            bare.push_chunks(),
            vec![(tag::BANNER_TYPE, b"GIFf".to_vec())]
        );
    }

    #[test]
    fn files_too_large_or_of_no_known_format_are_refused() {
        let path = scratch("big.jpg");
        let mut big = vec![0xff, 0xd8, 0xff];
        big.resize(MAX_BANNER_BYTES + 1, 0);
        std::fs::write(&path, &big).unwrap();
        assert!(Banner::file(&path, None, registry())
            .err()
            .unwrap()
            .contains("at most 1024 KiB"));
        big.truncate(MAX_BANNER_BYTES);
        std::fs::write(&path, &big).unwrap();
        assert_eq!(
            Banner::file(&path, None, registry()).unwrap().image_len(),
            Some(MAX_BANNER_BYTES)
        );

        let path = scratch("banner.jpg");
        std::fs::write(&path, b"not an image").unwrap();
        assert!(Banner::file(&path, None, registry())
            .err()
            .unwrap()
            .contains("JPEG, GIF or PNG"));
        assert!(Banner::file(&scratch("missing.jpg"), None, registry()).is_err());
    }

    #[test]
    fn a_reload_takes_the_new_image_or_keeps_the_old_one() {
        let path = scratch("reload");
        std::fs::write(&path, b"GIF89a-old").unwrap();
        let banner = Banner::file(&path, None, registry()).unwrap();

        std::fs::write(&path, [0xff, 0xd8, 0xff, 1]).unwrap();
        banner.reload().unwrap();
        assert_eq!(banner.kind(), *b"JPEG");
        assert_eq!(banner.image_len(), Some(4));

        std::fs::write(&path, b"broken").unwrap();
        assert!(banner.reload().is_err());
        assert_eq!(banner.kind(), *b"JPEG");
        assert_eq!(&*banner.image().unwrap().0.bytes, [0xff, 0xd8, 0xff, 1]);
    }
}
