use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::TryStreamExt;
use hxd_core::{FileBody, FileEntry, FileError, FileInfo, FileKind, FilePath, FileSource};
use reqwest::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, ETAG, IF_MATCH, RANGE};
use serde::de::{self, Visitor};
use serde::Deserialize;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::io::StreamReader;
use url::Url;

#[derive(Debug, Clone, Copy)]
pub struct ManifestLimits {
    pub max_file_size: u64,
    pub max_entries: usize,
    pub max_concurrent: usize,
    pub request_timeout: Duration,
}

impl Default for ManifestLimits {
    fn default() -> Self {
        ManifestLimits {
            max_file_size: 64 * 1024 * 1024 * 1024,
            max_entries: 100_000,
            max_concurrent: 8,
            request_timeout: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    files: Vec<Record>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    path: String,
    #[serde(deserialize_with = "decimal_u64")]
    size: u64,
    #[serde(default)]
    media_type: Option<String>,
    #[serde(default)]
    etag: Option<String>,
    #[serde(default)]
    ranges: bool,
    #[serde(default)]
    created: Option<u32>,
    #[serde(default)]
    modified: Option<u32>,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Debug, Clone)]
struct Object {
    info: FileInfo,
    etag: Option<String>,
    ranges: bool,
}

#[derive(Clone)]
pub struct HttpManifestSource {
    origin: Url,
    objects: Arc<BTreeMap<FilePath, Object>>,
    children: Arc<BTreeMap<FilePath, Vec<FileEntry>>>,
    client: reqwest::Client,
    permits: Arc<Semaphore>,
    request_timeout: Duration,
}

impl HttpManifestSource {
    pub fn from_json(
        origin: &str,
        manifest_json: &[u8],
        limits: ManifestLimits,
    ) -> Result<Self, FileError> {
        if limits.max_entries == 0 || limits.max_concurrent == 0 {
            return Err(FileError::Unavailable(
                "entry and concurrency limits must be non-zero".into(),
            ));
        }
        let mut origin = Url::parse(origin)
            .map_err(|e| FileError::Unavailable(format!("invalid origin URL: {e}")))?;
        if !matches!(origin.scheme(), "http" | "https")
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(FileError::Unavailable(
                "origin must be an http(s) base URL without credentials, query, or fragment".into(),
            ));
        }
        if !origin.path().ends_with('/') {
            origin
                .path_segments_mut()
                .map_err(|_| FileError::InvalidPath)?
                .push("");
        }

        let manifest: Manifest = serde_json::from_slice(manifest_json)
            .map_err(|e| FileError::Unavailable(format!("invalid files manifest: {e}")))?;
        if manifest.version != 1 {
            return Err(FileError::Unavailable(format!(
                "unsupported files manifest version {}",
                manifest.version
            )));
        }
        if manifest.files.len() > limits.max_entries {
            return Err(FileError::Unavailable(
                "files manifest has too many entries".into(),
            ));
        }

        let mut objects = BTreeMap::new();
        let mut folders = BTreeSet::from([FilePath::root()]);
        for record in manifest.files {
            let path = FilePath::parse(&record.path)?;
            if path.is_root() || record.size > limits.max_file_size {
                return Err(if record.size > limits.max_file_size {
                    FileError::TooLarge
                } else {
                    FileError::InvalidPath
                });
            }
            if objects.contains_key(&path) {
                return Err(FileError::Unavailable(format!(
                    "duplicate manifest path {path}"
                )));
            }
            if folders.contains(&path) {
                return Err(FileError::Unavailable(format!(
                    "manifest path is both a file and folder: {path}"
                )));
            }
            let mut parent = path.parent();
            while let Some(folder) = parent {
                if objects.contains_key(&folder) {
                    return Err(FileError::Unavailable(format!(
                        "manifest file is used as a folder: {folder}"
                    )));
                }
                folders.insert(folder.clone());
                parent = folder.parent();
            }
            objects.insert(
                path.clone(),
                Object {
                    info: FileInfo {
                        path,
                        kind: FileKind::File,
                        size: record.size,
                        resource_size: 0,
                        type_code: None,
                        creator_code: None,
                        media_type: record.media_type,
                        created: record.created,
                        modified: record.modified,
                        comment: record.comment,
                    },
                    etag: record.etag,
                    ranges: record.ranges,
                },
            );
        }

        for folder in folders {
            objects.entry(folder.clone()).or_insert_with(|| Object {
                info: FileInfo {
                    path: folder,
                    kind: FileKind::Folder,
                    size: 0,
                    resource_size: 0,
                    type_code: None,
                    creator_code: None,
                    media_type: None,
                    created: None,
                    modified: None,
                    comment: None,
                },
                etag: None,
                ranges: false,
            });
        }

        let keys: Vec<_> = objects.keys().cloned().collect();
        let mut children: BTreeMap<FilePath, Vec<FileEntry>> = BTreeMap::new();
        for path in keys.iter().filter(|p| !p.is_root()) {
            let parent = path.parent().expect("non-root path has parent");
            let object = &objects[path];
            children.entry(parent).or_default().push(FileEntry {
                name: path.name().expect("non-root path has name").to_owned(),
                kind: object.info.kind,
                size: object.info.size,
                media_type: object.info.media_type.clone(),
                modified: object.info.modified,
            });
        }
        for values in children.values_mut() {
            values.sort_by(|a, b| a.name.cmp(&b.name));
        }
        for (path, object) in &mut objects {
            if object.info.kind == FileKind::Folder {
                object.info.size = children.get(path).map_or(0, |v| v.len() as u64);
            }
        }

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(limits.request_timeout)
            .build()
            .map_err(|e| FileError::Unavailable(format!("HTTP client: {e}")))?;
        Ok(HttpManifestSource {
            origin,
            objects: Arc::new(objects),
            children: Arc::new(children),
            client,
            permits: Arc::new(Semaphore::new(limits.max_concurrent)),
            request_timeout: limits.request_timeout,
        })
    }

    fn object_url(&self, path: &FilePath) -> Result<Url, FileError> {
        let mut url = self.origin.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| FileError::InvalidPath)?;
            segments.pop_if_empty();
            for component in path.components() {
                segments.push(component);
            }
        }
        if url.origin() != self.origin.origin() {
            return Err(FileError::InvalidPath);
        }
        Ok(url)
    }
}

impl FileSource for HttpManifestSource {
    fn list<'a>(&'a self, path: &'a FilePath) -> hxd_core::FileFuture<'a, Vec<FileEntry>> {
        Box::pin(async move {
            let object = self.objects.get(path).ok_or(FileError::NotFound)?;
            if object.info.kind != FileKind::Folder {
                return Err(FileError::NotFolder);
            }
            Ok(self.children.get(path).cloned().unwrap_or_default())
        })
    }

    fn info<'a>(&'a self, path: &'a FilePath) -> hxd_core::FileFuture<'a, FileInfo> {
        Box::pin(async move {
            self.objects
                .get(path)
                .map(|object| object.info.clone())
                .ok_or(FileError::NotFound)
        })
    }

    fn open<'a>(&'a self, path: &'a FilePath, from: u64) -> hxd_core::FileFuture<'a, FileBody> {
        let path = path.clone();
        Box::pin(async move {
            let object = self
                .objects
                .get(&path)
                .cloned()
                .ok_or(FileError::NotFound)?;
            if object.info.kind != FileKind::File {
                return Err(FileError::NotFile);
            }
            if from > object.info.size {
                return Err(FileError::RangeInvalid);
            }
            if from != 0 && !object.ranges {
                return Err(FileError::RangeUnsupported);
            }
            let permit =
                tokio::time::timeout(self.request_timeout, self.permits.clone().acquire_owned())
                    .await
                    .map_err(|_| FileError::Busy)?
                    .map_err(|_| FileError::Unavailable("file source stopped".into()))?;
            let url = self.object_url(&path)?;
            let mut request = self.client.get(url);
            if from != 0 {
                request = request.header(RANGE, format!("bytes={from}-"));
            }
            if let Some(etag) = &object.etag {
                request = request.header(IF_MATCH, etag);
            }
            let response = tokio::time::timeout(self.request_timeout, request.send())
                .await
                .map_err(|_| FileError::Unavailable("origin request timed out".into()))?
                .map_err(|e| FileError::Unavailable(e.to_string()))?;
            let expected = object.info.size - from;
            let expected_status = if from == 0 { 200 } else { 206 };
            if response.status().as_u16() == 412 {
                return Err(FileError::OriginChanged);
            }
            if response.status().as_u16() != expected_status {
                return Err(FileError::Unavailable(format!(
                    "origin returned {}",
                    response.status()
                )));
            }
            let length = header_u64(response.headers().get(CONTENT_LENGTH))
                .ok_or_else(|| FileError::Unavailable("origin omitted Content-Length".into()))?;
            if length != expected {
                return Err(FileError::OriginChanged);
            }
            if from != 0 {
                let expected_range =
                    format!("bytes {from}-{}/{}", object.info.size - 1, object.info.size);
                if response
                    .headers()
                    .get(CONTENT_RANGE)
                    .and_then(|v| v.to_str().ok())
                    != Some(expected_range.as_str())
                {
                    return Err(FileError::OriginChanged);
                }
            }
            if let Some(expected_etag) = object.etag.as_deref() {
                if response.headers().get(ETAG).and_then(|v| v.to_str().ok()) != Some(expected_etag)
                {
                    return Err(FileError::OriginChanged);
                }
            }
            if object.ranges
                && response
                    .headers()
                    .get(ACCEPT_RANGES)
                    .and_then(|v| v.to_str().ok())
                    != Some("bytes")
            {
                return Err(FileError::OriginChanged);
            }
            let stream = response
                .bytes_stream()
                .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e));
            let reader = PermitReader {
                inner: StreamReader::new(stream),
                _permit: permit,
            };
            Ok(FileBody {
                len: expected,
                reader: Box::pin(reader),
            })
        })
    }
}

fn header_u64(value: Option<&reqwest::header::HeaderValue>) -> Option<u64> {
    value?.to_str().ok()?.parse().ok()
}

struct PermitReader<R> {
    inner: R,
    _permit: OwnedSemaphorePermit,
}

impl<R: AsyncRead + Unpin> AsyncRead for PermitReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

fn decimal_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Decimal;
    impl Visitor<'_> for Decimal {
        type Value = u64;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a decimal u64 string")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<u64, E> {
            if value.is_empty()
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(E::custom("u64 is not in canonical decimal form"));
            }
            value.parse().map_err(E::custom)
        }
    }
    deserializer.deserialize_str(Decimal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const MANIFEST: &[u8] = br#"{
      "version": 1,
      "files": [
        {"path":"manuals/read me.txt","size":"12","media_type":"text/plain","ranges":true},
        {"path":"archive.sit","size":"4294967297"}
      ]
    }"#;

    #[tokio::test]
    async fn manifest_builds_stable_hierarchy_with_u64_sizes() {
        let source = HttpManifestSource::from_json(
            "https://example.invalid/files/",
            MANIFEST,
            ManifestLimits::default(),
        )
        .unwrap();
        let root = source.list(&FilePath::root()).await.unwrap();
        assert_eq!(
            root.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            ["archive.sit", "manuals"]
        );
        assert_eq!(root[0].size, 4_294_967_297);
        let folder = FilePath::parse("manuals").unwrap();
        assert_eq!(source.info(&folder).await.unwrap().size, 1);
        assert_eq!(source.list(&folder).await.unwrap()[0].name, "read me.txt");
    }

    #[test]
    fn manifest_rejects_escape_duplicates_and_numeric_sizes() {
        for manifest in [
            br#"{"version":1,"files":[{"path":"../secret","size":"1"}]}"#.as_slice(),
            br#"{"version":1,"files":[{"path":"x","size":"1"},{"path":"x","size":"2"}]}"#
                .as_slice(),
            br#"{"version":1,"files":[{"path":"x","size":1}]}"#.as_slice(),
            br#"{"version":1,"files":[{"path":"x","size":"01"}]}"#.as_slice(),
            br#"{"version":1,"files":[{"path":"x","size":"1"},{"path":"x/y","size":"1"}]}"#
                .as_slice(),
            br#"{"version":1,"files":[{"path":"x/y","size":"1"},{"path":"x","size":"1"}]}"#
                .as_slice(),
        ] {
            assert!(HttpManifestSource::from_json(
                "https://example.invalid/",
                manifest,
                ManifestLimits::default()
            )
            .is_err());
        }
        assert!(
            HttpManifestSource::from_json("file:///tmp/", MANIFEST, ManifestLimits::default())
                .is_err()
        );
    }

    #[tokio::test]
    async fn redirects_and_changed_lengths_fail_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 1024];
                let read = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                let response = if request.starts_with("GET /redirect ") {
                    "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nxx"
                };
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let source = HttpManifestSource::from_json(
            &format!("http://{address}/"),
            br#"{"version":1,"files":[
                {"path":"redirect","size":"1"},
                {"path":"changed","size":"1"}
            ]}"#,
            ManifestLimits::default(),
        )
        .unwrap();

        let redirected = source.open(&FilePath::parse("redirect").unwrap(), 0).await;
        assert!(matches!(redirected, Err(FileError::Unavailable(_))));
        let changed = source.open(&FilePath::parse("changed").unwrap(), 0).await;
        assert!(matches!(changed, Err(FileError::OriginChanged)));
    }
}
