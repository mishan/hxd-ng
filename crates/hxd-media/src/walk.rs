//! Container walkers: follow each format's structure to its end, and
//! insist that the end is the end of the payload.
//!
//! This is the one piece of parsing the `image` crate does not do for
//! us, and it is the first gate a hostile upload meets after the sniff.
//! Two things come out of it. The walk **refuses polyglots** — a PNG
//! with a ZIP glued to its tail is a file two programs read differently,
//! and a server that re-serves it is a server that decides which of them
//! was right. And it is a cheap structural check ahead of a decoder:
//! anything that cannot be walked is not handed to `image` at all.
//!
//! There is no allowance for trailing padding. A client that appends
//! anything to a file it is about to upload has a bug, and papering over
//! it here would mean the check no longer says what it says.
//!
//! Every walker is bounds-checked arithmetic over a borrowed slice: no
//! allocation, no recursion, no panic on any input. They answer the
//! payload's structural facts, not its pixels.

/// What the leading bytes say this is — including the formats the
/// capability forbids, which are recognized *by name* so a rejection can
/// say why rather than "unsupported".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Jpeg,
    Png,
    Gif,
    // Named refusals. The spec forbids each of these, and a log line
    // that says "SVG" is worth more to an operator than one that says
    // "not an image".
    Svg,
    WebP,
    Avif,
    Heic,
    Tiff,
    Ico,
    Bmp,
    Unknown,
}

impl Format {
    /// Is this one of the three the capability allows?
    pub const fn allowed(self) -> bool {
        matches!(self, Format::Jpeg | Format::Png | Format::Gif)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Format::Jpeg => "JPEG",
            Format::Png => "PNG",
            Format::Gif => "GIF",
            Format::Svg => "SVG",
            Format::WebP => "WebP",
            Format::Avif => "AVIF",
            Format::Heic => "HEIC",
            Format::Tiff => "TIFF",
            Format::Ico => "ICO",
            Format::Bmp => "BMP",
            Format::Unknown => "unrecognized",
        }
    }
}

const PNG_MAGIC: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// The magic-byte sniff. Bounded: it reads a fixed leading window
/// however long the input is, and the declared MIME type is never
/// consulted — it is a hint the client offered, and this is the server
/// deciding.
pub fn sniff(data: &[u8]) -> Format {
    let head = &data[..data.len().min(32)];
    if head.starts_with(PNG_MAGIC) {
        return Format::Png;
    }
    if head.starts_with(&[0xff, 0xd8, 0xff]) {
        return Format::Jpeg;
    }
    if head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a") {
        return Format::Gif;
    }
    if head.starts_with(b"RIFF") && head.len() >= 12 && &head[8..12] == b"WEBP" {
        return Format::WebP;
    }
    // ISO-BMFF: the brand after `ftyp` says which of the family it is.
    if head.len() >= 12 && &head[4..8] == b"ftyp" {
        return match &head[8..12] {
            b"avif" | b"avis" => Format::Avif,
            b"heic" | b"heix" | b"hevc" | b"heim" | b"heis" | b"mif1" | b"msf1" => Format::Heic,
            _ => Format::Unknown,
        };
    }
    if head.starts_with(&[0x49, 0x49, 0x2a, 0x00]) || head.starts_with(&[0x4d, 0x4d, 0x00, 0x2a]) {
        return Format::Tiff;
    }
    if head.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        return Format::Ico;
    }
    if head.starts_with(b"BM") {
        return Format::Bmp;
    }
    // SVG is text and has no magic number, so the sniff is a scan of the
    // leading window for the two shapes an SVG can start with — enough
    // to name it in a rejection, which is all this arm is for.
    let text = &head[..head.len().min(32)];
    let lowered: Vec<u8> = text.iter().map(u8::to_ascii_lowercase).collect();
    if window_has(&lowered, b"<svg") || window_has(&lowered, b"<?xml") {
        return Format::Svg;
    }
    Format::Unknown
}

fn window_has(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Why a walk stopped. Every one of these is the same answer to the
/// client (`Unsupported`); the distinction is for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    /// The structure ran off the end of the payload.
    Truncated,
    /// A length, marker or block that cannot be part of this format.
    Malformed,
    /// The container ended before the payload did: bytes after `IEND`,
    /// `FFD9` or the GIF trailer. A polyglot, or a client with a bug.
    TrailingBytes,
}

/// What a successful walk learned. Dimensions come from the container's
/// own header, which is what makes them checkable before a decoder
/// allocates anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Walked {
    pub format: Format,
    pub width: u32,
    pub height: u32,
    /// GIF only: how many image descriptors the walk counted, and the
    /// sum of the frame delays in milliseconds. A still is one frame and
    /// no duration.
    pub frames: u32,
    pub duration_ms: u32,
}

/// Walk `data` as `format`, from its first byte to its last.
pub fn walk(format: Format, data: &[u8]) -> Result<Walked, WalkError> {
    match format {
        Format::Png => walk_png(data),
        Format::Jpeg => walk_jpeg(data),
        Format::Gif => walk_gif(data),
        _ => Err(WalkError::Malformed),
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// PNG: an eight-byte signature and then length-tagged chunks to `IEND`.
///
/// The lengths are what makes this walkable exactly: every chunk says
/// how long it is, so a walk that lands anywhere but the final byte
/// means a length lied or something was appended.
fn walk_png(data: &[u8]) -> Result<Walked, WalkError> {
    if !data.starts_with(PNG_MAGIC) {
        return Err(WalkError::Malformed);
    }
    let mut at = PNG_MAGIC.len();
    let (mut width, mut height) = (0u32, 0u32);
    let mut seen_ihdr = false;
    loop {
        if at + 8 > data.len() {
            return Err(WalkError::Truncated);
        }
        let len = be32(&data[at..at + 4]) as usize;
        let kind = &data[at + 4..at + 8];
        // The spec's own ceiling on a chunk length. Beyond it the file is
        // not a PNG, and the addition below would be the interesting
        // kind of wrong.
        if len > 0x7fff_ffff {
            return Err(WalkError::Malformed);
        }
        let end = at
            .checked_add(12)
            .and_then(|n| n.checked_add(len))
            .ok_or(WalkError::Malformed)?;
        if end > data.len() {
            return Err(WalkError::Truncated);
        }
        if kind == b"IHDR" {
            if seen_ihdr || len != 13 {
                return Err(WalkError::Malformed);
            }
            seen_ihdr = true;
            width = be32(&data[at + 8..at + 12]);
            height = be32(&data[at + 12..at + 16]);
        } else if !seen_ihdr {
            // `IHDR` is required to be first, and everything downstream
            // reads its dimensions.
            return Err(WalkError::Malformed);
        }
        at = end;
        if kind == b"IEND" {
            break;
        }
    }
    if at != data.len() {
        return Err(WalkError::TrailingBytes);
    }
    Ok(Walked {
        format: Format::Png,
        width,
        height,
        frames: 1,
        duration_ms: 0,
    })
}

/// JPEG: `FFD8`, then marker segments, then entropy-coded data after
/// `SOS`, ending at `FFD9`.
///
/// The scan data is the part with no length field, so the walk resumes
/// by looking for the next marker that is not a stuffed `FF00` or a
/// restart marker — which is exactly how a decoder finds it.
fn walk_jpeg(data: &[u8]) -> Result<Walked, WalkError> {
    if !data.starts_with(&[0xff, 0xd8]) {
        return Err(WalkError::Malformed);
    }
    let mut at = 2;
    let (mut width, mut height) = (0u32, 0u32);
    loop {
        // Fill bytes are legal between segments.
        while at < data.len() && data[at] == 0xff && data.get(at + 1) == Some(&0xff) {
            at += 1;
        }
        if at + 2 > data.len() {
            return Err(WalkError::Truncated);
        }
        if data[at] != 0xff {
            return Err(WalkError::Malformed);
        }
        let marker = data[at + 1];
        at += 2;
        match marker {
            // End of image: the walk is done.
            0xd9 => break,
            // Standalone markers: no length, nothing to skip.
            0x01 | 0xd0..=0xd7 => continue,
            _ => {}
        }
        if at + 2 > data.len() {
            return Err(WalkError::Truncated);
        }
        let len = u16::from_be_bytes([data[at], data[at + 1]]) as usize;
        if len < 2 {
            return Err(WalkError::Malformed);
        }
        let seg = at + 2..at.checked_add(len).ok_or(WalkError::Malformed)?;
        if seg.end > data.len() {
            return Err(WalkError::Truncated);
        }
        match marker {
            // The frame headers this server accepts: baseline,
            // extended sequential, progressive. Everything else in the
            // SOF family — arithmetic coding, lossless, hierarchical —
            // is refused rather than handed to a decoder, because
            // nothing a client can produce today needs them and each is
            // a decoder path far less travelled than the other three.
            0xc0..=0xc2 => {
                if seg.len() < 5 {
                    return Err(WalkError::Malformed);
                }
                let b = &data[seg.start..];
                height = u16::from_be_bytes([b[1], b[2]]) as u32;
                width = u16::from_be_bytes([b[3], b[4]]) as u32;
            }
            0xc3 | 0xc5..=0xc7 | 0xc9..=0xcf => return Err(WalkError::Malformed),
            _ => {}
        }
        at = seg.end;
        if marker == 0xda {
            // Entropy-coded data: scan to the next marker that is
            // neither a stuffed zero nor a restart.
            loop {
                if at >= data.len() {
                    return Err(WalkError::Truncated);
                }
                if data[at] != 0xff {
                    at += 1;
                    continue;
                }
                match data.get(at + 1) {
                    None => return Err(WalkError::Truncated),
                    Some(0x00) | Some(0xff) => at += 2,
                    Some(0xd0..=0xd7) => at += 2,
                    Some(_) => break,
                }
            }
        }
    }
    if at != data.len() {
        return Err(WalkError::TrailingBytes);
    }
    if width == 0 || height == 0 {
        return Err(WalkError::Malformed);
    }
    Ok(Walked {
        format: Format::Jpeg,
        width,
        height,
        frames: 1,
        duration_ms: 0,
    })
}

/// GIF: header, logical screen descriptor, then blocks until the `3B`
/// trailer.
///
/// The walk counts image descriptors and sums graphic-control delays,
/// which is where the animation caps get their numbers — before a
/// decoder collects a single frame.
fn walk_gif(data: &[u8]) -> Result<Walked, WalkError> {
    if data.len() < 13 {
        return Err(WalkError::Truncated);
    }
    if !(data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a")) {
        return Err(WalkError::Malformed);
    }
    let width = u16::from_le_bytes([data[6], data[7]]) as u32;
    let height = u16::from_le_bytes([data[8], data[9]]) as u32;
    let packed = data[10];
    let mut at: usize = 13;
    if packed & 0x80 != 0 {
        let entries = 2usize << (packed & 0x07);
        at = at.checked_add(entries * 3).ok_or(WalkError::Malformed)?;
        if at > data.len() {
            return Err(WalkError::Truncated);
        }
    }
    let (mut frames, mut duration_ms) = (0u32, 0u32);
    let mut pending_delay = 0u32;
    loop {
        let block = *data.get(at).ok_or(WalkError::Truncated)?;
        at += 1;
        match block {
            // Trailer.
            0x3b => break,
            // Extension: a label, then sub-blocks.
            0x21 => {
                let label = *data.get(at).ok_or(WalkError::Truncated)?;
                at += 1;
                if label == 0xf9 {
                    // Graphic control: a five-byte sub-block whose
                    // middle two are the delay in hundredths.
                    if data.get(at) != Some(&4) || at + 6 > data.len() {
                        return Err(WalkError::Malformed);
                    }
                    pending_delay = u16::from_le_bytes([data[at + 2], data[at + 3]]) as u32 * 10;
                }
                at = skip_subblocks(data, at)?;
            }
            // Image descriptor: nine bytes, an optional local colour
            // table, then LZW data in sub-blocks.
            0x2c => {
                if at + 9 > data.len() {
                    return Err(WalkError::Truncated);
                }
                let flags = data[at + 8];
                at += 9;
                if flags & 0x80 != 0 {
                    let entries = 2usize << (flags & 0x07);
                    at = at.checked_add(entries * 3).ok_or(WalkError::Malformed)?;
                    if at > data.len() {
                        return Err(WalkError::Truncated);
                    }
                }
                // The LZW minimum code size, then the sub-blocks.
                if at >= data.len() {
                    return Err(WalkError::Truncated);
                }
                at += 1;
                at = skip_subblocks(data, at)?;
                frames = frames.saturating_add(1);
                // A zero delay means "as fast as the renderer likes",
                // which every renderer floors at about a tenth of a
                // second. Counting it as zero would let a thousand-frame
                // animation claim no duration at all.
                duration_ms = duration_ms.saturating_add(pending_delay.max(10));
                pending_delay = 0;
            }
            _ => return Err(WalkError::Malformed),
        }
    }
    if at != data.len() {
        return Err(WalkError::TrailingBytes);
    }
    if frames == 0 || width == 0 || height == 0 {
        return Err(WalkError::Malformed);
    }
    Ok(Walked {
        format: Format::Gif,
        width,
        height,
        frames,
        duration_ms,
    })
}

/// GIF sub-blocks: length-prefixed runs ending with a zero length.
fn skip_subblocks(data: &[u8], mut at: usize) -> Result<usize, WalkError> {
    loop {
        let len = *data.get(at).ok_or(WalkError::Truncated)? as usize;
        at += 1;
        if len == 0 {
            return Ok(at);
        }
        at = at.checked_add(len).ok_or(WalkError::Malformed)?;
        if at > data.len() {
            return Err(WalkError::Truncated);
        }
    }
}
