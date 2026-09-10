//! The inline-media pipeline: `hxd_core::MediaCodec` implemented on the
//! [`image`] crate plus the container walkers of [`walk`].
//!
//! Design: [`docs/inline-media.md`](../../../docs/inline-media.md) §3.
//! This crate knows nothing about Hotline. It takes bytes somebody
//! uploaded and returns bytes this server encoded, or a coarse reason
//! why not.
//!
//! The order is the spec's, and each step exists to make the next one
//! safe to attempt:
//!
//! 1. **Size.** Below the floor there is nothing to decode; above the
//!    ceiling there is nothing to discuss.
//! 2. **Sniff.** Three signatures. The declared MIME type is never
//!    consulted — it is the client's hint, and the reply overwrites it.
//! 3. **Walk.** The container's own structure, to the payload's exact
//!    last byte. Refuses polyglots and anything structurally strange
//!    before a decoder is involved at all.
//! 4. **Probe.** Dimensions from the header the walk already read,
//!    checked against the caps before a pixel is allocated.
//! 5. **Decode**, under `image`'s allocation limits and a concurrency
//!    permit.
//! 6. **Re-encode** from the decoded pixels.
//!
//! **Stripping metadata is a property of the re-encode, not a filter.**
//! The canonical bytes are written by this crate's encoders from a pixel
//! buffer; EXIF, ICC, XMP, PNG text chunks and GIF comments are not
//! removed, they are never carried in the first place. The one thing
//! taken *from* the metadata is EXIF orientation, applied to the pixels
//! so that the canonical image is upright and needs no tag to say so.
//!
//! **Format follows source** (§3.3), a deliberate departure from the
//! spec's recommendation: JPEG in, JPEG out; PNG in, PNG out; animated
//! GIF in, GIF out; a *static* GIF becomes PNG, because there is no
//! reason to keep a palette format for a still. The recommendation
//! would re-encode an opaque screenshot of text as JPEG, which is
//! visibly worse and no smaller. Nothing in the security argument turns
//! on the choice: a re-encode by a known-good encoder is the property,
//! and both rules have it.

pub mod walk;

use std::io::Cursor;
use std::sync::{Condvar, Mutex};

use hxd_core::media::{Canonical, CodecLimits, MediaCodec, MediaReject, MediaType};
use image::codecs::gif::{GifDecoder, GifEncoder};
use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::{AnimationDecoder, DynamicImage, ImageDecoder, ImageEncoder, ImageReader, Limits};
use tracing::debug;
use walk::{Format, WalkError};

/// JPEG quality for a re-encode. High enough that a photograph survives
/// a round trip without visible loss at normal viewing size, low enough
/// that the canonical bytes are usually smaller than what arrived.
const JPEG_QUALITY: u8 = 85;

/// The pipeline. One per server, shared: it carries the limits and the
/// decode permits.
pub struct Codec {
    limits: CodecLimits,
    permits: Permits,
}

impl Codec {
    pub fn new(limits: CodecLimits) -> Self {
        Codec {
            permits: Permits::new(limits.max_concurrent_decodes.max(1)),
            limits,
        }
    }

    /// Everything before the decode: the cheap gates, in the order that
    /// makes each next one safe. Separated so the tests can reach it
    /// without a decoder, and so the expensive half has one entry.
    fn inspect(&self, input: &[u8]) -> Result<walk::Walked, MediaReject> {
        if input.len() < self.limits.min_bytes || input.len() > self.limits.max_bytes {
            return Err(MediaReject::TooLarge);
        }
        let format = walk::sniff(input);
        if !format.allowed() {
            debug!(target: "media", format = format.name(), "refused at the sniff");
            return Err(MediaReject::Unsupported);
        }
        let walked = walk::walk(format, input).map_err(|e| {
            debug!(
                target: "media",
                format = format.name(),
                reason = match e {
                    WalkError::Truncated => "truncated",
                    WalkError::Malformed => "malformed",
                    WalkError::TrailingBytes => "trailing bytes",
                },
                "refused at the walk",
            );
            MediaReject::Unsupported
        })?;
        // The header's own numbers, checked before anything allocates a
        // raster. A file claiming 20000×20000 in thirty bytes is refused
        // here, which is the whole point of reading them from the
        // container rather than from a decoded image.
        let (w, h) = (walked.width, walked.height);
        if w == 0 || h == 0 || w > self.limits.max_dimension || h > self.limits.max_dimension {
            debug!(target: "media", w, h, "refused: dimensions");
            return Err(MediaReject::TooLarge);
        }
        if u64::from(w) * u64::from(h) > self.limits.max_pixels {
            debug!(target: "media", w, h, "refused: pixel count");
            return Err(MediaReject::TooLarge);
        }
        // Frames × pixels is the decompression bomb this format has:
        // every cap above can pass and a hundred and fifty frames of two
        // thousand pixels square still decodes to gigabytes. Checked
        // from the walk's count, so it costs nothing.
        if u64::from(walked.frames) * u64::from(w) * u64::from(h) * 4 > self.limits.max_alloc_bytes
        {
            debug!(
                frames = walked.frames,
                w, h, "media refused: animation budget"
            );
            return Err(MediaReject::TooLarge);
        }
        if walked.frames > self.limits.max_frames
            || walked.duration_ms > self.limits.max_duration_ms
        {
            debug!(
                target: "media",
                frames = walked.frames,
                duration_ms = walked.duration_ms,
                "refused: animation",
            );
            return Err(MediaReject::TooLarge);
        }
        Ok(walked)
    }

    /// `image`'s own ceilings, which is what turns a decompression bomb
    /// into an error instead of an out-of-memory kill.
    fn image_limits(&self) -> Limits {
        let mut limits = Limits::default();
        limits.max_image_width = Some(self.limits.max_dimension);
        limits.max_image_height = Some(self.limits.max_dimension);
        limits.max_alloc = Some(self.limits.max_alloc_bytes);
        limits
    }

    fn decode_still(
        &self,
        input: &[u8],
        walked: &walk::Walked,
    ) -> Result<DynamicImage, MediaReject> {
        let mut reader = ImageReader::new(Cursor::new(input));
        reader.set_format(match walked.format {
            Format::Png => image::ImageFormat::Png,
            Format::Jpeg => image::ImageFormat::Jpeg,
            Format::Gif => image::ImageFormat::Gif,
            _ => return Err(MediaReject::Unsupported),
        });
        // PNG takes its limits at construction (its decoder has no way
        // to change them afterwards); every other format takes them from
        // `set_limits` below. Setting both is how one call site covers
        // the three.
        reader.limits(self.image_limits());
        let mut decoder = reader.into_decoder().map_err(decode_failed)?;
        decoder
            .set_limits(self.image_limits())
            .map_err(decode_failed)?;
        // A decoder that disagrees with the container header is reading
        // something the walk did not, and neither reading is then worth
        // trusting. Compared *before* the orientation is applied: that
        // is a transform this server performs, not a disagreement.
        if decoder.dimensions() != (walked.width, walked.height) {
            debug!(target: "media", "refused: decoded dimensions disagree with the header");
            return Err(MediaReject::Unsupported);
        }
        // Read before the pixels: applying the tag to the buffer is what
        // lets the canonical image carry no tag and still be upright.
        let orientation = decoder
            .orientation()
            .unwrap_or(image::metadata::Orientation::NoTransforms);
        let mut img = DynamicImage::from_decoder(decoder).map_err(decode_failed)?;
        img.apply_orientation(orientation);
        Ok(img)
    }
}

impl MediaCodec for Codec {
    fn canonicalize(&self, input: &[u8]) -> Result<Canonical, MediaReject> {
        let walked = self.inspect(input)?;
        // Only the expensive half needs a permit: everything above is
        // bounded arithmetic over the input, and making a client queue
        // for that would turn a cheap rejection into a slow one.
        let _permit = self.permits.acquire(self.limits.permit_wait)?;
        let animated = walked.format == Format::Gif && walked.frames > 1;
        if animated {
            return self.reencode_gif(input);
        }
        let img = self.decode_still(input, &walked)?;
        // Post-orientation: a portrait photograph tagged "rotate 90°" is
        // a landscape image once the tag has been honored, and the
        // canonical metadata has to describe the bytes this server
        // produced rather than the ones it was handed.
        let (width, height) = (img.width(), img.height());
        let (mime, bytes) = match walked.format {
            Format::Jpeg => (MediaType::Jpeg, encode_jpeg(&img)?),
            // A still GIF becomes a PNG: nothing needs a palette format
            // for one frame, and PNG is lossless over it.
            Format::Png | Format::Gif => (MediaType::Png, encode_png(&img)?),
            _ => return Err(MediaReject::Unsupported),
        };
        Ok(Canonical {
            mime,
            width,
            height,
            bytes,
        })
    }
}

impl Codec {
    /// An animation survives as an animation. Frames are collected under
    /// the same allocation ceiling as a still and re-encoded into a GIF
    /// this crate wrote — which is what drops the comment blocks,
    /// application extensions and anything else that rode along.
    fn reencode_gif(&self, input: &[u8]) -> Result<Canonical, MediaReject> {
        let mut decoder = GifDecoder::new(Cursor::new(input)).map_err(decode_failed)?;
        decoder
            .set_limits(self.image_limits())
            .map_err(decode_failed)?;
        let (width, height) = decoder.dimensions();
        let mut out = Vec::new();
        let mut count = 0u32;
        {
            let mut encoder = GifEncoder::new(Cursor::new(&mut out));
            encoder
                .set_repeat(image::codecs::gif::Repeat::Infinite)
                .map_err(encode_failed)?;
            // One frame decoded, one frame encoded, one frame alive: an
            // animation's cost in memory is its largest frame and not
            // its length.
            for frame in decoder.into_frames() {
                if count >= self.limits.max_frames {
                    return Err(MediaReject::TooLarge);
                }
                encoder
                    .encode_frame(frame.map_err(decode_failed)?)
                    .map_err(encode_failed)?;
                count += 1;
            }
        }
        if count == 0 {
            return Err(MediaReject::Unsupported);
        }
        Ok(Canonical {
            mime: MediaType::Gif,
            width,
            height,
            bytes: out,
        })
    }
}

fn encode_png(img: &DynamicImage) -> Result<Vec<u8>, MediaReject> {
    let mut out = Vec::new();
    // Colour type follows the decoded buffer: an opaque image stays
    // opaque, and one with alpha keeps it. Neither is a re-quantisation.
    let img = match img {
        DynamicImage::ImageLuma8(_) | DynamicImage::ImageRgb8(_) | DynamicImage::ImageRgba8(_) => {
            img.clone()
        }
        other if other.color().has_alpha() => DynamicImage::ImageRgba8(other.to_rgba8()),
        other => DynamicImage::ImageRgb8(other.to_rgb8()),
    };
    PngEncoder::new(Cursor::new(&mut out))
        .write_image(
            img.as_bytes(),
            img.width(),
            img.height(),
            img.color().into(),
        )
        .map_err(encode_failed)?;
    Ok(out)
}

fn encode_jpeg(img: &DynamicImage) -> Result<Vec<u8>, MediaReject> {
    let mut out = Vec::new();
    // JPEG has no alpha. Flattening onto white rather than letting the
    // encoder decide is the difference between a transparent PNG-turned-
    // JPEG looking like itself and looking like a black rectangle — and
    // this path is only reached for a JPEG source, which had no alpha to
    // begin with.
    let rgb = DynamicImage::ImageRgb8(img.to_rgb8());
    JpegEncoder::new_with_quality(Cursor::new(&mut out), JPEG_QUALITY)
        .write_image(
            rgb.as_bytes(),
            rgb.width(),
            rgb.height(),
            rgb.color().into(),
        )
        .map_err(encode_failed)?;
    Ok(out)
}

fn decode_failed(e: image::ImageError) -> MediaReject {
    match e {
        // The allocation ceiling and the dimension caps land here: the
        // file is legal and this server will not spend that much on it.
        image::ImageError::Limits(_) => {
            debug!(target: "media", "refused: decode exceeded its limits");
            MediaReject::TooLarge
        }
        other => {
            debug!(target: "media", "refused: decode failed: {other}");
            MediaReject::Unsupported
        }
    }
}

fn encode_failed(e: image::ImageError) -> MediaReject {
    // Not the client's fault: the pixels decoded and this server could
    // not write them back out.
    debug!(target: "media", "re-encode failed: {e}");
    MediaReject::Busy
}

/// A counting semaphore over `std`, because the pipeline runs on
/// blocking threads and has no runtime to await on.
///
/// It bounds how many decodes exist at once. A decode cannot be
/// interrupted from outside — that is what makes the caps above the real
/// protection — so this is what stops a queue of legal-but-expensive
/// images from occupying every blocking thread the server has.
struct Permits {
    available: Mutex<usize>,
    changed: Condvar,
}

struct Permit<'a>(&'a Permits);

impl Permits {
    fn new(n: usize) -> Self {
        Permits {
            available: Mutex::new(n),
            changed: Condvar::new(),
        }
    }

    /// Wait up to `within` for a permit. A caller that cannot have one
    /// in that time is told the server is busy, which is a better answer
    /// than a request that eventually succeeds long after its client
    /// gave up.
    fn acquire(&self, within: std::time::Duration) -> Result<Permit<'_>, MediaReject> {
        let mut available = self.available.lock().unwrap();
        let deadline = std::time::Instant::now() + within;
        while *available == 0 {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                debug!(target: "media", "refused: no decode permit within the budget");
                return Err(MediaReject::Busy);
            }
            let (guard, _) = self
                .changed
                .wait_timeout(available, left)
                .unwrap_or_else(|e| e.into_inner());
            available = guard;
        }
        *available -= 1;
        Ok(Permit(self))
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.available.lock().unwrap() += 1;
        self.0.changed.notify_one();
    }
}
