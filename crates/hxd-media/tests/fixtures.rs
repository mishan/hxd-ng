//! Fixtures for the pipeline tests.
//!
//! Built here rather than committed as binaries. A committed corpus
//! would be opaque — "what makes this JPEG the EXIF one?" is a question
//! you cannot answer by reading a directory listing — and the awkward
//! cases (a tag-carrying JPEG, a polyglot, a header that lies about its
//! dimensions) are all *edits* to a valid file, which is exactly what
//! the code below is: encode something small, then splice.

use image::{DynamicImage, ImageEncoder, RgbImage, RgbaImage};
use std::io::Cursor;

/// A small opaque image with some structure in it, so a JPEG round trip
/// has something to be lossy about.
pub fn rgb(w: u32, h: u32) -> DynamicImage {
    let mut img = RgbImage::new(w, h);
    for (x, y, p) in img.enumerate_pixels_mut() {
        *p = image::Rgb([(x * 7 % 256) as u8, (y * 11 % 256) as u8, 0x40]);
    }
    DynamicImage::ImageRgb8(img)
}

/// The same with an alpha channel, for the "PNG keeps its transparency"
/// case.
pub fn rgba(w: u32, h: u32) -> DynamicImage {
    let mut img = RgbaImage::new(w, h);
    for (x, y, p) in img.enumerate_pixels_mut() {
        *p = image::Rgba([(x % 256) as u8, (y % 256) as u8, 0x20, 0x80]);
    }
    DynamicImage::ImageRgba8(img)
}

pub fn png(img: &DynamicImage) -> Vec<u8> {
    let mut out = Vec::new();
    image::codecs::png::PngEncoder::new(Cursor::new(&mut out))
        .write_image(
            img.as_bytes(),
            img.width(),
            img.height(),
            img.color().into(),
        )
        .unwrap();
    out
}

pub fn jpeg(img: &DynamicImage) -> Vec<u8> {
    let mut out = Vec::new();
    let rgb = DynamicImage::ImageRgb8(img.to_rgb8());
    image::codecs::jpeg::JpegEncoder::new_with_quality(Cursor::new(&mut out), 90)
        .write_image(
            rgb.as_bytes(),
            rgb.width(),
            rgb.height(),
            rgb.color().into(),
        )
        .unwrap();
    out
}

/// An animated GIF: `frames` frames, each `delay_ms` long.
pub fn animated_gif(frames: usize, delay_ms: u32, w: u32, h: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut enc = image::codecs::gif::GifEncoder::new(Cursor::new(&mut out));
        enc.set_repeat(image::codecs::gif::Repeat::Infinite)
            .unwrap();
        for n in 0..frames {
            let mut img = RgbaImage::new(w, h);
            for (x, y, p) in img.enumerate_pixels_mut() {
                *p = image::Rgba([(x + n as u32) as u8, y as u8, 0x10, 0xff]);
            }
            enc.encode_frame(image::Frame::from_parts(
                img,
                0,
                0,
                image::Delay::from_numer_denom_ms(delay_ms, 1),
            ))
            .unwrap();
        }
    }
    out
}

/// A static GIF — one frame, no graphic control block worth the name.
pub fn static_gif(w: u32, h: u32) -> Vec<u8> {
    animated_gif(1, 0, w, h)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Splice an ancillary PNG chunk in after `IHDR`.
pub fn png_with_chunk(png: &[u8], kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    chunk.extend_from_slice(kind);
    chunk.extend_from_slice(payload);
    let mut crc_over = kind.to_vec();
    crc_over.extend_from_slice(payload);
    chunk.extend_from_slice(&crc32(&crc_over).to_be_bytes());
    // 8 signature + 25 IHDR (4 len + 4 type + 13 data + 4 crc).
    let at = 8 + 25;
    let mut out = png[..at].to_vec();
    out.extend_from_slice(&chunk);
    out.extend_from_slice(&png[at..]);
    out
}

/// Rewrite `IHDR`'s width and height, leaving the pixel data alone: a
/// header that lies, which is what the probe exists to catch.
pub fn png_claiming(png: &[u8], w: u32, h: u32) -> Vec<u8> {
    let mut out = png.to_vec();
    out[16..20].copy_from_slice(&w.to_be_bytes());
    out[20..24].copy_from_slice(&h.to_be_bytes());
    // The CRC now disagrees, so fix it: the point of this fixture is a
    // *plausible* file whose header lies, not a corrupt one.
    let crc = crc32(&out[12..29]);
    out[29..33].copy_from_slice(&crc.to_be_bytes());
    out
}

/// Splice an APP1 EXIF segment carrying an orientation tag straight
/// after the SOI, which is where a camera writes it.
pub fn jpeg_with_orientation(jpeg: &[u8], orientation: u16) -> Vec<u8> {
    // A minimal little-endian TIFF header with one IFD entry.
    let mut tiff = Vec::new();
    tiff.extend_from_slice(b"II\x2a\x00");
    tiff.extend_from_slice(&8u32.to_le_bytes()); // IFD at offset 8
    tiff.extend_from_slice(&1u16.to_le_bytes()); // one entry
    tiff.extend_from_slice(&0x0112u16.to_le_bytes()); // Orientation
    tiff.extend_from_slice(&3u16.to_le_bytes()); // SHORT
    tiff.extend_from_slice(&1u32.to_le_bytes()); // count
    tiff.extend_from_slice(&orientation.to_le_bytes());
    tiff.extend_from_slice(&[0, 0]); // pad the value field to four bytes
    tiff.extend_from_slice(&0u32.to_le_bytes()); // no next IFD

    let mut payload = b"Exif\x00\x00".to_vec();
    payload.extend_from_slice(&tiff);

    let mut out = jpeg[..2].to_vec();
    out.extend_from_slice(&[0xff, 0xe1]);
    out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(&jpeg[2..]);
    out
}

/// A GIF with a comment extension spliced in before its first block.
pub fn gif_with_comment(gif: &[u8], comment: &[u8]) -> Vec<u8> {
    // Header (6) + logical screen descriptor (7), then the global colour
    // table if the packed byte says there is one.
    let packed = gif[10];
    let mut at = 13;
    if packed & 0x80 != 0 {
        at += 3 * (2usize << (packed & 0x07));
    }
    let mut ext = vec![0x21, 0xfe, comment.len() as u8];
    ext.extend_from_slice(comment);
    ext.push(0x00);
    let mut out = gif[..at].to_vec();
    out.extend_from_slice(&ext);
    out.extend_from_slice(&gif[at..]);
    out
}

/// The chunk, marker or block types a file actually contains — what the
/// "canonical output carries nothing but structure" assertions read.
pub fn inventory(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if data.starts_with(&[0x89, b'P', b'N', b'G']) {
        let mut at = 8;
        while at + 8 <= data.len() {
            let len = u32::from_be_bytes(data[at..at + 4].try_into().unwrap()) as usize;
            let kind = String::from_utf8_lossy(&data[at + 4..at + 8]).into_owned();
            out.push(kind.clone());
            at += 12 + len;
            if kind == "IEND" {
                break;
            }
        }
    } else if data.starts_with(&[0xff, 0xd8]) {
        let mut at = 2;
        while at + 2 <= data.len() {
            if data[at] != 0xff {
                break;
            }
            let marker = data[at + 1];
            at += 2;
            if marker == 0xd9 || marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
                out.push(format!("FF{marker:02X}"));
                if marker == 0xd9 {
                    break;
                }
                continue;
            }
            out.push(format!("FF{marker:02X}"));
            if at + 2 > data.len() {
                break;
            }
            let len = u16::from_be_bytes([data[at], data[at + 1]]) as usize;
            at += len;
            if marker == 0xda {
                // Skip the entropy-coded data to the next real marker.
                while at + 1 < data.len() {
                    if data[at] == 0xff
                        && data[at + 1] != 0x00
                        && data[at + 1] != 0xff
                        && !(0xd0..=0xd7).contains(&data[at + 1])
                    {
                        break;
                    }
                    at += 1;
                }
            }
        }
    } else if data.starts_with(b"GIF") {
        let packed = data[10];
        let mut at = 13;
        if packed & 0x80 != 0 {
            at += 3 * (2usize << (packed & 0x07));
        }
        while at < data.len() {
            match data[at] {
                0x3b => {
                    out.push("trailer".into());
                    break;
                }
                0x21 => {
                    let label = data[at + 1];
                    out.push(match label {
                        0xf9 => "graphic-control".into(),
                        0xfe => "comment".into(),
                        0xff => "application".into(),
                        0x01 => "plain-text".into(),
                        other => format!("extension-{other:02x}"),
                    });
                    at += 2;
                    at = skip_subblocks(data, at);
                }
                0x2c => {
                    out.push("image".into());
                    let flags = data[at + 8];
                    at += 9;
                    if flags & 0x80 != 0 {
                        at += 3 * (2usize << (flags & 0x07));
                    }
                    at += 1;
                    at = skip_subblocks(data, at);
                }
                _ => break,
            }
        }
    }
    out
}

fn skip_subblocks(data: &[u8], mut at: usize) -> usize {
    while at < data.len() {
        let len = data[at] as usize;
        at += 1;
        if len == 0 {
            return at;
        }
        at += len;
    }
    at
}
