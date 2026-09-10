//! The pipeline against a corpus: what it accepts, what it refuses, and
//! what it strips (`docs/inline-media.md` §12, stage M1).

mod fixtures;

use fixtures::*;
use hxd_core::media::{CodecLimits, MediaCodec, MediaReject, MediaType};
use hxd_media::walk::{self, Format};
use hxd_media::Codec;

fn codec() -> Codec {
    Codec::new(CodecLimits::default())
}

/// Tighter than the defaults where a test wants to cross a cap without
/// building something enormous.
fn codec_with(f: impl FnOnce(&mut CodecLimits)) -> Codec {
    let mut limits = CodecLimits::default();
    f(&mut limits);
    Codec::new(limits)
}

#[test]
fn each_allowed_format_round_trips() {
    let c = codec();

    let out = c.canonicalize(&png(&rgba(32, 24))).unwrap();
    assert_eq!(out.mime, MediaType::Png, "PNG in, PNG out");
    assert_eq!((out.width, out.height), (32, 24));

    let out = c.canonicalize(&jpeg(&rgb(32, 24))).unwrap();
    assert_eq!(out.mime, MediaType::Jpeg, "JPEG in, JPEG out");
    assert_eq!((out.width, out.height), (32, 24));

    let out = c.canonicalize(&animated_gif(3, 100, 16, 16)).unwrap();
    assert_eq!(out.mime, MediaType::Gif, "an animation stays an animation");

    // Format follows source, with one deliberate exception: a still GIF
    // has no reason to keep a palette format, and PNG is lossless over
    // it (§3.3).
    let out = c.canonicalize(&static_gif(16, 16)).unwrap();
    assert_eq!(out.mime, MediaType::Png, "a still GIF becomes a PNG");
}

#[test]
fn canonical_output_walks_clean() {
    // Whatever the pipeline emits must itself pass the gate the pipeline
    // applies to arrivals — including the "no trailing bytes" rule.
    let c = codec();
    for input in [
        png(&rgba(16, 16)),
        jpeg(&rgb(16, 16)),
        animated_gif(2, 60, 16, 16),
    ] {
        let out = c.canonicalize(&input).unwrap();
        let format = walk::sniff(&out.bytes);
        assert!(
            format.allowed(),
            "canonical output sniffs as an allowed format"
        );
        walk::walk(format, &out.bytes).expect("canonical output walks to its exact end");
    }
}

#[test]
fn metadata_does_not_survive_the_re_encode() {
    let c = codec();

    // PNG: text, colour profile and EXIF chunks all spliced in, none of
    // them present afterwards. Stripping is by construction — the
    // encoder writes structure and pixels and has nothing else to say.
    let mut dirty = png(&rgba(16, 16));
    dirty = png_with_chunk(&dirty, b"tEXt", b"Comment\0something private");
    dirty = png_with_chunk(&dirty, b"iCCP", b"p\0\0some-profile-bytes");
    dirty = png_with_chunk(&dirty, b"eXIf", b"II\x2a\x00\x08\x00\x00\x00");
    let before = inventory(&dirty);
    assert!(before.contains(&"tEXt".to_string()), "the fixture is dirty");
    let out = c.canonicalize(&dirty).unwrap();
    let after = inventory(&out.bytes);
    for junk in ["tEXt", "iTXt", "zTXt", "iCCP", "eXIf"] {
        assert!(
            !after.contains(&junk.to_string()),
            "{junk} survived the re-encode: {after:?}"
        );
    }
    assert!(after.contains(&"IHDR".to_string()) && after.contains(&"IDAT".to_string()));

    // GIF: a comment extension goes the same way.
    let dirty = gif_with_comment(&animated_gif(2, 80, 16, 16), b"private note");
    assert!(inventory(&dirty).contains(&"comment".to_string()));
    let out = c.canonicalize(&dirty).unwrap();
    assert!(
        !inventory(&out.bytes).contains(&"comment".to_string()),
        "a GIF comment survived the re-encode"
    );

    // JPEG: the APP1 the orientation rode in on is gone with it.
    let dirty = jpeg_with_orientation(&jpeg(&rgb(16, 24)), 1);
    assert!(inventory(&dirty).contains(&"FFE1".to_string()));
    let out = c.canonicalize(&dirty).unwrap();
    assert!(
        !inventory(&out.bytes).contains(&"FFE1".to_string()),
        "an EXIF segment survived the re-encode"
    );
}

#[test]
fn exif_orientation_is_applied_to_the_pixels() {
    // Orientation 6 is "rotate 90° clockwise": a portrait image whose
    // tag says so is a landscape image once the tag is honored. The
    // canonical bytes carry no tag, so the rotation has to be in the
    // pixels or it is lost.
    let c = codec();
    let upright = c.canonicalize(&jpeg(&rgb(16, 32))).unwrap();
    assert_eq!((upright.width, upright.height), (16, 32));

    let rotated = c
        .canonicalize(&jpeg_with_orientation(&jpeg(&rgb(16, 32)), 6))
        .unwrap();
    assert_eq!(
        (rotated.width, rotated.height),
        (32, 16),
        "the tag was applied to the buffer, not dropped"
    );
}

#[test]
fn polyglots_and_trailing_bytes_are_refused() {
    let c = codec();

    // A PNG with a ZIP glued to its tail: two programs read this file
    // differently, and a server that re-serves it has picked a side.
    let mut polyglot = png(&rgba(16, 16));
    polyglot.extend_from_slice(b"PK\x03\x04trailing archive");
    assert_eq!(c.canonicalize(&polyglot), Err(MediaReject::Unsupported));

    let mut trailing = jpeg(&rgb(16, 16));
    trailing.extend_from_slice(&[0u8; 64]);
    assert_eq!(c.canonicalize(&trailing), Err(MediaReject::Unsupported));

    let mut gif = animated_gif(2, 50, 16, 16);
    gif.push(0x00);
    assert_eq!(c.canonicalize(&gif), Err(MediaReject::Unsupported));

    // Truncation is the same answer from the same gate.
    let short = png(&rgba(16, 16));
    assert_eq!(
        c.canonicalize(&short[..short.len() - 8]),
        Err(MediaReject::Unsupported)
    );
}

#[test]
fn a_header_that_lies_is_refused_before_any_decode() {
    // A small PNG whose IHDR claims 20000×20000. The probe reads the
    // container's own numbers, so this never reaches a decoder — which
    // is the whole reason the dimensions are checked from the header.
    let c = codec();
    let liar = png_claiming(&png(&rgba(16, 16)), 20_000, 20_000);
    assert_eq!(c.canonicalize(&liar), Err(MediaReject::TooLarge));
}

#[test]
fn canonical_metadata_describes_the_canonical_bytes() {
    // The same trick inside the caps: a header that says 8×8 over pixel
    // data written for 16×16. A PNG decoder is driven by `IHDR`, so this
    // decodes as the 8×8 the header claims — and the point is that what
    // comes out says 8×8 *and is* 8×8. The reported metadata is measured
    // from the image this server encoded, never copied from the one it
    // was handed, so a client sizing a placeholder from it cannot be
    // lied to by an uploader.
    let c = codec();
    let liar = png_claiming(&png(&rgba(16, 16)), 8, 8);
    let out = c.canonicalize(&liar).unwrap();
    assert_eq!((out.width, out.height), (8, 8));
    let walked = walk::walk(walk::sniff(&out.bytes), &out.bytes).unwrap();
    assert_eq!(
        (walked.width, walked.height),
        (out.width, out.height),
        "the canonical header agrees with the canonical metadata"
    );
}

#[test]
fn the_caps_are_enforced() {
    // Dimensions.
    let c = codec_with(|l| l.max_dimension = 16);
    assert_eq!(
        c.canonicalize(&png(&rgba(32, 8))),
        Err(MediaReject::TooLarge)
    );

    // Pixel count, which a wide-and-short image passes the per-axis cap
    // to reach.
    let c = codec_with(|l| l.max_pixels = 64);
    assert_eq!(
        c.canonicalize(&png(&rgba(32, 8))),
        Err(MediaReject::TooLarge)
    );

    // Encoded size, both ends. Below the floor there is nothing to
    // decode; above the ceiling there is nothing to discuss.
    let c = codec_with(|l| l.max_bytes = 64);
    assert_eq!(
        c.canonicalize(&png(&rgba(64, 64))),
        Err(MediaReject::TooLarge)
    );
    assert_eq!(codec().canonicalize(&[]), Err(MediaReject::TooLarge));

    // Frames, and cumulative duration — counted by the walker, so
    // neither costs a decode.
    let c = codec_with(|l| l.max_frames = 3);
    assert_eq!(
        c.canonicalize(&animated_gif(6, 40, 8, 8)),
        Err(MediaReject::TooLarge)
    );
    let c = codec_with(|l| l.max_duration_ms = 200);
    assert_eq!(
        c.canonicalize(&animated_gif(6, 100, 8, 8)),
        Err(MediaReject::TooLarge)
    );

    // The animation budget: frames × pixels, which is the shape a
    // decompression bomb takes in a format where every other cap can
    // pass. Small file in, gigabytes of raster out — refused from the
    // walk's own frame count, before a frame is decoded.
    let c = codec_with(|l| l.max_alloc_bytes = 64 * 1024);
    assert_eq!(
        c.canonicalize(&animated_gif(40, 40, 128, 128)),
        Err(MediaReject::TooLarge)
    );
}

#[test]
fn the_forbidden_formats_are_refused_by_name() {
    // Each of these is recognized rather than merely unrecognized, so a
    // rejection can say *why* in the log — and so a future decoder that
    // learns one of them cannot quietly start accepting it.
    let cases: [(&[u8], Format); 6] = [
        (
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
            Format::Svg,
        ),
        (b"RIFF\x00\x00\x00\x00WEBPVP8 ", Format::WebP),
        (b"\x00\x00\x00\x20ftypavif\x00\x00\x00\x00", Format::Avif),
        (b"\x00\x00\x00\x20ftypheic\x00\x00\x00\x00", Format::Heic),
        (
            b"BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00",
            Format::Bmp,
        ),
        (
            b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00",
            Format::Ico,
        ),
    ];
    let c = codec();
    for (bytes, expected) in cases {
        assert_eq!(walk::sniff(bytes), expected, "sniffed {}", expected.name());
        assert!(!expected.allowed());
        let mut padded = bytes.to_vec();
        padded.resize(128, 0);
        assert_eq!(
            c.canonicalize(&padded),
            Err(MediaReject::Unsupported),
            "{} reached the pipeline",
            expected.name()
        );
    }
    // TIFF too, which the spec forbids and which shares its magic with
    // the EXIF payloads this pipeline strips.
    assert_eq!(walk::sniff(b"II\x2a\x00\x08\x00\x00\x00"), Format::Tiff);
}

#[test]
fn an_arithmetic_coded_jpeg_is_refused_at_the_walk() {
    // SOF9 and its neighbours are decoder paths far less travelled than
    // baseline and progressive, and nothing a client can produce today
    // needs them. The walk refuses them without a decoder involved.
    let mut arith = jpeg(&rgb(16, 16));
    // The first SOF in the encoder's output is baseline (FFC0); make it
    // arithmetic.
    let at = arith
        .windows(2)
        .position(|w| w == [0xff, 0xc0])
        .expect("a baseline SOF to rewrite");
    arith[at + 1] = 0xc9;
    assert_eq!(codec().canonicalize(&arith), Err(MediaReject::Unsupported));
}

#[test]
fn fill_bytes_before_a_marker_do_not_derail_the_walk() {
    // A marker may be preceded by any number of `0xff` fill bytes, and
    // an odd-length run is the case a two-byte skip gets wrong: it eats
    // the marker's own `0xff` and walks off the end. Every length has
    // to arrive at the same image.
    let base = jpeg(&rgb(16, 16));
    assert_eq!(&base[base.len() - 2..], &[0xff, 0xd9], "EOI to pad before");
    for fill in 1..=4 {
        let mut padded = base[..base.len() - 2].to_vec();
        padded.extend(std::iter::repeat_n(0xffu8, fill));
        padded.extend_from_slice(&[0xff, 0xd9]);
        let out = codec()
            .canonicalize(&padded)
            .unwrap_or_else(|e| panic!("{fill} fill byte(s) refused: {e:?}"));
        assert_eq!((out.width, out.height), (16, 16));
    }
}

#[test]
fn concurrent_decodes_are_bounded_rather_than_refused() {
    // The permit is a queue, not a wall: two threads through a
    // one-permit codec both succeed, one after the other.
    let c = std::sync::Arc::new(codec_with(|l| l.max_concurrent_decodes = 1));
    let input = std::sync::Arc::new(png(&rgba(64, 64)));
    let hands: Vec<_> = (0..4)
        .map(|_| {
            let (c, input) = (c.clone(), input.clone());
            std::thread::spawn(move || c.canonicalize(&input).map(|o| o.mime))
        })
        .collect();
    for hand in hands {
        assert_eq!(hand.join().unwrap(), Ok(MediaType::Png));
    }
}
