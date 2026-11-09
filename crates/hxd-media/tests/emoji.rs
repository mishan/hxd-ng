//! Server emoji through the pipeline: fitted, a PNG for a still and a GIF
//! for an animation, stepped down until it fits, and held to bounds of
//! its own before anything is decoded.

#[allow(dead_code)]
mod fixtures;

use fixtures::*;
use hxd_core::emoji::EmojiPolicy;
use hxd_core::media::{CodecLimits, MediaCodec, MediaReject, MediaType};
use hxd_media::Codec;
use image::{DynamicImage, RgbaImage};

/// Chat's limits: what `emoji` must narrow for itself.
fn codec() -> Codec {
    Codec::new(CodecLimits::default())
}

fn frames_of(gif: &[u8]) -> usize {
    use image::AnimationDecoder;
    image::codecs::gif::GifDecoder::new(std::io::Cursor::new(gif))
        .unwrap()
        .into_frames()
        .count()
}

/// Pixels nothing compresses, to stand for a photograph, which barely does.
fn noise(w: u32, h: u32, seed: u32) -> RgbaImage {
    let mut state = 0x2545_f491u32 ^ seed;
    RgbaImage::from_fn(w, h, |_, _| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let [a, b, c, _] = state.to_le_bytes();
        image::Rgba([a, b, c, 0xff])
    })
}

fn noisy_gif(frames: u32, side: u32) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut enc = image::codecs::gif::GifEncoder::new(&mut out);
        enc.set_repeat(image::codecs::gif::Repeat::Infinite)
            .unwrap();
        for n in 0..frames {
            enc.encode_frame(image::Frame::from_parts(
                noise(side, side, n),
                0,
                0,
                image::Delay::from_numer_denom_ms(100, 1),
            ))
            .unwrap();
        }
    }
    out
}

#[test]
fn a_still_comes_out_a_png_fitted_within_the_square() {
    for (input, size) in [
        (png(&rgba(512, 256)), (128, 64)),
        (jpeg(&rgb(300, 600)), (64, 128)),
        (static_gif(40, 40), (40, 40)),
        (png(&rgba(32, 32)), (32, 32)),
    ] {
        let out = codec().emoji(&input, &EmojiPolicy::default()).unwrap();
        assert_eq!(out.mime, MediaType::Png);
        assert!(!out.animated);
        assert_eq!((out.width, out.height), size);
        let decoded = image::load_from_memory(&out.bytes).unwrap();
        assert_eq!(
            (decoded.width(), decoded.height()),
            (u32::from(size.0), u32::from(size.1)),
            "measured from the bytes"
        );
    }
}

#[test]
fn a_still_past_max_bytes_is_stepped_down_until_it_fits_or_refused() {
    let photo = jpeg(&DynamicImage::ImageRgba8(noise(256, 256, 0)));
    let policy = EmojiPolicy::default();
    let out = codec().emoji(&photo, &policy).unwrap();
    assert_eq!(out.mime, MediaType::Png);
    assert!(out.bytes.len() <= policy.max_bytes);
    assert!(out.width < 128 && out.width >= 30, "{}", out.width);
    assert_eq!(out.width, out.height);

    let tiny = EmojiPolicy {
        max_bytes: 64,
        ..policy
    };
    assert_eq!(codec().emoji(&photo, &tiny), Err(MediaReject::TooLarge));
}

#[test]
fn an_animation_stays_one_fitted_or_becomes_its_first_frame() {
    let roomy = EmojiPolicy {
        max_bytes: 65535,
        ..EmojiPolicy::default()
    };
    let out = codec()
        .emoji(&animated_gif(4, 100, 200, 100), &roomy)
        .unwrap();
    assert_eq!(out.mime, MediaType::Gif);
    assert!(out.animated);
    assert_eq!((out.width, out.height), (128, 64));
    assert_eq!(frames_of(&out.bytes), 4);

    let policy = EmojiPolicy::default();
    let out = codec().emoji(&noisy_gif(8, 128), &policy).unwrap();
    assert_eq!(out.mime, MediaType::Png);
    assert!(!out.animated);
    assert!(out.bytes.len() <= policy.max_bytes);
    let first = codec().emoji(&noisy_gif(1, 128), &policy).unwrap();
    assert_eq!(out.bytes, first.bytes, "its first frame");
}

#[test]
fn an_emojis_own_bounds_refuse_before_any_decode() {
    let tight = EmojiPolicy {
        max_frames: 16,
        ..EmojiPolicy::default()
    };
    for (what, input, policy) in [
        (
            "past max_frames",
            animated_gif(51, 20, 16, 16),
            EmojiPolicy::default(),
        ),
        (
            "past a tighter max_frames",
            animated_gif(17, 20, 16, 16),
            tight,
        ),
        (
            "past ten seconds",
            animated_gif(20, 600, 16, 16),
            EmojiPolicy::default(),
        ),
        // A header that lies: refused for what it claims, where a decode
        // would have been refused for disagreeing with it.
        (
            "a source past 1024 px",
            png_claiming(&png(&rgba(16, 16)), 1025, 16),
            EmojiPolicy::default(),
        ),
    ] {
        assert_eq!(
            codec().emoji(&input, &policy),
            Err(MediaReject::TooLarge),
            "{what}"
        );
    }
}

#[test]
fn no_metadata_survives() {
    let png_text = png_with_chunk(&png(&rgba(16, 16)), b"tEXt", b"Comment\0private");
    let gif_comment = gif_with_comment(&animated_gif(2, 80, 16, 16), b"private note");
    let jpeg_exif = jpeg_with_orientation(&jpeg(&rgb(16, 24)), 1);
    // Structure and pixels, and the loop an animation needs.
    let structure = [
        "IHDR",
        "PLTE",
        "tRNS",
        "IDAT",
        "IEND",
        "application",
        "graphic-control",
        "image",
        "trailer",
    ];
    for (input, junk) in [
        (png_text, "tEXt"),
        (gif_comment, "comment"),
        (jpeg_exif, "FFE1"),
    ] {
        assert!(inventory(&input).contains(&junk.to_string()), "dirty");
        let out = codec().emoji(&input, &EmojiPolicy::default()).unwrap();
        let kept = inventory(&out.bytes);
        assert!(
            kept.iter().all(|k| structure.contains(&k.as_str())),
            "{junk}: {kept:?}"
        );
    }
}
