//! Avatars through the pipeline (`docs/avatars.md` §1): fitted, format
//! following source, and a legacy GIF within its ceiling or none.

#[allow(dead_code)]
mod fixtures;

use fixtures::*;
use hxd_core::avatar::AvatarLimits;
use hxd_core::media::{CodecLimits, MediaCodec, MediaReject, MediaType};
use hxd_media::Codec;
use image::{DynamicImage, RgbaImage};

fn codec() -> Codec {
    Codec::new(CodecLimits::default())
}

fn limits() -> AvatarLimits {
    AvatarLimits {
        max_bytes: 256 * 1024,
        max_dimension: 128,
        legacy_max_bytes: 32 * 1024,
    }
}

fn frames_of(gif: &[u8]) -> usize {
    use image::AnimationDecoder;
    image::codecs::gif::GifDecoder::new(std::io::Cursor::new(gif))
        .unwrap()
        .into_frames()
        .count()
}

/// Pixels a GIF cannot palette away, for a rendition that must shrink.
fn noise(w: u32, h: u32) -> DynamicImage {
    let mut state = 0x2545_f491u32;
    DynamicImage::ImageRgba8(RgbaImage::from_fn(w, h, |_, _| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let [a, b, c, _] = state.to_le_bytes();
        image::Rgba([a, b, c, 0xff])
    }))
}

#[test]
fn a_still_is_fitted_and_keeps_its_format_and_its_shape() {
    let out = codec().avatar(&png(&rgba(512, 256)), &limits()).unwrap();
    assert_eq!(out.canonical.mime, MediaType::Png);
    assert_eq!((out.canonical.width, out.canonical.height), (128, 64));
    let gif = out.legacy_gif.expect("a small still fits");
    assert!(gif.starts_with(b"GIF89a"));
    assert!(gif.len() <= 32 * 1024);

    let out = codec().avatar(&jpeg(&rgb(300, 600)), &limits()).unwrap();
    assert_eq!(out.canonical.mime, MediaType::Jpeg);
    assert_eq!((out.canonical.width, out.canonical.height), (64, 128));

    // Smaller than the box is left alone: fitting never enlarges.
    let out = codec().avatar(&png(&rgba(32, 32)), &limits()).unwrap();
    assert_eq!((out.canonical.width, out.canonical.height), (32, 32));

    // A still GIF becomes a PNG, as any still GIF upload does.
    let out = codec().avatar(&static_gif(40, 40), &limits()).unwrap();
    assert_eq!(out.canonical.mime, MediaType::Png);
}

#[test]
fn an_animation_stays_one_with_every_frame_fitted() {
    let input = animated_gif(4, 100, 200, 100);
    let out = codec().avatar(&input, &limits()).unwrap();
    assert_eq!(out.canonical.mime, MediaType::Gif);
    assert_eq!((out.canonical.width, out.canonical.height), (128, 64));
    assert_eq!(frames_of(&out.canonical.bytes), 4);
    // Small enough to be its own legacy rendition.
    assert_eq!(out.legacy_gif.as_deref(), Some(&out.canonical.bytes[..]));
}

#[test]
fn an_animation_past_the_legacy_ceiling_is_sent_as_its_first_frame() {
    let tight = AvatarLimits {
        legacy_max_bytes: 4 * 1024,
        ..limits()
    };
    let out = codec()
        .avatar(&animated_gif(12, 100, 128, 128), &tight)
        .unwrap();
    assert!(out.canonical.bytes.len() > tight.legacy_max_bytes);
    let gif = out.legacy_gif.expect("a first frame fits");
    assert!(gif.len() <= tight.legacy_max_bytes);
    assert_eq!(frames_of(&gif), 1);
}

#[test]
fn a_legacy_rendition_shrinks_to_fit_or_is_left_out() {
    let input = png(&noise(128, 128));
    let tight = AvatarLimits {
        legacy_max_bytes: 3 * 1024,
        ..limits()
    };
    let out = codec().avatar(&input, &tight).unwrap();
    assert_eq!((out.canonical.width, out.canonical.height), (128, 128));
    let gif = out.legacy_gif.expect("noise fits once it is small enough");
    assert!(gif.len() <= tight.legacy_max_bytes);

    let impossible = AvatarLimits {
        legacy_max_bytes: 16,
        ..limits()
    };
    assert_eq!(
        codec().avatar(&input, &impossible).unwrap().legacy_gif,
        None
    );
}

#[test]
fn the_avatar_ceiling_is_its_own_and_the_gates_still_hold() {
    let input = png(&noise(256, 256));
    let small = AvatarLimits {
        max_bytes: input.len() - 1,
        ..limits()
    };
    assert_eq!(codec().avatar(&input, &small), Err(MediaReject::TooLarge));
    // Past the size floor, so it is the sniff that refuses it.
    let text = "not an image at all ".repeat(8);
    assert_eq!(
        codec().avatar(text.as_bytes(), &limits()),
        Err(MediaReject::Unsupported)
    );
    // Metadata goes the way it goes for every upload: not carried.
    let tagged = gif_with_comment(&animated_gif(2, 100, 16, 16), b"secret");
    let out = codec().avatar(&tagged, &limits()).unwrap();
    assert!(!inventory(&out.canonical.bytes)
        .iter()
        .any(|k| k.contains("comment")));
}
