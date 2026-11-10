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

fn codec_with(f: impl FnOnce(&mut CodecLimits)) -> Codec {
    let mut limits = CodecLimits::default();
    f(&mut limits);
    Codec::new(limits)
}

/// Every row that came out other than expected, all at once, so a table
/// says which of its rows fail rather than only the first.
fn rows<T: std::fmt::Debug + PartialEq>(rows: impl IntoIterator<Item = (&'static str, T, T)>) {
    let wrong: Vec<String> = rows
        .into_iter()
        .filter(|(_, got, want)| got != want)
        .map(|(what, got, want)| format!("{what}: {got:?}, not {want:?}"))
        .collect();
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The answer without the image, for tables about whether one is made.
fn made(input: &[u8], codec: &Codec, policy: &EmojiPolicy) -> Result<(), MediaReject> {
    codec.emoji(input, policy).map(|_| ())
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

/// A looping GIF of `frames`, each shown for its delay in milliseconds.
fn gif_of(frames: impl IntoIterator<Item = (RgbaImage, u32)>) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut enc = image::codecs::gif::GifEncoder::new(&mut out);
        enc.set_repeat(image::codecs::gif::Repeat::Infinite)
            .unwrap();
        for (frame, ms) in frames {
            enc.encode_frame(image::Frame::from_parts(
                frame,
                0,
                0,
                image::Delay::from_numer_denom_ms(ms, 1),
            ))
            .unwrap();
        }
    }
    out
}

fn noisy_gif(frames: u32, side: u32) -> Vec<u8> {
    gif_of((0..frames).map(|n| (noise(side, side, n), 100)))
}

/// `img` with its left half cleared to nothing.
fn half_clear(mut img: RgbaImage) -> RgbaImage {
    let w = img.width();
    for (x, _, p) in img.enumerate_pixels_mut() {
        if x < w / 2 {
            *p = image::Rgba([0, 0, 0, 0]);
        }
    }
    img
}

fn frames_and_delays(gif: &[u8]) -> Vec<u32> {
    use image::AnimationDecoder;
    image::codecs::gif::GifDecoder::new(std::io::Cursor::new(gif))
        .unwrap()
        .into_frames()
        .map(|f| {
            let (n, d) = f.unwrap().delay().numer_denom_ms();
            n / d
        })
        .collect()
}

#[test]
fn a_still_comes_out_a_png_fitted_within_the_square() {
    rows(
        [
            ("a wide PNG", png(&rgba(512, 256)), (128, 64)),
            ("a tall PNG", png(&rgba(100, 400)), (32, 128)),
            ("a PNG the square's size", png(&rgba(128, 128)), (128, 128)),
            ("a PNG a pixel high", png(&rgba(1024, 8)), (128, 1)),
            ("a tall JPEG", jpeg(&rgb(300, 600)), (64, 128)),
            ("a wide JPEG", jpeg(&rgb(600, 200)), (128, 43)),
            (
                "a JPEG tagged to turn a quarter",
                jpeg_with_orientation(&jpeg(&rgb(300, 150)), 6),
                (64, 128),
            ),
            ("a wide still GIF", static_gif(300, 100), (128, 43)),
            ("a tall still GIF", static_gif(100, 300), (43, 128)),
            // Smaller than the square is left as it is: fitting never enlarges.
            ("a small still GIF", static_gif(40, 40), (40, 40)),
            ("a small PNG", png(&rgba(32, 16)), (32, 16)),
            ("a small JPEG", jpeg(&rgb(20, 40)), (20, 40)),
        ]
        .map(|(what, input, size)| {
            let out = codec().emoji(&input, &EmojiPolicy::default()).unwrap();
            let decoded = image::load_from_memory(&out.bytes).unwrap();
            (
                what,
                (
                    out.mime,
                    out.animated,
                    out.width,
                    out.height,
                    decoded.width(),
                    decoded.height(),
                ),
                (
                    MediaType::Png,
                    false,
                    size.0,
                    size.1,
                    u32::from(size.0),
                    u32::from(size.1),
                ),
            )
        }),
    );
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
fn an_animation_stays_one_fitted_at_its_delays_or_becomes_its_first_frame() {
    let roomy = EmojiPolicy {
        max_bytes: 65535,
        ..EmojiPolicy::default()
    };
    let delays = [100, 250, 40];
    let input = gif_of(delays.map(|ms| (noise(200, 100, ms), ms)));
    let out = codec().emoji(&input, &roomy).unwrap();
    assert_eq!(out.mime, MediaType::Gif);
    assert!(out.animated);
    assert_eq!((out.width, out.height), (128, 64));
    assert_eq!(
        frames_and_delays(&out.bytes),
        delays,
        "every frame, at its delay"
    );

    let policy = EmojiPolicy::default();
    let out = codec().emoji(&noisy_gif(8, 128), &policy).unwrap();
    assert_eq!(out.mime, MediaType::Png);
    assert!(!out.animated);
    assert!(out.bytes.len() <= policy.max_bytes);
    let first = codec().emoji(&noisy_gif(1, 128), &policy).unwrap();
    assert_eq!(out.bytes, first.bytes, "its first frame");
}

#[test]
fn an_emojis_own_bounds_hold_at_their_edges() {
    let policy = EmojiPolicy::default();
    let tight = EmojiPolicy {
        max_frames: 16,
        ..policy
    };
    let c = codec();
    rows([
        (
            "1024 px a side",
            made(&png(&rgba(1024, 8)), &c, &policy),
            Ok(()),
        ),
        (
            "1025 px high",
            made(&png(&rgba(8, 1025)), &c, &policy),
            Err(MediaReject::TooLarge),
        ),
        (
            "1025 px a side",
            made(&png(&rgba(1025, 8)), &c, &policy),
            Err(MediaReject::TooLarge),
        ),
        // A header that lies: refused for what it claims, where a decode
        // would have been refused for disagreeing with it.
        (
            "a header claiming 1025 px",
            made(&png_claiming(&png(&rgba(16, 16)), 1025, 16), &c, &policy),
            Err(MediaReject::TooLarge),
        ),
        (
            "max_frames frames",
            made(&animated_gif(50, 20, 16, 16), &c, &policy),
            Ok(()),
        ),
        (
            "a frame past max_frames",
            made(&animated_gif(51, 20, 16, 16), &c, &policy),
            Err(MediaReject::TooLarge),
        ),
        (
            "a tighter max_frames",
            made(&animated_gif(16, 20, 16, 16), &c, &tight),
            Ok(()),
        ),
        (
            "a frame past a tighter max_frames",
            made(&animated_gif(17, 20, 16, 16), &c, &tight),
            Err(MediaReject::TooLarge),
        ),
        (
            "ten seconds",
            made(&animated_gif(20, 500, 16, 16), &c, &policy),
            Ok(()),
        ),
        (
            "past ten seconds",
            made(&animated_gif(20, 510, 16, 16), &c, &policy),
            Err(MediaReject::TooLarge),
        ),
    ]);
}

/// What a row is called, its input, and the limit that should refuse it.
type Tightened = (&'static str, Vec<u8>, fn(&mut CodecLimits));

#[test]
fn a_codec_tighter_than_an_emojis_bounds_stays_as_tight() {
    let policy = EmojiPolicy::default();
    let rows_of: [Tightened; 5] = [
        ("max_frames", animated_gif(11, 20, 16, 16), |l| {
            l.max_frames = 10
        }),
        ("max_duration_ms", animated_gif(4, 400, 16, 16), |l| {
            l.max_duration_ms = 1000
        }),
        ("max_dimension", png(&rgba(100, 50)), |l| {
            l.max_dimension = 64
        }),
        ("max_pixels", png(&rgba(100, 50)), |l| {
            l.max_pixels = 64 * 64
        }),
        (
            "max_bytes",
            png(&DynamicImage::ImageRgba8(noise(64, 64, 0))),
            |l| l.max_bytes = 1000,
        ),
    ];
    for (what, input, _) in &rows_of {
        assert_eq!(made(input, &codec(), &policy), Ok(()), "{what} untightened");
    }
    rows(rows_of.iter().map(|(what, input, tighten)| {
        (
            *what,
            made(input, &codec_with(tighten), &policy),
            Err(MediaReject::TooLarge),
        )
    }));
}

#[test]
fn an_animation_is_held_to_its_frames_times_its_pixels() {
    // Every frame is decoded at the source's full canvas, larger than
    // the square it is fitted to.
    let c = codec_with(|l| l.max_alloc_bytes = 16 * 256 * 256 * 4);
    let policy = EmojiPolicy::default();
    rows([
        (
            "at the budget",
            made(&animated_gif(16, 20, 256, 256), &c, &policy),
            Ok(()),
        ),
        (
            "a frame past it",
            made(&animated_gif(17, 20, 256, 256), &c, &policy),
            Err(MediaReject::TooLarge),
        ),
    ]);
}

#[test]
fn what_is_not_an_image_is_refused_for_what_it_is() {
    let policy = EmojiPolicy::default();
    let c = codec();
    let whole = png(&rgba(16, 16));
    let mut polyglot = whole.clone();
    polyglot.extend_from_slice(b"PK\x03\x04trailing archive");
    let mut webp = b"RIFF\x00\x00\x00\x00WEBPVP8 ".to_vec();
    webp.resize(128, 0);
    rows([
        (
            "text",
            made("not an image at all ".repeat(8).as_bytes(), &c, &policy),
            Err(MediaReject::Unsupported),
        ),
        (
            "a truncated PNG",
            made(&whole[..whole.len() - 8], &c, &policy),
            Err(MediaReject::Unsupported),
        ),
        (
            "a polyglot",
            made(&polyglot, &c, &policy),
            Err(MediaReject::Unsupported),
        ),
        (
            "a WebP",
            made(&webp, &c, &policy),
            Err(MediaReject::Unsupported),
        ),
    ]);
}

#[test]
fn transparency_is_kept() {
    let policy = EmojiPolicy::default();
    let clear = half_clear(RgbaImage::from_pixel(64, 32, image::Rgba([200, 0, 0, 255])));
    let still = (MediaType::Png, false, (0, 255));
    rows(
        [
            (
                "a PNG",
                png(&DynamicImage::ImageRgba8(clear.clone())),
                still,
            ),
            ("a still GIF", gif_of([(clear.clone(), 0)]), still),
            (
                "an animation",
                gif_of([(clear.clone(), 100), (clear, 100)]),
                (MediaType::Gif, true, (0, 255)),
            ),
            (
                "an animation too large to keep, as a still",
                gif_of((0..8).map(|n| (half_clear(noise(128, 128, n)), 100))),
                still,
            ),
        ]
        .map(|(what, input, want)| {
            let out = codec().emoji(&input, &policy).unwrap();
            let img = image::load_from_memory(&out.bytes).unwrap().to_rgba8();
            let y = img.height() / 2;
            let alpha = (img.get_pixel(0, y)[3], img.get_pixel(img.width() - 1, y)[3]);
            (what, (out.mime, out.animated, alpha), want)
        }),
    );
}

#[test]
fn a_still_is_refused_once_shrunk_to_32_px_or_less() {
    let at = |side, max_bytes| {
        codec()
            .emoji(
                &png(&DynamicImage::ImageRgba8(noise(side, side, 0))),
                &EmojiPolicy {
                    max_bytes,
                    ..EmojiPolicy::default()
                },
            )
            .map(|e| (e.width, e.bytes.len()))
    };
    // Each a byte short of fitting at the size before it.
    let (_, at_43) = at(43, 65535).unwrap();
    let (stepped, at_32) = at(43, at_43 - 1).unwrap();
    assert_eq!(stepped, 32);
    assert_eq!(at(43, at_32 - 1), Err(MediaReject::TooLarge), "not past 32");
    let (_, at_44) = at(44, 65535).unwrap();
    let (stepped, at_33) = at(44, at_44 - 1).unwrap();
    assert_eq!(stepped, 33);
    assert_eq!(at(44, at_33 - 1).map(|(w, _)| w), Ok(24), "33 shrinks on");
}

#[test]
fn the_square_is_the_policys() {
    let at = |max_dimension| EmojiPolicy {
        max_dimension,
        max_bytes: 65535,
        ..EmojiPolicy::default()
    };
    let still = png(&rgba(512, 256));
    let animation = animated_gif(2, 100, 200, 100);
    rows(
        [
            ("a still at 64", &still, 64, (MediaType::Png, 64, 32)),
            ("a still at 256", &still, 256, (MediaType::Png, 256, 128)),
            (
                "an animation at 64",
                &animation,
                64,
                (MediaType::Gif, 64, 32),
            ),
        ]
        .map(|(what, input, side, want)| {
            let out = codec().emoji(input, &at(side)).unwrap();
            (what, (out.mime, out.width, out.height), want)
        }),
    );
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
