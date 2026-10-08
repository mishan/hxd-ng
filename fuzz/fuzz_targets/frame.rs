//! The classic read path short of a session: frames cut from one stream,
//! each walked chunk by chunk and its fields through the decoders a
//! transaction's parser hands them to.
#![no_main]

use hxd_session::frame::{pack_frame, read_frame, MAX_FRAME_DATA};
use hxd_session::TextEncoding;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fuzz_target!(|data: &[u8]| {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    });
    let mut rest = data;
    loop {
        let before = rest;
        let Ok(frame) = rt.block_on(read_frame(&mut rest)) else {
            break;
        };
        let wire = &before[..before.len() - rest.len()];
        assert_eq!(wire.len(), frame.wire_len());
        assert!(wire.len() <= 22 + MAX_FRAME_DATA as usize);
        let chunks: Vec<_> = frame.chunks().map(|c| (c.tag, c.data.to_vec())).collect();
        for (_, field) in &chunks {
            let _ = hxd_session::voice::parse_ice(field);
            let _ = hxd_session::video::parse_subscriptions(field);
            let text = TextEncoding::MacRoman.decode(field);
            assert_eq!(TextEncoding::MacRoman.encode(&text), *field);
        }
        // A frame its chunks fill exactly is one this server could have
        // sent; one whose data size is short of the hc it counts is read as
        // empty, and is not.
        let len2 = u32::from_be_bytes(wire[16..20].try_into().unwrap()) as usize;
        let filled: usize = chunks.iter().map(|(_, d)| 4 + d.len()).sum();
        if filled + 2 == len2 && chunks.len() == usize::from(frame.hc) {
            assert_eq!(pack_frame(frame.ty, frame.trans, frame.flag, &chunks), wire);
        }
    }
});
