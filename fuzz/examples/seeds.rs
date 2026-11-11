//! Writes a seed corpus of real frames: `cargo run --example seeds`, from
//! this directory, before the first `cargo fuzz run`.

use hxd_session::frame::pack_frame;

fn xor(s: &[u8]) -> Vec<u8> {
    s.iter().map(|b| !b).collect()
}

fn main() {
    let login_as = |login: &[u8], password: &[u8], caps: Vec<u8>| {
        pack_frame(
            0x6b,
            1,
            0,
            &[
                (0x69, xor(login)),
                (0x6a, xor(password)),
                (0x66, b"fuzz".to_vec()),
                (0x68, vec![0, 0x80]),
                (0xa0, vec![0, 185]),
                (0x1f0, caps),
            ],
        )
    };
    let login_offering = |caps| login_as(b"guest", b"\xff", caps);
    let login = login_offering(vec![0, 0x1f]);
    // Bits 0 to 4 and 20, server emoji, in four bytes.
    let login_emoji = login_offering(vec![0, 0x10, 0, 0x1f]);
    // Bits 1, 4, 17, 19 and 20, as a client of the reactions draft offers
    // them, from an account that may react.
    let login_reacting = login_as(b"fuzz", b"fuzz", vec![0, 0x1a, 0, 0x12]);
    let refs = [
        &[0, 2, 0, 0, 0, 1, 5][..],
        b"party",
        &[0, 0, 0, 2, 2],
        b"ok",
    ]
    .concat();
    let requests = [
        pack_frame(0x79, 2, 0, &[(0x66, b"fuzz".to_vec()), (0x68, vec![0, 1])]),
        pack_frame(0x12c, 3, 0, &[]),
        pack_frame(
            0x69,
            4,
            0,
            &[(0x65, b"hello\rthere".to_vec()), (0x6d, vec![0, 1])],
        ),
        pack_frame(0x6c, 5, 0, &[(0x67, vec![0, 1]), (0x65, b"psst".to_vec())]),
        pack_frame(0x12f, 6, 0, &[(0x67, vec![0, 1])]),
        pack_frame(0x130, 7, 0, &[(0x66, b"renamed".to_vec())]),
        pack_frame(0x65, 8, 0, &[]),
        pack_frame(0x1f4, 9, 0, &[]),
        pack_frame(
            0x69,
            10,
            0,
            &[(0x65, b"a :party:".to_vec()), (0xf3e, refs.clone())],
        ),
        pack_frame(
            0x6c,
            11,
            0,
            &[
                (0x67, vec![0, 1]),
                (0x65, b":party:".to_vec()),
                (0xf3e, refs),
            ],
        ),
        pack_frame(713, 12, 0, &[(0xf3c, vec![0, 0, 0, 1])]),
        pack_frame(714, 13, 0, &[(0xf38, vec![0, 0, 0, 1])]),
        pack_frame(
            716,
            14,
            0,
            &[(0xf3d, vec![0, 3]), (0xf38, vec![0, 0, 0, 1])],
        ),
    ];
    // A line to react to, then Send Reaction (710) in each action on each
    // kind of target, and Get Reactions (712) at one, the most and one
    // past the most targets, and with a key. The target's core offers
    // lobby lines alone, so the other kinds stop at the parse.
    let line = |kind: u8, chat: u32, id: u64| {
        [&[kind][..], &chat.to_be_bytes(), &id.to_be_bytes()].concat()
    };
    let im = [&[2][..], &[7; 16], &[4], b"fuzz"].concat();
    let key = [&[1][..], "\u{1F44D}".as_bytes()].concat();
    let mut reacting = vec![pack_frame(0x69, 2, 0, &[(0x65, b"react".to_vec())])];
    let mut trans = 3;
    let mut next = || {
        trans += 1;
        trans - 1
    };
    let targets = [
        line(1, 0, 1),
        line(4, 0, 1),
        line(4, 4000, 1),
        line(3, 0, 1),
        im.clone(),
        [&[5, 1][..], &[9; 16]].concat(),
    ];
    for target in &targets {
        for action in 0u16..=5 {
            let mut fields = vec![
                (0xf24, target.clone()),
                (0xf26, action.to_be_bytes().to_vec()),
            ];
            if action != 3 {
                fields.push((0xf25, key.clone()));
            }
            reacting.push(pack_frame(710, next(), 0, &fields));
        }
    }
    reacting.push(pack_frame(
        710,
        next(),
        0,
        &[
            (0xf24, im),
            (0x600, b"fuzz".to_vec()),
            (0xf26, vec![0, 1]),
            (0xf25, key.clone()),
        ],
    ));
    for n in [1, 50, 51] {
        reacting.push(pack_frame(712, next(), 0, &vec![(0xf24, line(1, 0, 1)); n]));
    }
    reacting.push(pack_frame(
        712,
        next(),
        0,
        &[(0xf24, line(1, 0, 1)), (0xf25, key)],
    ));
    for dir in ["corpus/frame", "corpus/session"] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let mut session = b"TRTPHOTL\x00\x01\x00\x02".to_vec();
    session.extend_from_slice(&login);
    std::fs::write("corpus/frame/login", &login).unwrap();
    std::fs::write("corpus/session/login", &session).unwrap();
    for (n, r) in requests.iter().enumerate() {
        std::fs::write(format!("corpus/frame/{n}"), r).unwrap();
        session.extend_from_slice(r);
    }
    std::fs::write("corpus/frame/all", &session[12..]).unwrap();
    std::fs::write("corpus/session/all", &session).unwrap();
    std::fs::write("corpus/frame/login-emoji", &login_emoji).unwrap();
    let mut session = b"TRTPHOTL\x00\x01\x00\x02".to_vec();
    session.extend_from_slice(&login_reacting);
    for (n, r) in reacting.iter().enumerate() {
        std::fs::write(format!("corpus/frame/react-{n}"), r).unwrap();
        session.extend_from_slice(r);
    }
    std::fs::write("corpus/session/reactions", &session).unwrap();
}
