//! Writes a seed corpus of real frames: `cargo run --example seeds`, from
//! this directory, before the first `cargo fuzz run`.

use hxd_session::frame::pack_frame;

fn xor(s: &[u8]) -> Vec<u8> {
    s.iter().map(|b| !b).collect()
}

fn main() {
    let login = pack_frame(
        0x6b,
        1,
        0,
        &[
            (0x69, xor(b"guest")),
            (0x6a, vec![0]),
            (0x66, b"fuzz".to_vec()),
            (0x68, vec![0, 0x80]),
            (0xa0, vec![0, 185]),
            (0x1f0, vec![0, 0x1f]),
        ],
    );
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
    ];
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
}
