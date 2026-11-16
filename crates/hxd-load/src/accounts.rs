//! Account files for a run, in `hxd-auth-file`'s format: one TOML file
//! each, in the server's accounts directory.

use std::path::Path;

/// `<prefix>0` up to `<prefix><count - 1>`, each with `password`, allowed
/// to chat and to use any nick; an account with a password may detach by
/// default. With `admin`, one more account by that name, allowed to
/// disconnect users and to send private messages. With `linked`, each of
/// the numbered accounts is linked to an identity of its own, so a server
/// grouping a person's devices makes one row of each account's
/// connections: a password login of an account linked to an identity is
/// that person's. Nothing signs as these identities; they exist to be
/// linked. If any of the files exists already, none is written.
pub fn write(
    dir: &Path,
    prefix: &str,
    count: usize,
    password: &str,
    admin: Option<&str>,
    linked: bool,
) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let quoted = toml::Value::String(password.to_owned()).to_string();
    let user = |name: &str, extra: &str| {
        format!(
            "name = {}\npassword = {quoted}\n\n[access]\nread_chat = true\nsend_chat = true\n\
             use_any_name = true\nget_user_info = true\n{extra}",
            toml::Value::String(name.to_owned())
        )
    };
    let mut files: Vec<(String, String)> = (0..count)
        .map(|i| {
            let login = format!("{prefix}{i}");
            let mut text = user(&login, "");
            if linked {
                text.push_str(&format!(
                    "\n[identity]\nfingerprint = \"{}\"\n",
                    fingerprint(&identity(prefix, i))
                ));
            }
            (login, text)
        })
        .collect();
    if let Some(admin) = admin {
        files.push((
            admin.to_owned(),
            user(
                admin,
                "disconnect_users = true\ncant_be_disconnected = true\nsend_msgs = true\n",
            ),
        ));
    }
    // All or nothing: a clash found halfway would leave half a set.
    for (login, _) in &files {
        let path = dir.join(format!("{login}.toml"));
        if path.exists() {
            return Err(format!(
                "{} already exists; nothing written",
                path.display()
            ));
        }
    }
    for (login, text) in files {
        let path = dir.join(format!("{login}.toml"));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        std::io::Write::write_all(&mut f, text.as_bytes())
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}

/// A key of its own for account `i` of `prefix`: its first eight bytes
/// FNV-1a of the prefix, so two sets written with different prefixes
/// link no identity twice, and its last eight `i`.
fn identity(prefix: &str, i: usize) -> [u8; 32] {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in prefix.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    let mut key = [0x6cu8; 32];
    key[..8].copy_from_slice(&h.to_be_bytes());
    key[24..].copy_from_slice(&(i as u64).to_be_bytes());
    key
}

/// 32 bytes as an account file spells a fingerprint: 52 digits of
/// Crockford's base32, lower case, the last padded with zero bits.
fn fingerprint(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut out = String::with_capacity(52);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(DIGITS[((acc >> bits) & 31) as usize] as char);
        }
    }
    out.push(DIGITS[((acc << (5 - bits)) & 31) as usize] as char);
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_two_accounts_link_one_identity_whatever_their_prefix() {
        let keys: std::collections::HashSet<_> = ["a", "b"]
            .iter()
            .flat_map(|p| (0..3).map(move |i| super::identity(p, i)))
            .collect();
        assert_eq!(keys.len(), 6);
    }

    #[test]
    fn a_fingerprint_is_spelled_as_an_account_file_spells_one() {
        // `[7; 32]`, as hl-identity's `Fingerprint` displays it.
        assert_eq!(
            super::fingerprint(&[7; 32]),
            "0w3ge1r70w3ge1r70w3ge1r70w3ge1r70w3ge1r70w3ge1r70w3g"
        );
    }
}
