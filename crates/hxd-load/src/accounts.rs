//! Account files for a run, in `hxd-auth-file`'s format: one TOML file
//! each, in the server's accounts directory.

use std::path::Path;

/// `<prefix>0` up to `<prefix><count - 1>`, each with `password`, allowed
/// to chat and to use any nick; an account with a password may detach by
/// default. With `admin`, one more account by that name, allowed to
/// disconnect users. If any of the files exists already, none is
/// written.
pub fn write(
    dir: &Path,
    prefix: &str,
    count: usize,
    password: &str,
    admin: Option<&str>,
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
            let text = user(&login, "");
            (login, text)
        })
        .collect();
    if let Some(admin) = admin {
        files.push((
            admin.to_owned(),
            user(
                admin,
                "disconnect_users = true\ncant_be_disconnected = true\n",
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
