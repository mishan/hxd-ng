//! `[banner]`: the server banner a 1.5+ client shows above its windows.

use std::path::PathBuf;
use std::sync::Arc;

use hxd_files::TransferRegistry;
use hxd_session::Banner;
use serde::Deserialize;

use crate::Config;

/// The longest URL sent: what GtkHx keeps of one, and far past any a
/// banner needs.
const MAX_URL: usize = 1024;

/// A banner held here, a banner somewhere else, or one held here that
/// links somewhere else.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BannerSection {
    /// A JPEG, GIF or PNG this server sends to every client that asks,
    /// over HTXF, at most 1 MiB. Classic clients show JPEG and GIF. Re-read
    /// on SIGHUP.
    pub file: Option<PathBuf>,
    /// With `file`, where a click on the banner goes. Alone, where the
    /// client fetches the banner from.
    pub url: Option<String>,
}

pub fn check(config: &Config) -> Result<(), String> {
    let Some(section) = config.banner.as_ref() else {
        return Ok(());
    };
    if section.file.is_none() && section.url.is_none() {
        return Err("[banner] needs a file, a url, or both".into());
    }
    if let Some(url) = &section.url {
        // Sent as it is written, in either text encoding: printable ASCII
        // is the one spelling every client reads the same way.
        if url.is_empty() || url.len() > MAX_URL || !url.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(format!(
                "[banner] url must be 1 to {MAX_URL} characters of ASCII with no spaces; \
                 percent-encode anything else"
            ));
        }
        // A client fetches it or opens it from wherever it is, which only
        // an absolute address names; a path would be read against the
        // client's own idea of where it is.
        let scheme = url.split_once("://");
        if !matches!(scheme, Some((s, host)) if (s.eq_ignore_ascii_case("http")
            || s.eq_ignore_ascii_case("https")) && !host.is_empty() && !host.starts_with('/'))
        {
            return Err("[banner] url must be an absolute http:// or https:// address".into());
        }
    }
    Ok(())
}

/// Load the banner, issuing its transfers from `transfers` — which there
/// is whenever there is a banner file, since [`crate::files::htxf`] opens
/// a transfer listener for one.
pub fn build(
    config: &Config,
    transfers: Option<&Arc<TransferRegistry>>,
) -> Result<Option<Arc<Banner>>, String> {
    let Some(section) = config.banner.as_ref() else {
        return Ok(None);
    };
    check(config)?;
    let banner = match (&section.file, &section.url) {
        (Some(file), url) => {
            let transfers = transfers.expect("a banner file has a transfer listener");
            Banner::file(file, url.clone(), transfers.clone())
                .map_err(|e| format!("[banner] {e}"))?
        }
        (None, Some(url)) => Banner::url(url.clone()),
        (None, None) => unreachable!("checked above"),
    };
    Ok(Some(Arc::new(banner)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(toml: &str) -> Config {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn a_banner_needs_something_to_show() {
        assert!(check(&config("[banner]\n"))
            .unwrap_err()
            .contains("a file, a url"));
        check(&config("[banner]\nurl = \"https://hl.example/b.gif\"\n")).unwrap();
        check(&config("[banner]\nfile = \"b.gif\"\n")).unwrap();
        check(&config("")).unwrap();
    }

    #[test]
    fn a_url_is_printable_ascii() {
        for bad in ["", "https://hl.example/a b.gif", "https://hl.example/é.gif"] {
            let toml = format!("[banner]\nurl = {bad:?}\n");
            assert!(
                check(&config(&toml)).unwrap_err().contains("ASCII"),
                "{bad}"
            );
        }
        let long = format!("[banner]\nurl = \"https://{}\"\n", "a".repeat(MAX_URL));
        assert!(check(&config(&long)).is_err());
    }

    #[test]
    fn a_url_is_absolute_http() {
        for bad in [
            "banner.jpg",
            "/img/b.jpg",
            "//cdn.example/b.jpg",
            "ftp://h/b.jpg",
            "https://",
            "https:///b",
        ] {
            let toml = format!("[banner]\nurl = {bad:?}\n");
            assert!(
                check(&config(&toml)).unwrap_err().contains("absolute"),
                "{bad}"
            );
        }
        for good in ["http://hl.example/b.gif", "HTTPS://hl.example/"] {
            check(&config(&format!("[banner]\nurl = {good:?}\n"))).unwrap();
        }
    }
}
