use super::*;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Mutex;
use tokio::net::TcpListener;

type Log = Arc<Mutex<Vec<String>>>;

/// A loopback server answering each request with what `reply` makes of
/// its head, and keeping the heads, lowercased.
async fn server(reply: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static) -> (SocketAddr, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log = Log::default();
    let seen = log.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            let head = String::from_utf8_lossy(&head).to_lowercase();
            let out = reply(&head);
            seen.lock().unwrap().push(head);
            let _ = s.write_all(&out).await;
            let _ = s.shutdown().await;
        }
    });
    (addr, log)
}

fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut r = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        r.push_str(&format!("{k}: {v}\r\n"));
    }
    r.push_str("\r\n");
    let mut r = r.into_bytes();
    r.extend_from_slice(body);
    r
}

fn path(head: &str) -> &str {
    head.split(' ').nth(1).unwrap_or_default()
}

fn gzip(body: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(body).unwrap();
    e.finish().unwrap()
}

fn cfg() -> FetchConfig {
    FetchConfig {
        timeout: Duration::from_secs(5),
        max_bytes: 1024,
        proxy: None,
        user_agent: "hxd-ng-test/1".into(),
    }
}

/// The public entry point, spawned, which is how a poller will hold it.
async fn get_url(cfg: FetchConfig, url: String, v: Validators) -> Result<Fetched, FetchError> {
    tokio::spawn(async move { fetch(&cfg, &url, &v).await })
        .await
        .unwrap()
}

fn body(r: Result<Fetched, FetchError>) -> (Vec<u8>, Validators, Option<String>) {
    match r {
        Ok(Fetched::Body {
            bytes,
            validators,
            moved_to,
        }) => (bytes, validators, moved_to),
        other => panic!("not a body: {other:?}"),
    }
}

#[tokio::test]
async fn a_body_comes_with_its_validators_and_the_next_fetch_is_conditional() {
    let (addr, log) = server(|head| {
        if head.contains("if-none-match: \"v1\"")
            && head.contains("if-modified-since: sat, 01 jan 2026 00:00:00 gmt")
        {
            response("304 Not Modified", &[], b"")
        } else {
            response(
                "200 OK",
                &[
                    ("ETag", "\"v1\""),
                    ("Last-Modified", "Sat, 01 Jan 2026 00:00:00 GMT"),
                ],
                b"<feed/>",
            )
        }
    })
    .await;
    let url = format!("http://{addr}/feed.xml#frag");
    let (bytes, validators, moved_to) =
        body(get_url(cfg(), url.clone(), Validators::default()).await);
    assert_eq!(bytes, b"<feed/>");
    assert_eq!(
        validators,
        Validators {
            etag: Some("\"v1\"".into()),
            last_modified: Some("Sat, 01 Jan 2026 00:00:00 GMT".into()),
        }
    );
    assert_eq!(moved_to, None);
    let head = log.lock().unwrap()[0].clone();
    assert!(head.starts_with("get /feed.xml http/1.1\r\n"), "{head}");
    for h in [
        "user-agent: hxd-ng-test/1",
        "accept-encoding: gzip",
        &format!("host: {addr}"),
    ] {
        assert!(head.contains(h), "{h} in {head}");
    }

    assert!(matches!(
        get_url(cfg(), url, validators).await,
        Ok(Fetched::NotModified)
    ));
}

#[tokio::test]
async fn gzip_is_decoded_and_held_to_the_limit_after_decoding() {
    let text = b"<rss>".repeat(150);
    let zeros = vec![b' '; 4096];
    let (small, large) = (gzip(&text), gzip(&zeros));
    assert!(large.len() < 1024, "the wire's bytes are under the limit");
    let (addr, _) = server(move |head| {
        let body = if path(head) == "/small" {
            &small
        } else {
            &large
        };
        response("200 OK", &[("Content-Encoding", "gzip")], body)
    })
    .await;
    let (bytes, ..) =
        body(get_url(cfg(), format!("http://{addr}/small"), Validators::default()).await);
    assert_eq!(bytes, text);
    assert_eq!(
        get_url(cfg(), format!("http://{addr}/large"), Validators::default())
            .await
            .unwrap_err(),
        FetchError::TooLarge
    );

    let (addr, _) = server(|_| response("200 OK", &[], &[b'x'; 1025])).await;
    assert_eq!(
        get_url(cfg(), format!("http://{addr}/"), Validators::default())
            .await
            .unwrap_err(),
        FetchError::TooLarge
    );
}

#[tokio::test]
async fn redirects_are_followed_five_deep_and_permanent_ones_reported() {
    // /r/N redirects to /r/N-1; /p/ and /t/ are permanent and temporary
    // hops onto /r/0.
    let (addr, _) = server(|head| {
        let p = path(head);
        let to = |l: &str| response("302 Found", &[("Location", l)], b"");
        match p {
            "/r/0" => response("200 OK", &[], b"ok"),
            "/p" => response("301 Moved Permanently", &[("Location", "/p2")], b""),
            "/p2" => response("308 Permanent Redirect", &[("Location", "/r/0")], b""),
            "/t" => to("/p2"),
            _ => to(&format!("/r/{}", p[3..].parse::<u32>().unwrap() - 1)),
        }
    })
    .await;
    let fetch = |p: &str| get_url(cfg(), format!("http://{addr}{p}"), Validators::default());
    let (bytes, _, moved_to) = body(fetch("/r/5").await);
    assert_eq!(bytes, b"ok");
    assert_eq!(moved_to, None, "a temporary redirect moves nothing");
    assert_eq!(
        fetch("/r/6").await.unwrap_err(),
        FetchError::TooManyRedirects
    );
    assert_eq!(
        body(fetch("/p").await).2,
        Some(format!("http://{addr}/r/0"))
    );
    assert_eq!(
        body(fetch("/t").await).2,
        None,
        "a permanent hop after a temporary one says nothing of the configured URL"
    );
}

#[test]
fn a_redirect_target_is_checked() {
    let from = Url::parse("https://feeds.example/a").unwrap();
    let cases = [
        ("/b?x=1", Ok("https://feeds.example/b?x=1")),
        ("https://other.example/", Ok("https://other.example/")),
        ("http://feeds.example/a", Err(FetchError::Downgrade)),
        (
            "ftp://feeds.example/a",
            Err(FetchError::BadUrl("ftp is not http".into())),
        ),
        (
            "https://u:p@feeds.example/",
            Err(FetchError::BadUrl("userinfo".into())),
        ),
    ];
    for (location, want) in cases {
        assert_eq!(
            redirect(&from, location).map(String::from),
            want.map(String::from),
            "{location}"
        );
    }
    let plain = Url::parse("http://feeds.example/a").unwrap();
    assert!(
        redirect(&plain, "https://feeds.example/").is_ok(),
        "an upgrade is fine"
    );
}

#[tokio::test]
async fn a_refusal_carries_its_retry_after() {
    let (addr, _) = server(|head| match path(head) {
        "/slow" => response("429 Too Many Requests", &[("Retry-After", "120")], b""),
        "/down" => response("503 Service Unavailable", &[("Retry-After", "soon")], b""),
        _ => response("500 Internal Server Error", &[("Retry-After", "5")], b""),
    })
    .await;
    let cases = [
        ("/slow", 429, Some(Duration::from_secs(120))),
        ("/down", 503, None),
        ("/err", 500, None),
    ];
    for (p, code, retry_after) in cases {
        assert_eq!(
            get_url(cfg(), format!("http://{addr}{p}"), Validators::default())
                .await
                .unwrap_err(),
            FetchError::Status { code, retry_after },
            "{p}"
        );
    }
}

#[tokio::test]
async fn a_server_that_never_answers_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(listener.accept().await.unwrap());
        }
    });
    let cfg = FetchConfig {
        timeout: Duration::from_millis(200),
        ..cfg()
    };
    assert_eq!(
        get_url(
            cfg.clone(),
            format!("http://{addr}/"),
            Validators::default()
        )
        .await
        .unwrap_err(),
        FetchError::Timeout
    );
}

#[tokio::test]
async fn a_feed_on_the_local_network_is_fetched_as_configured() {
    let (addr, log) = server(|head| match path(head) {
        "/moved" => response("302 Found", &[("Location", "/feed")], b""),
        _ => response("200 OK", &[], b"x"),
    })
    .await;
    let port = addr.port();
    for url in [
        format!("http://127.0.0.1:{port}/moved"),
        format!("http://localhost:{port}/feed"),
        format!("http://[::ffff:127.0.0.1]:{port}/feed"),
        format!("http://2130706433:{port}/feed"),
    ] {
        assert_eq!(
            body(get_url(cfg(), url.clone(), Validators::default()).await).0,
            b"x",
            "{url}"
        );
    }
    assert_eq!(log.lock().unwrap().len(), 5, "the redirect within it, too");
}

/// Names answer what the test says; every connection lands on `route`.
struct TestNet {
    names: HashMap<&'static str, Vec<IpAddr>>,
    route: SocketAddr,
}

impl Net for TestNet {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let ips = self
            .names
            .get(host)
            .ok_or_else(|| io::Error::other("NXDOMAIN"))?;
        Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
    }
    async fn connect(&self, _: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(self.route).await
    }
}

#[tokio::test]
async fn every_hop_is_checked_where_it_resolves() {
    let (route, log) = server(|head| {
        let to = |l: &str| response("302 Found", &[("Location", l)], b"");
        match path(head) {
            "/feed" => response("200 OK", &[], b"ok"),
            "/to-private" => to("http://private.test/feed"),
            "/to-mixed" => to("http://mixed.test/feed"),
            "/to-literal" => to("http://10.0.0.1/feed"),
            _ => to("http://nowhere.test/feed"),
        }
    })
    .await;
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let net = TestNet {
        names: HashMap::from([
            ("public.test", vec![ip("93.184.216.34")]),
            ("private.test", vec![ip("10.1.2.3")]),
            ("mixed.test", vec![ip("93.184.216.34"), ip("192.168.1.1")]),
        ]),
        route,
    };
    let fetch = |p: &str| {
        let url = format!("http://public.test{p}");
        let net = &net;
        async move { fetch_with(net, &cfg(), &url, &Validators::default()).await }
    };
    assert_eq!(
        body(fetch("/feed").await).0,
        b"ok",
        "a public name is connected to"
    );
    let cases = [
        ("/to-private", FetchError::AddressRefused),
        ("/to-mixed", FetchError::AddressRefused),
        ("/to-literal", FetchError::AddressRefused),
        ("/to-nowhere", FetchError::Unresolvable),
    ];
    for (p, want) in &cases {
        assert_eq!(&fetch(p).await.unwrap_err(), want, "{p}");
    }
    assert_eq!(
        log.lock().unwrap().len(),
        1 + cases.len(),
        "each refused hop was never connected to"
    );
}

#[tokio::test]
async fn through_a_proxy_a_public_feed_is_checked_by_its_literal_addresses() {
    let (proxy, log) = server(|head| {
        if head.starts_with("connect ") {
            response("200 Connection Established", &[], b"")
        } else if path(head).ends_with("/to-metadata") {
            response(
                "302 Found",
                &[("Location", "http://169.254.169.254/feed")],
                b"",
            )
        } else {
            response("200 OK", &[], b"via proxy")
        }
    })
    .await;
    let cfg = FetchConfig {
        proxy: Some(format!("http://{proxy}")),
        ..cfg()
    };
    let (bytes, ..) = body(
        get_url(
            cfg.clone(),
            "http://feed.example/news?x=1".into(),
            Validators::default(),
        )
        .await,
    );
    assert_eq!(bytes, b"via proxy");
    let head = log.lock().unwrap()[0].clone();
    assert!(
        head.starts_with("get http://feed.example/news?x=1 http/1.1\r\n"),
        "absolute form: {head}"
    );
    assert!(head.contains("host: feed.example\r\n"), "{head}");

    let (bytes, ..) = body(
        get_url(
            cfg.clone(),
            "http://10.0.0.1/feed".into(),
            Validators::default(),
        )
        .await,
    );
    assert_eq!(bytes, b"via proxy", "a feed on the local network");
    assert_eq!(
        get_url(
            cfg.clone(),
            "http://feed.example/to-metadata".into(),
            Validators::default()
        )
        .await
        .unwrap_err(),
        FetchError::AddressRefused
    );
    assert_eq!(
        log.lock().unwrap().len(),
        3,
        "a public feed's redirect to a literal private address never reaches the proxy"
    );

    // The proxy says yes to a tunnel and then hangs up, so TLS fails
    // after the CONNECT has been seen.
    assert!(matches!(
        get_url(
            cfg.clone(),
            "https://feed.example/news".into(),
            Validators::default()
        )
        .await,
        Err(FetchError::Transport(_))
    ));
    let head = log.lock().unwrap()[3].clone();
    assert!(
        head.starts_with("connect feed.example:443 http/1.1\r\n"),
        "{head}"
    );
}
