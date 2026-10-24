use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn restricted(allow: &str) -> Floor {
    Floor::parse(Some("deny"), Some(allow)).unwrap()
}

#[test]
fn ipv4_range_edges_and_embedded_ipv6() {
    let ranges = [
        ("0.0.0.0", 8),
        ("10.0.0.0", 8),
        ("100.64.0.0", 10),
        ("127.0.0.0", 8),
        ("169.254.0.0", 16),
        ("172.16.0.0", 12),
        ("192.0.0.0", 24),
        ("192.168.0.0", 16),
        ("198.18.0.0", 15),
        ("224.0.0.0", 4),
        ("240.0.0.0", 4),
    ];
    let intervals: Vec<_> = ranges
        .into_iter()
        .map(|(base, bits)| {
            let start = u32::from(base.parse::<Ipv4Addr>().unwrap());
            (start, start | (u32::MAX >> bits))
        })
        .collect();
    for &(start, end) in &intervals {
        for n in [
            Some(start),
            Some(end),
            start.checked_sub(1),
            end.checked_add(1),
        ]
        .into_iter()
        .flatten()
        {
            let expected = intervals.iter().any(|&(lo, hi)| (lo..=hi).contains(&n));
            let ip = Ipv4Addr::from(n);
            assert_eq!(denied(ip.into()), expected, "{ip}");
            assert_eq!(denied(ip.to_ipv6_mapped().into()), expected, "mapped {ip}");
            let nat64 = format!("64:ff9b::{:x}:{:x}", n >> 16, n & 0xffff);
            assert_eq!(denied(nat64.parse().unwrap()), expected, "{nat64}");
            let six_to_four = format!("2002:{:x}:{:x}::", n >> 16, n & 0xffff);
            assert_eq!(
                denied(six_to_four.parse().unwrap()),
                expected,
                "{six_to_four}"
            );
        }
    }
}

#[test]
fn six_to_four_embedded_range_edges() {
    for (ip, expected) in [
        ("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        ("2002::", true),
        ("2002:9ff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        ("2002:a00::", true),
        ("2002:aff:ffff:ffff:ffff:ffff:ffff:ffff", true),
        ("2002:b00::", false),
        ("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
        ("2003::", false),
    ] {
        assert_eq!(denied(ip.parse().unwrap()), expected, "{ip}");
    }
}

#[test]
fn ipv6_range_edges() {
    for (ip, expected) in [
        ("::", true),
        ("::1", true),
        ("::2", false),
        ("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        ("fc00::", true),
        ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
        ("fe00::", false),
        ("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        ("fe80::", true),
        ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
        ("fec0::", false),
        ("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        ("ff00::", true),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
        ("2606:4700:4700::1111", false),
        ("64:ff9b::808:808", false),
    ] {
        assert_eq!(denied(ip.parse().unwrap()), expected, "{ip}");
    }
}

#[test]
fn config_and_literal_only_exceptions() {
    assert!(Floor::parse(Some("no"), None).is_err());
    for invalid in ["localhost:80", "127.0.0.1", "127.0.0.1:80,", "[::1]"] {
        assert!(Floor::parse(Some("deny"), Some(invalid)).is_err());
    }
    let floor = restricted("127.0.0.1:80,[::1]:8080");
    for url in ["http://127.0.0.1", "http://[::1]:8080"] {
        assert!(floor.check_url(&Url::parse(url).unwrap()).is_ok());
    }
    for url in [
        "http://127.0.0.1:81",
        "https://127.0.0.1",
        "http://[::1]:80",
        "http://[::ffff:127.0.0.1]",
        "http://[64:ff9b::7f00:1]",
    ] {
        assert!(floor.check_url(&Url::parse(url).unwrap()).is_err(), "{url}");
    }
    let named = Url::parse("http://caller.test/").unwrap();
    let literal = Url::parse("http://127.0.0.1/").unwrap();
    assert!(floor.check_redirect(&literal, &[named]).is_err());
    assert!(floor
        .check_redirect(&literal, std::slice::from_ref(&literal))
        .is_ok());
    assert!(Floor::default().check_url(&literal).is_ok());
    // WHATWG canonicalization cannot sidestep the literal check.
    for url in [
        "http://2130706433",
        "http://0177.0.0.1",
        "http://0x7f000001",
    ] {
        assert!(restricted("").check_url(&Url::parse(url).unwrap()).is_err());
    }
    assert!(is_refusal(&Refusal.to_string()));
    assert!(!is_refusal("another network failure"));
}

struct Stub {
    calls: AtomicUsize,
    answers: Vec<Vec<SocketAddr>>,
}
impl Resolve for Stub {
    fn resolve(&self, _: Name) -> Resolving {
        let index = self
            .calls
            .fetch_add(1, Ordering::SeqCst)
            .min(self.answers.len() - 1);
        let addresses = self.answers[index].clone();
        Box::pin(async move { Ok(Box::new(addresses.into_iter()) as Addrs) })
    }
}

struct Listener {
    address: SocketAddr,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Listener {
    // The fixture listener is outside the Worker execution boundary.
    #[allow(clippy::disallowed_methods)]
    async fn start(location: Option<String>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let count = hits.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = [0; 4096];
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let count = stream.read(&mut bytes).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    request.extend_from_slice(&bytes[..count]);
                }
                count.fetch_add(1, Ordering::SeqCst);
                let response = match &location {
                    Some(location) => format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
                    None => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".into(),
                };
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        Self {
            address,
            hits,
            task,
        }
    }
    fn url(&self) -> Url {
        Url::parse(&format!("http://{}/", self.address)).unwrap()
    }
}

fn client(floor: &Floor, resolver: Arc<dyn Resolve>) -> reqwest::Client {
    floor
        .following(floor.with_resolver(reqwest::Client::builder().no_proxy(), resolver))
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap()
}

async fn fetch(
    floor: &Floor,
    client: &reqwest::Client,
    url: Url,
) -> Result<reqwest::Response, String> {
    floor.check_url(&url).map_err(|e| e.to_string())?;
    client.get(url).send().await.map_err(|e| {
        let mut source: &(dyn std::error::Error + 'static) = &e;
        loop {
            if source.is::<Refusal>() {
                return Refusal.to_string();
            }
            match source.source() {
                Some(next) => source = next,
                None => return e.to_string(),
            }
        }
    })
}

fn stub(answers: Vec<Vec<SocketAddr>>) -> Arc<Stub> {
    Arc::new(Stub {
        calls: AtomicUsize::new(0),
        answers,
    })
}

#[tokio::test]
async fn loopback_off_denied_and_exact_exception() {
    let listener = Listener::start(None).await;
    let resolver = stub(vec![vec![listener.address]]);
    let off = Floor::default();
    assert_eq!(
        fetch(&off, &client(&off, resolver.clone()), listener.url())
            .await
            .unwrap()
            .status(),
        200
    );
    let on = restricted("");
    assert_eq!(
        fetch(&on, &client(&on, resolver.clone()), listener.url())
            .await
            .unwrap_err(),
        REFUSAL
    );
    let allow = restricted(&listener.address.to_string());
    assert_eq!(
        fetch(&allow, &client(&allow, resolver), listener.url())
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(listener.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn rebinding_connect_uses_filtered_answer_not_preflight() {
    let listener = Listener::start(None).await;
    let resolver = stub(vec![
        vec!["8.8.8.8:0".parse().unwrap()],
        vec![listener.address],
    ]);
    // A preflight would accept this answer. The connection must use the next
    // (rebound) answer, which may never inherit a literal exception.
    let probe = resolver
        .resolve("rebind.test".parse().unwrap())
        .await
        .unwrap();
    assert!(probe.into_iter().all(|addr| !denied(addr.ip())));
    let floor = restricted(&listener.address.to_string());
    let url = Url::parse(&format!("http://rebind.test:{}/", listener.address.port())).unwrap();
    let error = fetch(&floor, &client(&floor, resolver.clone()), url)
        .await
        .unwrap_err();
    assert_eq!(error, REFUSAL);
    assert!(!error.contains("127.0.0.1"));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    assert_eq!(listener.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn redirect_to_private_literal_is_blocked_before_connect() {
    let target = Listener::start(None).await;
    let origin = Listener::start(Some(target.url().to_string())).await;
    let floor = restricted(&origin.address.to_string());
    let resolver = stub(vec![vec![target.address]]);
    let error = fetch(&floor, &client(&floor, resolver), origin.url())
        .await
        .unwrap_err();
    assert_eq!(error, REFUSAL);
    assert_eq!(origin.hits.load(Ordering::SeqCst), 1);
    assert_eq!(target.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn named_loopback_and_named_redirect_do_not_inherit_exception() {
    let target = Listener::start(None).await;
    let floor = restricted(&target.address.to_string());
    let resolver = stub(vec![vec![target.address]]);
    let url = Url::parse(&format!("http://loopback.test:{}/", target.address.port())).unwrap();
    assert_eq!(
        fetch(&floor, &client(&floor, resolver.clone()), url.clone())
            .await
            .unwrap_err(),
        REFUSAL
    );
    let origin = Listener::start(Some(url.to_string())).await;
    let floor = restricted(&format!("{},{}", origin.address, target.address));
    assert_eq!(
        fetch(&floor, &client(&floor, resolver), origin.url())
            .await
            .unwrap_err(),
        REFUSAL
    );
    assert_eq!(target.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn filters_every_answer_and_fails_closed_on_empty() {
    let public: SocketAddr = "8.8.8.8:0".parse().unwrap();
    let private: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let resolver = PublicResolver {
        inner: stub(vec![vec![private, public, private], vec![]]),
    };
    let addresses: Vec<_> = resolver
        .resolve("mixed.test".parse().unwrap())
        .await
        .unwrap()
        .collect();
    assert_eq!(addresses, vec![public]);
    assert!(resolver
        .resolve("empty.test".parse().unwrap())
        .await
        .is_err());
}
