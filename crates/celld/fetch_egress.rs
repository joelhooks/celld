//! Optional address floor for direct Worker fetches, not host/provider traffic.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{ClientBuilder, Url};

const REFUSAL: &str = "fetch: CELLD_FETCH_PRIVATE=deny refused a non-public destination; use a public URL or configure CELLD_FETCH_ALLOW for an exact IP-literal URL and port";

#[derive(Debug)]
pub(crate) struct Refusal;

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REFUSAL)
    }
}
impl std::error::Error for Refusal {}

#[derive(Clone, Debug, Default)]
pub(crate) struct Floor {
    deny_private: bool,
    allow: Vec<SocketAddr>,
}

impl Floor {
    fn parse(mode: Option<&str>, allow: Option<&str>) -> Result<Self, String> {
        let deny_private = match mode {
            None => false,
            Some("deny") => true,
            _ => return Err("CELLD_FETCH_PRIVATE must be unset or deny".into()),
        };
        let allow = match allow {
            None | Some("") => Vec::new(),
            Some(value) => value
                .split(',')
                .map(|entry| {
                    entry.trim().parse::<SocketAddr>().map_err(|_| {
                        "CELLD_FETCH_ALLOW must contain comma-separated IP:port literals (bracket IPv6)".to_string()
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        Ok(Self {
            deny_private,
            allow,
        })
    }

    pub(crate) fn from_env() -> Result<Self, String> {
        let read = |name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(format!("{name} must be valid Unicode")),
        };
        Self::parse(
            read("CELLD_FETCH_PRIVATE")?.as_deref(),
            read("CELLD_FETCH_ALLOW")?.as_deref(),
        )
    }

    pub(crate) fn check_url(&self, url: &Url) -> Result<(), Refusal> {
        if !self.deny_private {
            return Ok(());
        }
        // reqwest's connector bypasses Resolve for IP-literal hosts. URL parsing
        // also canonicalizes unusual IPv4 spellings before this comparison.
        let ip = match url.host() {
            Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
            Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
            _ => return Ok(()),
        };
        if denied(ip)
            && !url
                .port_or_known_default()
                .is_some_and(|port| self.allow.contains(&SocketAddr::new(ip, port)))
        {
            return Err(Refusal);
        }
        Ok(())
    }

    pub(crate) fn check_redirect(&self, url: &Url, previous: &[Url]) -> Result<(), Refusal> {
        self.check_url(url)?;
        // A named origin cannot gain a private literal exception by redirecting
        // to it. Exceptions are for caller-selected literal destinations only.
        if self.deny_private
            && previous
                .iter()
                .any(|url| matches!(url.host(), Some(url::Host::Domain(_))))
            && match url.host() {
                Some(url::Host::Ipv4(ip)) => denied(IpAddr::V4(ip)),
                Some(url::Host::Ipv6(ip)) => denied(IpAddr::V6(ip)),
                _ => false,
            }
        {
            return Err(Refusal);
        }
        Ok(())
    }

    fn with_resolver(&self, builder: ClientBuilder, inner: Arc<dyn Resolve>) -> ClientBuilder {
        if !self.deny_private {
            return builder;
        }
        // A forward proxy resolves/connects on our behalf, beyond this filter.
        // Do not silently inherit HTTP(S)_PROXY/ALL_PROXY in restricted mode.
        builder
            .no_proxy()
            .dns_resolver(Arc::new(PublicResolver { inner }))
    }

    pub(crate) fn builder(&self) -> ClientBuilder {
        self.with_resolver(reqwest::Client::builder(), Arc::new(SystemResolver))
    }

    pub(crate) fn following_builder(&self) -> ClientBuilder {
        self.following(self.builder())
    }

    fn following(&self, builder: ClientBuilder) -> ClientBuilder {
        if !self.deny_private {
            return builder;
        }
        let floor = self.clone();
        builder.redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if let Err(error) = floor.check_redirect(attempt.url(), attempt.previous()) {
                return attempt.error(error);
            }
            reqwest::redirect::Policy::default().redirect(attempt)
        }))
    }
}

pub(crate) fn is_refusal(message: &str) -> bool {
    message == REFUSAL
}

pub(crate) fn floor() -> &'static Floor {
    static FLOOR: OnceLock<Floor> = OnceLock::new();
    FLOOR.get_or_init(|| Floor::from_env().expect("validated fetch egress settings"))
}

struct SystemResolver;
impl Resolve for SystemResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

struct PublicResolver {
    inner: Arc<dyn Resolve>,
}
impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let future = self.inner.resolve(name);
        Box::pin(async move {
            // Filter the very answers passed to the connector, not a separate
            // preflight lookup. Never apply literal exceptions to DNS answers.
            let addresses: Vec<_> = future.await?.filter(|addr| !denied(addr.ip())).collect();
            if addresses.is_empty() {
                return Err(Box::new(Refusal) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

fn denied_v4(ip: Ipv4Addr) -> bool {
    let n = u32::from(ip);
    [
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xe000_0000, 4),
        (0xf000_0000, 4),
    ]
    .into_iter()
    .any(|(base, bits)| n >> (32 - bits) == base >> (32 - bits))
}

pub(crate) fn denied(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => denied_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return denied_v4(v4);
            }
            let segments = ip.segments();
            if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let bytes = ip.octets();
                return denied_v4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
            }
            if segments[0] == 0x2002 {
                let bytes = ip.octets();
                return denied_v4(Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]));
            }
            ip.is_unspecified()
                || ip.is_loopback()
                || segments[0] & 0xfe00 == 0xfc00
                || segments[0] & 0xffc0 == 0xfe80
                || segments[0] & 0xff00 == 0xff00
        }
    }
}

#[cfg(test)]
#[path = "fetch_egress_tests.rs"]
mod tests;
