//! Client address and scheme. Forwarded headers (X-Forwarded-For,
//! X-Forwarded-Proto, optionally CF-Connecting-IP) are honored ONLY when the
//! direct peer is in TRUSTED_PROXIES; otherwise the socket address is used,
//! so rate limits and logs cannot be spoofed. Also: CIDR lists and IP
//! truncation for privacy-friendly logs (LOG_IP_MODE).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;

use crate::state::AppState;

/// Default TRUSTED_PROXIES: loopback and Docker's default bridge range.
pub const DEFAULT_TRUSTED_PROXIES: &str = "127.0.0.0/8,::1/128,172.16.0.0/12";

/// An IPv4 or IPv6 network, e.g. `10.0.0.0/8` or `fd00::/8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parses `ip/prefix` or a bare IP (a single host).
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = ip
            .parse()
            .map_err(|_| format!("'{s}' is not an IP address or CIDR"))?;
        let addr = canonical(addr);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("'{s}' has an invalid prefix length"))?,
        };
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, canonical(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// Parses a comma-separated CIDR list ("" = empty list).
pub fn parse_cidr_list(s: &str) -> Result<Vec<Cidr>, String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(Cidr::parse)
        .collect()
}

pub fn in_any(list: &[Cidr], ip: IpAddr) -> bool {
    list.iter().any(|c| c.contains(ip))
}

/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) as plain IPv4.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Which header carries the client IP when the peer is a trusted proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientIpHeader {
    /// X-Forwarded-For, walked from the right, skipping trusted proxies.
    XForwardedFor,
    /// CF-Connecting-IP (set by Cloudflare / cloudflared). Only safe if the
    /// origin is reachable exclusively through Cloudflare.
    CfConnectingIp,
}

impl ClientIpHeader {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "x-forwarded-for" => Some(Self::XForwardedFor),
            "cf-connecting-ip" => Some(Self::CfConnectingIp),
            _ => None,
        }
    }
}

/// How client IPs appear in logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogIpMode {
    None,
    /// IPv4 /24, IPv6 /48 (default).
    Truncated,
    Full,
}

impl LogIpMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "truncated" => Some(Self::Truncated),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

/// Formats an IP for logging according to LOG_IP_MODE.
pub fn log_ip(ip: IpAddr, mode: LogIpMode) -> String {
    match (mode, canonical(ip)) {
        (LogIpMode::None, _) => "-".into(),
        (LogIpMode::Full, ip) => ip.to_string(),
        (LogIpMode::Truncated, IpAddr::V4(v4)) => {
            let [a, b, c, _] = v4.octets();
            format!("{}/24", Ipv4Addr::new(a, b, c, 0))
        }
        (LogIpMode::Truncated, IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{}/48", Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0))
        }
    }
}

/// Proxy trust settings (TRUSTED_PROXIES, CLIENT_IP_HEADER).
#[derive(Clone, Debug)]
pub struct ProxyPolicy {
    pub trusted: Vec<Cidr>,
    pub header: ClientIpHeader,
}

/// Who is on the other end of a request.
#[derive(Clone, Copy, Debug)]
pub struct ClientInfo {
    pub ip: IpAddr,
    /// True if a trusted proxy says the browser-facing connection was HTTPS.
    pub https: bool,
}

/// Resolves the client from the socket peer and, only if the peer is a
/// trusted proxy, the forwarded headers.
pub fn client_info(peer: IpAddr, headers: &HeaderMap, policy: &ProxyPolicy) -> ClientInfo {
    let peer = canonical(peer);
    if !in_any(&policy.trusted, peer) {
        return ClientInfo {
            ip: peer,
            https: false,
        };
    }
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let ip = match policy.header {
        ClientIpHeader::CfConnectingIp => header("cf-connecting-ip")
            .and_then(|v| v.trim().parse().ok())
            .map(canonical)
            .unwrap_or(peer),
        ClientIpHeader::XForwardedFor => header("x-forwarded-for")
            .map(|v| forwarded_client(v, &policy.trusted).unwrap_or(peer))
            .unwrap_or(peer),
    };
    // With chained proxies the leftmost value is the browser-facing scheme.
    let https = header("x-forwarded-proto")
        .and_then(|v| v.split(',').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"));
    ClientInfo { ip, https }
}

/// Walks X-Forwarded-For from the right (the entry our trusted peer added),
/// skipping further trusted proxies; the first untrusted address is the
/// client. Entries left of it were supplied by the client and are ignored.
fn forwarded_client(xff: &str, trusted: &[Cidr]) -> Option<IpAddr> {
    let mut last = None;
    for entry in xff.rsplit(',') {
        let ip = canonical(entry.trim().parse().ok()?);
        if !in_any(trusted, ip) {
            return Some(ip);
        }
        last = Some(ip);
    }
    last
}

/// Peer address from the connection, or loopback when absent (tests).
pub fn peer_ip(parts: &Parts) -> IpAddr {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
}

impl FromRequestParts<AppState> for ClientInfo {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Self::Rejection> {
        Ok(client_info(
            peer_ip(parts),
            &parts.headers,
            &st.config.security.proxy,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(trusted: &str, header: ClientIpHeader) -> ProxyPolicy {
        ProxyPolicy {
            trusted: parse_cidr_list(trusted).unwrap(),
            header,
        }
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_matching() {
        let c = Cidr::parse("172.16.0.0/12").unwrap();
        assert!(c.contains(ip("172.17.0.3")));
        assert!(c.contains(ip("172.31.255.255")));
        assert!(!c.contains(ip("172.32.0.1")));
        assert!(!c.contains(ip("::1")));
        assert!(c.contains(ip("::ffff:172.18.0.2")), "IPv4-mapped IPv6");
        assert!(Cidr::parse("::1/128").unwrap().contains(ip("::1")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(Cidr::parse("fd00::/8").unwrap().contains(ip("fd12::1")));
        assert!(Cidr::parse("10.0.0.5").unwrap().contains(ip("10.0.0.5")));
        assert!(!Cidr::parse("10.0.0.5").unwrap().contains(ip("10.0.0.6")));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nope").is_err());
        assert_eq!(parse_cidr_list(" ,10.0.0.0/8, ").unwrap().len(), 1);
    }

    #[test]
    fn untrusted_peer_headers_ignored() {
        let p = policy(DEFAULT_TRUSTED_PROXIES, ClientIpHeader::XForwardedFor);
        let h = headers(&[
            ("x-forwarded-for", "1.2.3.4"),
            ("x-forwarded-proto", "https"),
            ("cf-connecting-ip", "5.6.7.8"),
        ]);
        let c = client_info(ip("8.8.8.8"), &h, &p);
        assert_eq!(c.ip, ip("8.8.8.8"));
        assert!(!c.https);
        // A LAN address is no longer trusted by default.
        let c = client_info(ip("192.168.1.50"), &h, &p);
        assert_eq!(c.ip, ip("192.168.1.50"));
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted_forwarded_for() {
        let p = policy(DEFAULT_TRUSTED_PROXIES, ClientIpHeader::XForwardedFor);
        // Client tried to spoof 6.6.6.6; NPM appended the real address.
        let h = headers(&[
            ("x-forwarded-for", "6.6.6.6, 203.0.113.9"),
            ("x-forwarded-proto", "https"),
        ]);
        let c = client_info(ip("172.18.0.3"), &h, &p);
        assert_eq!(c.ip, ip("203.0.113.9"));
        assert!(c.https);
    }

    #[test]
    fn chained_proxies_are_skipped() {
        // browser -> Cloudflare -> cloudflared (172.18.0.5) -> NPM (172.18.0.2) -> app
        let p = policy(DEFAULT_TRUSTED_PROXIES, ClientIpHeader::XForwardedFor);
        let h = headers(&[("x-forwarded-for", "6.6.6.6, 198.51.100.7, 172.18.0.5")]);
        let c = client_info(ip("172.18.0.2"), &h, &p);
        assert_eq!(c.ip, ip("198.51.100.7"));
    }

    #[test]
    fn cf_connecting_ip_only_when_configured_and_trusted() {
        let h = headers(&[
            ("cf-connecting-ip", "198.51.100.7"),
            ("x-forwarded-for", "172.18.0.5"),
        ]);
        let cf = policy(DEFAULT_TRUSTED_PROXIES, ClientIpHeader::CfConnectingIp);
        assert_eq!(client_info(ip("127.0.0.1"), &h, &cf).ip, ip("198.51.100.7"));
        assert_eq!(client_info(ip("8.8.8.8"), &h, &cf).ip, ip("8.8.8.8"));
        let xff = policy(DEFAULT_TRUSTED_PROXIES, ClientIpHeader::XForwardedFor);
        assert_eq!(client_info(ip("127.0.0.1"), &h, &xff).ip, ip("172.18.0.5"));
    }

    #[test]
    fn garbage_forwarded_for_falls_back_to_peer() {
        let p = policy(DEFAULT_TRUSTED_PROXIES, ClientIpHeader::XForwardedFor);
        let h = headers(&[("x-forwarded-for", "not-an-ip")]);
        assert_eq!(client_info(ip("127.0.0.1"), &h, &p).ip, ip("127.0.0.1"));
    }

    #[test]
    fn log_ip_modes() {
        assert_eq!(
            log_ip(ip("203.0.113.9"), LogIpMode::Truncated),
            "203.0.113.0/24"
        );
        assert_eq!(
            log_ip(ip("2001:db8:1:2:3::9"), LogIpMode::Truncated),
            "2001:db8:1::/48"
        );
        assert_eq!(
            log_ip(ip("::ffff:203.0.113.9"), LogIpMode::Truncated),
            "203.0.113.0/24"
        );
        assert_eq!(log_ip(ip("203.0.113.9"), LogIpMode::Full), "203.0.113.9");
        assert_eq!(log_ip(ip("203.0.113.9"), LogIpMode::None), "-");
    }
}
