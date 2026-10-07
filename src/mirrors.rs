//! Admin-curated mirrors: URL validation per kind, "quick add" URL builders
//! (pure string templating, no network calls), and the opt-in Verify job.
//!
//! Verify is the ONLY outbound request the app ever makes, and only when an
//! admin clicks it. It is SSRF-hardened: only http/https on ports 80/443,
//! every hostname is resolved by [`GuardedResolver`] which refuses internal
//! addresses (so the checked address is the one connected to), IP literals
//! are checked directly, redirects are followed by hand (max 3) and
//! re-checked, no proxy env vars are honored, and the body is capped at the
//! recorded size plus a small margin.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use sha2::{Digest, Sha256};
use url::Url;

use crate::config::validate_mirror_url;
use crate::util::encode_path_segment;

/// `file_mirrors.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MirrorKind {
    /// A direct download of the same file elsewhere.
    Http,
    /// A .torrent file (http/https) or a magnet link hosted elsewhere.
    Torrent,
}

impl MirrorKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "http" => Some(Self::Http),
            "torrent" => Some(Self::Torrent),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Torrent => "torrent",
        }
    }
}

/// Mirror statuses (`file_mirrors.status`).
pub mod status {
    pub const PENDING: &str = "pending";
    pub const APPROVED: &str = "approved";
    pub const REJECTED: &str = "rejected";
    pub const FAILED: &str = "failed";
}

/// Validates a mirror URL for its kind. http: http/https only. torrent:
/// http/https (a .torrent file) or a `magnet:?xt=urn:...` link.
pub fn validate_mirror(kind: MirrorKind, input: &str) -> Result<String, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("URL is required.".into());
    }
    if input.len() > 2048 {
        return Err("URL must be at most 2048 characters.".into());
    }
    if kind == MirrorKind::Torrent
        && input
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("magnet:?"))
    {
        let ok = input.contains("xt=urn:")
            && !input
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '<' || c == '>');
        return if ok {
            Ok(input.to_string())
        } else {
            Err("Magnet links must look like magnet:?xt=urn:btih:...".into())
        };
    }
    match validate_mirror_url(input) {
        Ok(Some(u)) => Ok(u),
        Ok(None) => Err("URL is required.".into()),
        Err(_) if kind == MirrorKind::Torrent => Err(
            "Torrent mirrors must be an http(s) link to a .torrent file or a magnet: link.".into(),
        ),
        Err(_) => Err("Mirror URLs must be http:// or https:// addresses.".into()),
    }
}

/// Cleans a label (at most 100 characters, no control characters). Blank
/// labels default to the URL's host name.
pub fn clean_label(label: &str, url: &str) -> Result<String, String> {
    let label: String = label.trim().chars().filter(|c| !c.is_control()).collect();
    if label.chars().count() > 100 {
        return Err("Label must be at most 100 characters.".into());
    }
    if !label.is_empty() {
        return Ok(label);
    }
    Ok(Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "magnet".into()))
}

fn identifier_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !s.starts_with('.')
}

fn segment_ok(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 255 && !s.chars().any(char::is_control)
}

/// URLs for one file in an Archive.org item: the direct download, and the
/// torrent Archive.org generates for the whole item.
pub fn archive_org_urls(identifier: &str, filename: &str) -> Result<(String, String), String> {
    let identifier = identifier.trim();
    if !identifier_ok(identifier) {
        return Err("Archive.org identifiers use letters, digits, '.', '_' and '-'.".into());
    }
    if !segment_ok(filename) {
        return Err("A file name is required.".into());
    }
    Ok((
        format!(
            "https://archive.org/download/{identifier}/{}",
            encode_path_segment(filename.trim())
        ),
        format!("https://archive.org/download/{identifier}/{identifier}_archive.torrent"),
    ))
}

/// Download URL of a GitHub release asset.
pub fn github_release_url(
    owner: &str,
    repo: &str,
    tag: &str,
    asset: &str,
) -> Result<String, String> {
    let (owner, repo) = (owner.trim(), repo.trim());
    if !identifier_ok(owner) || !identifier_ok(repo) {
        return Err("GitHub owner and repository use letters, digits, '.', '_' and '-'.".into());
    }
    if !segment_ok(tag) || !segment_ok(asset) {
        return Err("Release tag and asset name are required.".into());
    }
    Ok(format!(
        "https://github.com/{owner}/{repo}/releases/download/{}/{}",
        encode_path_segment(tag.trim()),
        encode_path_segment(asset.trim())
    ))
}

// ---- SSRF protection ---------------------------------------------------------

/// True for addresses Verify must never connect to: loopback, private
/// (RFC 1918), link-local, CGNAT, unique-local IPv6, multicast, broadcast,
/// unspecified, documentation/benchmark ranges, and IPv6 forms that embed
/// such an IPv4 address.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => blocked_v4(v4),
        IpAddr::V6(v6) => blocked_v6(v6),
    }
}

fn blocked_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0 // "this network"
        || (a == 100 && (64..128).contains(&b)) // CGNAT 100.64.0.0/10
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || a >= 240 // reserved
}

fn blocked_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return blocked_v4(v4);
    }
    let seg = ip.segments();
    // IPv4-compatible (::a.b.c.d), NAT64 (64:ff9b::/96) and 6to4 (2002::/16)
    // all embed an IPv4 address.
    let tail_v4 = Ipv4Addr::new(
        (seg[6] >> 8) as u8,
        seg[6] as u8,
        (seg[7] >> 8) as u8,
        seg[7] as u8,
    );
    if seg[..6] == [0; 6] && !ip.is_loopback() && !ip.is_unspecified() {
        return blocked_v4(tail_v4);
    }
    if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6] == [0; 4] {
        return blocked_v4(tail_v4);
    }
    if seg[0] == 0x2002 {
        let v4 = Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            seg[1] as u8,
            (seg[2] >> 8) as u8,
            seg[2] as u8,
        );
        return blocked_v4(v4);
    }
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unique_local() // fc00::/7
        || ip.is_unicast_link_local() // fe80::/10
        || (seg[0] & 0xffc0) == 0xfec0 // deprecated site-local
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // documentation
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("blocked: {0}")]
    Blocked(String),
    #[error("request failed: {0}")]
    Http(String),
    #[error("the mirror returned HTTP {0}")]
    Status(u16),
    #[error("too many redirects (more than {MAX_REDIRECTS})")]
    TooManyRedirects,
    #[error("the mirror sent more than the expected {0} bytes")]
    TooLarge(u64),
    #[error("size mismatch: expected {expected} bytes, the mirror sent {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("SHA-256 mismatch: the mirror's file differs from ours")]
    HashMismatch,
}

pub const MAX_REDIRECTS: usize = 3;

/// Checks a URL Verify is about to request: http/https, port 80 or 443, no
/// credentials, and an IP-literal host must not be internal. (Host names are
/// checked at resolution time by [`GuardedResolver`].)
pub fn check_target(url: &Url) -> Result<(), VerifyError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(VerifyError::Blocked(
            "only http and https are allowed".into(),
        ));
    }
    if !matches!(url.port_or_known_default(), Some(80 | 443)) {
        return Err(VerifyError::Blocked(
            "only ports 80 and 443 are allowed".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(VerifyError::Blocked(
            "URLs with credentials are not allowed".into(),
        ));
    }
    match url.host() {
        None => Err(VerifyError::Blocked("the URL has no host".into())),
        Some(url::Host::Ipv4(ip)) if blocked_v4(ip) => {
            Err(VerifyError::Blocked(format!("{ip} is an internal address")))
        }
        Some(url::Host::Ipv6(ip)) if blocked_v6(ip) => {
            Err(VerifyError::Blocked(format!("{ip} is an internal address")))
        }
        Some(_) => Ok(()),
    }
}

/// Resolves a redirect's Location against the current URL and checks it.
pub fn next_hop(current: &Url, location: &str) -> Result<Url, VerifyError> {
    let next = current
        .join(location)
        .map_err(|_| VerifyError::Http("invalid redirect location".into()))?;
    check_target(&next)?;
    Ok(next)
}

/// Rejects a name if ANY of its addresses is internal (no partial results,
/// so a mixed public/private record set cannot be used to reach inside).
pub fn check_resolved(name: &str, addrs: &[SocketAddr]) -> Result<(), VerifyError> {
    if addrs.is_empty() {
        return Err(VerifyError::Http(format!("{name} did not resolve")));
    }
    if let Some(bad) = addrs.iter().find(|a| is_blocked_ip(a.ip())) {
        return Err(VerifyError::Blocked(format!(
            "{name} resolves to an internal address ({})",
            bad.ip()
        )));
    }
    Ok(())
}

/// DNS resolver for the Verify client: resolves with the system resolver and
/// refuses internal addresses. The connection uses exactly these addresses.
///
/// This is the pinning: hyper connects to exactly the addresses returned
/// here (which were all validated), while the Host header and TLS SNI keep
/// the original name. Every new connection (each redirect hop to a new
/// host) resolves and validates again, so DNS rebinding cannot slip an
/// internal address in between check and connect.
struct GuardedResolver {
    lookup: Lookup,
}

/// Name -> addresses; the system resolver in production, a fake in tests.
type Lookup = Arc<
    dyn Fn(
            String,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>,
        > + Send
        + Sync,
>;

fn system_lookup() -> Lookup {
    Arc::new(|host: String| {
        Box::pin(async move { Ok(tokio::net::lookup_host((host.as_str(), 0)).await?.collect()) })
    })
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let lookup = self.lookup.clone();
        Box::pin(async move {
            let addrs = lookup(host.clone()).await?;
            check_resolved(&host, &addrs)?;
            let iter: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

/// Streams a body through SHA-256, failing as soon as it exceeds `cap` bytes.
pub async fn hash_capped<S, E>(mut body: S, cap: u64) -> Result<(u64, String), VerifyError>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| VerifyError::Http(e.to_string()))?;
        total += chunk.len() as u64;
        if total > cap {
            return Err(VerifyError::TooLarge(cap));
        }
        hasher.update(&chunk);
    }
    Ok((total, hex::encode(hasher.finalize())))
}

/// Compares what a mirror sent with the recorded size and SHA-256.
pub fn compare(
    expected_size: u64,
    expected_sha256: &str,
    got: (u64, String),
) -> Result<(), VerifyError> {
    if got.0 != expected_size {
        return Err(VerifyError::SizeMismatch {
            expected: expected_size,
            actual: got.0,
        });
    }
    if !got.1.eq_ignore_ascii_case(expected_sha256) {
        return Err(VerifyError::HashMismatch);
    }
    Ok(())
}

/// Bytes tolerated beyond the recorded size before aborting.
const SIZE_MARGIN: u64 = 64 * 1024;

/// Downloads an http mirror and checks it is byte-identical to our file
/// (size + SHA-256, one streaming pass). Only ever called from an admin's
/// explicit Verify click.
///
/// `proxy` (VERIFY_PROXY_URL) routes the request through an HTTP or SOCKS
/// proxy so the mirror sees the proxy's address, not this server's. An
/// HTTP proxy (or `socks5h://`) resolves names itself, so the per-connection
/// pinning above cannot apply there; names are still pre-checked here
/// (best effort) and the proxy should enforce its own egress rules.
pub async fn verify_http_mirror(
    url: &str,
    expected_size: u64,
    expected_sha256: &str,
    proxy: Option<&str>,
) -> Result<(), VerifyError> {
    verify_with_lookup(url, expected_size, expected_sha256, proxy, system_lookup()).await
}

async fn verify_with_lookup(
    url: &str,
    expected_size: u64,
    expected_sha256: &str,
    proxy: Option<&str>,
    lookup: Lookup,
) -> Result<(), VerifyError> {
    let mut current = Url::parse(url).map_err(|_| VerifyError::Http("invalid URL".into()))?;
    check_target(&current)?;
    // Generous overall limit: 2 minutes plus 256 KiB/s for the file, max 12h.
    let total = Duration::from_secs((120 + expected_size / (256 * 1024)).min(12 * 3600));
    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    let builder = match proxy {
        Some(p) => builder.proxy(
            reqwest::Proxy::all(p)
                .map_err(|e| VerifyError::Http(format!("VERIFY_PROXY_URL: {e}")))?,
        ),
        None => builder,
    };
    let client = builder
        .dns_resolver(Arc::new(GuardedResolver {
            lookup: lookup.clone(),
        }))
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(30))
        .timeout(total)
        // No version or site name: reveal as little as possible.
        .user_agent("mirror-verify")
        .build()
        .map_err(|e| VerifyError::Http(e.to_string()))?;
    let cap = expected_size + SIZE_MARGIN;

    for hop in 0..=MAX_REDIRECTS {
        if proxy.is_some()
            && let Some(url::Host::Domain(host)) = current.host()
        {
            let addrs = lookup(host.to_string())
                .await
                .map_err(|e| VerifyError::Http(e.to_string()))?;
            check_resolved(host, &addrs)?;
        }
        let resp = client
            .get(current.clone())
            .send()
            .await
            .map_err(|e| VerifyError::Http(error_chain(&e)))?;
        let status = resp.status();
        if status.is_redirection() {
            if hop == MAX_REDIRECTS {
                return Err(VerifyError::TooManyRedirects);
            }
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| VerifyError::Http("redirect without a Location header".into()))?;
            current = next_hop(&current, location)?;
            continue;
        }
        if !status.is_success() {
            return Err(VerifyError::Status(status.as_u16()));
        }
        if resp.content_length().is_some_and(|len| len > cap) {
            return Err(VerifyError::TooLarge(cap));
        }
        let got = hash_capped(resp.bytes_stream(), cap).await?;
        return compare(expected_size, expected_sha256, got);
    }
    Err(VerifyError::TooManyRedirects)
}

/// reqwest errors hide the interesting part (e.g. our resolver's refusal)
/// in their source chain.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg = format!("{msg}: {s}");
        src = s.source();
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(s: &str) -> bool {
        is_blocked_ip(s.parse().unwrap())
    }

    #[test]
    fn ssrf_blocklist() {
        for ip in [
            "127.0.0.1",
            "127.8.9.10",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.254",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "64:ff9b::a00:1",
            "2002:c0a8:0101::1",
            "::127.0.0.1",
        ] {
            assert!(blocked(ip), "{ip} should be blocked");
        }
        for ip in [
            "93.184.216.34",
            "1.1.1.1",
            "8.8.8.8",
            "100.128.0.1",
            "2606:4700::1111",
            "2001:4860::8888",
        ] {
            assert!(!blocked(ip), "{ip} should be allowed");
        }
    }

    #[test]
    fn target_checks() {
        let ok = |u: &str| check_target(&Url::parse(u).unwrap()).is_ok();
        assert!(ok("https://archive.org/download/x/y.iso"));
        assert!(ok("http://example.com:80/x"));
        assert!(!ok("http://127.0.0.1/x"));
        assert!(!ok("http://2130706433/x"), "decimal 127.0.0.1");
        assert!(!ok("http://[::1]/x"));
        assert!(!ok("http://10.0.0.1/x"));
        assert!(!ok("http://192.168.0.10/"));
        assert!(!ok("http://169.254.169.254/latest/meta-data/"));
        assert!(!ok("https://example.com:8443/x"), "only 80/443");
        assert!(!ok("http://example.com:22/"));
        assert!(!ok("ftp://example.com/x"));
        assert!(!ok("https://user:pw@example.com/x"));
    }

    #[test]
    fn redirect_to_private_is_refused() {
        let start = Url::parse("https://mirror.example.com/a.iso").unwrap();
        assert!(next_hop(&start, "https://cdn.example.net/a.iso").is_ok());
        assert!(next_hop(&start, "/other/a.iso").is_ok());
        for bad in [
            "http://127.0.0.1/a.iso",
            "http://192.168.1.1/",
            "http://[::1]:80/",
            "http://169.254.169.254/",
            "https://mirror.example.com:8080/a.iso",
            "file:///etc/passwd",
        ] {
            assert!(
                matches!(next_hop(&start, bad), Err(VerifyError::Blocked(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn resolved_addresses_are_checked() {
        let a = |s: &str| SocketAddr::new(s.parse().unwrap(), 0);
        assert!(check_resolved("ok.example", &[a("93.184.216.34")]).is_ok());
        assert!(check_resolved("evil.example", &[a("93.184.216.34"), a("10.0.0.1")]).is_err());
        assert!(check_resolved("evil.example", &[a("::1")]).is_err());
        assert!(check_resolved("none.example", &[]).is_err());
    }

    #[tokio::test]
    async fn resolver_refuses_localhost() {
        use reqwest::dns::Resolve;
        let name: reqwest::dns::Name = "localhost".parse().unwrap();
        let r = GuardedResolver {
            lookup: system_lookup(),
        };
        assert!(r.resolve(name).await.is_err());
    }

    /// A DNS server that answers with a public address first and an internal
    /// one afterwards (rebinding).
    fn rebinding_lookup(internal: &'static str) -> (Lookup, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        let lookup: Lookup = Arc::new(move |_host: String| {
            let n = c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                let ip: IpAddr = if n == 0 {
                    "93.184.216.34".parse().unwrap()
                } else {
                    internal.parse().unwrap()
                };
                Ok(vec![SocketAddr::new(ip, 0)])
            })
        });
        (lookup, calls)
    }

    #[tokio::test]
    async fn rebinding_to_internal_is_refused_on_every_resolution() {
        use reqwest::dns::Resolve;
        for internal in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.5",
            "fd00:ec2::254",
            "::ffff:192.168.0.1",
        ] {
            let (lookup, calls) = rebinding_lookup(internal);
            let r = GuardedResolver { lookup };
            let first = r.resolve("mirror.example".parse().unwrap()).await;
            assert!(first.is_ok(), "public answer accepted");
            let second = r.resolve("mirror.example".parse().unwrap()).await;
            assert!(second.is_err(), "rebound answer {internal} refused");
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn proxied_verify_prechecks_names() {
        // With a proxy the proxy resolves; the app still refuses names that
        // resolve internally before sending anything (proxy is never contacted).
        let lookup: Lookup = Arc::new(|_h: String| {
            Box::pin(async { Ok(vec![SocketAddr::new("10.1.2.3".parse().unwrap(), 0)]) })
        });
        let err = verify_with_lookup(
            "https://internal.example/x.iso",
            10,
            "00",
            Some("http://127.0.0.1:9"),
            lookup,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, VerifyError::Blocked(_)), "{err}");
    }

    #[test]
    fn cloud_metadata_addresses_are_blocked() {
        for ip in [
            "169.254.169.254",
            "169.254.170.2",
            "fd00:ec2::254",
            "fd00:ec2::23",
            "100.100.100.200",
        ] {
            assert!(blocked(ip), "{ip}");
        }
    }

    fn body(chunks: &[&'static [u8]]) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Unpin {
        futures_util::stream::iter(
            chunks
                .iter()
                .map(|c| Ok(Bytes::from_static(c)))
                .collect::<Vec<_>>(),
        )
    }

    #[tokio::test]
    async fn hash_match_mismatch_and_size_cap() {
        let sha = hex::encode(Sha256::digest(b"hello world"));
        let got = hash_capped(body(&[b"hello ", b"world"]), 100)
            .await
            .unwrap();
        assert!(compare(11, &sha, got).is_ok());

        let got = hash_capped(body(&[b"hello there"]), 100).await.unwrap();
        assert!(matches!(
            compare(11, &sha, got),
            Err(VerifyError::HashMismatch)
        ));

        let got = hash_capped(body(&[b"hello"]), 100).await.unwrap();
        assert!(matches!(
            compare(11, &sha, got),
            Err(VerifyError::SizeMismatch { .. })
        ));

        assert!(matches!(
            hash_capped(body(&[b"0123456789", b"0123456789"]), 15).await,
            Err(VerifyError::TooLarge(15))
        ));
    }

    #[tokio::test]
    async fn verify_refuses_internal_targets_without_connecting() {
        for url in [
            "http://127.0.0.1/x.iso",
            "http://localhost/x.iso",
            "http://10.0.0.1/x",
            "http://[::1]/x",
        ] {
            let err = verify_http_mirror(url, 10, "00", None).await.unwrap_err();
            assert!(
                err.to_string().contains("internal") || err.to_string().contains("blocked"),
                "{url}: {err}"
            );
        }
    }

    /// Real network round trip (run with `cargo test -- --ignored`): a public
    /// https file with a known size and SHA-256 verifies; a wrong hash fails.
    #[tokio::test]
    #[ignore = "needs internet access"]
    async fn verify_against_a_real_public_file() {
        let url = "https://www.rfc-editor.org/rfc/rfc9110.txt";
        let sha = "21c1cdce6ab0e5509b04d84a28000836c7a087cf786efe6f04877ebfff47232a";
        verify_http_mirror(url, 502941, sha, None).await.unwrap();
        assert!(matches!(
            verify_http_mirror(url, 502941, &"0".repeat(64), None).await,
            Err(VerifyError::HashMismatch)
        ));
    }

    #[test]
    fn url_validation_per_kind() {
        assert!(validate_mirror(MirrorKind::Http, "https://archive.org/download/x/y.iso").is_ok());
        assert!(validate_mirror(MirrorKind::Http, "magnet:?xt=urn:btih:abc").is_err());
        assert!(validate_mirror(MirrorKind::Http, "javascript:alert(1)").is_err());
        assert!(validate_mirror(MirrorKind::Http, "ftp://x.org/y").is_err());
        assert!(validate_mirror(MirrorKind::Http, "").is_err());
        assert!(
            validate_mirror(
                MirrorKind::Torrent,
                "magnet:?xt=urn:btih:0123456789abcdef&dn=x"
            )
            .is_ok()
        );
        assert!(validate_mirror(MirrorKind::Torrent, "MAGNET:?xt=urn:btih:abc").is_ok());
        assert!(validate_mirror(MirrorKind::Torrent, "magnet:?dn=no-hash").is_err());
        assert!(validate_mirror(MirrorKind::Torrent, "magnet:?xt=urn:btih:a\"><b").is_err());
        assert!(
            validate_mirror(
                MirrorKind::Torrent,
                "https://archive.org/download/x/x_archive.torrent"
            )
            .is_ok()
        );
        assert!(validate_mirror(MirrorKind::Torrent, "javascript:alert(1)").is_err());
        assert!(
            validate_mirror(
                MirrorKind::Torrent,
                &format!("magnet:?xt=urn:btih:{}", "a".repeat(2100))
            )
            .is_err()
        );
    }

    #[test]
    fn labels() {
        assert_eq!(
            clean_label("", "https://archive.org/download/x").unwrap(),
            "archive.org"
        );
        assert_eq!(
            clean_label("", "magnet:?xt=urn:btih:abc").unwrap(),
            "magnet"
        );
        assert_eq!(
            clean_label(" EU\nmirror ", "https://x.org").unwrap(),
            "EUmirror"
        );
        assert!(clean_label(&"x".repeat(101), "https://x.org").is_err());
    }

    #[test]
    fn quick_add_builders() {
        let (http, torrent) = archive_org_urls("my-distro-2.0", "my distro.iso").unwrap();
        assert_eq!(
            http,
            "https://archive.org/download/my-distro-2.0/my%20distro.iso"
        );
        assert_eq!(
            torrent,
            "https://archive.org/download/my-distro-2.0/my-distro-2.0_archive.torrent"
        );
        assert!(archive_org_urls("../etc", "x").is_err());
        assert!(archive_org_urls("id with space", "x").is_err());
        assert!(archive_org_urls("ok", "").is_err());
        assert_eq!(
            github_release_url("owner", "repo", "v1.0", "app 1.0.iso").unwrap(),
            "https://github.com/owner/repo/releases/download/v1.0/app%201.0.iso"
        );
        assert_eq!(
            github_release_url("o", "r", "release/2", "a.iso").unwrap(),
            "https://github.com/o/r/releases/download/release%2F2/a.iso"
        );
        assert!(github_release_url("o/x", "r", "t", "a").is_err());
        assert!(github_release_url("o", "r", "", "a").is_err());
    }
}
