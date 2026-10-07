//! Cross-cutting request guards (middleware): per-IP rate limiting, the
//! admin surface gate (ADMIN_HOST / ADMIN_ALLOWED_CIDRS), no-store on
//! account pages, the Origin check on state-changing requests, request
//! timeouts, and HSTS.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::AppError;
use crate::net::{ClientInfo, client_info, in_any, log_ip};
use crate::state::AppState;

/// The admin area: only on ADMIN_HOST / from ADMIN_ALLOWED_CIDRS (when set).
pub fn is_admin_path(path: &str) -> bool {
    path == "/admin" || path.starts_with("/admin/")
}

/// Paths only served where [`admin_access_allowed`]: the admin area, and
/// /setup (it creates the administrator, so it must not be raced from
/// outside the allowed hosts / networks).
pub fn is_admin_gated(path: &str) -> bool {
    is_admin_path(path) || path == "/setup"
}

/// The member workspace.
pub fn is_member_path(path: &str) -> bool {
    path == "/my" || path.starts_with("/my/")
}

/// Pages with accounts and forms (admin, member area, sign-in, setup,
/// registration): never cached, `Referrer-Policy: same-origin`.
pub fn is_private_path(path: &str) -> bool {
    is_admin_path(path)
        || is_member_path(path)
        || path == "/login"
        || path.starts_with("/login/")
        || path == "/logout"
        || path == "/setup"
        || path == "/register"
}

/// True if an administrator may use this request: it arrived on ADMIN_HOST
/// (when set) from an address in ADMIN_ALLOWED_CIDRS (when set). Applies to
/// the /admin pages and to signing in as an administrator.
pub fn admin_access_allowed(
    st: &AppState,
    client_ip: std::net::IpAddr,
    headers: &HeaderMap,
) -> bool {
    let sec = &st.config.security;
    if let Some(admin_host) = &sec.admin_host
        && request_host(headers).as_deref() != Some(admin_host.as_str())
    {
        return false;
    }
    sec.admin_allowed_cidrs.is_empty() || in_any(&sec.admin_allowed_cidrs, client_ip)
}

fn client(st: &AppState, req: &Request) -> ClientInfo {
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or([127, 0, 0, 1].into());
    client_info(peer, req.headers(), &st.config.security.proxy)
}

/// Host header without port, lowercased, no trailing dot.
fn request_host(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let host = if host.starts_with('[') {
        host.split(']').next().map(|h| format!("{h}]"))?
    } else {
        host.split(':').next()?.to_string()
    };
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

/// Per-IP request budget on every route except health checks and CSS.
pub async fn rate_limit(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path != "/healthz" && !path.starts_with("/static/") {
        let c = client(&st, &req);
        if !st.request_limiter.allow(c.ip) {
            tracing::warn!(client = %log_ip(c.ip, st.config.security.log_ip_mode), "request rate limit hit");
            return AppError::TooManyRequests(
                "Too many requests. Please slow down and try again in a minute.".into(),
            )
            .into_response();
        }
    }
    next.run(req).await
}

/// The admin area and /setup are 404 unless [`admin_access_allowed`];
/// account pages (see [`is_private_path`]) are never cached.
pub async fn admin_gate(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if !is_private_path(path) {
        return next.run(req).await;
    }
    if is_admin_gated(path) && !admin_access_allowed(&st, client(&st, &req).ip, req.headers()) {
        return AppError::NotFound.into_response();
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    // These pages hold the forms. Under the site-wide `no-referrer`, browsers
    // submit forms with `Origin: null` and no Referer, which origin_check
    // must refuse. `same-origin` sends the real origin to this site only and
    // still nothing to other sites (public pages keep `no-referrer`).
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    resp
}

/// scheme://host[:port] of an absolute URL.
fn origin_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    let origin = u.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// True if a state-changing request is same-origin: its Origin (or, if
/// absent, its Referer's origin) is PUBLIC_URL's origin, the ADMIN_HOST
/// origin, or equals the request's own Host. Requests carrying neither
/// header are refused.
pub fn origin_allowed(
    headers: &HeaderMap,
    public_url: Option<&str>,
    admin_host: Option<&str>,
) -> bool {
    let text = |name| {
        headers
            .get(name)
            .and_then(|v: &HeaderValue| v.to_str().ok())
    };
    let Some(origin) = text(header::ORIGIN)
        .filter(|o| *o != "null")
        .and_then(origin_of)
        .or_else(|| text(header::REFERER).and_then(origin_of))
    else {
        return false;
    };
    if let Some(public) = public_url.and_then(origin_of) {
        if origin == public {
            return true;
        }
        if let (Some(admin), Ok(public)) = (admin_host, url::Url::parse(&public))
            && origin == format!("{}://{}", public.scheme(), admin)
        {
            return true;
        }
    }
    // Same-origin by Host: the browser sets Host to our address, so a
    // cross-site page cannot make Origin match it.
    let Some(host) = text(header::HOST) else {
        return false;
    };
    url::Url::parse(&origin)
        .ok()
        .and_then(|u| {
            let authority = match u.port() {
                Some(p) => format!("{}:{p}", u.host_str()?),
                None => u.host_str()?.to_string(),
            };
            Some(authority.eq_ignore_ascii_case(host))
        })
        .unwrap_or(false)
}

/// Refuses cross-site POSTs (on top of the per-session CSRF tokens).
pub async fn origin_check(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe
        && !origin_allowed(
            req.headers(),
            st.config.public_url.as_deref(),
            st.config.security.admin_host.as_deref(),
        )
    {
        return AppError::Forbidden(
            "This form was submitted from another site (or your browser sent no Origin header) and was refused."
                .into(),
        )
        .into_response();
    }
    next.run(req).await
}

/// Time limit for producing a response (downloads and uploads stream for
/// as long as they need and are exempt).
pub async fn request_timeout(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path.starts_with("/download/") || path.ends_with("/upload") {
        return next.run(req).await;
    }
    match tokio::time::timeout(st.config.security.request_timeout, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => {
            AppError::ServiceUnavailable("The request took too long. Please try again.".into())
                .into_response()
        }
    }
}

/// HSTS, opt-in (HSTS_ENABLED), and only when cookies are Secure and a
/// trusted proxy says the request arrived over HTTPS.
pub async fn hsts(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let sec = &st.config.security;
    let send = sec.hsts_enabled && st.config.cookie_secure && client(&st, &req).https;
    let mut resp = next.run(req).await;
    if send {
        let value = if sec.hsts_include_subdomains {
            "max-age=31536000; includeSubDomains"
        } else {
            "max-age=31536000"
        };
        resp.headers_mut().insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(value),
        );
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(*k, v.parse().unwrap());
        }
        m
    }

    const PUBLIC: Option<&str> = Some("https://files.example.com");

    #[test]
    fn origin_rules() {
        let ok = |pairs, admin| origin_allowed(&h(pairs), PUBLIC, admin);
        assert!(ok(&[("origin", "https://files.example.com")], None));
        assert!(ok(
            &[("referer", "https://files.example.com/admin/projects")],
            None
        ));
        assert!(!ok(&[("origin", "https://evil.example")], None));
        assert!(
            !ok(&[("origin", "http://files.example.com")], None),
            "scheme matters"
        );
        assert!(!ok(&[("referer", "https://evil.example/x")], None));
        assert!(!ok(&[], None), "no Origin and no Referer");
        assert!(!ok(&[("origin", "null")], None));
        assert!(ok(
            &[("origin", "https://admin.example.com")],
            Some("admin.example.com")
        ));
        assert!(!ok(&[("origin", "https://admin.example.com")], None));
        // Same-origin by Host (PUBLIC_URL not matching how the site is reached).
        assert!(ok(
            &[
                ("origin", "http://192.168.1.10:8081"),
                ("host", "192.168.1.10:8081")
            ],
            None
        ));
        assert!(!ok(
            &[
                ("origin", "http://evil.example:8081"),
                ("host", "192.168.1.10:8081")
            ],
            None
        ));
        // A null Origin cannot be rescued by a Referer from elsewhere.
        assert!(!ok(
            &[("origin", "null"), ("referer", "https://evil.example/")],
            None
        ));
    }

    #[test]
    fn admin_paths() {
        for p in ["/admin", "/admin/projects", "/admin/users"] {
            assert!(is_admin_path(p), "{p}");
            assert!(is_private_path(p), "{p}");
        }
        for p in [
            "/login",
            "/login/2fa",
            "/logout",
            "/setup",
            "/register",
            "/my",
            "/my/projects",
        ] {
            assert!(!is_admin_path(p), "{p}");
            assert!(is_private_path(p), "{p}");
        }
        for p in [
            "/",
            "/p/x",
            "/download/1",
            "/administrator",
            "/loginx",
            "/mystuff",
            "/registers",
            "/static/style.css",
        ] {
            assert!(!is_admin_path(p), "{p}");
            assert!(!is_private_path(p), "{p}");
        }
    }

    #[test]
    fn host_parsing() {
        assert_eq!(
            request_host(&h(&[("host", "Admin.Example.com.:443")])).as_deref(),
            Some("admin.example.com")
        );
        assert_eq!(
            request_host(&h(&[("host", "[::1]:8080")])).as_deref(),
            Some("[::1]")
        );
        assert_eq!(request_host(&HeaderMap::new()), None);
    }
}
