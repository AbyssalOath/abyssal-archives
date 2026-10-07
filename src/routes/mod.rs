//! Router assembly and cross-cutting middleware (logging, security headers,
//! themed error pages).

pub mod account;
pub mod admin;
pub mod auth;
pub mod members;
pub mod public;
pub mod storage;

use std::net::SocketAddr;

use askama::Template;
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::error::ErrorPage;
use crate::guard;
use crate::net::{client_info, log_ip};
use crate::state::AppState;
use crate::views::Layout;

/// Request bodies outside the upload route (all forms are small).
pub const BODY_LIMIT: usize = 64 * 1024;

/// No script, font or connection sources at all (zero JavaScript), images
/// only from this origin (remote images would leak visitors' IPs).
const CSP: &str = "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'none'; \
                   connect-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Every browser feature off.
const PERMISSIONS_POLICY: &str = "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), \
     bluetooth=(), browsing-topics=(), camera=(), display-capture=(), document-domain=(), \
     encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), \
     idle-detection=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), \
     picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), \
     usb=(), web-share=(), xr-spatial-tracking=()";

pub fn router(state: AppState) -> Router {
    let security_headers = [
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        // Account pages (admin, member, sign-in) override this with
        // `same-origin` (see guard::admin_gate) so their forms carry a real
        // Origin.
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::CONTENT_SECURITY_POLICY, CSP),
        (
            HeaderName::from_static("permissions-policy"),
            PERMISSIONS_POLICY,
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            "same-origin",
        ),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            "same-origin",
        ),
    ];

    // Layers wrap inside-out: the guards below error_pages get themed pages.
    let mut app = Router::new()
        .merge(public::routes())
        .merge(auth::routes())
        .merge(account::routes())
        .merge(admin::routes(&state.config))
        .merge(members::routes())
        .merge(storage::routes())
        .fallback(public::not_found)
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            guard::request_timeout,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            guard::origin_check,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            guard::admin_gate,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            guard::rate_limit,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), error_pages))
        .layer(middleware::from_fn_with_state(state.clone(), guard::hsts));
    for (name, value) in security_headers {
        app = app.layer(SetResponseHeaderLayer::if_not_present(
            name,
            HeaderValue::from_static(value),
        ));
    }
    let policy = state.config.security.proxy.clone();
    let ip_mode = state.config.security.log_ip_mode;
    app.layer(
        TraceLayer::new_for_http()
            .make_span_with(move |req: &Request<Body>| {
                let peer = req
                    .extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|c| c.0.ip())
                    .unwrap_or([127, 0, 0, 1].into());
                let client = log_ip(client_info(peer, req.headers(), &policy).ip, ip_mode);
                // Path only: never log query strings, headers or cookies.
                tracing::info_span!("http", method = %req.method(), path = %req.uri().path(), client = %client)
            })
            .on_response(DefaultOnResponse::new().level(Level::INFO)),
    )
    .with_state(state)
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    l: Layout,
    status: u16,
    reason: String,
    message: String,
}

/// Replaces responses marked with [`ErrorPage`] by a themed page.
async fn error_pages(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    let Some(page) = resp.extensions().get::<ErrorPage>().cloned() else {
        return resp;
    };
    let reason = page
        .status
        .canonical_reason()
        .unwrap_or("Error")
        .to_string();
    let t = ErrorTemplate {
        l: state.layout(reason.clone(), None),
        status: page.status.as_u16(),
        reason,
        message: page.message.clone(),
    };
    match t.render() {
        Ok(html) => {
            let (mut parts, _) = resp.into_parts();
            parts.headers.remove(header::CONTENT_LENGTH);
            parts.headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            Response::from_parts(parts, Body::from(html))
        }
        Err(e) => {
            tracing::error!(error = %e, "rendering error page failed");
            (page.status, page.message).into_response()
        }
    }
}
