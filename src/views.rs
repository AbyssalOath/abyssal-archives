//! Shared template plumbing. Every page template has an `l: Layout` field
//! that `templates/base.html` reads, so the site name (and everything else
//! in the header and footer) comes from AppState, never from a template.

use askama::Template;
use axum::response::{Html, IntoResponse, Response};
use chrono::Datelike;

use crate::error::AppError;
use crate::routes::auth::Actor;
use crate::settings::SiteSettings;
use crate::state::AppState;

pub struct Layout {
    pub site: SiteSettings,
    /// Page title; the site name is appended by the base template.
    pub title: String,
    pub css_version: String,
    pub year: i32,
    /// Present when signed in: the admin or member nav and sign-out form.
    pub nav: Option<Nav>,
    /// Seconds for a `<meta http-equiv="refresh">` (no JavaScript).
    pub refresh: Option<u32>,
    /// Show the 2FA page link (TOTP_ENABLED).
    pub totp_enabled: bool,
}

impl Layout {
    /// The session CSRF token for forms (empty on public pages).
    pub fn csrf(&self) -> &str {
        self.nav
            .as_ref()
            .map(|n| n.csrf.as_str())
            .unwrap_or_default()
    }

    /// Workspace URL prefix: "/admin" or "/my" ("" on public pages).
    pub fn base(&self) -> &'static str {
        self.nav.as_ref().map(|n| n.base).unwrap_or_default()
    }

    pub fn is_admin(&self) -> bool {
        self.nav.as_ref().is_some_and(|n| n.is_admin)
    }
}

pub struct Nav {
    pub username: String,
    pub csrf: String,
    pub is_admin: bool,
    pub base: &'static str,
}

impl AppState {
    pub fn layout(&self, title: impl Into<String>, user: Option<&Actor>) -> Layout {
        Layout {
            site: self.site(),
            title: title.into(),
            css_version: self.css_version.to_string(),
            year: chrono::Utc::now().year(),
            nav: user.map(|u| Nav {
                username: u.username.clone(),
                csrf: u.csrf.clone(),
                is_admin: u.is_admin,
                base: u.base(),
            }),
            refresh: None,
            totp_enabled: self.config.security.totp_enabled,
        }
    }
}

/// Renders a template into an HTML response.
pub fn render(t: &impl Template) -> Result<Response, AppError> {
    Ok(Html(t.render()?).into_response())
}
