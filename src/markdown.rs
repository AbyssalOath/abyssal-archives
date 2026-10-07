//! Markdown to sanitized HTML for project descriptions and release notes.
//!
//! Two layers: raw HTML in the Markdown is turned into visible text before
//! rendering (no HTML pass-through at all), then ammonia cleans the result
//! with an explicit allowlist: no scripts, styles, event handlers, forms or
//! frames; links only to http/https/mailto with rel="noopener noreferrer
//! nofollow"; images only from this site (remote images would leak
//! visitors' IP addresses to third parties).

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use pulldown_cmark::{CowStr, Event, Options, Parser, html};

/// True for a same-origin path such as `/static/x.png` (not `//host/x`).
fn same_origin_path(url: &str) -> bool {
    url.starts_with('/') && !url.starts_with("//") && !url.contains('\\')
}

fn cleaner() -> &'static ammonia::Builder<'static> {
    static CLEANER: OnceLock<ammonia::Builder<'static>> = OnceLock::new();
    CLEANER.get_or_init(|| {
        let tags: HashSet<&str> = [
            "a",
            "blockquote",
            "br",
            "code",
            "del",
            "div",
            "em",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "hr",
            "img",
            "input",
            "li",
            "ol",
            "p",
            "pre",
            "strong",
            "sup",
            "table",
            "tbody",
            "td",
            "th",
            "thead",
            "tr",
            "ul",
        ]
        .into_iter()
        .collect();
        let attrs: HashMap<&str, HashSet<&str>> = HashMap::from([
            ("a", HashSet::from(["href", "title"])),
            ("img", HashSet::from(["src", "alt", "title"])),
            ("input", HashSet::from(["type", "checked", "disabled"])),
            ("ol", HashSet::from(["start"])),
        ]);
        let mut b = ammonia::Builder::empty();
        b.tags(tags)
            .tag_attributes(attrs)
            .url_schemes(HashSet::from(["http", "https", "mailto"]))
            .url_relative(ammonia::UrlRelative::PassThrough)
            .link_rel(Some("noopener noreferrer nofollow"))
            .attribute_filter(|element, attribute, value| match (element, attribute) {
                // Same-origin images only.
                ("img", "src") => same_origin_path(value).then(|| value.into()),
                // Task-list checkboxes only.
                ("input", "type") => (value == "checkbox").then(|| value.into()),
                _ => Some(value.into()),
            });
        b
    })
}

/// Renders Markdown to safe HTML.
pub fn render(md: &str) -> String {
    let opts = Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_FOOTNOTES;
    // Raw HTML becomes literal text (escaped by the HTML writer).
    let events = Parser::new_ext(md, opts).map(|e| match e {
        Event::Html(s) | Event::InlineHtml(s) => Event::Text(CowStr::from(s.into_string())),
        other => other,
    });
    let mut out = String::new();
    html::push_html(&mut out, events);
    cleaner().clean(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_basic_markdown() {
        let html =
            render("# Hi\n\n**bold** and `code`\n\n- [x] done\n\n| a | b |\n|---|---|\n| 1 | 2 |");
        assert!(html.contains("<h1>Hi</h1>"));
        assert!(html.contains("<strong>bold</strong>"));
        assert!(html.contains("<code>code</code>"));
        assert!(html.contains("<table>"));
        assert!(html.contains("type=\"checkbox\""));
    }

    #[test]
    fn raw_html_is_shown_as_text_never_executed() {
        for (input, forbidden) in [
            ("<script>alert(1)</script>", "<script"),
            ("<img src=x onerror=alert(1)>", "<img"),
            ("<iframe src=https://evil.example></iframe>", "<iframe"),
            ("<svg onload=alert(1)>", "<svg"),
            ("<a href=\"javascript:alert(1)\">x</a>", "<a "),
            ("<style>body{display:none}</style>", "<style"),
            (
                "<form action=https://evil.example><input name=p></form>",
                "<form",
            ),
            ("<details open ontoggle=alert(1)>", "<details"),
        ] {
            let html = render(input);
            assert!(!html.contains(forbidden), "{input} -> {html}");
            assert!(
                !html.contains("onerror=") && !html.contains("onload=\"") || html.contains("&lt;"),
                "{html}"
            );
        }
        assert!(render("<b>x</b>").contains("&lt;b&gt;x&lt;/b&gt;"));
    }

    #[test]
    fn dangerous_urls_are_dropped() {
        for md in [
            "[x](javascript:alert(1))",
            "[x](JaVaScRiPt:alert(1))",
            "[x](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)",
            "[x](vbscript:msgbox(1))",
        ] {
            let html = render(md);
            assert!(
                !html.to_lowercase().contains("script:") && !html.contains("data:"),
                "{md} -> {html}"
            );
        }
    }

    #[test]
    fn links_get_nofollow_and_remote_images_are_blocked() {
        let html = render("[site](https://example.org/x)");
        assert!(html.contains("href=\"https://example.org/x\""));
        assert!(html.contains("rel=\"noopener noreferrer nofollow\""));
        for remote in [
            "![t](https://tracker.example/pixel.gif)",
            "![t](//tracker.example/pixel.gif)",
            "![t](http://192.168.1.1/x.png)",
            "![t](data:image/png;base64,AAAA)",
        ] {
            assert!(!render(remote).contains("src="), "{remote}");
        }
        assert!(render("![logo](/static/logo.png)").contains("src=\"/static/logo.png\""));
    }
}
