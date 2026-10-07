//! Parsing of a single-range HTTP `Range: bytes=...` header (RFC 9110).

#[derive(Debug, PartialEq, Eq)]
pub enum RangeResult {
    /// No (usable) range: send the whole file with 200.
    Full,
    /// Send bytes `start..=end` with 206.
    Partial { start: u64, end: u64 },
    /// Range lies outside the file: 416.
    Unsatisfiable,
}

/// Longest Range header considered at all.
pub const MAX_RANGE_HEADER: usize = 200;

/// Interprets a Range header for an object of `size` bytes. Malformed
/// headers and other units are ignored (the whole file is sent), which RFC
/// 9110 permits. Multi-range requests and oversized headers are refused
/// (416): one range per request keeps range abuse cheap to serve.
pub fn parse_range(header: Option<&str>, size: u64) -> RangeResult {
    if header.is_some_and(|h| h.len() > MAX_RANGE_HEADER) {
        return RangeResult::Unsatisfiable;
    }
    let Some(spec) = header.and_then(|h| h.trim().strip_prefix("bytes=")) else {
        return RangeResult::Full;
    };
    if spec.contains(',') {
        return RangeResult::Unsatisfiable;
    }
    if size == 0 {
        return RangeResult::Full;
    }
    let Some((a, b)) = spec.trim().split_once('-') else {
        return RangeResult::Full;
    };
    let (a, b) = (a.trim(), b.trim());
    match (a.is_empty(), b.is_empty()) {
        // bytes=-N : the last N bytes
        (true, false) => match b.parse::<u64>() {
            Ok(0) => RangeResult::Unsatisfiable,
            Ok(n) => RangeResult::Partial {
                start: size.saturating_sub(n),
                end: size - 1,
            },
            Err(_) => RangeResult::Full,
        },
        // bytes=S- : from S to the end
        (false, true) => match a.parse::<u64>() {
            Ok(s) if s >= size => RangeResult::Unsatisfiable,
            Ok(s) => RangeResult::Partial {
                start: s,
                end: size - 1,
            },
            Err(_) => RangeResult::Full,
        },
        // bytes=S-E
        (false, false) => match (a.parse::<u64>(), b.parse::<u64>()) {
            (Ok(s), Ok(e)) if s > e => RangeResult::Full,
            (Ok(s), Ok(_)) if s >= size => RangeResult::Unsatisfiable,
            (Ok(s), Ok(e)) => RangeResult::Partial {
                start: s,
                end: e.min(size - 1),
            },
            _ => RangeResult::Full,
        },
        (true, true) => RangeResult::Full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use RangeResult::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range(None, 100), Full);
        assert_eq!(
            parse_range(Some("bytes=0-9"), 100),
            Partial { start: 0, end: 9 }
        );
        assert_eq!(
            parse_range(Some("bytes=90-"), 100),
            Partial { start: 90, end: 99 }
        );
        assert_eq!(
            parse_range(Some("bytes=-10"), 100),
            Partial { start: 90, end: 99 }
        );
        assert_eq!(
            parse_range(Some("bytes=-500"), 100),
            Partial { start: 0, end: 99 }
        );
        assert_eq!(
            parse_range(Some("bytes=50-5000"), 100),
            Partial { start: 50, end: 99 }
        );
        assert_eq!(parse_range(Some("bytes=100-"), 100), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=-0"), 100), Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=9-0"), 100), Full);
        assert_eq!(
            parse_range(Some("bytes=0-1,5-6"), 100),
            Unsatisfiable,
            "multi-range refused"
        );
        assert_eq!(
            parse_range(Some("bytes=0-0,1-1,2-2,3-3"), 100),
            Unsatisfiable
        );
        let long = format!("bytes=0-{}", "9".repeat(300));
        assert_eq!(
            parse_range(Some(&long), 100),
            Unsatisfiable,
            "oversized header"
        );
        assert_eq!(parse_range(Some("items=0-1"), 100), Full);
        assert_eq!(parse_range(Some("bytes=x-y"), 100), Full);
        assert_eq!(parse_range(Some("bytes=0-0"), 0), Full);
    }
}
