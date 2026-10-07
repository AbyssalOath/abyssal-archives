//! Checksum files in GNU coreutils format (`<hex>  <filename>\n`), generated
//! on the fly from the database so `sha256sum -c SHA256SUMS` works.

use crate::db::models::{FileRow, status};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    Sha256,
    Sha512,
}

impl Algo {
    /// The digest stored for `f`, if any (older rows may lack SHA-512).
    pub fn hash_of(self, f: &FileRow) -> Option<&str> {
        let h = match self {
            Algo::Sha256 => Some(f.sha256.as_str()),
            Algo::Sha512 => f.sha512.as_deref(),
        };
        h.filter(|h| !h.is_empty())
    }

    /// The command users verify with, e.g. `sha256sum -c SHA256SUMS`.
    pub fn verify_hint(self) -> &'static str {
        match self {
            Algo::Sha256 => "sha256sum -c SHA256SUMS",
            Algo::Sha512 => "sha512sum -c SHA512SUMS",
        }
    }
}

/// Makes a filename safe for a checksum line: no control characters (so no
/// newline or carriage return can start a forged line), no backslash (which
/// switches coreutils to escaped mode), and no leading `*` (binary-mode
/// marker) or whitespace. DB filenames are already sanitized; this is a
/// second, format-specific line of defense.
pub fn safe_sums_name(name: &str) -> String {
    let is_lead = |c: char| c == '*' || c.is_whitespace();
    let mapped: String = name
        .trim_start_matches(is_lead)
        .chars()
        .map(|c| if c.is_control() || c == '\\' { '_' } else { c })
        .collect();
    let trimmed = mapped.trim_start_matches(is_lead);
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.to_string()
    }
}

/// One `<hash>  <filename>\n` line.
pub fn sums_line(hash: &str, filename: &str) -> String {
    format!("{hash}  {}\n", safe_sums_name(filename))
}

/// A SUMS file for the ready files that have a digest for `algo`.
pub fn build_sums<'a>(files: impl IntoIterator<Item = &'a FileRow>, algo: Algo) -> String {
    files
        .into_iter()
        .filter(|f| f.status == status::READY)
        .filter_map(|f| algo.hash_of(f).map(|h| sums_line(h, &f.filename)))
        .collect()
}

/// Validates pasted ASCII armor (`kind` e.g. "PGP SIGNATURE") and returns
/// it normalized (LF line endings, trailing newline). Rejects anything that
/// is not plain printable ASCII between the BEGIN/END lines.
pub fn validate_armored(text: &str, kind: &str, max_len: usize) -> Result<String, String> {
    let norm = text.replace("\r\n", "\n").trim().to_string();
    if norm.len() > max_len {
        return Err(format!("Too long (at most {max_len} bytes)."));
    }
    let begin = format!("-----BEGIN {kind}-----");
    let end = format!("-----END {kind}-----");
    if !norm.starts_with(&begin) || !norm.ends_with(&end) {
        return Err(format!(
            "Paste the ASCII-armored block, from {begin} to {end}."
        ));
    }
    if !norm.chars().all(|c| c == '\n' || (' '..='~').contains(&c)) {
        return Err("Only plain ASCII text is accepted.".into());
    }
    if norm.matches("-----BEGIN ").count() != 1 {
        return Err("Paste exactly one block.".into());
    }
    Ok(format!("{norm}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, status: &str, sha512: Option<&str>) -> FileRow {
        FileRow {
            id: 1,
            release_id: 1,
            filename: name.into(),
            size_bytes: 1,
            sha256: "a".repeat(64),
            sha512: sha512.map(str::to_string),
            storage_backend: "local".into(),
            storage_key: "k".into(),
            download_count: 0,
            status: status.into(),
            error_message: None,
            torrent_infohash: None,
            created_at: chrono::NaiveDateTime::default(),
        }
    }

    #[test]
    fn armored_validation() {
        let sig = "-----BEGIN PGP SIGNATURE-----\r\n\r\niQEzBAABCAAdFiEE\r\n=abcd\r\n-----END PGP SIGNATURE-----\r\n";
        let ok = validate_armored(sig, "PGP SIGNATURE", 16384).unwrap();
        assert!(
            ok.starts_with("-----BEGIN PGP SIGNATURE-----\n")
                && ok.ends_with("-----END PGP SIGNATURE-----\n")
        );
        assert!(!ok.contains('\r'));
        assert!(validate_armored("hello", "PGP SIGNATURE", 16384).is_err());
        assert!(validate_armored(sig, "PGP PUBLIC KEY BLOCK", 16384).is_err());
        assert!(
            validate_armored(&sig.replace("abcd", "ab<script>"), "PGP SIGNATURE", 16384).is_ok(),
            "ASCII is fine; it is served as text/plain"
        );
        assert!(validate_armored(&sig.replace("abcd", "äb"), "PGP SIGNATURE", 16384).is_err());
        assert!(validate_armored(&format!("{sig}{sig}"), "PGP SIGNATURE", 16384).is_err());
        assert!(validate_armored(sig, "PGP SIGNATURE", 20).is_err());
    }

    #[test]
    fn line_format_is_gnu_compatible() {
        assert_eq!(sums_line("abc", "my file.iso"), "abc  my file.iso\n");
    }

    #[test]
    fn filename_edge_cases() {
        assert_eq!(safe_sums_name("cool distro (1).iso"), "cool distro (1).iso");
        assert_eq!(safe_sums_name("naïve-ünïcode.txt"), "naïve-ünïcode.txt");
        assert_eq!(
            safe_sums_name("a\nffff  /etc/passwd"),
            "a_ffff  /etc/passwd"
        );
        assert_eq!(safe_sums_name("x\r\ny"), "x__y");
        assert_eq!(safe_sums_name("*binary.iso"), "binary.iso");
        assert_eq!(safe_sums_name(" \t*  lead.iso"), "lead.iso");
        assert_eq!(safe_sums_name("back\\slash"), "back_slash");
        assert_eq!(safe_sums_name("***"), "file");
        assert_eq!(safe_sums_name(""), "file");
        // Every produced line is exactly one line.
        let line = sums_line("ab", "evil\nname\r");
        assert_eq!(line.matches('\n').count(), 1);
        assert!(!line.contains('\r'));
    }

    #[test]
    fn only_ready_files_with_the_digest_are_listed() {
        let files = [
            file("ready.iso", "ready", Some(&"b".repeat(128))),
            file("old.iso", "ready", None),
            file("importing.iso", "importing", Some("c")),
            file("hashing.iso", "hashing", Some("c")),
            file("failed.iso", "failed", Some("c")),
        ];
        let s256 = build_sums(&files, Algo::Sha256);
        assert_eq!(
            s256,
            format!("{a}  ready.iso\n{a}  old.iso\n", a = "a".repeat(64))
        );
        let s512 = build_sums(&files, Algo::Sha512);
        assert_eq!(s512, format!("{}  ready.iso\n", "b".repeat(128)));
        assert_eq!(build_sums(&[], Algo::Sha256), "");
    }
}
