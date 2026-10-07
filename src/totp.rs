//! Optional TOTP second factor (TOTP_ENABLED): RFC 6238 codes (SHA-1, 30 s,
//! 6 digits, what authenticator apps expect), the secret sealed with
//! AES-256-GCM under TOTP_ENCRYPTION_KEY, single-use recovery codes, and a
//! server-rendered SVG QR code (no JavaScript).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::util::{os_random, sha256_hex};

pub const STEP_SECS: i64 = 30;
pub const DIGITS: u32 = 6;
pub const RECOVERY_CODES: usize = 10;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding (the form authenticator apps take).
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// A new 160-bit TOTP secret from the OS RNG.
pub fn new_secret() -> [u8; 20] {
    let mut s = [0u8; 20];
    os_random(&mut s);
    s
}

/// HOTP (RFC 4226) value for `counter`.
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac =
        <Hmac<Sha1> as hmac::KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(DIGITS)
}

/// Checks a 6-digit code at `unix_time`, allowing one step of clock drift.
/// Returns the matched time step, which must be newer than `last_step`
/// (each code works once).
pub fn verify(secret: &[u8], code: &str, unix_time: i64, last_step: Option<i64>) -> Option<i64> {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let now = unix_time.div_euclid(STEP_SECS);
    (now - 1..=now + 1)
        .filter(|s| *s >= 0 && last_step.is_none_or(|l| *s > l))
        .find(|s| {
            crate::util::ct_eq(
                &format!("{:06}", hotp(secret, *s as u64)),
                &format!("{want:06}"),
            )
        })
}

/// `otpauth://` URI for authenticator apps.
pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let enc = |s: &str| crate::util::encode_path_segment(s);
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        enc(issuer),
        enc(account),
        base32_encode(secret),
        enc(issuer)
    )
}

/// The URI as an inline SVG QR code (rendered on the server).
pub fn qr_svg(uri: &str) -> String {
    match qrcode::QrCode::new(uri.as_bytes()) {
        Ok(code) => code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(220, 220)
            .dark_color(qrcode::render::svg::Color("#000000"))
            .light_color(qrcode::render::svg::Color("#ffffff"))
            .quiet_zone(true)
            .build()
            // Inline in HTML: drop the XML declaration.
            .split_once("<svg")
            .map(|(_, rest)| format!("<svg{rest}"))
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/// Seals `plain` as nonce (12 bytes) || AES-256-GCM ciphertext.
pub fn encrypt(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    let mut nonce = [0u8; 12];
    os_random(&mut nonce);
    let mut out = nonce.to_vec();
    out.extend(
        cipher
            .encrypt(&Nonce::from(nonce), plain)
            .expect("AES-GCM encryption of a small buffer cannot fail"),
    );
    out
}

/// Opens [`encrypt`]'s output; None if the key is wrong or data tampered.
pub fn decrypt(key: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 12 + 16 {
        return None;
    }
    let (nonce, ct) = sealed.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().ok()?;
    Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key))
        .decrypt(&Nonce::from(nonce), ct)
        .ok()
}

/// Ten fresh recovery codes, 80 bits each, shown as XXXX-XXXX-XXXX-XXXX.
pub fn new_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut b = [0u8; 10];
            os_random(&mut b);
            let s = base32_encode(&b);
            format!("{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16])
        })
        .collect()
}

/// What is stored for a recovery code: SHA-256 of its normalized form (the
/// codes carry 80 random bits, so a fast hash is enough).
pub fn recovery_hash(code: &str) -> String {
    let norm: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    sha256_hex(norm.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648_vectors() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238 appendix B (8 digits there; the last 6 digits here).
        let secret = b"12345678901234567890";
        for (t, code) in [
            (59, "287082"),
            (1111111109, "081804"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ] {
            assert_eq!(
                format!("{:06}", hotp(secret, (t / 30) as u64)),
                code,
                "t={t}"
            );
            assert!(verify(secret, code, t, None).is_some());
        }
    }

    #[test]
    fn verify_window_replay_and_format() {
        let secret = b"12345678901234567890";
        let code = format!("{:06}", hotp(secret, 1000));
        assert_eq!(verify(secret, &code, 1000 * 30, None), Some(1000));
        assert_eq!(
            verify(secret, &code, 1001 * 30, None),
            Some(1000),
            "one step of drift"
        );
        assert_eq!(verify(secret, &code, 1003 * 30, None), None, "too old");
        assert_eq!(
            verify(secret, &code, 1000 * 30, Some(1000)),
            None,
            "replayed"
        );
        assert_eq!(verify(secret, "12345", 1000 * 30, None), None);
        assert_eq!(verify(secret, "abcdef", 1000 * 30, None), None);
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert_eq!(verify(secret, &spaced, 1000 * 30, None), Some(1000));
    }

    #[test]
    fn encryption_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let sealed = encrypt(&key, b"secret");
        assert_eq!(decrypt(&key, &sealed).as_deref(), Some(&b"secret"[..]));
        assert_ne!(encrypt(&key, b"secret"), sealed, "random nonce");
        assert!(decrypt(&[8u8; 32], &sealed).is_none(), "wrong key");
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(decrypt(&key, &bad).is_none(), "tampered");
        assert!(decrypt(&key, b"short").is_none());
    }

    #[test]
    fn recovery_codes_and_qr() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert!(codes.iter().all(|c| c.len() == 19));
        assert_eq!(
            recovery_hash(&codes[0]),
            recovery_hash(&codes[0].to_lowercase().replace('-', " "))
        );
        let uri = otpauth_uri("My Site", "admin", b"12345678901234567890");
        assert!(uri.starts_with("otpauth://totp/My%20Site:admin?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=My%20Site"));
        let svg = qr_svg(&uri);
        assert!(svg.starts_with("<svg") && !svg.contains("<script") && !svg.contains("<?xml"));
    }
}
