//! In-memory rate limiting (single instance; resets on restart).
//!
//! * [`LoginLimiter`]: failed logins, tracked per client IP AND per username.
//!   After [`FREE_FAILURES`] failures each further failure doubles a lockout
//!   ([`BASE_LOCKOUT`] .. [`MAX_LOCKOUT`]). Per-username tracking stops a
//!   distributed guesser; the cap keeps a deliberate lockout of the admin short.
//! * [`SignupLimiter`]: account requests (/register) per client IP, with
//!   the same backoff: a few are free, then each one doubles the wait.
//! * [`RequestLimiter`]: a generous per-IP requests-per-minute budget for
//!   every route.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const FREE_FAILURES: u32 = 5;
pub const BASE_LOCKOUT: Duration = Duration::from_secs(30);
pub const MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Failure records older than this are forgotten.
const FORGET_AFTER: Duration = Duration::from_secs(24 * 3600);
const MAX_ENTRIES: usize = 50_000;

#[derive(Clone, Copy)]
struct Failures {
    count: u32,
    last: Instant,
    locked_until: Option<Instant>,
}

struct Backoff<K> {
    map: Mutex<HashMap<K, Failures>>,
}

impl<K: Hash + Eq + Clone> Backoff<K> {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Remaining lockout for `key`, if any.
    fn locked_for(&self, key: &K, now: Instant) -> Option<Duration> {
        let map = self.map.lock().unwrap();
        let until = map.get(key)?.locked_until?;
        (until > now).then(|| until - now)
    }

    fn fail(&self, key: &K, now: Instant) {
        let mut map = self.map.lock().unwrap();
        if map.len() > MAX_ENTRIES {
            map.retain(|_, f| now.duration_since(f.last) < FORGET_AFTER);
        }
        let entry = map.entry(key.clone()).or_insert(Failures {
            count: 0,
            last: now,
            locked_until: None,
        });
        if now.duration_since(entry.last) >= FORGET_AFTER {
            entry.count = 0;
        }
        entry.count += 1;
        entry.last = now;
        if entry.count >= FREE_FAILURES {
            let exp = (entry.count - FREE_FAILURES).min(16);
            let lock = BASE_LOCKOUT.saturating_mul(1 << exp).min(MAX_LOCKOUT);
            entry.locked_until = Some(now + lock);
        }
    }

    fn reset(&self, key: &K) {
        self.map.lock().unwrap().remove(key);
    }
}

/// Failed-login tracking per IP and per (lowercased) username.
pub struct LoginLimiter {
    by_ip: Backoff<IpAddr>,
    by_user: Backoff<String>,
}

impl Default for LoginLimiter {
    fn default() -> Self {
        Self {
            by_ip: Backoff::new(),
            by_user: Backoff::new(),
        }
    }
}

impl LoginLimiter {
    /// Ok, or how long the caller must wait before trying again.
    pub fn check(&self, ip: IpAddr, username: &str) -> Result<(), Duration> {
        self.check_at(ip, username, Instant::now())
    }

    pub fn record_failure(&self, ip: IpAddr, username: &str) {
        self.fail_at(ip, username, Instant::now());
    }

    pub fn reset(&self, ip: IpAddr, username: &str) {
        self.by_ip.reset(&ip);
        self.by_user.reset(&username.trim().to_lowercase());
    }

    fn check_at(&self, ip: IpAddr, username: &str, now: Instant) -> Result<(), Duration> {
        let user = username.trim().to_lowercase();
        let wait = [
            self.by_ip.locked_for(&ip, now),
            self.by_user.locked_for(&user, now),
        ]
        .into_iter()
        .flatten()
        .max();
        wait.map_or(Ok(()), Err)
    }

    fn fail_at(&self, ip: IpAddr, username: &str, now: Instant) {
        self.by_ip.fail(&ip, now);
        self.by_user.fail(&username.trim().to_lowercase(), now);
    }
}

/// Account requests per client IP.
pub struct SignupLimiter {
    by_ip: Backoff<IpAddr>,
}

impl Default for SignupLimiter {
    fn default() -> Self {
        Self {
            by_ip: Backoff::new(),
        }
    }
}

impl SignupLimiter {
    /// Ok, or how long this address must wait before the next request.
    pub fn check(&self, ip: IpAddr) -> Result<(), Duration> {
        self.by_ip
            .locked_for(&ip, Instant::now())
            .map_or(Ok(()), Err)
    }

    pub fn record(&self, ip: IpAddr) {
        self.by_ip.fail(&ip, Instant::now());
    }
}

/// Fixed one-minute window per client IP.
pub struct RequestLimiter {
    per_minute: u32,
    map: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RequestLimiter {
    /// `per_minute` = 0 disables the limit.
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    fn allow_at(&self, ip: IpAddr, now: Instant) -> bool {
        if self.per_minute == 0 {
            return true;
        }
        let window = Duration::from_secs(60);
        let mut map = self.map.lock().unwrap();
        if map.len() > MAX_ENTRIES {
            map.retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let entry = map.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.per_minute
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn exponential_backoff_per_ip() {
        let l = LoginLimiter::default();
        let t0 = Instant::now();
        for i in 0..FREE_FAILURES - 1 {
            assert!(l.check_at(ip("10.0.0.1"), &format!("u{i}"), t0).is_ok());
            l.fail_at(ip("10.0.0.1"), &format!("u{i}"), t0);
        }
        assert!(l.check_at(ip("10.0.0.1"), "x", t0).is_ok());
        l.fail_at(ip("10.0.0.1"), "x", t0); // 5th failure: 30 s lockout
        assert_eq!(l.check_at(ip("10.0.0.1"), "y", t0), Err(BASE_LOCKOUT));
        assert!(
            l.check_at(ip("10.0.0.2"), "y", t0).is_ok(),
            "other IPs unaffected"
        );
        let t1 = t0 + BASE_LOCKOUT;
        assert!(l.check_at(ip("10.0.0.1"), "y", t1).is_ok());
        l.fail_at(ip("10.0.0.1"), "z", t1); // 6th: 60 s
        assert_eq!(l.check_at(ip("10.0.0.1"), "y", t1), Err(BASE_LOCKOUT * 2));
        for _ in 0..20 {
            l.fail_at(ip("10.0.0.1"), "z", t1);
        }
        assert_eq!(
            l.check_at(ip("10.0.0.1"), "y", t1),
            Err(MAX_LOCKOUT),
            "capped"
        );
    }

    #[test]
    fn per_username_limit_stops_distributed_guessing() {
        let l = LoginLimiter::default();
        let t0 = Instant::now();
        for i in 0..FREE_FAILURES {
            l.fail_at(ip(&format!("198.51.100.{i}")), "Admin", t0);
        }
        // A fresh IP is still locked out for that username (case-insensitive)...
        assert!(l.check_at(ip("203.0.113.9"), "admin", t0).is_err());
        // ...but not for others.
        assert!(l.check_at(ip("203.0.113.9"), "someone", t0).is_ok());
        l.reset(ip("203.0.113.9"), "ADMIN");
        assert!(l.check_at(ip("203.0.113.9"), "admin", t0).is_ok());
    }

    #[test]
    fn request_limiter_window() {
        let r = RequestLimiter::new(3);
        let t0 = Instant::now();
        assert!((0..3).all(|_| r.allow_at(ip("10.0.0.1"), t0)));
        assert!(!r.allow_at(ip("10.0.0.1"), t0));
        assert!(r.allow_at(ip("10.0.0.2"), t0));
        assert!(r.allow_at(ip("10.0.0.1"), t0 + Duration::from_secs(60)));
        assert!((0..1000).all(|_| RequestLimiter::new(0).allow_at(ip("10.0.0.1"), t0)));
    }
}
