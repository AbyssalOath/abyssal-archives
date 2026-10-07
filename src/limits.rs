//! Resource limits: connections (global / per IP), concurrent downloads
//! (global / per IP) and free disk space. All in memory, single instance.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::net::{Cidr, in_any};

/// Counts holders per IP; a permit decrements on drop.
#[derive(Default)]
struct PerIp {
    counts: Mutex<HashMap<IpAddr, usize>>,
}

impl PerIp {
    fn try_add(&self, ip: IpAddr, max: usize) -> bool {
        let mut map = self.counts.lock().unwrap();
        let n = map.entry(ip).or_insert(0);
        if *n >= max {
            return false;
        }
        *n += 1;
        true
    }

    fn remove(&self, ip: IpAddr) {
        let mut map = self.counts.lock().unwrap();
        if let Some(n) = map.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                map.remove(&ip);
            }
        }
    }
}

/// Held for the lifetime of a connection or a download.
pub struct Slot {
    _global: OwnedSemaphorePermit,
    per_ip: Option<(Arc<PerIpShared>, IpAddr)>,
}

/// Shared per-IP counter (Arc so slots can outlive the borrow).
pub struct PerIpShared(PerIp);

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some((counts, ip)) = &self.per_ip {
            counts.0.remove(*ip);
        }
    }
}

/// A global cap plus a per-IP cap. Addresses in `exempt` (trusted proxies,
/// which carry everyone's traffic) only count against the global cap.
pub struct Limiter {
    global: Arc<Semaphore>,
    per_ip: Arc<PerIpShared>,
    max_per_ip: usize,
    exempt: Vec<Cidr>,
}

impl Limiter {
    pub fn new(max_total: usize, max_per_ip: usize, exempt: Vec<Cidr>) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_total)),
            per_ip: Arc::new(PerIpShared(PerIp::default())),
            max_per_ip,
            exempt,
        }
    }

    /// A slot, or None when either limit is reached.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<Slot> {
        let global = self.global.clone().try_acquire_owned().ok()?;
        if in_any(&self.exempt, ip) {
            return Some(Slot {
                _global: global,
                per_ip: None,
            });
        }
        self.per_ip.0.try_add(ip, self.max_per_ip).then(|| Slot {
            _global: global,
            per_ip: Some((self.per_ip.clone(), ip)),
        })
    }
}

/// Bytes available to unprivileged users on the filesystem holding `path`.
pub fn available_bytes(path: &Path) -> std::io::Result<u64> {
    let s = rustix::fs::statvfs(path)?;
    Ok(s.f_bavail.saturating_mul(s.f_frsize))
}

/// Ok if storing `incoming` more bytes would still leave `reserve` free.
pub fn check_free_space(path: &Path, incoming: u64, reserve: u64) -> Result<(), String> {
    match available_bytes(path) {
        Ok(avail) if avail >= incoming.saturating_add(reserve) => Ok(()),
        Ok(avail) => Err(format!(
            "Not enough free space in storage: {} available, {} needed plus a {} reserve (STORAGE_MIN_FREE_BYTES).",
            crate::util::human_size(avail),
            crate::util::human_size(incoming),
            crate::util::human_size(reserve)
        )),
        Err(e) => Err(format!("Cannot check free space in storage: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::parse_cidr_list;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn per_ip_and_global_caps() {
        let l = Limiter::new(3, 2, parse_cidr_list("127.0.0.0/8").unwrap());
        let a1 = l.try_acquire(ip("203.0.113.1")).unwrap();
        let _a2 = l.try_acquire(ip("203.0.113.1")).unwrap();
        assert!(l.try_acquire(ip("203.0.113.1")).is_none(), "per-IP cap");
        let _b = l.try_acquire(ip("203.0.113.2")).unwrap();
        assert!(l.try_acquire(ip("203.0.113.3")).is_none(), "global cap");
        drop(a1);
        assert!(
            l.try_acquire(ip("203.0.113.1")).is_some(),
            "slot released on drop"
        );
    }

    #[test]
    fn trusted_proxies_only_count_globally() {
        let l = Limiter::new(10, 1, parse_cidr_list("127.0.0.0/8").unwrap());
        let held: Vec<_> = (0..5)
            .map(|_| l.try_acquire(ip("127.0.0.1")).unwrap())
            .collect();
        assert_eq!(held.len(), 5);
    }

    #[test]
    fn free_space_check() {
        let dir = tempfile::tempdir().unwrap();
        assert!(available_bytes(dir.path()).unwrap() > 0);
        assert!(check_free_space(dir.path(), 0, 0).is_ok());
        assert!(check_free_space(dir.path(), u64::MAX / 2, 0).is_err());
        assert!(check_free_space(Path::new("/definitely/not/here"), 0, 0).is_err());
    }
}
