//! .torrent generation: STUB. The signature is fixed so the route and config
//! can be wired up; see docs/TORRENTS.md for the plan (single-file torrents,
//! streamed SHA-1 piece hashes, trackers from TORRENT_TRACKERS, and a BEP 19
//! web seed pointing at this server's download URL).

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum TorrentError {
    #[error("torrent generation is not implemented yet")]
    NotImplemented,
}

/// Builds a single-file `.torrent` (bencoded metainfo) for `file_path`.
///
/// * `name` - the file name advertised in the torrent (the sanitized DB name)
/// * `piece_length` - bytes per piece (power of two, TORRENT_PIECE_LENGTH)
/// * `trackers` - announce URLs (TORRENT_TRACKERS); the first becomes
///   `announce`, all go into `announce-list`
/// * `web_seeds` - BEP 19 `url-list` entries, normally the file's absolute
///   HTTP download URL from `AppState::download_url_for_torrent`
///
/// Returns the bencoded bytes. Currently always `TorrentError::NotImplemented`.
pub fn generate_torrent(
    file_path: &Path,
    name: &str,
    piece_length: u64,
    trackers: &[String],
    web_seeds: &[String],
) -> Result<Vec<u8>, TorrentError> {
    let _ = (file_path, name, piece_length, trackers, web_seeds);
    Err(TorrentError::NotImplemented)
}
