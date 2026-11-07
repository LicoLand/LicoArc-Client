//! A wall-clock [`Clock`] for standalone CLI operation.

use crate::ports::{Clock, PortFailure};

/// Reads the host wall clock.
///
/// The SDK uses this for prekey validity windows; the caller owns the fact.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> Result<u64, PortFailure> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| PortFailure::Unavailable)
    }
}
