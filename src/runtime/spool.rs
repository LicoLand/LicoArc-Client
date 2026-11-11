//! The durable local inbox: deliveries land on disk before the ACK, and the
//! session side consumes them afterwards.
//!
//! Layout: `<spool>/<handle-b64>/<seq-hex>.packet` written owner-only and
//! fsync'd before the ACK, keyed by the Station's own delivery sequence —
//! a redelivery overwrites the same file. `EndpointSink`-side consumers
//! delete each file after the SDK commits it; permanently refused ones
//! move to `<handle-b64>/refused/`.

use std::path::{Path, PathBuf};

use crate::carrier::HandleToken;
use crate::providers::fs::write_atomic;

use super::mailbox::{PacketSink, Verdict};

/// A [`PacketSink`] that durably stores each delivery, then reports `Done`.
///
/// A failed write is local and transient — `Defer` keeps the packet stored
/// on the Station and stops the loop.
pub struct Spool {
    dir: PathBuf,
}

impl Spool {
    /// Creates the spool directory (owner-only) when absent.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        private_dir(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// The spool file for one delivery.
    #[must_use]
    pub fn path(&self, handle: HandleToken, sequence: u64) -> PathBuf {
        self.dir
            .join(handle.as_text())
            .join(format!("{sequence:016x}.packet"))
    }

    /// Every stored packet under one handle directory, ordered by sequence.
    pub fn stored(&self, handle: HandleToken) -> std::io::Result<Vec<(u64, PathBuf)>> {
        let mut items = vec![];
        let dir = self.dir.join(handle.as_text());
        if !dir.is_dir() {
            return Ok(items);
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().unwrap_or_default();
            if let Some(hex) = name.strip_suffix(".packet")
                && let Ok(sequence) = u64::from_str_radix(hex, 16)
            {
                items.push((sequence, entry.path()));
            }
        }
        items.sort_by_key(|(sequence, _)| *sequence);
        Ok(items)
    }

    /// Marks one stored file consumed (delete) or refused (`refused/`).
    pub fn resolve(&self, path: &Path, refused: bool) -> std::io::Result<()> {
        if refused {
            let refused_dir = path.parent().unwrap_or(self.dir.as_path()).join("refused");
            private_dir(&refused_dir)?;
            if let Some(name) = path.file_name() {
                std::fs::rename(path, refused_dir.join(name))?;
            }
        } else {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

impl PacketSink for Spool {
    fn accept(&mut self, sequence: u64, handle: HandleToken, packet: &[u8]) -> Verdict {
        let dir = self.dir.join(handle.as_text());
        if private_dir(&dir).is_err() {
            return Verdict::Defer;
        }
        let path = dir.join(format!("{sequence:016x}.packet"));
        match write_atomic(&path, packet) {
            Ok(()) => Verdict::Done,
            Err(_) => Verdict::Defer,
        }
    }
}

fn private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
