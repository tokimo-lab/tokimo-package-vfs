use std::{io, path::PathBuf, sync::Arc};

use crate::driver::traits::Reader;

/// Unified synchronous random-read function type.
///
/// `(offset, max_bytes) → Ok(Vec<u8>)` — may return fewer bytes at EOF.
/// Empty Vec signals end-of-file.
///
/// This is the single canonical type used across the entire codebase for
/// synchronous positional reads (FFmpeg AVIO, Matroska Cues parsing, etc.).
pub type ReadAt = Arc<dyn Fn(u64, usize) -> io::Result<Vec<u8>> + Send + Sync>;

/// Bridge any async [`Reader`] + path into a synchronous [`ReadAt`] closure.
///
/// Internally captures `tokio::runtime::Handle::current()` and calls
/// `handle.block_on(reader.read_bytes(...))`.
///
/// # Panics
///
/// Must be called from within a Tokio runtime context (the returned closure
/// uses `block_on`, which panics on tokio worker threads — callers must invoke
/// the closure from a blocking thread or a non-tokio thread).
pub fn make_sync_reader<R: Reader + 'static>(reader: Arc<R>, path: impl Into<PathBuf>) -> ReadAt {
    let handle = tokio::runtime::Handle::current();
    let path: PathBuf = path.into();
    Arc::new(move |offset: u64, size: usize| {
        let reader = reader.clone();
        let path = path.clone();
        handle
            .block_on(reader.read_bytes(&path, offset, Some(size as u64)))
            .map_err(|e| io::Error::other(e.to_string()))
    })
}
