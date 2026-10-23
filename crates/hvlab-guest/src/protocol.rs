//! Length-prefixed JSON framing for the sidecar protocol (H-49).
//!
//! A frame is 4 bytes little-endian length followed by exactly that many
//! JSON bytes. Every read is bounded by [`MAX_FRAME_LEN`]; a malformed,
//! truncated, or oversized frame is an error, never salvaged.

use std::io::{Read, Write};

/// Maximum accepted frame payload: 16 MiB.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// A framing failure: the stream is desynchronized or oversized.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct FrameError(pub String);

fn write_all_fully<W: Write>(w: &mut W, mut buf: &[u8]) -> Result<(), FrameError> {
    while !buf.is_empty() {
        let n = w
            .write(buf)
            .map_err(|e| FrameError(format!("write failed: {e}")))?;
        if n == 0 {
            return Err(FrameError("write returned zero bytes".to_owned()));
        }
        buf = &buf[n..];
    }
    Ok(())
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), FrameError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r
            .read(&mut buf[filled..])
            .map_err(|e| FrameError(format!("read failed: {e}")))?;
        if n == 0 {
            return Err(FrameError("stream ended mid-frame".to_owned()));
        }
        filled += n;
    }
    Ok(())
}

/// Serialize `value` and write one framed message.
///
/// # Errors
/// [`FrameError`] on I/O failure, serialization failure, or a payload
/// exceeding [`MAX_FRAME_LEN`].
pub fn write_frame<W: Write, T: serde::Serialize>(w: &mut W, value: &T) -> Result<(), FrameError> {
    let json =
        serde_json::to_vec(value).map_err(|e| FrameError(format!("serialize failed: {e}")))?;
    let len =
        u32::try_from(json.len()).map_err(|_| FrameError("frame exceeds u32 length".to_owned()))?;
    if len > MAX_FRAME_LEN {
        return Err(FrameError(format!(
            "frame too large to write: {len} > {MAX_FRAME_LEN}"
        )));
    }
    write_all_fully(w, &len.to_le_bytes())?;
    write_all_fully(w, &json)
}

/// Read one length prefix and its JSON payload, deserializing into `T`.
///
/// # Errors
/// [`FrameError`] on stream end mid-frame, a length prefix above
/// [`MAX_FRAME_LEN`], or JSON that does not deserialize into `T`.
pub fn read_frame<R: Read, T: serde::de::DeserializeOwned>(r: &mut R) -> Result<T, FrameError> {
    let mut len_buf = [0u8; 4];
    read_exact(r, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(FrameError(format!(
            "frame length {len} exceeds cap {MAX_FRAME_LEN}"
        )));
    }
    let mut json = vec![0u8; len as usize];
    read_exact(r, &mut json)?;
    serde_json::from_slice(&json).map_err(|e| FrameError(format!("malformed frame: {e}")))
}
