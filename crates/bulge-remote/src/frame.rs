//! Length-prefixed frames (u16 big-endian length, then the bytes) — the unit
//! of both the relay control protocol and the end-to-end Noise messages.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// The largest frame (and the Noise message limit).
pub const MAX_FRAME: usize = 65535;

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, max: usize) -> Result<Vec<u8>, String> {
    read_frame_or_end(reader, max).await?.ok_or_else(|| "the connection closed".to_string())
}

/// Like [`read_frame`], but a close between frames is `Ok(None)`.
async fn read_frame_or_end<R: AsyncRead + Unpin>(reader: &mut R, max: usize) -> Result<Option<Vec<u8>>, String> {
    read_frame_io(reader, max).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::InvalidData => e.to_string(),
        _ => format!("read: {e}"),
    })
}

/// The frame reader with the I/O error kept, so a caller can tell the peer
/// going away from a broken frame. A close between frames is `Ok(None)`; an
/// oversized frame is `InvalidData`.
pub(crate) async fn read_frame_io<R: AsyncRead + Unpin>(reader: &mut R, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut first = [0u8; 1];
    if reader.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let second = reader.read_u8().await?;
    let len = usize::from(u16::from_be_bytes([first[0], second]));
    if len > max {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("frame of {len} bytes exceeds the {max}-byte limit")));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Whether a read failed because the other side went away (closed, reset,
/// or the connection was lost) rather than because of what it sent.
#[cfg(feature = "direct")]
pub(crate) fn is_gone(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, NotConnected};
    matches!(error.kind(), ConnectionReset | ConnectionAborted | NotConnected | BrokenPipe)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> Result<(), String> {
    let len = u16::try_from(bytes.len()).map_err(|_| format!("frame of {} bytes is too large", bytes.len()))?;
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    writer.write_all(&out).await.map_err(|e| format!("write: {e}"))?;
    writer.flush().await.map_err(|e| format!("write: {e}"))
}

/// Read frames on a task of their own, so callers can `select!` on them
/// without losing half-read frames when another branch wins. The channel
/// closes after the first error (which it delivers) or a clean close between
/// frames (which it does not: the receiver just sees the channel end).
pub fn spawn_reader<R: AsyncRead + Unpin + Send + 'static>(mut reader: R, max: usize) -> mpsc::Receiver<Result<Vec<u8>, String>> {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        loop {
            let frame = match read_frame_or_end(&mut reader, max).await {
                Ok(Some(frame)) => Ok(frame),
                Ok(None) => return,
                Err(error) => Err(error),
            };
            let failed = frame.is_err();
            if tx.send(frame).await.is_err() || failed {
                return;
            }
        }
    });
    rx
}

/// A message-oriented connection: whole frames in, whole frames out,
/// whatever carries them (the encrypted relay tunnel or a direct QUIC
/// stream). Both halves run on tasks of their own, so `recv` is cancel-safe.
pub struct Duplex {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Result<Vec<u8>, String>>,
}

impl Duplex {
    pub fn new(tx: mpsc::Sender<Vec<u8>>, rx: mpsc::Receiver<Result<Vec<u8>, String>>) -> Self {
        Self { tx, rx }
    }

    pub async fn send(&self, frame: Vec<u8>) -> Result<(), String> {
        self.tx.send(frame).await.map_err(|_| "the connection closed".to_string())
    }

    /// The next frame; `None` once the connection has closed cleanly.
    pub async fn recv(&mut self) -> Option<Result<Vec<u8>, String>> {
        self.rx.recv().await
    }

    /// The next frame within `wait`, with closes and timeouts as errors.
    pub async fn recv_within(&mut self, wait: std::time::Duration) -> Result<Vec<u8>, String> {
        match tokio::time::timeout(wait, self.rx.recv()).await {
            Ok(Some(frame)) => frame,
            Ok(None) => Err("the connection closed".into()),
            Err(_) => Err("timed out".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_and_oversize_is_refused() {
        let (mut a, mut b) = tokio::io::duplex(1 << 17);
        write_frame(&mut a, b"hello").await.unwrap();
        write_frame(&mut a, &[]).await.unwrap();
        write_frame(&mut a, &[7u8; 300]).await.unwrap();
        assert_eq!(read_frame(&mut b, 10).await.unwrap(), b"hello");
        assert_eq!(read_frame(&mut b, 10).await.unwrap(), b"");
        assert!(read_frame(&mut b, 10).await.unwrap_err().contains("exceeds"));
        assert!(write_frame(&mut a, &vec![0u8; MAX_FRAME + 1]).await.is_err());
    }

    #[tokio::test]
    async fn a_clean_close_ends_the_reader_but_a_torn_frame_is_an_error() {
        let (mut a, b) = tokio::io::duplex(1024);
        write_frame(&mut a, b"one").await.unwrap();
        drop(a);
        let mut frames = spawn_reader(b, 100);
        assert_eq!(frames.recv().await.unwrap().unwrap(), b"one");
        assert!(frames.recv().await.is_none());

        let (mut a, b) = tokio::io::duplex(1024);
        a.write_all(&[0, 9, 1, 2]).await.unwrap();
        drop(a);
        let mut frames = spawn_reader(b, 100);
        assert!(frames.recv().await.unwrap().is_err());
    }
}
