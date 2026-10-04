//! Portable libpcap (`.pcap`) reader and writer.
//!
//! Implemented by hand so offline replay, the test-suite, and the pcap generator
//! need no `libpcap` and work identically on Windows and Linux. Live capture uses
//! this only for file input; `ingressd-capture` does AF_PACKET separately.
//!
//! Supported: classic pcap with microsecond (magic `0xa1b2c3d4`) or nanosecond
//! (`0xa1b23c4d`) timestamps, either byte order.

use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Errors from reading or writing a pcap stream.
#[derive(Debug, thiserror::Error)]
pub enum PcapError {
    /// Underlying I/O error.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// The global header is not a recognised pcap magic.
    #[error("bad pcap magic: {0:#010x}")]
    BadMagic(u32),
    /// A truncated record.
    #[error("truncated record")]
    Truncated,
    /// The stream was opened for writing with a linktype we cannot represent.
    #[error("unsupported linktype {0}")]
    UnsupportedLinkType(u32),
}

/// DLT_EN10MB — Ethernet. This is the linktype ingressd writes and expects.
pub const LINKTYPE_ETHERNET: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ByteOrder {
    Big,
    Little,
}

impl ByteOrder {
    fn u32(self, b: [u8; 4]) -> u32 {
        match self {
            ByteOrder::Big => u32::from_be_bytes(b),
            ByteOrder::Little => u32::from_le_bytes(b),
        }
    }
    fn u16(self, b: [u8; 2]) -> u16 {
        match self {
            ByteOrder::Big => u16::from_be_bytes(b),
            ByteOrder::Little => u16::from_le_bytes(b),
        }
    }
}

/// A streaming pcap reader.
pub struct PcapReader<R: Read> {
    inner: R,
    order: ByteOrder,
    nano: bool,
    linktype: u32,
    snaplen: u32,
}

impl<R: Read> PcapReader<R> {
    /// Read and validate the global header, then be ready for records.
    pub fn new(mut inner: R) -> Result<Self, PcapError> {
        let mut hdr = [0u8; 24];
        read_exact_or_eof(&mut inner, &mut hdr)?.ok_or(PcapError::Truncated)?;
        let raw_magic = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let (order, nano) = match raw_magic {
            0xa1b2_c3d4 => (ByteOrder::Big, false),
            0xa1b2_3c4d => (ByteOrder::Big, true),
            0xd4c3_b2a1 => (ByteOrder::Little, false),
            0x4d3c_b2a1 => (ByteOrder::Little, true),
            other => return Err(PcapError::BadMagic(other)),
        };
        let _vmaj = order.u16([hdr[4], hdr[5]]);
        let _vmin = order.u16([hdr[6], hdr[7]]);
        let _thiszone = order.u32([hdr[8], hdr[9], hdr[10], hdr[11]]);
        let _sigfigs = order.u32([hdr[12], hdr[13], hdr[14], hdr[15]]);
        let snaplen = order.u32([hdr[16], hdr[17], hdr[18], hdr[19]]);
        let linktype = order.u32([hdr[20], hdr[21], hdr[22], hdr[23]]);
        Ok(PcapReader { inner, order, nano, linktype, snaplen })
    }

    /// Linktype of the file ([`LINKTYPE_ETHERNET`] for our writers).
    pub fn linktype(&self) -> u32 {
        self.linktype
    }

    /// Snaplen recorded in the header.
    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }

    /// Read the next record, or `None` at clean end-of-stream.
    pub fn next_packet(&mut self) -> Result<Option<(SystemTime, Vec<u8>)>, PcapError> {
        let mut rh = [0u8; 16];
        if read_exact_or_eof(&mut self.inner, &mut rh)?.is_none() {
            return Ok(None);
        }
        let ts_sec = self.order.u32([rh[0], rh[1], rh[2], rh[3]]);
        let ts_frac = self.order.u32([rh[4], rh[5], rh[6], rh[7]]);
        let incl_len = self.order.u32([rh[8], rh[9], rh[10], rh[11]]) as usize;
        let _orig_len = self.order.u32([rh[12], rh[13], rh[14], rh[15]]);

        // Guard against absurd lengths from a corrupt file.
        if incl_len > 268 * 1024 * 1024 {
            return Err(PcapError::Truncated);
        }
        let mut data = vec![0u8; incl_len];
        if incl_len > 0 && read_exact_or_eof(&mut self.inner, &mut data)?.is_none() {
            return Err(PcapError::Truncated);
        }

        let subsec = if self.nano {
            Duration::from_nanos(ts_frac as u64)
        } else {
            Duration::from_micros(ts_frac as u64)
        };
        let ts = UNIX_EPOCH + Duration::from_secs(ts_sec as u64) + subsec;
        Ok(Some((ts, data)))
    }
}

/// Read every packet in a stream into memory (used by replay and tests).
pub fn read_all<R: Read>(mut reader: R) -> Result<Vec<(SystemTime, Vec<u8>)>, PcapError> {
    let mut pr = PcapReader::new(&mut reader)?;
    let mut out = Vec::new();
    while let Some((ts, data)) = pr.next_packet()? {
        out.push((ts, data));
    }
    Ok(out)
}

/// A streaming pcap writer (little-endian, microsecond timestamps, ENET).
pub struct PcapWriter<W: Write> {
    inner: W,
}

impl<W: Write> PcapWriter<W> {
    /// Write the global header.
    pub fn new(mut inner: W) -> Result<Self, PcapError> {
        let hdr: [u8; 24] = [
            0xd4, 0xc3, 0xb2, 0xa1, // magic: little-endian, microseconds
            2, 0, 4, 0, // version 2.4
            0, 0, 0, 0, // thiszone
            0, 0, 0, 0, // sigfigs
            0xff, 0xff, 0, 0, // snaplen 65535
            1, 0, 0, 0, // network = LINKTYPE_ETHERNET
        ];
        inner.write_all(&hdr)?;
        Ok(PcapWriter { inner })
    }

    /// Write one packet.
    pub fn write_packet(&mut self, ts: SystemTime, data: &[u8]) -> Result<(), PcapError> {
        let (secs, micro) = split_time(ts);
        let len = data.len() as u32;
        let mut rh = [0u8; 16];
        rh[0..4].copy_from_slice(&secs.to_le_bytes());
        rh[4..8].copy_from_slice(&micro.to_le_bytes());
        rh[8..12].copy_from_slice(&len.to_le_bytes());
        rh[12..16].copy_from_slice(&len.to_le_bytes());
        self.inner.write_all(&rh)?;
        self.inner.write_all(data)?;
        Ok(())
    }

    /// Flush buffered bytes.
    pub fn flush(&mut self) -> Result<(), PcapError> {
        self.inner.flush()?;
        Ok(())
    }

    /// Finish and return the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

fn split_time(ts: SystemTime) -> (u32, u32) {
    let d = ts
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|e| e.duration()); // clamp pre-epoch to positive magnitude
    (d.as_secs() as u32, d.subsec_micros() as u32)
}

/// `read_exact` that distinguishes clean EOF-at-start (returns Ok(None)) from a
/// partial read mid-record (returns Err via io::Error).
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<Option<()>, PcapError> {
    if buf.is_empty() {
        return Ok(Some(()));
    }
    let mut filled = 0usize;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(None); // clean EOF at a record boundary
                }
                return Err(PcapError::Truncated);
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(PcapError::Io(e)),
        }
    }
    Ok(Some(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn roundtrip() {
        let ts = UNIX_EPOCH + Duration::new(1_700_000_000, 123_000_000);
        let frames: Vec<Vec<u8>> = vec![vec![1, 2, 3, 4], vec![9; 60], vec![]];
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        for f in &frames {
            w.write_packet(ts, f).unwrap();
        }
        let bytes = w.into_inner();

        let got = read_all(&bytes[..]).unwrap();
        assert_eq!(got.len(), frames.len());
        for (i, (t, data)) in got.iter().enumerate() {
            assert_eq!(data, &frames[i]);
            // 123 ms -> 123000 us
            assert_eq!(t.duration_since(ts).unwrap().as_micros(), 0);
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let bogus = [0u8; 24];
        assert!(PcapReader::new(&bogus[..]).is_err());
    }
}
