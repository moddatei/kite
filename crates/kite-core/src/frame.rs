//! Zero-allocation, high-throughput wire framing for the Kite protocol.
//!
//! ### Wire Layout Specification (28 bytes minimum header + payload + CRC32):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Version (1)  |Frame Type (1) |   Flags (1)   |    TTL (1)    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Source Address (8)                      |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Destination Address (8)                    |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |        Sequence (2)           |       Payload Length (2)      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Payload (Variable)                     |
//! |                               ...                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        CRC32 Checksum (4)                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::error::{Error, Result};
use crate::identity::NodeAddress;
use crate::PROTOCOL_VERSION;
use crc32fast::Hasher as CrcHasher;

/// Minimum valid frame size with zero payload (Header: 24 bytes + CRC32: 4 bytes).
pub const MIN_FRAME_SIZE: usize = 28;

/// Maximum transmission unit size for over-the-air raw frame encapsulation.
pub const MAX_FRAME_SIZE: usize = 512;

/// Maximum payload capacity per individual unfragmented frame.
pub const MAX_PAYLOAD_SIZE: usize = MAX_FRAME_SIZE - MIN_FRAME_SIZE;

/// Default Time-To-Live (hop count limit) for opportunistic dissemination.
pub const DEFAULT_TTL: u8 = 7;

/// Type classification for over-the-air Kite frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// Neighbor discovery and presence announcement.
    Beacon = 0x01,
    /// Encrypted or plaintext payload data.
    Data = 0x02,
    /// Selective hop-by-hop acknowledgment.
    Ack = 0x03,
    /// Epidemic routing digest and bloom filter gossip.
    GossipDigest = 0x04,
    /// Cryptographic Noise_XX ephemeral handshake message.
    Handshake = 0x05,
}

impl FrameType {
    /// Parse from raw byte.
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(FrameType::Beacon),
            0x02 => Ok(FrameType::Data),
            0x03 => Ok(FrameType::Ack),
            0x04 => Ok(FrameType::GossipDigest),
            0x05 => Ok(FrameType::Handshake),
            other => Err(Error::InvalidFrameType(other)),
        }
    }

    /// Convert to wire byte representation.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Bitfield flags modifying frame behavior and processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameFlags(pub u8);

impl FrameFlags {
    /// Payload is encrypted with active session cipher.
    pub const ENCRYPTED: u8 = 0b0000_0001;
    /// Frame is high-priority and should bypass standard delay queues.
    pub const URGENT: u8 = 0b0000_0010;
    /// Opportunistic relaying requested across air-gapped nodes.
    pub const STORE_AND_FORWARD: u8 = 0b0000_0100;
    /// Frame represents a diagnostic telemetry probe.
    pub const PROBE: u8 = 0b0000_1000;

    /// Construct new flag set.
    pub const fn new(flags: u8) -> Self {
        Self(flags)
    }

    /// Check if a specific bit flag is set.
    pub const fn contains(&self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }

    /// Set or unset a specific flag.
    pub fn set(&mut self, flag: u8, value: bool) {
        if value {
            self.0 |= flag;
        } else {
            self.0 &= !flag;
        }
    }
}

/// Zero-copy parsed view of a wire-level Kite frame referencing memory directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KiteFrame<'a> {
    pub version: u8,
    pub frame_type: FrameType,
    pub flags: FrameFlags,
    pub ttl: u8,
    pub src: NodeAddress,
    pub dst: NodeAddress,
    pub seq: u16,
    pub payload: &'a [u8],
}

impl<'a> KiteFrame<'a> {
    /// Parse a raw byte slice into a zero-copy `KiteFrame`.
    ///
    /// Validates protocol version, length markers, and CRC32 integrity.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        if buf.len() < MIN_FRAME_SIZE {
            return Err(Error::BufferTooShort);
        }

        let version = buf[0];
        if version != PROTOCOL_VERSION {
            return Err(Error::InvalidProtocolVersion(version));
        }

        let frame_type = FrameType::from_u8(buf[1])?;
        let flags = FrameFlags::new(buf[2]);
        let ttl = buf[3];

        let mut src_bytes = [0u8; 8];
        src_bytes.copy_from_slice(&buf[4..12]);
        let src = NodeAddress::from_bytes(src_bytes);

        let mut dst_bytes = [0u8; 8];
        dst_bytes.copy_from_slice(&buf[12..20]);
        let dst = NodeAddress::from_bytes(dst_bytes);

        let seq = u16::from_be_bytes([buf[20], buf[21]]);
        let payload_len = u16::from_be_bytes([buf[22], buf[23]]) as usize;

        let expected_frame_size = 24 + payload_len + 4;
        if buf.len() < expected_frame_size {
            return Err(Error::BufferTooShort);
        }

        let payload = &buf[24..24 + payload_len];

        // CRC32 Checksum verification
        let checksum_offset = 24 + payload_len;
        let wire_checksum = u32::from_be_bytes([
            buf[checksum_offset],
            buf[checksum_offset + 1],
            buf[checksum_offset + 2],
            buf[checksum_offset + 3],
        ]);

        let mut hasher = CrcHasher::new();
        hasher.update(&buf[0..checksum_offset]);
        let calculated_checksum = hasher.finalize();

        if wire_checksum != calculated_checksum {
            return Err(Error::ChecksumMismatch);
        }

        Ok(Self {
            version,
            frame_type,
            flags,
            ttl,
            src,
            dst,
            seq,
            payload,
        })
    }

    /// Serialize this frame into a caller-provided destination buffer with zero allocations.
    /// Returns the exact number of bytes written to `out`.
    pub fn serialize_into(&self, out: &mut [u8]) -> Result<usize> {
        let total_len = 24 + self.payload.len() + 4;
        if out.len() < total_len {
            return Err(Error::BufferOverflow);
        }

        out[0] = self.version;
        out[1] = self.frame_type.to_u8();
        out[2] = self.flags.0;
        out[3] = self.ttl;
        out[4..12].copy_from_slice(self.src.as_bytes());
        out[12..20].copy_from_slice(self.dst.as_bytes());

        let seq_bytes = self.seq.to_be_bytes();
        out[20] = seq_bytes[0];
        out[21] = seq_bytes[1];

        let len_bytes = (self.payload.len() as u16).to_be_bytes();
        out[22] = len_bytes[0];
        out[23] = len_bytes[1];

        out[24..24 + self.payload.len()].copy_from_slice(self.payload);

        // Compute and append CRC32
        let mut hasher = CrcHasher::new();
        hasher.update(&out[0..24 + self.payload.len()]);
        let checksum = hasher.finalize();

        let crc_offset = 24 + self.payload.len();
        let crc_bytes = checksum.to_be_bytes();
        out[crc_offset..crc_offset + 4].copy_from_slice(&crc_bytes);

        Ok(total_len)
    }

    /// Decrement Time-To-Live for multi-hop propagation. Returns false if frame has expired.
    pub fn decrement_ttl(&mut self) -> bool {
        if self.ttl > 1 {
            self.ttl -= 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_serialization_and_parsing() {
        let src = NodeAddress::from_bytes([0xAA; 8]);
        let dst = NodeAddress::from_bytes([0xBB; 8]);
        let payload = b"KITE_PROTO_BEACON_PAYLOAD_001";

        let frame = KiteFrame {
            version: PROTOCOL_VERSION,
            frame_type: FrameType::Data,
            flags: FrameFlags::new(FrameFlags::ENCRYPTED | FrameFlags::STORE_AND_FORWARD),
            ttl: 5,
            src,
            dst,
            seq: 42,
            payload,
        };

        let mut buf = [0u8; 128];
        let bytes_written = frame.serialize_into(&mut buf).expect("serialization ok");
        assert_eq!(bytes_written, 24 + payload.len() + 4);

        let parsed = KiteFrame::parse(&buf[..bytes_written]).expect("parsing ok");
        assert_eq!(parsed.version, PROTOCOL_VERSION);
        assert_eq!(parsed.frame_type, FrameType::Data);
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.seq, 42);
        assert_eq!(parsed.ttl, 5);
        assert_eq!(parsed.payload, payload);
    }
}
