//! Bounded zero-allocation error definitions for the Kite protocol stack.

use core::fmt;

/// Result type specialized for Kite operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Comprehensive protocol and parsing error enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Provided buffer is smaller than the minimum header size.
    BufferTooShort,
    /// Frame payload exceeds maximum allowable link MTU.
    BufferOverflow,
    /// Invalid protocol version byte encountered in wire header.
    InvalidProtocolVersion(u8),
    /// Unrecognized frame type flag.
    InvalidFrameType(u8),
    /// Checksum or Poly1305 authentication tag mismatch.
    ChecksumMismatch,
    /// Hop count limit (TTL) reached, frame must be dropped.
    TtlExceeded,
    /// Frame sequence number is outside of the sliding acceptance window (replay attack prevention).
    ReplayDetected,
    /// Destination address length mismatch or malformed node identifier.
    InvalidAddress,
    /// Cryptographic operation failed (MAC verification or bad ciphertext).
    CryptoFailure,
    /// Ring buffer capacity exceeded; oldest opportunistic packet dropped.
    BufferFull,
    /// Channel or medium is congested or currently busy.
    ChannelBusy,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BufferTooShort => write!(f, "Buffer is too short to contain a valid Kite frame"),
            Error::BufferOverflow => write!(f, "Frame payload exceeds maximum MTU limit"),
            Error::InvalidProtocolVersion(v) => {
                write!(f, "Unsupported protocol version: 0x{:02X}", v)
            }
            Error::InvalidFrameType(t) => write!(f, "Unknown frame type: 0x{:02X}", t),
            Error::ChecksumMismatch => {
                write!(f, "Frame integrity checksum or MAC validation failed")
            }
            Error::TtlExceeded => write!(f, "Frame hop limit exceeded (TTL expired)"),
            Error::ReplayDetected => write!(f, "Detected duplicate or replayed frame sequence"),
            Error::InvalidAddress => write!(f, "Malformed or invalid NodeAddress"),
            Error::CryptoFailure => {
                write!(f, "Cryptographic decryption or authentication failure")
            }
            Error::BufferFull => write!(f, "Opportunistic ring buffer at capacity"),
            Error::ChannelBusy => write!(f, "Physical RF transport medium is congested"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

