//! Stochastic obfuscation and entropy whitening.
//!
//! Provides statistical whitening to disguise physical layer frames as uniform random noise,
//! defeating Deep Packet Inspection (DPI) and radio fingerprinting classifiers.

use sha2::{Digest, Sha256};

/// Maximum padding boundary for constant-length frame masking.
pub const ALIGNED_FRAME_BLOCK: usize = 64;

pub struct StochasticMask;

impl StochasticMask {
    /// Mask a slice in-place by XORing with a deterministic pseudo-random keystream
    /// derived from an ephemeral seed (e.g. physical channel timestamp or preamble).
    pub fn apply_in_place(data: &mut [u8], ephemeral_seed: &[u8; 32]) {
        let mut block_index: u32 = 0;
        let mut offset = 0;

        while offset < data.len() {
            let mut hasher = Sha256::new();
            hasher.update(ephemeral_seed);
            hasher.update(block_index.to_be_bytes());
            let stream_block = hasher.finalize();

            let chunk_size = core::cmp::min(32, data.len() - offset);
            for i in 0..chunk_size {
                data[offset + i] ^= stream_block[i];
            }

            offset += chunk_size;
            block_index += 1;
        }
    }

    /// Calculate padded length to align to constant transmission blocks, preventing
    /// side-channel length leakage.
    pub fn calculate_padded_len(raw_len: usize) -> usize {
        let remainder = raw_len % ALIGNED_FRAME_BLOCK;
        if remainder == 0 {
            raw_len
        } else {
            raw_len + (ALIGNED_FRAME_BLOCK - remainder)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stochastic_mask_involution() {
        let seed = [0x42u8; 32];
        let original = b"STOCHASTIC_ENTROPY_WHITENING_PAYLOAD_TEST";
        let mut buffer = original.to_vec();

        // First pass masks data
        StochasticMask::apply_in_place(&mut buffer, &seed);
        assert_ne!(&buffer, original);

        // Second pass unmasks data (XOR involution)
        StochasticMask::apply_in_place(&mut buffer, &seed);
        assert_eq!(&buffer, original);
    }
}
