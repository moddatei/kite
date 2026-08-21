//! # `kite-crypto`
//!
//! Cryptographic building blocks for Kite:
//! - **Noise_XX Handshake Pattern:** Mutual authentication without pre-shared identity disclosure.
//! - **Ratcheted Session State:** Forward-secure symmetric encryption using ChaCha20-Poly1305.
//! - **Stochastic Obfuscation:** Statistical noise generation ensuring physical frames are indistinguishable from uniform thermal entropy.

pub mod noise;
pub mod obfuscation;

pub use noise::{CipherState, HandshakeState, Keypair, NoiseRole, Session};
pub use obfuscation::StochasticMask;
