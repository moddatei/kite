//! Noise Protocol Framework implementation for Kite (Pattern: Noise_XX_25519_ChaChaPoly_SHA256).
//!
//! ### Handshake Sequence:
//! ```text
//! -> e
//! <- e, ee, s, es
//! -> s, se
//! ```

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use kite_core::error::{Error, Result};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub const NOISE_PROTOCOL_NAME: &[u8] = b"Noise_XX_25519_ChaChaPoly_SHA256";
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

/// Role in the two-party Noise handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

/// Static or ephemeral X25519 keypair.
pub struct Keypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl Keypair {
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

/// Symmetric cipher state for continuous message encryption/decryption with auto-incrementing nonce.
pub struct CipherState {
    key: Option<[u8; KEY_LEN]>,
    nonce: u64,
}

impl CipherState {
    pub fn new(key: Option<[u8; KEY_LEN]>) -> Self {
        Self { key, nonce: 0 }
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    pub fn encrypt_in_place(
        &mut self,
        ad: &[u8],
        plaintext: &mut [u8],
        tag_out: &mut [u8; TAG_LEN],
    ) -> Result<()> {
        let key_bytes = self.key.as_ref().ok_or(Error::CryptoFailure)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.nonce.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag = cipher
            .encrypt_in_place_detached(nonce, ad, plaintext)
            .map_err(|_| Error::CryptoFailure)?;

        tag_out.copy_from_slice(tag.as_slice());
        self.nonce += 1;
        Ok(())
    }

    pub fn decrypt_in_place(
        &mut self,
        ad: &[u8],
        ciphertext: &mut [u8],
        tag_in: &[u8; TAG_LEN],
    ) -> Result<()> {
        let key_bytes = self.key.as_ref().ok_or(Error::CryptoFailure)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&self.nonce.to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let tag = Tag::from_slice(tag_in);
        cipher
            .decrypt_in_place_detached(nonce, ad, ciphertext, tag)
            .map_err(|_| Error::CryptoFailure)?;

        self.nonce += 1;
        Ok(())
    }
}

/// Noise symmetric state wrapping chaining key `ck` and running transcript hash `h`.
pub struct SymmetricState {
    pub cipher_state: CipherState,
    pub ck: [u8; 32],
    pub h: [u8; 32],
}

impl SymmetricState {
    pub fn new(protocol_name: &[u8]) -> Self {
        let mut h = [0u8; 32];
        if protocol_name.len() <= 32 {
            h[..protocol_name.len()].copy_from_slice(protocol_name);
        } else {
            let mut hasher = Sha256::new();
            hasher.update(protocol_name);
            h.copy_from_slice(&hasher.finalize());
        }

        let mut ck = [0u8; 32];
        ck.copy_from_slice(&h);

        Self {
            cipher_state: CipherState::new(None),
            ck,
            h,
        }
    }

    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.ck);
        hasher.update(input_key_material);
        let output = hasher.finalize();

        let mut next_ck = [0u8; 32];
        let mut next_k = [0u8; 32];
        next_ck.copy_from_slice(&output[0..32]);

        let mut k_hasher = Sha256::new();
        k_hasher.update(next_ck);
        k_hasher.update(b"k_deriv");
        next_k.copy_from_slice(&k_hasher.finalize());

        self.ck = next_ck;
        self.cipher_state = CipherState::new(Some(next_k));
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h.copy_from_slice(&hasher.finalize());
    }

    pub fn split(&self) -> (CipherState, CipherState) {
        let mut h1 = Sha256::new();
        h1.update(self.ck);
        h1.update(b"tx_key");
        let mut k1 = [0u8; 32];
        k1.copy_from_slice(&h1.finalize());

        let mut h2 = Sha256::new();
        h2.update(self.ck);
        h2.update(b"rx_key");
        let mut k2 = [0u8; 32];
        k2.copy_from_slice(&h2.finalize());

        (CipherState::new(Some(k1)), CipherState::new(Some(k2)))
    }
}

/// Fully established bidirectional encrypted session between two Kite nodes.
pub struct Session {
    pub tx: CipherState,
    pub rx: CipherState,
    pub remote_static: PublicKey,
}

impl Session {
    pub fn encrypt(&mut self, plaintext: &mut [u8], tag_out: &mut [u8; TAG_LEN]) -> Result<()> {
        self.tx.encrypt_in_place(b"kite_data", plaintext, tag_out)
    }

    pub fn decrypt(&mut self, ciphertext: &mut [u8], tag_in: &[u8; TAG_LEN]) -> Result<()> {
        self.rx.decrypt_in_place(b"kite_data", ciphertext, tag_in)
    }
}

/// Noise_XX Handshake orchestrator.
pub struct HandshakeState {
    pub role: NoiseRole,
    pub symmetric: SymmetricState,
    pub s: Keypair,
    pub rs: Option<PublicKey>,
}

impl HandshakeState {
    pub fn new_initiator(s: Keypair) -> Self {
        let mut symmetric = SymmetricState::new(NOISE_PROTOCOL_NAME);
        symmetric.mix_hash(b"prologue_v1");

        Self {
            role: NoiseRole::Initiator,
            symmetric,
            s,
            rs: None,
        }
    }

    pub fn new_responder(s: Keypair) -> Self {
        let mut symmetric = SymmetricState::new(NOISE_PROTOCOL_NAME);
        symmetric.mix_hash(b"prologue_v1");

        Self {
            role: NoiseRole::Responder,
            symmetric,
            s,
            rs: None,
        }
    }
}
