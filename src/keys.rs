//! Device identity keypair — the Ed25519 signing key every fleet op and attestation is signed with.
//!
//! This is the *key material* half of device identity: a deterministic Ed25519 keypair built from a 32-byte seed.
//! Where the seed comes from (the platform fingerprint oracle, never stored, derived on every launch) is an app concern — photon's `fingerprint.rs` owns the oracle read and hands the seed here.
//! The crate keeps only the primitive: seed in, signing key out.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Ed25519 keypair for FGTW device/handle identity.
///
/// NEVER persisted to disk — derived deterministically from a device-fingerprint-derived seed.
/// The app hashes its platform oracle (Linux `/etc/machine-id`, macOS `IOPlatformUUID`, Android device fingerprint, …) into the 32-byte seed and calls [`Keypair::from_seed`].
#[derive(Clone)]
pub struct Keypair {
    pub secret: SigningKey,
    pub public: VerifyingKey,
}

impl Keypair {
    /// Create a keypair from a 32-byte seed (deterministic).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let secret = SigningKey::from_bytes(seed);
        let public = secret.verifying_key();
        Self { secret, public }
    }

    /// Sign a message with the device secret.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(message)
    }
}
