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

/// Derive the device keypair from a machine fingerprint (deterministic, never stored).
///
/// BLAKE3-hashes the fingerprint into the 32-byte Ed25519 seed; the same fingerprint always produces the same keypair.
/// Reading the fingerprint oracle (Linux `/etc/machine-id`, Windows `MachineGuid`, macOS `IOPlatformUUID`, Android `ANDROID_ID` — see `tohu::device`) stays an app concern; every TOKEN app on a machine hands the same oracle bytes here and gets the same device identity.
pub fn derive_device_keypair(fingerprint: &[u8]) -> Keypair {
    let hash = blake3::hash(fingerprint);
    let seed: [u8; 32] = *hash.as_bytes();
    Keypair::from_seed(&seed)
}

// HANDLES ARE BYTE-PRECISE (Nick's rule): every derivation hashes the raw typed string as VSF x text — case, spacing, tabs, control characters, all of it is the human's choice and the human's entropy. The ONLY validation anywhere is non-empty; the ONLY transform anywhere is NFC, inside the vsf `x` encoder. No fold, no trim, no filter, in any repo, ever.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_keypair_known_answer() {
        // Frozen contract: fingerprint → BLAKE3 → Ed25519 seed. If this ever changes, every enrolled device on every app changes identity — the KAT is the tripwire.
        let kp = derive_device_keypair(b"fgtw-test-fingerprint");
        assert_eq!(
            kp.public.to_bytes(),
            [
                152, 166, 58, 172, 55, 164, 171, 242, 252, 188, 86, 114, 117, 50, 140, 198, 30,
                167, 116, 64, 199, 91, 251, 14, 171, 123, 92, 238, 93, 247, 14, 94
            ],
        );
    }
}
