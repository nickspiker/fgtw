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

/// The ONE canonical spelling of a handle, applied before EVERY derivation (handle proof + identity seed). ihi only does Unicode NFC, so without this the same handle typed with different case, spacing, or camelCase concatenation derives a DIFFERENT identity — the observed "double handle proof": one device attests `FractalDecoder`, another types `fractal decoder`, the probe finds no chain, and a second genesis forks the identity.
/// Rules: split on whitespace AND lower→Upper camelCase boundaries, lowercase every word, join with single spaces. `"FractalDecoder"`, `" Fractal  Decoder "`, and `"fractal decoder"` all canonicalize to `"fractal decoder"`.
pub fn canonical_handle(handle: &str) -> String {
    let mut words: Vec<String> = Vec::new();
    for token in handle.split_whitespace() {
        let mut cur = String::new();
        let mut prev_lower = false;
        for c in token.chars() {
            if c.is_uppercase() && prev_lower && !cur.is_empty() {
                words.push(core::mem::take(&mut cur));
            }
            prev_lower = c.is_lowercase();
            cur.extend(c.to_lowercase());
        }
        if !cur.is_empty() {
            words.push(cur);
        }
    }
    words.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_folds_case_spacing_and_camel() {
        assert_eq!(canonical_handle("FractalDecoder"), "fractal decoder");
        assert_eq!(canonical_handle(" Fractal  Decoder "), "fractal decoder");
        assert_eq!(canonical_handle("fractal decoder"), "fractal decoder");
        assert_eq!(canonical_handle("nem"), "nem");
        // ALL-CAPS is a single word (no lower→Upper boundary), not per-letter splits.
        assert_eq!(canonical_handle("NASA"), "nasa");
    }

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
