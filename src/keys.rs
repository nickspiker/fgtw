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

/// HANDLES ARE BYTE-PRECISE (Nick's rule, restored 2026-08-18 after the folding crept in against it): `Zeno` ≠ `zeno`, `"   "` is a literal handle, and the ONLY validation anywhere is non-empty. Every derivation hashes the raw typed string as VSF x text — case, spacing, tabs, all of it is the human's choice and the human's entropy. The old case/space/camelCase folding (justified by the "double handle proof" fork) is deleted: a mistyped handle surfaces as a FRESH identity behind the permanence interstitial — a loud, human-decidable moment — never a silent rewrite of their input.
///
/// MIGRATION-EXPIRES: v58 — identities attested while the folding was live are keyed to their FOLDED string (e.g. an identity always typed `Adam` lives under `adam`). Until every affected person has re-learned or re-attested, photon's fresh-claim screen carries a hint about the old folding; that hint (and this note) go when the marker does.
pub fn legacy_folded_handle(handle: &str) -> String {
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

    /// The legacy folder still folds the way old builds did — it exists ONLY so the migration hint can name where a pre-2026-08-18 identity lives. It is NEVER applied to a derivation.
    #[test]
    fn legacy_folder_reproduces_the_old_folding() {
        assert_eq!(legacy_folded_handle("FractalDecoder"), "fractal decoder");
        assert_eq!(legacy_folded_handle(" Fractal  Decoder "), "fractal decoder");
        assert_eq!(legacy_folded_handle("Adam"), "adam");
        assert_eq!(legacy_folded_handle("NASA"), "nasa");
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
