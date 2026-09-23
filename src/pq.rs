//! Multi-scheme signing: the key bundle a device declares, verification dispatched by scheme tag, and (client-only) the signing side.
//!
//! # Why three families, not twelve
//!
//! Signature security comes from INDEPENDENT hardness assumptions, not from count. There are three families available — elliptic-curve (Ed25519), lattice (Falcon), hash-based (SPHINCS+) — and stacking more lattice schemes buys size, not independence: they fall to the same advance. Three deep is the whole menu, with SPHINCS+ as the backstop if curves and lattices both fall, since preimage resistance is the assumption everything else already rests on anyway.
//!
//! # Keys are committed, not carried — except in the chain
//!
//! Everywhere OUTSIDE the membership chain (phonebook records, the RustDesk handshake, fstate) a device is named by [`KeyBundle::commit`]: 32 bytes regardless of how many schemes the bundle holds, so nothing stored grows when a fourth family is added. The bundle itself rides at verification time and is checked against the commitment.
//!
//! INSIDE the chain the full bundle is carried once per device, on its `Declare` op. The FGTW worker holds nothing but the chain, so the chain must be self-verifying — a bundle it could not see is a bundle it could not check. Once per device, ~1 KB, against 8.6 KB of signatures on the same op.
//!
//! # Verify is base; sign is `client`
//!
//! The worker (wasm32) folds chains with this exact code, so [`verify_egg`] and [`KeyBundle`] compile in base with the verify-only crates (`fn-dsa-vrfy`, `fips205` without its RNG). Keygen and signing live behind `client`.
//!
//! # PQ keys derive from the machine, like the device key does
//!
//! [`SigningBundle::derive`] seeds each scheme's keygen from `BLAKE3(fingerprint ‖ scheme)`, so a wiped device on the same hardware re-derives the same Falcon and SPHINCS+ keys — the property the Ed25519 device key already has, extended to every scheme. Without it, "same hardware, same keys" would be true for one scheme out of three, and the stateless-host design would quietly not hold for the PQ half. (The fingerprint itself is hardware-backed on macOS only; see the plan's known-limits note.)

use crate::fleet::{scheme, Egg};

/// Domain tag for [`KeyBundle::commit`], so a bundle commitment can never be confused with any other 32-byte hash in the system.
const COMMIT_DOMAIN: &str = "PHOTON_KEY_BUNDLE_v1";

/// Public-key size for each scheme, so a bundle can be validated before any crypto runs.
fn pubkey_len(scheme_tag: u8) -> Option<usize> {
    match scheme_tag {
        scheme::ED25519 => Some(32),
        scheme::FALCON512 => Some(fn_dsa_vrfy::vrfy_key_size(fn_dsa_vrfy::FN_DSA_LOGN_512)),
        scheme::SPHINCS_PLUS => Some(fips205::slh_dsa_sha2_128s::PK_LEN),
        _ => None,
    }
}

/// A device's public keys, one per scheme it can sign with.
///
/// Always sorted by scheme tag with no duplicates, and always containing Ed25519 — the device key itself, which the chain already names as `device_pubkey`. The fold checks that entry against the op's `device_pubkey`, which is what binds a bundle to the device that declared it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundle {
    keys: Vec<(u8, Vec<u8>)>,
}

impl KeyBundle {
    /// Build from `(scheme, pubkey)` pairs. Sorts by scheme; rejects duplicates, unknown schemes, wrong-length keys, and a bundle without Ed25519.
    pub fn new(mut keys: Vec<(u8, Vec<u8>)>) -> Result<Self, &'static str> {
        keys.sort_by_key(|(s, _)| *s);
        if keys.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err("key bundle: duplicate scheme");
        }
        for (s, k) in &keys {
            match pubkey_len(*s) {
                Some(n) if n == k.len() => {}
                Some(_) => return Err("key bundle: wrong key length for scheme"),
                None => return Err("key bundle: unknown scheme"),
            }
        }
        if !keys.iter().any(|(s, _)| *s == scheme::ED25519) {
            return Err("key bundle: missing Ed25519 — every device holds one");
        }
        Ok(Self { keys })
    }

    /// The Ed25519-only bundle, which is what an undeclared device honestly has.
    pub fn ed25519_only(device_pubkey: &[u8; 32]) -> Self {
        Self { keys: vec![(scheme::ED25519, device_pubkey.to_vec())] }
    }

    /// The public key for `scheme`, if this bundle holds one.
    pub fn pubkey(&self, scheme_tag: u8) -> Option<&[u8]> {
        self.keys.iter().find(|(s, _)| *s == scheme_tag).map(|(_, k)| k.as_slice())
    }

    /// Which schemes this bundle covers, as the fleet floor's currency.
    pub fn mask(&self) -> scheme::Mask {
        self.keys.iter().fold(0, |m, (s, _)| m | (1 << *s))
    }

    /// The bundle's Ed25519 key — present by construction.
    pub fn ed25519(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if let Some(k) = self.pubkey(scheme::ED25519) {
            out.copy_from_slice(k);
        }
        out
    }

    /// The 32-byte name for this bundle everywhere outside the chain. Domain-tagged BLAKE3 over the framed wire form, so two bundles with the same keys in any order commit identically and no other hash in the system can collide with it.
    pub fn commit(&self) -> [u8; 32] {
        blake3::derive_key(COMMIT_DOMAIN, &self.to_bytes())
    }

    /// Wire form: `u8 count`, then per key `u8 scheme ‖ u16 LE len ‖ bytes`. Every element framed, so it is safe to embed in a signing preimage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + self.keys.iter().map(|(_, k)| 3 + k.len()).sum::<usize>());
        v.push(self.keys.len() as u8);
        for (s, k) in &self.keys {
            v.push(*s);
            v.extend_from_slice(&(k.len() as u16).to_le_bytes());
            v.extend_from_slice(k);
        }
        v
    }

    /// Inverse of [`to_bytes`](Self::to_bytes), with every validation [`new`](Self::new) applies. Trailing bytes are an error — a bundle is never a prefix of something else.
    pub fn from_bytes(b: &[u8]) -> Result<Self, &'static str> {
        let Some((&count, mut rest)) = b.split_first() else {
            return Err("key bundle: empty");
        };
        let mut keys = Vec::with_capacity(count as usize);
        for _ in 0..count {
            if rest.len() < 3 {
                return Err("key bundle: truncated entry");
            }
            let s = rest[0];
            let n = u16::from_le_bytes([rest[1], rest[2]]) as usize;
            rest = &rest[3..];
            if rest.len() < n {
                return Err("key bundle: truncated key");
            }
            keys.push((s, rest[..n].to_vec()));
            rest = &rest[n..];
        }
        if !rest.is_empty() {
            return Err("key bundle: trailing bytes");
        }
        Self::new(keys)
    }
}

/// Verify one egg against the public key for its scheme. Unknown scheme, wrong key length, or malformed signature all verify FALSE — a verifier must never treat what it cannot check as satisfied.
///
/// Every scheme signs the same message bytes. That is the intended hybrid: three independent keys over one preimage, all of which must hold.
pub fn verify_egg(scheme_tag: u8, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match scheme_tag {
        scheme::ED25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let Ok(pk): Result<[u8; 32], _> = pubkey.try_into() else { return false };
            let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
            let Ok(sig_arr): Result<[u8; 64], _> = sig.try_into() else { return false };
            vk.verify(msg, &Signature::from_bytes(&sig_arr)).is_ok()
        }
        scheme::FALCON512 => {
            use fn_dsa_vrfy::{VerifyingKey, VerifyingKey512, DOMAIN_NONE, HASH_ID_RAW};
            let Some(vk) = VerifyingKey512::decode(pubkey) else { return false };
            vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, msg)
        }
        scheme::SPHINCS_PLUS => {
            use fips205::slh_dsa_sha2_128s::{PublicKey, SIG_LEN};
            use fips205::traits::{SerDes, Verifier};
            let Ok(pk): Result<[u8; 32], _> = pubkey.try_into() else { return false };
            let Ok(vk) = PublicKey::try_from_bytes(&pk) else { return false };
            let Ok(sig_arr): Result<[u8; SIG_LEN], _> = sig.try_into() else { return false };
            vk.verify(msg, &sig_arr, &[])
        }
        _ => false,
    }
}

/// The egg-list wire form lives in `vsf::eggs` — the lowest layer — so the VSF header's `gm` slot and every slot above it share one codec. Re-exported so fgtw callers keep their paths.
pub use vsf::eggs::{eggs_from_bytes, eggs_to_bytes};

/// The one rule for a consent, a vouch, or a handshake: every listed egg verifies against `bundle`, AND the listed set covers `required`. An egg for a scheme the bundle lacks fails closed; a list that is short of `required` fails even if everything in it is valid.
pub fn verify_eggs(eggs: &[Egg], bundle: &KeyBundle, msg: &[u8], required: scheme::Mask) -> bool {
    if eggs.is_empty() {
        return false;
    }
    for e in eggs {
        let Some(pk) = bundle.pubkey(e.scheme) else { return false };
        if !verify_egg(e.scheme, pk, msg, &e.sig) {
            return false;
        }
    }
    scheme::covers(egg_mask(eggs), required)
}

/// The schemes a per-message ENVELOPE carries: Ed25519 + Falcon-512. SPHINCS+ is left to the chain, where an op is rare and archival — at 7.8 KB a signature it has no place on every relay frame or status ping. The same tier the RustDesk handshake uses.
pub const ENVELOPE_TIER: scheme::Mask = scheme::MASK_BASE | (1 << scheme::FALCON512);

/// Signature length for each scheme — what a header slot must reserve. Falcon and SLH-DSA both have fixed (padded) signature sizes, which is what makes reserve-then-patch sound.
pub fn sig_len(scheme_tag: u8) -> Option<usize> {
    match scheme_tag {
        scheme::ED25519 => Some(64),
        scheme::FALCON512 => Some(fn_dsa_vrfy::signature_size(fn_dsa_vrfy::FN_DSA_LOGN_512)),
        scheme::SPHINCS_PLUS => Some(fips205::slh_dsa_sha2_128s::SIG_LEN),
        _ => None,
    }
}

/// The `(scheme, length)` slots a header must reserve to carry every scheme in `mask`, in scheme order — the argument to `VsfBuilder::signed_only_eggs`.
pub fn reserve_eggs(mask: scheme::Mask) -> Vec<(u8, usize)> {
    (0u8..16)
        .filter(|s| mask & (1 << s) != 0)
        .filter_map(|s| sig_len(s).map(|n| (s, n)))
        .collect()
}

/// What `signer` signs an envelope with: everything it holds, clipped to the envelope tier. Ed25519 always; Falcon when the signer has it; never SPHINCS+.
pub fn envelope_mask(signer: &(impl FleetSigner + ?Sized)) -> scheme::Mask {
    signer.bundle().map(|b| b.mask()).unwrap_or(scheme::MASK_BASE) & ENVELOPE_TIER
}

/// Sign a VSF document whose header was reserved with `signed_only_eggs(ke, &reserve_eggs(envelope_mask(signer)))`. vsf hands us the 32-byte file hash; every scheme signs it.
pub fn sign_envelope(unsigned: Vec<u8>, signer: &(impl FleetSigner + ?Sized)) -> Result<Vec<u8>, String> {
    let mask = envelope_mask(signer);
    vsf::verification::sign_file_with(unsigned, |file_hash| signer.eggs(file_hash, mask))
}

/// Verify a signed VSF document's header eggs against the signer's declared `bundle`, requiring `required` — the policy half that vsf leaves to us. vsf has already checked the Ed25519 anchor; this checks the rest and that nothing required is missing. Returns the signer's device key.
/// The ENVELOPE rule, one step looser than [`verify_eggs`]: every egg for a scheme the bundle HAS must verify, and those verified eggs must cover `required`; an egg for a scheme the bundle lacks is skipped, not fatal.
///
/// Why the difference (field 2026-09-23): a device signs envelopes with everything it holds, but the chain only knows what it has DECLARED — and the Declare itself travels in an envelope. Under the strict rule a fresh phone with a bundle sent Ed25519 + Falcon, the worker verified against the Ed25519-only bundle the chain held, hit the Falcon egg, failed closed, and the phone could never attest, never declare, never get in. An egg nobody can check is noise, not a forgery: it proves nothing and it is not counted toward coverage, so ignoring it weakens no gate. Chain ops keep the strict rule — a fold sees the whole history and knows exactly which keys apply.
pub fn verify_eggs_declared(eggs: &[Egg], bundle: &KeyBundle, msg: &[u8], required: scheme::Mask) -> bool {
    let mut verified: scheme::Mask = 0;
    for e in eggs {
        let Some(pk) = bundle.pubkey(e.scheme) else { continue };
        if !verify_egg(e.scheme, pk, msg, &e.sig) {
            return false;
        }
        verified |= 1 << e.scheme;
    }
    verified != 0 && scheme::covers(verified, required)
}

pub fn verify_envelope(doc: &[u8], bundle: &KeyBundle, required: scheme::Mask) -> Result<[u8; 32], String> {
    let (signer, eggs, file_hash) = vsf::verification::header_eggs(doc)?;
    if bundle.ed25519() != signer {
        return Err("envelope: bundle is not the signer's".into());
    }
    if !verify_eggs_declared(&eggs, bundle, &file_hash, required) {
        return Err("envelope: eggs do not verify at the required tier".into());
    }
    Ok(signer)
}

/// The mask of schemes an egg list actually carries — what an op PROVED, as opposed to what its signer declared.
pub fn egg_mask(eggs: &[Egg]) -> scheme::Mask {
    eggs.iter().fold(0, |m, e| if (e.scheme as usize) < 16 { m | (1 << e.scheme) } else { m })
}

/// What a fleet-op builder needs from whoever is signing: the Ed25519 device keypair (identity, and the one egg every device can always produce), the full egg list over a message, and the public bundle to declare. Implemented for a bare [`Keypair`](crate::keys::Keypair) so every existing single-scheme caller keeps working unchanged, and for [`SigningBundle`] under `client`.
pub trait FleetSigner {
    /// The Ed25519 device keypair. Always present — it IS the device.
    fn keypair(&self) -> &crate::keys::Keypair;
    /// Sign `msg` with the schemes in `schemes` that this signer holds, Ed25519 first. Ed25519 is always emitted — it is the device key, and every op requires it.
    ///
    /// The mask is what the CHAIN knows this device can sign with: Ed25519 alone before its `Declare`, everything it declared afterwards, and the new bundle's full set on the `Declare` itself. Emitting an egg for a scheme the verifier holds no key for would fail closed under the every-egg-must-verify rule, so a signer never produces one.
    fn eggs(&self, msg: &[u8], schemes: scheme::Mask) -> Vec<Egg>;
    /// The public bundle to put on a `Declare`. `None` for an Ed25519-only signer, which has nothing beyond the device key the chain already knows.
    fn bundle(&self) -> Option<KeyBundle>;
}

impl FleetSigner for crate::keys::Keypair {
    fn keypair(&self) -> &crate::keys::Keypair {
        self
    }
    fn eggs(&self, msg: &[u8], _schemes: scheme::Mask) -> Vec<Egg> {
        vec![Egg { scheme: scheme::ED25519, sig: self.sign(msg).to_bytes().to_vec() }]
    }
    fn bundle(&self) -> Option<KeyBundle> {
        None
    }
}

#[cfg(feature = "client")]
pub use signing::{epoch_bundle, SigningBundle};

#[cfg(feature = "client")]
mod signing {
    use super::{scheme, Egg, FleetSigner, KeyBundle};
    use crate::keys::Keypair;
    use rand::{rngs::StdRng, SeedableRng};

    /// One device's secret keys across every scheme it can sign with.
    ///
    /// `Clone` because apps hold it beside a cloned `Keypair`. Derived, never generated at random: see [`derive`](Self::derive). Holds the Falcon and SPHINCS+ secrets as opaque byte forms and re-decodes them per signature, so nothing here has a lifetime tied to a library-internal type.
    #[derive(Clone)]
    pub struct SigningBundle {
        ed: Keypair,
        falcon_sk: Vec<u8>,
        falcon_vk: Vec<u8>,
        sphincs_sk: [u8; fips205::slh_dsa_sha2_128s::SK_LEN],
        sphincs_pk: [u8; fips205::slh_dsa_sha2_128s::PK_LEN],
    }

    impl SigningBundle {
        /// Derive every scheme's keypair from the machine fingerprint, deterministically.
        ///
        /// The Ed25519 key comes from [`derive_device_keypair`](crate::keys::derive_device_keypair) exactly as today. Each PQ keygen is fed a `StdRng` seeded from `BLAKE3(fingerprint)` under a per-scheme domain, so the same hardware yields the same keys on every run and after a wipe — the property that makes a host stateless for every scheme rather than only the first.
        pub fn derive(fingerprint: &[u8]) -> Self {
            let ed = crate::keys::derive_device_keypair(fingerprint);

            let seed_for = |domain: &str| -> [u8; 32] { blake3::derive_key(domain, fingerprint) };

            let (falcon_sk, falcon_vk) = {
                use fn_dsa::{sign_key_size, vrfy_key_size, KeyPairGenerator, KeyPairGeneratorStandard, FN_DSA_LOGN_512};
                let mut rng = StdRng::from_seed(seed_for("PHOTON_DEVICE_FALCON512_v1"));
                let mut sk = vec![0u8; sign_key_size(FN_DSA_LOGN_512)];
                let mut vk = vec![0u8; vrfy_key_size(FN_DSA_LOGN_512)];
                KeyPairGeneratorStandard::default().keygen(FN_DSA_LOGN_512, &mut rng, &mut sk, &mut vk);
                (sk, vk)
            };

            let (sphincs_pk, sphincs_sk) = {
                use fips205::slh_dsa_sha2_128s;
                use fips205::traits::SerDes;
                let mut rng = StdRng::from_seed(seed_for("PHOTON_DEVICE_SPHINCS_PLUS_v1"));
                // Keygen from a caller-seeded CSPRNG is deterministic by construction; the only failure mode is an internal invariant, which is a bug rather than a runtime condition.
                let (pk, sk) = slh_dsa_sha2_128s::try_keygen_with_rng(&mut rng).expect("slh-dsa keygen from a seeded rng");
                (pk.into_bytes(), sk.into_bytes())
            };

            Self { ed, falcon_sk, falcon_vk, sphincs_sk, sphincs_pk }
        }

        /// The public bundle this signer will declare.
        pub fn public(&self) -> KeyBundle {
            KeyBundle::new(vec![
                (scheme::ED25519, self.ed.public.to_bytes().to_vec()),
                (scheme::FALCON512, self.falcon_vk.clone()),
                (scheme::SPHINCS_PLUS, self.sphincs_pk.to_vec()),
            ])
            .expect("a derived bundle is well-formed by construction")
        }
    }

    /// The fleet's EPOCH signing bundle: the keys a member proves current, unlocked membership with — to a stateless verifier that holds nothing but the fan-out header.
    ///
    /// Derived from the fleet key under its own domain rather than wrapped as a second secret. Everyone holding the fleet key is, by definition, an unlocked member of the current epoch (the fan-out wraps it to exactly that set and re-mints on every lock or departure), so this adds no exposure and leaves the wrap format, `fanout_open` and every recovery path untouched. A locked device cannot open the re-minted key, so it cannot derive this bundle, so it cannot sign an epoch proof. That is what makes lock-out a HANDSHAKE fact and not merely a fan-out fact.
    ///
    /// The public half rides the fan-out header; members detect a tampered header by re-deriving and comparing.
    pub fn epoch_bundle(fleet_key: &[u8; 32]) -> SigningBundle {
        SigningBundle::derive(&blake3::derive_key("PHOTON_FLEET_EPOCH_SIGNING_v1", fleet_key))
    }

    impl FleetSigner for SigningBundle {
        fn keypair(&self) -> &Keypair {
            &self.ed
        }

        fn eggs(&self, msg: &[u8], schemes: scheme::Mask) -> Vec<Egg> {
            let mut out = self.ed.eggs(msg, schemes);

            if scheme::covers(schemes, 1 << scheme::FALCON512) {
            // Falcon signing is randomised; seed its RNG from the secret and the message so a given (key, message) always produces the same egg. Deterministic output is what makes a re-signed op byte-identical, and it removes the RNG as an input an attacker could influence.
            {
                use fn_dsa::{signature_size, SigningKey, SigningKeyStandard, DOMAIN_NONE, HASH_ID_RAW};
                let mut h = blake3::Hasher::new_derive_key("PHOTON_FALCON512_SIGN_NONCE_v1");
                h.update(&self.falcon_sk);
                h.update(msg);
                let mut rng = StdRng::from_seed(*h.finalize().as_bytes());
                let mut sk = SigningKeyStandard::decode(&self.falcon_sk).expect("stored falcon key decodes");
                let mut sig = vec![0u8; signature_size(sk.get_logn())];
                sk.sign(&mut rng, &DOMAIN_NONE, &HASH_ID_RAW, msg, &mut sig);
                out.push(Egg { scheme: scheme::FALCON512, sig });
            }
            }

            if scheme::covers(schemes, 1 << scheme::SPHINCS_PLUS) {
            // SPHINCS+ hedged signing likewise: hedging guards against fault attacks, and seeding it from (secret, message) keeps the egg deterministic.
            {
                use fips205::slh_dsa_sha2_128s::PrivateKey;
                use fips205::traits::{SerDes, Signer};
                let mut h = blake3::Hasher::new_derive_key("PHOTON_SPHINCS_PLUS_SIGN_NONCE_v1");
                h.update(&self.sphincs_sk);
                h.update(msg);
                let mut rng = StdRng::from_seed(*h.finalize().as_bytes());
                let sk = PrivateKey::try_from_bytes(&self.sphincs_sk).expect("stored slh-dsa key decodes");
                let sig = sk.try_sign_with_rng(&mut rng, msg, &[], true).expect("slh-dsa sign");
                out.push(Egg { scheme: scheme::SPHINCS_PLUS, sig: sig.to_vec() });
            }
            }

            out
        }

        fn bundle(&self) -> Option<KeyBundle> {
            Some(self.public())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_round_trips_and_commits_stably() {
        let b = KeyBundle::new(vec![
            (scheme::SPHINCS_PLUS, vec![7u8; 32]),
            (scheme::ED25519, vec![1u8; 32]),
        ])
        .unwrap();
        // Sorted by scheme regardless of input order, so the commitment is order-independent.
        assert_eq!(b.mask(), (1 << scheme::ED25519) | (1 << scheme::SPHINCS_PLUS));
        let back = KeyBundle::from_bytes(&b.to_bytes()).unwrap();
        assert_eq!(back, b);
        assert_eq!(back.commit(), b.commit());
        assert_eq!(b.ed25519(), [1u8; 32]);
    }

    #[test]
    fn malformed_bundles_are_rejected() {
        assert!(KeyBundle::new(vec![(scheme::FALCON512, vec![0u8; 897])]).is_err(), "no Ed25519");
        assert!(KeyBundle::new(vec![(scheme::ED25519, vec![0u8; 31])]).is_err(), "wrong length");
        assert!(KeyBundle::new(vec![(scheme::ED25519, vec![0u8; 32]), (9, vec![0u8; 32])]).is_err(), "unknown scheme");
        assert!(KeyBundle::new(vec![(scheme::ED25519, vec![0u8; 32]), (scheme::ED25519, vec![1u8; 32])]).is_err(), "duplicate");
        let mut bytes = KeyBundle::ed25519_only(&[2u8; 32]).to_bytes();
        bytes.push(0);
        assert!(KeyBundle::from_bytes(&bytes).is_err(), "trailing bytes");
    }

    #[test]
    fn unknown_scheme_never_verifies() {
        assert!(!verify_egg(200, &[0u8; 32], b"m", &[0u8; 64]));
        assert!(!verify_egg(scheme::FALCON512, &[0u8; 5], b"m", &[0u8; 666]), "short key");
    }

    /// A three-scheme signer signs an envelope at the envelope tier (Ed25519 + Falcon, never SPHINCS+); vsf anchors it, we finish it against the declared bundle, and a short envelope is refused when Falcon is required.
    #[cfg(feature = "client")]
    #[test]
    fn envelope_signs_at_the_tier_and_verifies_against_the_bundle() {
        let a = SigningBundle::derive(b"envelope-machine");
        let ke = vsf::VsfType::ke(a.keypair().public.to_bytes().to_vec());
        let unsigned = vsf::VsfBuilder::new()
            .creation_time_oscillations(vsf::eagle_time_oscillations())
            .signed_only_eggs(ke.clone(), &reserve_eggs(envelope_mask(&a)))
            .add_section("relay", vec![("payload".to_string(), vsf::VsfType::v(b'r', vec![1, 2, 3]))])
            .build()
            .unwrap();
        let signed = sign_envelope(unsigned, &a).unwrap();
        assert!(vsf::verification::read_verified(&signed, Some(a.keypair().public.to_bytes())).is_ok(), "vsf anchors on Ed25519");
        let (_, eggs, _) = vsf::verification::header_eggs(&signed).unwrap();
        assert_eq!(egg_mask(&eggs), ENVELOPE_TIER, "Ed25519 + Falcon, and no SPHINCS+ on an envelope");
        assert_eq!(verify_envelope(&signed, &a.public(), ENVELOPE_TIER).unwrap(), a.keypair().public.to_bytes());
        // An Ed25519-only signer's envelope is fine when only Ed25519 is required, and refused when Falcon is.
        let bare = a.keypair();
        let unsigned2 = vsf::VsfBuilder::new()
            .signed_only_eggs(ke, &reserve_eggs(envelope_mask(bare)))
            .add_section("relay", vec![])
            .build()
            .unwrap();
        let short = sign_envelope(unsigned2, bare).unwrap();
        assert!(verify_envelope(&short, &a.public(), scheme::MASK_BASE).is_ok());
        assert!(verify_envelope(&short, &a.public(), ENVELOPE_TIER).is_err());
    }

    #[cfg(feature = "client")]
    #[test]
    fn derived_bundle_signs_with_all_three_and_is_deterministic() {
        let a = SigningBundle::derive(b"machine-fingerprint-A");
        let again = SigningBundle::derive(b"machine-fingerprint-A");
        let other = SigningBundle::derive(b"machine-fingerprint-B");
        assert_eq!(a.public(), again.public(), "same hardware, same keys — for every scheme");
        assert_ne!(a.public(), other.public());
        assert_eq!(a.public().mask(), scheme::MASK_ALL);

        let msg = b"fleet op signing bytes";
        let eggs = a.eggs(msg, scheme::MASK_ALL);
        assert_eq!(egg_mask(&eggs), scheme::MASK_ALL);
        // Filtered to what the chain knows: an undeclared device signs with Ed25519 alone.
        assert_eq!(egg_mask(&a.eggs(msg, scheme::MASK_BASE)), scheme::MASK_BASE);
        let pubs = a.public();
        for e in &eggs {
            assert!(verify_egg(e.scheme, pubs.pubkey(e.scheme).unwrap(), msg, &e.sig), "scheme {} verifies", e.scheme);
            assert!(!verify_egg(e.scheme, pubs.pubkey(e.scheme).unwrap(), b"tampered", &e.sig), "scheme {} rejects a tampered message", e.scheme);
            assert!(!verify_egg(e.scheme, other.public().pubkey(e.scheme).unwrap(), msg, &e.sig), "scheme {} rejects the wrong key", e.scheme);
        }
        // Deterministic: re-signing the same message yields byte-identical eggs.
        assert_eq!(a.eggs(msg, scheme::MASK_ALL), eggs);
    }
}

#[cfg(all(test, feature = "client"))]
mod declared_rule {
    use super::*;
    use crate::fleet::scheme;

    /// A device with a bundle the chain has not seen signs with everything it holds; the verifier checks what it can, ignores what it cannot, and the floor still binds.
    #[test]
    fn undeclared_eggs_are_noise_not_forgery() {
        let dev = SigningBundle::derive(b"fresh-phone");
        let msg = b"hello";
        let eggs = dev.eggs(msg, scheme::MASK_ALL);
        let chain_knows = KeyBundle::ed25519_only(&dev.keypair().public.to_bytes());
        assert!(!verify_eggs(&eggs, &chain_knows, msg, scheme::MASK_BASE), "the strict rule fails closed on the Falcon egg");
        assert!(verify_eggs_declared(&eggs, &chain_knows, msg, scheme::MASK_BASE), "the envelope rule verifies the anchor and skips the rest");
        assert!(!verify_eggs_declared(&eggs, &chain_knows, msg, scheme::MASK_ALL), "but an undeclared egg never counts toward the floor");
        // A verifiable egg that is WRONG is still fatal.
        let mut bad = eggs.clone();
        bad[0].sig[3] ^= 1;
        assert!(!verify_eggs_declared(&bad, &chain_knows, msg, scheme::MASK_BASE));
        // Once declared, the full bundle verifies everything and the full floor is met.
        assert!(verify_eggs_declared(&eggs, &dev.public(), msg, scheme::MASK_ALL));
        assert!(!verify_eggs_declared(&[], &chain_knows, msg, scheme::MASK_BASE), "nothing verified is not coverage");
    }
}
