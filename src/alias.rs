//! A kist's alias (ferros docs/FACETS.md "The alias"; decided 2026-11-12 on the owner's delegation: D0 the person key, D1 the kernel derives).
//!
//! The alias is a 32-byte seed for one kist alone, the same on every device of the person's: BLAKE3 `derive_key` under [`CONTEXT`] over the person key, the kist's developer key and its option, each exactly 32 bytes, in that order.
//! Three fixed-width fields and no length anywhere: 96 bytes in, so no two different triples hash the same input, and the context string is used for nothing else.
//! The person key is the person's own 32 random bytes ([`crate::person`]), never the handle or anything derived from it, so nobody who only knows the handle computes an alias.
//! The developer key is the kist's Ed25519 developer key and the option its `hp` (ORACLE.md §5), the pair the kist's answers and its vault domain are kept by: a rebuild signed by another developer is another kist and gets another alias.
//!
//! On ferros the kernel derives the seed (the only one that issues keys, VAULT-OUT.md "The rule") and hands it to the kist; on other platforms Photon, which carries the identity service, derives it here.
//! Whoever derives it, the bytes are these: [`seed`] is the one definition and its known answer is the tripwire.
//! From the seed the kist makes its keys: [`bundle`] (Ed25519, Falcon-512, SPHINCS+, as a developer's bundle is made) and [`agreement_secret`] (X25519).

/// The derivation's context. Frozen: every alias of every person in every kist is a function of it.
pub const CONTEXT: &str = "ferros 2026-11-12 kist alias v0";

/// The name the alias's post-quantum keys are derived under ([`crate::pq::SigningBundle::developer`]'s domains `{name}_FALCON512_v1`, `{name}_SPHINCS_PLUS_v1`). Frozen like the context.
pub const BUNDLE_NAME: &str = "FERROS_KIST_ALIAS";

/// The X25519 agreement secret's context, one way from the seed.
pub const AGREEMENT_CONTEXT: &str = "ferros 2026-11-12 kist alias x25519 v0";

/// The alias seed of the kist (`developer`, `option`) for the person whose person key this is.
pub fn seed(person_key: &[u8; 32], developer: &[u8; 32], option: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(CONTEXT);
    h.update(person_key);
    h.update(developer);
    h.update(option);
    *h.finalize().as_bytes()
}

/// The alias's signing keys: the Ed25519 half is the seed itself, the Falcon-512 and SPHINCS+ halves derived from it under [`BUNDLE_NAME`]'s domains, so one 32-byte seed holds every scheme as a developer key does.
#[cfg(feature = "sign")]
pub fn bundle(seed: &[u8; 32]) -> crate::pq::SigningBundle {
    crate::pq::SigningBundle::developer(seed, BUNDLE_NAME)
}

/// The alias's X25519 secret for agreement (a sealed note to itself, a key exchange in its lane): one way from the seed, so it never equals the signing seed.
pub fn agreement_secret(seed: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(AGREEMENT_CONTEXT, seed)
}

/// The X25519 public key of [`agreement_secret`].
#[cfg(feature = "fanout")]
pub fn agreement_public(seed: &[u8; 32]) -> [u8; 32] {
    let mut s = agreement_secret(seed);
    let p = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(s)).to_bytes();
    s.fill(0);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The known-answer vector: the person key bytes 0 to 31, the developer 32 to 63, the option 64 to 95.
    fn vector() -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut p = [0u8; 32];
        let mut d = [0u8; 32];
        let mut o = [0u8; 32];
        for k in 0..32 {
            p[k] = k as u8;
            d[k] = 32 + k as u8;
            o[k] = 64 + k as u8;
        }
        (p, d, o)
    }

    #[test]
    fn seed_known_answer() {
        // Frozen contract, computed apart from this crate (b3sum --derive-key "ferros 2026-11-12 kist alias v0" over the 96 bytes 0 to 95): if it moves, every person's alias in every kist moves with it. The ferros kernel's derivation (process.rs `alias_seed`) is checked against the same answer (`diag alias`).
        let (p, d, o) = vector();
        let mut want = [0u8; 32];
        let hex = b"aa02ea5945db0207816bc2d19ef5808d2a7000be7ce0a4db9113bce8148c377f";
        for k in 0..32 {
            let n = |c: u8| (c as char).to_digit(16).unwrap() as u8;
            want[k] = n(hex[2 * k]) << 4 | n(hex[2 * k + 1]);
        }
        assert_eq!(seed(&p, &d, &o), want);
    }

    #[test]
    fn each_field_moves_it() {
        let (p, d, o) = vector();
        let s = seed(&p, &d, &o);
        // Another person, another developer, another option: each its own alias.
        let mut p1 = p;
        p1[0] ^= 1;
        let mut d1 = d;
        d1[31] ^= 1;
        let mut o1 = o;
        o1[16] ^= 1;
        assert_ne!(seed(&p1, &d, &o), s);
        assert_ne!(seed(&p, &d1, &o), s);
        assert_ne!(seed(&p, &d, &o1), s);
        // The fields do not slide into each other: the developer and option swapped is another kist.
        assert_ne!(seed(&p, &o, &d), s);
        // Not the plain hash of the same bytes, nor any other context's.
        let mut all = [0u8; 96];
        all[..32].copy_from_slice(&p);
        all[32..64].copy_from_slice(&d);
        all[64..].copy_from_slice(&o);
        assert_ne!(*blake3::hash(&all).as_bytes(), s);
        assert_ne!(blake3::derive_key("ferros 2026-11-12 kist alias v1", &all), s);
    }

    #[test]
    fn agreement_is_not_the_seed() {
        let (p, d, o) = vector();
        let s = seed(&p, &d, &o);
        assert_ne!(agreement_secret(&s), s);
        assert_eq!(agreement_secret(&s), agreement_secret(&s));
    }

    #[cfg(feature = "sign")]
    #[test]
    fn bundle_is_deterministic_and_per_alias() {
        let (p, d, o) = vector();
        let s = seed(&p, &d, &o);
        let a = bundle(&s).public();
        assert_eq!(a.to_bytes(), bundle(&s).public().to_bytes());
        // The Ed25519 half is the seed's own key.
        assert_eq!(a.ed25519(), crate::keys::Keypair::from_seed(&s).public.to_bytes());
        let mut o1 = o;
        o1[0] ^= 1;
        assert_ne!(bundle(&seed(&p, &d, &o1)).public().commit(), a.commit());
    }
}
