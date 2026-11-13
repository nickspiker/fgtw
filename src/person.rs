//! The person key (ferros docs/FACETS.md "The alias", D0, decided 2026-11-12 on the owner's delegation): 32 random bytes that stand for the person, the root every kist's alias is derived from ([`crate::alias`]).
//!
//! - **Minted** once for an identity, at its genesis or by the first of its devices that runs this, from several independent entropy sources ([`mint`]: the single egg rule, no one source decides it). Never derived from the handle: nobody who knows the handle computes it.
//! - **Kept** by the fleet, as a fact of the person's space ([`crate::space`]) of its own kind ([`KIND`]), the key itself sealed under the fleet key inside the fact, so the space a device keeps in its vault holds it only sealed and it opens only with the fleet key, which a device holds in RAM.
//! - **Re-sealed, never rotated, at a shrink**: a device that holds the person key and sees its fact sealed under an earlier fleet key seals it again under the current one ([`put`] with the same mint stamp). The key itself does not change; changing it is an act of its own (it changes every alias).
//! - **One per identity**: should two devices mint at once (neither had heard the other's), both facts travel and every device takes the one minted first ([`find`]: the earliest mint stamp, then the smaller id), so the fleet settles on one key and keeps it.
//! - **Opened** by each device's identity service at attest with the fleet key it recovers, held in RAM only, and handed to whatever derives aliases (the ferros kernel; Photon elsewhere). Total loss of every device loses it as it loses the fleet key; TOKEN's custodian recovery is where it would come back from.

#[cfg(feature = "fanout")]
use crate::space::{Entry, Space};
#[cfg(feature = "fanout")]
use alloc::vec::Vec;
#[cfg(feature = "fanout")]
use vsf::types::EtType;
#[cfg(feature = "fanout")]
use vsf::VsfType;

/// The space kind the person key's fact is kept under: fgtw's own, counted down from the top so it never meets an embedding's vocabulary, which counts up from 0 (ferros_space's kinds).
pub const KIND: u8 = 255;

/// The context the eggs are mixed under.
pub const MINT_CONTEXT: &str = "ferros 2026-11-12 person key mint v0";
/// The context of a person key's id (the fact's id, one way from the key).
pub const ID_CONTEXT: &str = "ferros 2026-11-12 person key id v0";
/// The context of the key the person key is sealed under, from the fleet key.
#[cfg(feature = "fanout")]
const SEAL_CONTEXT: &str = "ferros 2026-11-12 person key XChaCha20-Poly1305 v0";

/// A person key from `eggs`, each an independent source's bytes (owner's single egg rule: never one source).
/// At least two, none empty, or None: the caller refuses to mint rather than mint from one.
/// Each egg is framed by its length (u64 LE) under [`MINT_CONTEXT`], so no two lists of eggs hash the same input.
pub fn mint(eggs: &[&[u8]]) -> Option<[u8; 32]> {
    if eggs.len() < 2 || eggs.iter().any(|e| e.is_empty()) {
        return None;
    }
    let mut h = blake3::Hasher::new_derive_key(MINT_CONTEXT);
    for e in eggs {
        h.update(&(e.len() as u64).to_le_bytes());
        h.update(e);
    }
    Some(*h.finalize().as_bytes())
}

/// A person key's id: one way from the key, what its fact is kept by, so two minted keys are two facts and neither writes over the other.
pub fn id(key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(ID_CONTEXT, key)
}

/// What the space holds of the person key, as this device can see it with the fleet key it holds.
#[cfg(feature = "fanout")]
#[derive(Debug, PartialEq)]
pub enum Found {
    /// No person key yet: the identity has none, and this device may mint it (once its space has heard from the fleet).
    None,
    /// The person key, opened under this fleet key, with its id and when it was minted.
    Key { key: [u8; 32], id: [u8; 32], minted: i64 },
    /// The fleet's person key (the first minted) is sealed under a fleet key this device does not hold, or does not open: never mint over it; wait for a device that holds the key to seal it under the current one.
    Elsewhere { id: [u8; 32], minted: i64 },
}

/// The fields of a person key's fact: its id, when it was minted, the fleet key's fingerprint it is sealed under, and the wrap. None for a fact that is not one.
#[cfg(feature = "fanout")]
fn fields(e: &Entry) -> Option<([u8; 32], i64, [u8; 32], &[u8])> {
    let id = match e.id.as_slice() {
        [VsfType::hb(b)] => <[u8; 32]>::try_from(b.as_slice()).ok()?,
        _ => return None,
    };
    let (mut minted, mut kfp, mut wrap) = (None, None, None);
    for v in &e.value {
        match v {
            VsfType::e(EtType::e6(t)) => minted = Some(*t),
            VsfType::hb(b) => kfp = <[u8; 32]>::try_from(b.as_slice()).ok(),
            VsfType::v(w, b) if *w == vsf::crypto_algorithms::WRAP_XCHACHA20POLY1305 => wrap = Some(b.as_slice()),
            _ => {}
        }
    }
    Some((id, minted?, kfp?, wrap?))
}

/// The associated data a person key is sealed with: the identity's handle proof, the fleet key's fingerprint and the key's id, so a wrap opens only for its own identity, under its own fleet key, as its own fact.
#[cfg(feature = "fanout")]
fn aad(handle_proof: &[u8; 32], kfp: &[u8; 32], id: &[u8; 32]) -> Vec<u8> {
    let mut a = Vec::with_capacity(96);
    a.extend_from_slice(handle_proof);
    a.extend_from_slice(kfp);
    a.extend_from_slice(id);
    a
}

/// The person key as the space holds it, opened with `fleet_key`: the first minted of its facts (the earliest stamp, then the smaller id), never a later one while that one does not open here.
#[cfg(feature = "fanout")]
pub fn find(space: &Space, handle_proof: &[u8; 32], fleet_key: &[u8; 32]) -> Found {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
    let Some((id, minted, kfp, wrap)) = space.live(KIND).filter_map(fields).min_by(|a, b| (a.1, a.0).cmp(&(b.1, b.0))) else {
        return Found::None;
    };
    let elsewhere = Found::Elsewhere { id, minted };
    if crate::fanout::fleet_key_fingerprint(fleet_key) != kfp {
        return elsewhere;
    }
    // WHY: the wrap comes from another device or fgtw.org; shorter than a nonce and a tag it is not one, and the split below would panic.
    if wrap.len() < 24 + 16 {
        return elsewhere;
    }
    let (nonce, ct) = wrap.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().unwrap();
    let mut sk = blake3::derive_key(SEAL_CONTEXT, fleet_key);
    let opened = XChaCha20Poly1305::new((&sk).into()).decrypt((&nonce).into(), Payload { msg: ct, aad: &aad(handle_proof, &kfp, &id) });
    sk.fill(0);
    let Ok(mut plain) = opened else { return elsewhere };
    // WHY: an authenticated wrap of another length was sealed by something that is not this module; a key is 32 bytes.
    if plain.len() != 32 {
        plain.fill(0);
        return elsewhere;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&plain);
    plain.fill(0);
    if self::id(&key) != id {
        key.fill(0);
        return elsewhere;
    }
    Found::Key { key, id, minted }
}

/// Whether the person key's fact is sealed under `fleet_key` already (false: a device holding the key should [`put`] it again).
#[cfg(feature = "fanout")]
pub fn sealed_under(space: &Space, key: &[u8; 32], fleet_key: &[u8; 32]) -> bool {
    let want = id(key);
    let kfp = crate::fanout::fleet_key_fingerprint(fleet_key);
    space.live(KIND).filter_map(fields).any(|(i, _, k, _)| i == want && k == kfp)
}

/// The person key's fact written into the space, sealed under `fleet_key` (a fresh nonce from [`crate::random32`]): at its mint, or again under a new fleet key with the same `minted` stamp. `by` is this device's key, `now` the Eagle time; the write is stamped past the fact's last. True when the space changed.
#[cfg(feature = "fanout")]
pub fn put(space: &mut Space, key: &[u8; 32], minted: i64, handle_proof: &[u8; 32], fleet_key: &[u8; 32], by: &[u8; 32], now: i64) -> Result<bool, alloc::string::String> {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
    let id = id(key);
    let kfp = crate::fanout::fleet_key_fingerprint(fleet_key);
    let r = crate::random32();
    let nonce: [u8; 24] = r[..24].try_into().unwrap();
    let mut sk = blake3::derive_key(SEAL_CONTEXT, fleet_key);
    let ct = XChaCha20Poly1305::new((&sk).into()).encrypt((&nonce).into(), Payload { msg: key, aad: &aad(handle_proof, &kfp, &id) });
    sk.fill(0);
    let ct = ct.map_err(|_| alloc::string::String::from("person key: seal failed"))?;
    let mut wrap = nonce.to_vec();
    wrap.extend_from_slice(&ct);
    let fact_id = alloc::vec![VsfType::hb(id.to_vec())];
    let updated = space.get(KIND, &fact_id).map_or(now, |e| now.max(e.updated + 1));
    let value = alloc::vec![VsfType::e(EtType::e6(minted)), VsfType::hb(kfp.to_vec()), VsfType::v(vsf::crypto_algorithms::WRAP_XCHACHA20POLY1305, wrap)];
    Ok(space.put(Entry { kind: KIND, id: fact_id, value, updated, by: *by, gone: false }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HP: [u8; 32] = [0x11; 32];
    const FK: [u8; 32] = [0x22; 32];
    const FK1: [u8; 32] = [0x33; 32];
    const ME: [u8; 32] = [0x44; 32];
    const SIB: [u8; 32] = [0x55; 32];

    #[test]
    fn mint_needs_two_eggs() {
        assert_eq!(mint(&[]), None);
        assert_eq!(mint(&[&[1u8; 32]]), None);
        assert_eq!(mint(&[&[1u8; 32], &[]]), None);
        let a = mint(&[&[1u8; 32], &[2u8; 32]]).unwrap();
        // Every egg counts, and its place and its length do.
        assert_ne!(a, mint(&[&[1u8; 32], &[3u8; 32]]).unwrap());
        assert_ne!(a, mint(&[&[2u8; 32], &[1u8; 32]]).unwrap());
        assert_ne!(mint(&[&[1u8; 2], &[1u8; 1]]), mint(&[&[1u8; 1], &[1u8; 2]]));
        assert_eq!(a, mint(&[&[1u8; 32], &[2u8; 32]]).unwrap());
    }

    #[cfg(feature = "fanout")]
    #[test]
    fn put_find_round_trip_thru_the_document() {
        let key = mint(&[&[7u8; 32], &[8u8; 32]]).unwrap();
        let mut s = Space::new();
        assert_eq!(find(&s, &HP, &FK), Found::None);
        assert!(put(&mut s, &key, 100, &HP, &FK, &ME, 100).unwrap());
        // As kept in the vault and handed between devices: the document, never the key in the clear.
        let doc = s.to_doc(101).unwrap();
        assert!(!doc.windows(32).any(|w| w == key));
        let back = Space::from_doc(&doc).unwrap();
        assert_eq!(find(&back, &HP, &FK), Found::Key { key, id: id(&key), minted: 100 });
        assert!(sealed_under(&back, &key, &FK));
        // Another identity's handle proof does not open it.
        assert_eq!(find(&back, &[0x12; 32], &FK), Found::Elsewhere { id: id(&key), minted: 100 });
    }

    #[cfg(feature = "fanout")]
    #[test]
    fn a_shrink_reseals_and_never_rotates() {
        let key = mint(&[&[7u8; 32], &[8u8; 32]]).unwrap();
        let mut s = Space::new();
        put(&mut s, &key, 100, &HP, &FK, &ME, 100).unwrap();
        // The fleet key rotated: a device with only the new key cannot open it, and must not mint.
        assert_eq!(find(&s, &HP, &FK1), Found::Elsewhere { id: id(&key), minted: 100 });
        assert!(!sealed_under(&s, &key, &FK1));
        // The device that held the key seals it again under the new one, the same mint stamp.
        assert!(put(&mut s, &key, 100, &HP, &FK1, &ME, 200).unwrap());
        assert_eq!(find(&s, &HP, &FK1), Found::Key { key, id: id(&key), minted: 100 });
        // The old key opens it no more (one fact, sealed once).
        assert_eq!(find(&s, &HP, &FK), Found::Elsewhere { id: id(&key), minted: 100 });
        // A sibling still holding the copy sealed under the old key merges in: the newer seal wins.
        let mut old = Space::new();
        put(&mut old, &key, 100, &HP, &FK, &SIB, 150).unwrap();
        s.merge(old);
        assert_eq!(find(&s, &HP, &FK1), Found::Key { key, id: id(&key), minted: 100 });
    }

    #[cfg(feature = "fanout")]
    #[test]
    fn two_mints_settle_on_the_first() {
        let first = mint(&[&[1u8; 32], &[2u8; 32]]).unwrap();
        let later = mint(&[&[3u8; 32], &[4u8; 32]]).unwrap();
        let mut a = Space::new();
        put(&mut a, &first, 100, &HP, &FK, &ME, 100).unwrap();
        let mut b = Space::new();
        put(&mut b, &later, 120, &HP, &FK, &SIB, 120).unwrap();
        let (mut ab, mut ba) = (a.clone(), b.clone());
        ab.merge(b);
        ba.merge(a);
        assert_eq!(ab, ba);
        assert_eq!(find(&ab, &HP, &FK), Found::Key { key: first, id: id(&first), minted: 100 });
        // Re-sealed later under a new key, the first stays first: its mint stamp, not its write stamp, decides.
        put(&mut ab, &first, 100, &HP, &FK1, &ME, 500).unwrap();
        put(&mut ab, &later, 120, &HP, &FK1, &SIB, 400).unwrap();
        assert_eq!(find(&ab, &HP, &FK1), Found::Key { key: first, id: id(&first), minted: 100 });
        // While the first is sealed under a key this device does not hold, the later one is never taken instead.
        let mut c = Space::new();
        put(&mut c, &first, 100, &HP, &FK, &ME, 100).unwrap();
        put(&mut c, &later, 120, &HP, &FK1, &SIB, 120).unwrap();
        assert_eq!(find(&c, &HP, &FK1), Found::Elsewhere { id: id(&first), minted: 100 });
    }

    #[cfg(feature = "fanout")]
    #[test]
    fn a_swapped_wrap_does_not_open() {
        let a = mint(&[&[1u8; 32], &[2u8; 32]]).unwrap();
        let b = mint(&[&[3u8; 32], &[4u8; 32]]).unwrap();
        let mut sa = Space::new();
        put(&mut sa, &a, 100, &HP, &FK, &ME, 100).unwrap();
        let mut sb = Space::new();
        put(&mut sb, &b, 100, &HP, &FK, &ME, 100).unwrap();
        // b's wrap under a's id: the id is bound in, so it does not open.
        let mut e = sa.entries()[0].clone();
        e.value = sb.entries()[0].value.clone();
        e.updated += 1;
        let mut s = Space::new();
        s.put(e);
        assert_eq!(find(&s, &HP, &FK), Found::Elsewhere { id: id(&a), minted: 100 });
    }
}
