//! Per-member fan-out — sealed per-device delivery of the current fleet key (photon docs/fleet-key.md).
//!
//! v2 (the ira fan-out): ONE fleet key, sealed separately to every unlocked member's permanent device ira — the pubkey already in the genesis-verified membership chain.
//! The wrap KEK is hybrid: per-wrap X25519 ECDH to the member ira (opening requires that machine's ira SECRET — a thief holding the identity seed still opens nothing but its own locked-out device's wrap) ‖ the identity seed (a quantum harvester who breaks the curve still needs the seed).
//! An identity-seed-only KEK is FORBIDDEN: a stolen attested device holds the seed, and a lock would be paper.
//! Wraps bind the key FINGERPRINT, not the publish revision, so grow publishes (add a wrap, same key) never invalidate existing wraps.
//! The key is minted only at genesis and on shrink (lock, self-departure); a locked/departed device is simply not a wrap target under the new key — and there is NO seal-under-the-prior-key chain (that would be a skeleton key).
//! A device recovers the current key by trial-decrypting its own wrap with its ira keypair + the identity seed — no live sibling, no ceremony, no side channel; the ira re-derives from the machine oracle, so a wiped device recovers by construction.
//!
//! This is the crypto core; the always-online transport that posts/fetches these blobs (and drives grow/shrink publishes) is the client's job.

use crate::keys::Keypair;
use ed25519_dalek::VerifyingKey;

/// A fresh random fleet key — minted at genesis and on shrink only; devices RECEIVE the current one from the fan-out.
pub fn new_fleet_key() -> [u8; 32] {
    rand::random()
}

/// The key's public identity: identifies the fleet key without revealing it. Same fingerprint across publishes = same key (a grow); a new fingerprint = a mint happened (a shrink) and the state slots are re-sealed under it.
pub fn fleet_key_fingerprint(fleet_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("photon.fleetkey.fp.v1", fleet_key)
}

// Version rides as a literal binary numeral, never an ASCII digit baked into the string (repo convention 2026-08-01).
const FANOUT_DOMAIN_TEXT: &[u8] = b"PHOTON_FLEET_FANOUT_v";
const FANOUT_MAGIC: &[u8; 3] = b"PFO";
pub const FANOUT_VERSION: u8 = 2;

/// One sealed copy of the fleet key for one (unlabelled) member. `epk` is a per-wrap ephemeral X25519 public; `commit` binds the ciphertext to the exact derived key (KEY-COMMITTING — so a malicious member can't craft one `ct` that opens to different keys for two devices, the invisible-salamander split); `ct` is XChaCha20-Poly1305(fleet_key) under the hybrid-derived key. No recipient label — a device recomputes `commit` to find its own — so the slot carries only a count, never recipient pubkeys.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FanoutWrap {
    pub epk: [u8; 32],
    pub commit: [u8; 32],
    pub ct: Vec<u8>,
}

/// Ed25519 device pubkey → its X25519 (Montgomery) counterpart, so we can seal to a key already in the membership chain. The matching secret side is `SigningKey::to_scalar_bytes` (§`fanout_open`); `to_montgomery` and the clamped scalar agree on the same point.
fn ed_to_x25519_public(ed_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
    Some(VerifyingKey::from_bytes(ed_pubkey).ok()?.to_montgomery().to_bytes())
}

/// Derive the per-wrap AEAD key AND its key-commitment from the ECDH shared secret + the identity seed (the hybrid: ira-secret possession, seed harvest-hardening).
/// Binds the FLEET (`handle_proof`) and the KEY (`kfp`), so a wrap is valid only for (this fleet, this key, this recipient) — no cross-fleet or cross-key splicing. The ROTATOR is deliberately NOT bound: a grow appends wraps minted by a different publisher than the original minter, so a rotator bind would strand every pre-grow wrap — and it bought nothing, because splicing a valid wrap of the SAME key is a no-op and any other key fails its fingerprint. The revision is not bound either (grows must not invalidate wraps). `epk` MUST stay in this hash: it is what makes each wrap's key unique, which is what makes the fixed AEAD nonce safe — never derive the key from `shared` alone. The 64-byte XOF splits into `(aead_key, commit)`; `commit` binds `ct` to this exact key (defeats the partitioning-oracle / invisible-salamander attack that Poly1305 alone allows) and doubles as the recipient selector.
#[allow(clippy::too_many_arguments)]
fn fanout_keys(
    handle_proof: &[u8; 32],
    kfp: &[u8; 32],
    recipient_ed: &[u8; 32],
    shared: &[u8; 32],
    epk: &[u8; 32],
    recipient_xpk: &[u8; 32],
    identity_seed: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut h = blake3::Hasher::new();
    h.update(FANOUT_DOMAIN_TEXT);
    h.update(&[FANOUT_VERSION]);
    h.update(handle_proof);
    h.update(kfp);
    // Bind the canonical Ed25519 device pubkey too: to_montgomery drops the sign bit, so two distinct Ed25519 keys can share a Montgomery u — this disambiguates them.
    h.update(recipient_ed);
    h.update(epk);
    h.update(recipient_xpk);
    h.update(shared);
    h.update(identity_seed);
    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    let mut ak = [0u8; 32];
    let mut cm = [0u8; 32];
    ak.copy_from_slice(&out[..32]);
    cm.copy_from_slice(&out[32..]);
    (ak, cm)
}

/// Seal `fleet_key` separately to each member ira for `(handle_proof, kfp)`. `members` carries bare ed25519 device pubkeys straight off the membership chain — the caller passes every UNLOCKED member (its own device included); a locked or departed ira is simply omitted and cannot recover the key.
pub fn fanout_seal(
    handle_proof: &[u8; 32],
    fleet_key: &[u8; 32],
    members: &[[u8; 32]],
    identity_seed: &[u8; 32],
) -> Result<Vec<FanoutWrap>, String> {
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
    use x25519_dalek::{PublicKey as XPublic, StaticSecret};
    let kfp = fleet_key_fingerprint(fleet_key);
    let mut wraps = Vec::with_capacity(members.len());
    for member_ed in members {
        let recipient_xpk =
            ed_to_x25519_public(member_ed).ok_or_else(|| "fanout: bad member pubkey".to_string())?;
        // Fresh ephemeral per wrap → the key is unique per wrap → a zero nonce is safe (no reuse).
        let esk = StaticSecret::from(rand::random::<[u8; 32]>());
        let epk = XPublic::from(&esk).to_bytes();
        let ss = esk.diffie_hellman(&XPublic::from(recipient_xpk));
        // Reject a low-order member pubkey (a zero/small-order shared secret would be attacker-predictable).
        if !ss.was_contributory() {
            return Err("fanout: member pubkey is low-order".into());
        }
        let shared = ss.to_bytes();
        let (ak, commit) = fanout_keys(
            handle_proof,
            &kfp,
            member_ed,
            &shared,
            &epk,
            &recipient_xpk,
            identity_seed,
        );
        // XChaCha20-Poly1305 with a fixed 24-byte zero nonce — safe because `ak` is unique per wrap (fresh ephemeral epk per member), so no nonce is ever reused across distinct plaintexts.
        let ct = XChaCha20Poly1305::new((&ak).into())
            .encrypt((&[0u8; 24]).into(), fleet_key.as_slice())
            .map_err(|_| "fanout: seal failed".to_string())?;
        wraps.push(FanoutWrap { epk, commit, ct });
    }
    Ok(wraps)
}

/// Recover the fleet key for `(handle_proof, kfp)` by finding this device's wrap (via the key-commitment) and decrypting with the ira keypair + the identity seed. `None` if this device has no wrap (locked, departed, or a blob for a different key). The recovered key is verified against `kfp` — a blob whose wraps and fingerprint disagree is refused.
pub fn fanout_open(
    handle_proof: &[u8; 32],
    kfp: &[u8; 32],
    wraps: &[FanoutWrap],
    device_key: &Keypair,
    identity_seed: &[u8; 32],
) -> Option<[u8; 32]> {
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
    use x25519_dalek::{PublicKey as XPublic, StaticSecret};
    let my_xsk = StaticSecret::from(device_key.secret.to_scalar_bytes());
    let my_xpk = device_key.public.to_montgomery().to_bytes();
    let my_ed = device_key.public.to_bytes();
    for w in wraps {
        let ss = my_xsk.diffie_hellman(&XPublic::from(w.epk));
        // Reject a low-order/attacker-chosen epk (a zero shared secret would let a malicious member install a chosen key).
        if !ss.was_contributory() {
            continue;
        }
        let shared = ss.to_bytes();
        let (ak, commit) = fanout_keys(
            handle_proof,
            kfp,
            &my_ed,
            &shared,
            &w.epk,
            &my_xpk,
            identity_seed,
        );
        // Key-commitment gate: accept only a wrap bound to THIS exact derived key (defeats a crafted ct that opens under two keys), which doubles as the recipient selector.
        if commit != w.commit {
            continue;
        }
        if let Ok(pt) = XChaCha20Poly1305::new((&ak).into()).decrypt((&[0u8; 24]).into(), w.ct.as_slice()) {
            if let Ok(k) = <[u8; 32]>::try_from(pt.as_slice()) {
                // The blob's fingerprint must name the key its wraps actually carry.
                if fleet_key_fingerprint(&k) == *kfp {
                    return Some(k);
                }
            }
        }
    }
    None
}

/// Serialize a fan-out (revision + kfp + rotator + wraps) for the always-online slot. Opaque per-wrap ciphertext, so a plain length-framed layout; the envelope on the wire stays VSF. `revision` sits at the same offset as every prior version's epoch, so the worker's version-agnostic monotonic guard reads it unchanged. The rotator's device pubkey is public (it is in the membership chain).
pub fn fanout_to_bytes(revision: u64, kfp: &[u8; 32], rotator_ed: &[u8; 32], wraps: &[FanoutWrap]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(FANOUT_MAGIC);
    out.push(FANOUT_VERSION);
    out.extend_from_slice(&revision.to_be_bytes());
    out.extend_from_slice(kfp);
    out.extend_from_slice(rotator_ed);
    out.extend_from_slice(&(wraps.len() as u32).to_be_bytes());
    for w in wraps {
        out.extend_from_slice(&w.epk);
        out.extend_from_slice(&w.commit);
        out.extend_from_slice(&(w.ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&w.ct);
    }
    out
}

// The version-agnostic revision reader lives at the crate root (`crate::fanout_blob_epoch`) because the WORKER needs it without compiling any fan-out crypto; re-exported so fan-out call sites read naturally.
pub use crate::fanout_blob_epoch;

/// Parse a fan-out blob. Bounds-checked — a truncated or corrupt blob fails rather than panicking. A pre-v2 blob fails the version gate and reads as an error the caller treats as absent — the first v2 publish steps OVER it (hard flag-day, no read-both), using [`fanout_blob_epoch`] to keep the revision monotonic across the boundary.
pub fn fanout_from_bytes(bytes: &[u8]) -> Result<(u64, [u8; 32], [u8; 32], Vec<FanoutWrap>), String> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], String> {
        if *p + n > bytes.len() {
            return Err("fanout: truncated".into());
        }
        let s = &bytes[*p..*p + n];
        *p += n;
        Ok(s)
    };
    if take(&mut p, 3)? != FANOUT_MAGIC {
        return Err("fanout: bad magic".into());
    }
    if take(&mut p, 1)? != [FANOUT_VERSION] {
        return Err("fanout: version mismatch".into());
    }
    let revision = u64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
    let kfp: [u8; 32] = take(&mut p, 32)?.try_into().unwrap();
    let rotator_ed: [u8; 32] = take(&mut p, 32)?.try_into().unwrap();
    let count = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    // A fleet is a person's devices — a four-figure count is adversarial. Reject before allocating/looping.
    if count > 1024 {
        return Err("fanout: implausible wrap count".into());
    }
    let mut wraps = Vec::with_capacity(count);
    for _ in 0..count {
        let epk: [u8; 32] = take(&mut p, 32)?.try_into().unwrap();
        let commit: [u8; 32] = take(&mut p, 32)?.try_into().unwrap();
        let ct_len = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
        let ct = take(&mut p, ct_len)?.to_vec();
        wraps.push(FanoutWrap { epk, commit, ct });
    }
    Ok((revision, kfp, rotator_ed, wraps))
}

/// The shrink trigger (docs/fleet-key.md): a fan-out wrapping MORE iras than the desired set (fold minus locked) means a departed/locked member's wrap lingers — any surviving member mints, and the mint carries the fstate re-seal atomically.
pub fn fanout_needs_rotation(wrap_count: usize, member_count: usize) -> bool {
    member_count > 0 && wrap_count > member_count
}

/// The grow trigger: fewer wraps than desired iras means a member is waiting for its wrap (fresh bind, unlock) — any keyholder publishes revision+1 with the SAME key and the missing wrap(s) added. Never a mint.
pub fn fanout_needs_grow(wrap_count: usize, member_count: usize) -> bool {
    wrap_count < member_count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }
    fn pk(k: &Keypair) -> [u8; 32] {
        k.public.to_bytes()
    }

    #[test]
    fn publish_predicates_split_shrink_from_grow() {
        // Shrink: a departed/locked member's wrap lingers → mint.
        assert!(fanout_needs_rotation(3, 2));
        assert!(fanout_needs_rotation(2, 1));
        // Steady state: counts match → nothing to do.
        assert!(!fanout_needs_rotation(3, 3));
        assert!(!fanout_needs_grow(3, 3));
        // Grow: a bound/unlocked member awaits its wrap → add under the SAME key, never mint.
        assert!(!fanout_needs_rotation(2, 3));
        assert!(fanout_needs_grow(2, 3));
        // No fold / empty fleet: never mint toward zero members (worker refuses zero-member folds anyway).
        assert!(!fanout_needs_rotation(1, 0));
        assert!(!fanout_needs_rotation(0, 0));
        // No fan-out yet (genesis): establish, don't heal.
        assert!(!fanout_needs_rotation(0, 1));
        assert!(fanout_needs_grow(0, 1));
        // Equal-counts residue, stated: simultaneous depart+bind is invisible to a count check until the next shrink or grow heals it.
        assert!(!fanout_needs_rotation(2, 2));
    }

    #[test]
    fn fanout_seals_to_member_iras_and_excludes_everyone_else() {
        let a = key(1); // the rotator
        let b = key(2);
        let c = key(3);
        let outsider = key(9);
        let hp = [0x11u8; 32];
        let seed = [0x42u8; 32];
        let fleet_key = new_fleet_key();
        let kfp = fleet_key_fingerprint(&fleet_key);
        let members = vec![pk(&a), pk(&b), pk(&c)];
        let wraps = fanout_seal(&hp, &fleet_key, &members, &seed).unwrap();
        assert_eq!(wraps.len(), 3);
        // Every member ira recovers the exact key with its device keypair + the identity seed — no ceremony artifact involved.
        for kp in [&a, &b, &c] {
            let got = fanout_open(&hp, &kfp, &wraps, kp, &seed);
            assert_eq!(got.expect("member opens"), fleet_key);
        }
        // The identity seed alone is NOT enough: a locked device's ira gets no wrap, and the seed it still holds opens nothing (the lock is not paper).
        assert!(fanout_open(&hp, &kfp, &wraps, &outsider, &seed).is_none());
        // The ira alone is NOT enough either: the right device with the wrong seed cannot open (the harvest-hardening half).
        assert!(fanout_open(&hp, &kfp, &wraps, &b, &[0u8; 32]).is_none());
        // Bound to (fleet, key): no cross-fleet or cross-key splicing. (The rotator is deliberately unbound — see fanout_keys.)
        assert!(fanout_open(&[0x22u8; 32], &kfp, &wraps, &b, &seed).is_none());
        assert!(fanout_open(&hp, &[0xEEu8; 32], &wraps, &b, &seed).is_none());
        // Serialize round-trips (revision + kfp + rotator + wraps) and the recovered blob still opens.
        let bytes = fanout_to_bytes(7, &kfp, &pk(&a), &wraps);
        let (rev, got_kfp, got_rotator, back) = fanout_from_bytes(&bytes).unwrap();
        assert_eq!(rev, 7);
        assert_eq!(got_kfp, kfp);
        assert_eq!(got_rotator, pk(&a));
        assert_eq!(back, wraps);
        assert_eq!(fanout_open(&hp, &kfp, &back, &b, &seed).unwrap(), fleet_key);
        assert!(fanout_from_bytes(&bytes[..bytes.len() - 5]).is_err());
        // A pre-v2 blob fails the version gate — the hard flag-day.
        let mut legacy = bytes.clone();
        legacy[3] = 1;
        assert!(fanout_from_bytes(&legacy).is_err());
        // …but its REVISION still reads, which is what lets a v2 publisher step OVER it instead of proposing revision 1 and being refused as stale forever.
        assert_eq!(fanout_blob_epoch(&legacy), Some(7));
        assert_eq!(fanout_blob_epoch(&bytes), Some(7));
        assert_eq!(fanout_blob_epoch(b"nope"), None);
        // A GROW keeps every existing wrap valid: revision moves, the key does not, and old wraps still open (the kfp bind, not a revision bind).
        let d = key(4);
        let mut grown = wraps.clone();
        grown.extend(fanout_seal(&hp, &fleet_key, &[pk(&d)], &seed).unwrap());
        // The GROWER (d's sponsor could be any keyholder — here b) publishes; the blob rotator changes, and every wrap still opens because the rotator is unbound.
        let grown_bytes = fanout_to_bytes(8, &kfp, &pk(&b), &grown);
        let (_, gk, _gr, gw) = fanout_from_bytes(&grown_bytes).unwrap();
        assert_eq!(fanout_open(&hp, &gk, &gw, &b, &seed).unwrap(), fleet_key, "pre-grow wrap survives the grow");
        assert_eq!(fanout_open(&hp, &gk, &gw, &d, &seed).unwrap(), fleet_key, "the added ira opens its new wrap");
        // A lying fingerprint is refused even where the wrap opens: the recovered key must MATCH the blob's kfp.
        let fake_kfp = [0xABu8; 32];
        let lying = fanout_seal_with_kfp_for_test(&hp, &fleet_key, &fake_kfp, &[pk(&b)], &seed);
        assert!(fanout_open(&hp, &fake_kfp, &lying, &b, &seed).is_none());
        // A tampered wrap fails its AEAD tag (no silent wrong key).
        let mut tampered = wraps.clone();
        *tampered[0].ct.last_mut().unwrap() ^= 1;
        assert!(fanout_open(&hp, &kfp, &tampered[..1], &a, &seed).is_none());
        // A low-order (all-zero) epk is rejected by the contributory-DH check, not opened.
        let mut loword = wraps.clone();
        loword[0].epk = [0u8; 32];
        assert!(fanout_open(&hp, &kfp, &loword[..1], &a, &seed).is_none());
        // Wrap-count sanity: an implausible count is rejected before allocation (count sits after magic+ver+revision+kfp+rotator).
        let mut huge = fanout_to_bytes(7, &kfp, &pk(&a), &wraps);
        huge[76..80].copy_from_slice(&2000u32.to_be_bytes());
        assert!(fanout_from_bytes(&huge).is_err());
    }

    /// Seal under a caller-chosen (wrong) fingerprint — exists only to prove `fanout_open` refuses a blob whose fingerprint lies about its key.
    fn fanout_seal_with_kfp_for_test(
        handle_proof: &[u8; 32],
        fleet_key: &[u8; 32],
        kfp: &[u8; 32],
        members: &[[u8; 32]],
        identity_seed: &[u8; 32],
    ) -> Vec<FanoutWrap> {
        use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
        use x25519_dalek::{PublicKey as XPublic, StaticSecret};
        let mut wraps = Vec::new();
        for member_ed in members {
            let recipient_xpk = ed_to_x25519_public(member_ed).unwrap();
            let esk = StaticSecret::from(rand::random::<[u8; 32]>());
            let epk = XPublic::from(&esk).to_bytes();
            let shared = esk.diffie_hellman(&XPublic::from(recipient_xpk)).to_bytes();
            let (ak, commit) = fanout_keys(handle_proof, kfp, member_ed, &shared, &epk, &recipient_xpk, identity_seed);
            let ct = XChaCha20Poly1305::new((&ak).into()).encrypt((&[0u8; 24]).into(), fleet_key.as_slice()).unwrap();
            wraps.push(FanoutWrap { epk, commit, ct });
        }
        wraps
    }
}
