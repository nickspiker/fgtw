//! Per-member fan-out — sealed per-device delivery of the current fleet key (BRAID v0.2 §14.2).
//!
//! Each epoch mints a FRESH fleet key and seals it SEPARATELY to every COMPLIANT member device.
//! v1 (the egged fanout): a wrap's key binds BOTH the per-wrap X25519 ECDH AND the durable pairwise CLUTCH-derived secret between the rotator and the recipient — the 8-egg ceremony is what makes the pair secret post-quantum, so a harvested blob is not opened by a future x25519 break.
//! ONE mode, no fallback: a member device with no pair secret to the rotator gets NO wrap — dark until it re-clutches and the next rotation includes it (hard flag-day, user directive 2026-08-01).
//! A device recovers the current key by trial-decrypting its own wrap with its device key + its pair secret to the rotator — no live sibling.
//! A removed device is simply not a wrap target next epoch, so the new key is unreadable to it: removal removes, and there is NO seal-under-the-prior-key chain (that would be a skeleton key).
//!
//! This is the crypto core; the always-online transport that posts/fetches these blobs (and drives epoch rotation) is the client's job.

use crate::keys::Keypair;
use ed25519_dalek::VerifyingKey;

/// A fresh random fleet key — minted per epoch by rotation; devices RECEIVE the current one from the fan-out.
pub fn new_fleet_key() -> [u8; 32] {
    rand::random()
}

// Version rides as a literal binary numeral, never an ASCII digit baked into the string (repo convention 2026-08-01).
const FANOUT_DOMAIN_TEXT: &[u8] = b"PHOTON_FLEET_FANOUT_v";
const FANOUT_MAGIC: &[u8; 3] = b"PFO";
pub const FANOUT_VERSION: u8 = 1;

/// One sealed copy of the fleet key for one (unlabelled) member. `epk` is a per-wrap ephemeral X25519 public; `commit` binds the ciphertext to the exact derived key (KEY-COMMITTING — so a malicious member can't craft one `ct` that opens to different keys for two devices, the invisible-salamander split); `ct` is ChaCha20-Poly1305(fleet_key) under the hybrid-derived key. No recipient label — a device recomputes `commit` to find its own — so the slot carries only a count, never recipient pubkeys.
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

/// Derive the per-wrap AEAD key AND its key-commitment from the ECDH shared secret + the rotator↔recipient pair secret (the hybrid: ECDH freshness, CLUTCH post-quantum depth).
/// Binds the FLEET (`handle_proof`), `epoch`, and the ROTATOR device, so a wrap is valid only for (this fleet, this epoch, this rotator, this recipient) — no cross-fleet, cross-epoch, or cross-rotator splicing. `epk` MUST stay in this hash: it is what makes each wrap's key unique, which is what makes the fixed AEAD nonce safe — never derive the key from `shared` alone. The 64-byte XOF splits into `(aead_key, commit)`; `commit` binds `ct` to this exact key (defeats the partitioning-oracle / invisible-salamander attack that Poly1305 alone allows) and doubles as the recipient selector.
#[allow(clippy::too_many_arguments)]
fn fanout_keys(
    handle_proof: &[u8; 32],
    epoch: u64,
    rotator_ed: &[u8; 32],
    recipient_ed: &[u8; 32],
    shared: &[u8; 32],
    epk: &[u8; 32],
    recipient_xpk: &[u8; 32],
    pair_secret: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut h = blake3::Hasher::new();
    h.update(FANOUT_DOMAIN_TEXT);
    h.update(&[FANOUT_VERSION]);
    h.update(handle_proof);
    h.update(&epoch.to_le_bytes());
    h.update(rotator_ed);
    // Bind the canonical Ed25519 device pubkey too: to_montgomery drops the sign bit, so two distinct Ed25519 keys can share a Montgomery u — this disambiguates them.
    h.update(recipient_ed);
    h.update(epk);
    h.update(recipient_xpk);
    h.update(shared);
    h.update(pair_secret);
    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    let mut ak = [0u8; 32];
    let mut cm = [0u8; 32];
    ak.copy_from_slice(&out[..32]);
    cm.copy_from_slice(&out[32..]);
    (ak, cm)
}

/// Seal `fleet_key` separately to each COMPLIANT member for `(handle_proof, epoch)`. `members` carries `(ed_pubkey, pair_secret)` — the caller passes ONLY devices holding a CLUTCH-derived pair secret with the rotator (its own self-pair included); anyone else gets no wrap and cannot recover the key until it re-clutches.
pub fn fanout_seal(
    handle_proof: &[u8; 32],
    epoch: u64,
    fleet_key: &[u8; 32],
    rotator_ed: &[u8; 32],
    members: &[([u8; 32], [u8; 32])],
) -> Result<Vec<FanoutWrap>, String> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
    use x25519_dalek::{PublicKey as XPublic, StaticSecret};
    let mut wraps = Vec::with_capacity(members.len());
    for (member_ed, pair_secret) in members {
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
            epoch,
            rotator_ed,
            member_ed,
            &shared,
            &epk,
            &recipient_xpk,
            pair_secret,
        );
        let ct = ChaCha20Poly1305::new((&ak).into())
            .encrypt((&[0u8; 12]).into(), fleet_key.as_slice())
            .map_err(|_| "fanout: seal failed".to_string())?;
        wraps.push(FanoutWrap { epk, commit, ct });
    }
    Ok(wraps)
}

/// Recover the fleet key for `(handle_proof, epoch)` by finding this device's wrap (via the key-commitment) and decrypting with the device key + the pair secret this device holds toward `rotator_ed`. `None` if this device has no wrap (removed, non-compliant, or a stale epoch) or holds no pair secret for the rotator.
pub fn fanout_open(
    handle_proof: &[u8; 32],
    epoch: u64,
    rotator_ed: &[u8; 32],
    wraps: &[FanoutWrap],
    device_key: &Keypair,
    pair_secret: &[u8; 32],
) -> Option<[u8; 32]> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
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
            epoch,
            rotator_ed,
            &my_ed,
            &shared,
            &w.epk,
            &my_xpk,
            pair_secret,
        );
        // Key-commitment gate: accept only a wrap bound to THIS exact derived key (defeats a crafted ct that opens under two keys), which doubles as the recipient selector.
        if commit != w.commit {
            continue;
        }
        if let Ok(pt) = ChaCha20Poly1305::new((&ak).into())
            .decrypt((&[0u8; 12]).into(), w.ct.as_slice())
        {
            if let Ok(k) = <[u8; 32]>::try_from(pt.as_slice()) {
                return Some(k);
            }
        }
    }
    None
}

/// Serialize a fan-out (epoch + rotator + wraps) for the always-online slot. Opaque per-wrap ciphertext, so a plain length-framed layout; the envelope on the wire stays VSF. The rotator's device pubkey is public (it is in the membership chain) and recipients need it to pick the right pair secret.
pub fn fanout_to_bytes(epoch: u64, rotator_ed: &[u8; 32], wraps: &[FanoutWrap]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(FANOUT_MAGIC);
    out.push(FANOUT_VERSION);
    out.extend_from_slice(&epoch.to_be_bytes());
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

/// Parse a fan-out blob. Bounds-checked — a truncated or corrupt blob fails rather than panicking. A pre-v1 blob (the old ASCII-tagged "PFO0") fails the version gate and reads as an error the caller treats as absent — rotation re-establishes (hard flag-day).
pub fn fanout_from_bytes(bytes: &[u8]) -> Result<(u64, [u8; 32], Vec<FanoutWrap>), String> {
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
    let epoch = u64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
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
    Ok((epoch, rotator_ed, wraps))
}

/// The removal-rotates trigger (braid.md §14.2): a fan-out wrapping MORE devices than the fold currently holds means a former member's wrap lingers — any surviving member should mint the next epoch.
/// Strictly greater-than: `wraps < members` is BOTH the two-phase ADD window (a device bound but awaiting the sponsor's confirm rotation) AND the non-compliant window (a member awaiting its pair-secret CLUTCH) and must NOT auto-rotate.
/// Wraps carry no plaintext target (recipients self-select by key-commitment), so count is the only enumerable signal; a simultaneous depart+bind can hide behind equal counts until the next shrink or confirm heals it (stated residue, braid.md §14.11 G7).
pub fn fanout_needs_rotation(wrap_count: usize, member_count: usize) -> bool {
    member_count > 0 && wrap_count > member_count
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
    fn pair_secret(a: u8, b: u8) -> [u8; 32] {
        // Deterministic stand-in for the CLUTCH-derived pair secret, symmetric in the pair.
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        [lo ^ 0xA5 ^ hi.wrapping_mul(3); 32]
    }

    #[test]
    fn rotation_predicate_fires_on_shrink_only() {
        // Shrink: a departed member's wrap lingers → rotate.
        assert!(fanout_needs_rotation(3, 2));
        assert!(fanout_needs_rotation(2, 1));
        // Steady state: counts match → nothing to heal.
        assert!(!fanout_needs_rotation(3, 3));
        // Grow (two-phase ADD or a non-compliant member awaiting its pair CLUTCH): must NOT auto-rotate.
        assert!(!fanout_needs_rotation(2, 3));
        // No fold / empty fleet: never rotate toward zero members (worker refuses zero-member folds anyway).
        assert!(!fanout_needs_rotation(1, 0));
        assert!(!fanout_needs_rotation(0, 0));
        // No fan-out yet (genesis): establish, don't heal.
        assert!(!fanout_needs_rotation(0, 1));
        // Equal-counts residue, stated: simultaneous depart+bind is invisible to a count check.
        assert!(!fanout_needs_rotation(2, 2));
    }

    #[test]
    fn fanout_seals_to_compliant_members_and_excludes_everyone_else() {
        let a = key(1); // the rotator
        let b = key(2);
        let c = key(3);
        let removed = key(9);
        let hp = [0x11u8; 32];
        let epoch = 5u64;
        let fleet_key = new_fleet_key();
        // The rotator wraps itself with its self-pair secret; b and c with their pair secrets toward a.
        let members = vec![
            (pk(&a), pair_secret(1, 1)),
            (pk(&b), pair_secret(1, 2)),
            (pk(&c), pair_secret(1, 3)),
        ];
        let wraps = fanout_seal(&hp, epoch, &fleet_key, &pk(&a), &members).unwrap();
        assert_eq!(wraps.len(), 3);
        // Every compliant member recovers the exact key with its device key + its pair secret toward the rotator.
        for (kp, seed) in [(&a, 1u8), (&b, 2), (&c, 3)] {
            let got = fanout_open(&hp, epoch, &pk(&a), &wraps, kp, &pair_secret(1, seed));
            assert_eq!(got.expect("member opens"), fleet_key);
        }
        // The device key alone is NOT enough: the right device with the WRONG pair secret cannot open (this is the egg doing its job).
        assert!(fanout_open(&hp, epoch, &pk(&a), &wraps, &b, &[0u8; 32]).is_none());
        // A device not in the member set (removed, never joined, or non-compliant) cannot — removal removes.
        assert!(fanout_open(&hp, epoch, &pk(&a), &wraps, &removed, &pair_secret(1, 9)).is_none());
        // Bound to (fleet, epoch, rotator): no cross-fleet, cross-epoch, or cross-rotator splicing.
        assert!(fanout_open(&[0x22u8; 32], epoch, &pk(&a), &wraps, &b, &pair_secret(1, 2)).is_none());
        assert!(fanout_open(&hp, epoch + 1, &pk(&a), &wraps, &b, &pair_secret(1, 2)).is_none());
        assert!(fanout_open(&hp, epoch, &pk(&b), &wraps, &b, &pair_secret(1, 2)).is_none());
        // Serialize round-trips (epoch + rotator + wraps) and the recovered blob still opens.
        let bytes = fanout_to_bytes(epoch, &pk(&a), &wraps);
        let (got_epoch, got_rotator, back) = fanout_from_bytes(&bytes).unwrap();
        assert_eq!(got_epoch, epoch);
        assert_eq!(got_rotator, pk(&a));
        assert_eq!(back, wraps);
        assert_eq!(fanout_open(&hp, epoch, &pk(&a), &back, &b, &pair_secret(1, 2)).unwrap(), fleet_key);
        assert!(fanout_from_bytes(&bytes[..bytes.len() - 5]).is_err());
        // A pre-v1 blob (old ASCII "PFO0" tag) fails the version gate — the hard flag-day.
        let mut legacy = bytes.clone();
        legacy[3] = b'0';
        assert!(fanout_from_bytes(&legacy).is_err());
        // A tampered wrap fails its AEAD tag (no silent wrong key).
        let mut tampered = wraps.clone();
        *tampered[0].ct.last_mut().unwrap() ^= 1;
        assert!(fanout_open(&hp, epoch, &pk(&a), &tampered[..1], &a, &pair_secret(1, 1)).is_none());
        // A low-order (all-zero) epk is rejected by the contributory-DH check, not opened.
        let mut loword = wraps.clone();
        loword[0].epk = [0u8; 32];
        assert!(fanout_open(&hp, epoch, &pk(&a), &loword[..1], &a, &pair_secret(1, 1)).is_none());
        // Wrap-count sanity: an implausible count is rejected before allocation (count sits after magic+ver+epoch+rotator).
        let mut huge = fanout_to_bytes(epoch, &pk(&a), &wraps);
        huge[44..48].copy_from_slice(&2000u32.to_be_bytes());
        assert!(fanout_from_bytes(&huge).is_err());
    }
}
