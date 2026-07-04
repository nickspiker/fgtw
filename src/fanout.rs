//! Per-member fan-out — sealed per-device delivery of the current fleet key (BRAID v0.2 §14.2).
//!
//! Each epoch mints a FRESH fleet key and seals it SEPARATELY to every CURRENT member device — a sealed box to the device's X25519 key, converted from the Ed25519 device key already in the membership chain (no chain-format change).
//! A device recovers the current key by trial-decrypting its own wrap with its device key — no live sibling.
//! A removed device is simply not a wrap target next epoch, so the new key is unreadable to it: removal removes, and there is NO seal-under-the-prior-key chain (that would be a skeleton key).
//!
//! This is the crypto core; the always-online transport that posts/fetches these blobs (and drives epoch rotation) is the client's job.

use crate::keys::Keypair;
use ed25519_dalek::VerifyingKey;

/// A fresh random fleet key — minted per epoch by rotation; devices RECEIVE the current one from the fan-out.
pub fn new_fleet_key() -> [u8; 32] {
    rand::random()
}

const FANOUT_DOMAIN: &[u8] = b"PHOTON_FLEET_FANOUT_v0";
const FANOUT_TAG: &[u8; 4] = b"PFO0";

/// One sealed copy of the fleet key for one (unlabelled) member. `epk` is a per-wrap ephemeral X25519 public; `commit` binds the ciphertext to the exact derived key (KEY-COMMITTING — so a malicious member can't craft one `ct` that opens to different keys for two devices, the invisible-salamander split); `ct` is ChaCha20-Poly1305(fleet_key) under the ECDH-derived key. No recipient label — a device recomputes `commit` to find its own — so the slot carries only a count, never pubkeys.
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

/// Derive the per-wrap AEAD key AND its key-commitment from the ECDH shared secret.
/// Binds the FLEET (`handle_proof`) and `epoch`, so a wrap is valid only for (this fleet, this epoch, this recipient) — no cross-fleet or cross-epoch splicing (a device key is the same across fleets, so without this a wrap lifts between them). `epk` MUST stay in this hash: it is what makes each wrap's key unique, which is what makes the fixed AEAD nonce safe — never derive the key from `shared` alone. The 64-byte XOF splits into `(aead_key, commit)`; `commit` binds `ct` to this exact key (defeats the partitioning-oracle / invisible-salamander attack that Poly1305 alone allows) and doubles as the recipient selector.
fn fanout_keys(
    handle_proof: &[u8; 32],
    epoch: u64,
    recipient_ed: &[u8; 32],
    shared: &[u8; 32],
    epk: &[u8; 32],
    recipient_xpk: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut h = blake3::Hasher::new();
    h.update(FANOUT_DOMAIN);
    h.update(handle_proof);
    h.update(&epoch.to_le_bytes());
    // Bind the canonical Ed25519 device pubkey too: to_montgomery drops the sign bit, so two distinct Ed25519 keys can share a Montgomery u — this disambiguates them.
    h.update(recipient_ed);
    h.update(epk);
    h.update(recipient_xpk);
    h.update(shared);
    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    let mut ak = [0u8; 32];
    let mut cm = [0u8; 32];
    ak.copy_from_slice(&out[..32]);
    cm.copy_from_slice(&out[32..]);
    (ak, cm)
}

/// Seal `fleet_key` separately to each current member (Ed25519 device pubkeys, e.g. from a folded `MembershipBlob`) for a given `(handle_proof, epoch)`. A device not in `members` gets no wrap and cannot recover the key.
pub fn fanout_seal(
    handle_proof: &[u8; 32],
    epoch: u64,
    fleet_key: &[u8; 32],
    members: &[[u8; 32]],
) -> Result<Vec<FanoutWrap>, String> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
    use x25519_dalek::{PublicKey as XPublic, StaticSecret};
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
        let (ak, commit) = fanout_keys(handle_proof, epoch, member_ed, &shared, &epk, &recipient_xpk);
        let ct = ChaCha20Poly1305::new((&ak).into())
            .encrypt(Nonce::from_slice(&[0u8; 12]), fleet_key.as_slice())
            .map_err(|_| "fanout: seal failed".to_string())?;
        wraps.push(FanoutWrap { epk, commit, ct });
    }
    Ok(wraps)
}

/// Recover the fleet key for `(handle_proof, epoch)` by finding this device's wrap (via the key-commitment) and decrypting. `None` if this device is not a recipient (removed, or a stale epoch it was never in) — and, because the key is bound to `(handle_proof, epoch)`, a wrap from a different fleet or epoch simply won't match.
pub fn fanout_open(
    handle_proof: &[u8; 32],
    epoch: u64,
    wraps: &[FanoutWrap],
    device_key: &Keypair,
) -> Option<[u8; 32]> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
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
        let (ak, commit) = fanout_keys(handle_proof, epoch, &my_ed, &shared, &w.epk, &my_xpk);
        // Key-commitment gate: accept only a wrap bound to THIS exact derived key (defeats a crafted ct that opens under two keys), which doubles as the recipient selector.
        if commit != w.commit {
            continue;
        }
        if let Ok(pt) = ChaCha20Poly1305::new((&ak).into())
            .decrypt(Nonce::from_slice(&[0u8; 12]), w.ct.as_slice())
        {
            if let Ok(k) = <[u8; 32]>::try_from(pt.as_slice()) {
                return Some(k);
            }
        }
    }
    None
}

/// Serialize a fan-out (epoch + wraps) for the always-online slot. Opaque per-wrap ciphertext, so a plain length-framed layout; the envelope on the wire stays VSF.
pub fn fanout_to_bytes(epoch: u64, wraps: &[FanoutWrap]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(FANOUT_TAG);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&(wraps.len() as u32).to_be_bytes());
    for w in wraps {
        out.extend_from_slice(&w.epk);
        out.extend_from_slice(&w.commit);
        out.extend_from_slice(&(w.ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&w.ct);
    }
    out
}

/// Parse a fan-out blob. Bounds-checked — a truncated or corrupt blob fails rather than panicking.
pub fn fanout_from_bytes(bytes: &[u8]) -> Result<(u64, Vec<FanoutWrap>), String> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], String> {
        if *p + n > bytes.len() {
            return Err("fanout: truncated".into());
        }
        let s = &bytes[*p..*p + n];
        *p += n;
        Ok(s)
    };
    if take(&mut p, 4)? != FANOUT_TAG {
        return Err("fanout: bad tag".into());
    }
    let epoch = u64::from_be_bytes(take(&mut p, 8)?.try_into().unwrap());
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
    Ok((epoch, wraps))
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
    fn fanout_seals_to_each_member_and_excludes_removed() {
        let a = key(1);
        let b = key(2);
        let c = key(3);
        let removed = key(9);
        let members = vec![pk(&a), pk(&b), pk(&c)];
        let hp = [0x11u8; 32];
        let epoch = 5u64;
        let fleet_key = new_fleet_key();
        let wraps = fanout_seal(&hp, epoch, &fleet_key, &members).unwrap();
        assert_eq!(wraps.len(), 3);
        // Every current member recovers the exact key with its own device key (no live sibling).
        for kp in [&a, &b, &c] {
            assert_eq!(fanout_open(&hp, epoch, &wraps, kp).expect("member opens"), fleet_key);
        }
        // A device not in the member set (removed, or never joined) cannot — removal removes.
        assert!(fanout_open(&hp, epoch, &wraps, &removed).is_none());
        // Bound to (fleet, epoch): a wrap won't open under a different handle_proof or epoch (no cross-fleet / cross-epoch splicing).
        assert!(fanout_open(&[0x22u8; 32], epoch, &wraps, &a).is_none());
        assert!(fanout_open(&hp, epoch + 1, &wraps, &a).is_none());
        // Serialize round-trips and the recovered blob still opens.
        let bytes = fanout_to_bytes(epoch, &wraps);
        let (got_epoch, back) = fanout_from_bytes(&bytes).unwrap();
        assert_eq!(got_epoch, epoch);
        assert_eq!(back, wraps);
        assert_eq!(fanout_open(&hp, epoch, &back, &a).unwrap(), fleet_key);
        assert!(fanout_from_bytes(&bytes[..bytes.len() - 5]).is_err());
        // A tampered wrap fails its AEAD tag (no silent wrong key).
        let mut tampered = wraps.clone();
        *tampered[0].ct.last_mut().unwrap() ^= 1;
        assert!(fanout_open(&hp, epoch, &tampered[..1], &a).is_none());
        // A low-order (all-zero) epk is rejected by the contributory-DH check, not opened.
        let mut loword = wraps.clone();
        loword[0].epk = [0u8; 32];
        assert!(fanout_open(&hp, epoch, &loword[..1], &a).is_none());
        // Wrap-count sanity: an implausible count is rejected before allocation.
        let mut huge = fanout_to_bytes(epoch, &wraps);
        huge[12..16].copy_from_slice(&2000u32.to_be_bytes());
        assert!(fanout_from_bytes(&huge).is_err());
    }
}
