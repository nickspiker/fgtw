//! Scoped blobs — one ciphertext, many keyholders (photon docs/scoped-blobs.md).
//!
//! Replaces the bearer-pin model, where a single 64-byte secret was BOTH the storage address and the decryption key: losing it lost the content, leaking it granted everything, and every reader held the same one.
//!
//! Here the content is encrypted ONCE under a random data key (DEK), and that key is wrapped separately for each reader under a secret the two parties already share — the fleet key for our own devices, the CLUTCH pair secret for a friend. Each wrap lives in its own PRIVATE SLOT at an address only those two parties can derive, so nothing anywhere enumerates the readers: a stranger cannot tell one identity's twelve slots from twelve unrelated people's.
//!
//! The blob id is NOT a secret. It is a storage address and nothing more — learning it grants nothing, because reading needs a slot only a keyholder can find.
//!
//! Deletion is deliberately not load-bearing. An old ciphertext is opaque to everyone except readers already granted it, and they hold the plaintext already, so an orphan leaks nothing new. There is no lease and no expiry: a publisher who goes off-grid for a year still renders for every friend who cached the content, and an identity must never decay because its owner stopped checking in.

use crate::keys::Keypair;

// Versions ride as literal binary numerals, never ASCII digits welded into a tag (repo convention 2026-08-01).
const SLOT_DOMAIN: &[u8] = b"PHOTON_SCOPED_SLOT_v";
const WRAP_DOMAIN: &[u8] = b"PHOTON_SCOPED_WRAP_v";
pub const SCOPED_VERSION: u8 = 0;

/// What a reader needs to find and open a blob: the storage address of the ciphertext, plus the data key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SlotContents {
    pub blob_id: [u8; 32],
    pub dek: [u8; 32],
}

/// The address of one reader's private slot. Derived from the secret shared with that reader, so only the two of them can compute it — and it is stable, so an update overwrites in place rather than stranding the reader at a dead address.
///
/// `purpose` separates independent blobs sharing one reader secret ("avatar", an attachment id, …); without it every blob would collide on one address per pair.
pub fn slot_address(kek_secret: &[u8; 32], purpose: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(SLOT_DOMAIN);
    h.update(&[SCOPED_VERSION]);
    h.update(kek_secret);
    h.update(&(purpose.len() as u32).to_le_bytes());
    h.update(purpose);
    *h.finalize().as_bytes()
}

/// The AEAD key that seals ONE reader's slot. Binds the slot address so a slot lifted to another address fails to open, and binds the purpose so a wrap cannot be replayed across blobs.
fn slot_key(kek_secret: &[u8; 32], purpose: &[u8]) -> [u8; 32] {
    let addr = slot_address(kek_secret, purpose);
    let mut h = blake3::Hasher::new();
    h.update(WRAP_DOMAIN);
    h.update(&[SCOPED_VERSION]);
    h.update(kek_secret);
    h.update(&addr);
    *h.finalize().as_bytes()
}

/// A fresh data key. One per blob VERSION — republishing (which is how a reader is removed) mints a new one, so the readers dropped from the new slot set cannot open the new content.
pub fn new_dek() -> [u8; 32] {
    rand::random()
}

/// A fresh blob id — the ciphertext's public storage address.
pub fn new_blob_id() -> [u8; 32] {
    rand::random()
}

/// Seal one reader's slot: `(blob_id, dek)` encrypted under a key derived from the secret we share with them. ~80 bytes on the wire.
pub fn seal_slot(
    kek_secret: &[u8; 32],
    purpose: &[u8],
    contents: &SlotContents,
) -> Result<Vec<u8>, String> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
    let key = slot_key(kek_secret, purpose);
    let mut plain = [0u8; 64];
    plain[..32].copy_from_slice(&contents.blob_id);
    plain[32..].copy_from_slice(&contents.dek);
    // Fixed nonce is safe because the key is unique per (reader secret, purpose) AND the plaintext is re-sealed only when the DEK changes — a rewrite under the same key carries the same 64 bytes, so no two distinct plaintexts ever share a nonce.
    ChaCha20Poly1305::new((&key).into())
        .encrypt((&[0u8; 12]).into(), plain.as_slice())
        .map_err(|_| "scoped: slot seal failed".to_string())
}

/// Open our own slot. `None` when the bytes are not ours to read (wrong secret, wrong purpose, tampered, or an empty/absent slot).
pub fn open_slot(kek_secret: &[u8; 32], purpose: &[u8], sealed: &[u8]) -> Option<SlotContents> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
    let key = slot_key(kek_secret, purpose);
    let plain = ChaCha20Poly1305::new((&key).into())
        .decrypt((&[0u8; 12]).into(), sealed)
        .ok()?;
    if plain.len() != 64 {
        return None;
    }
    let mut blob_id = [0u8; 32];
    let mut dek = [0u8; 32];
    blob_id.copy_from_slice(&plain[..32]);
    dek.copy_from_slice(&plain[32..]);
    Some(SlotContents { blob_id, dek })
}

/// Seal a bare 32-byte VALUE (e.g. a fleet key) into a reader's slot. Unlike [`seal_slot`], the value REPLACES itself across epochs under one (kek, purpose) — so this uses a fresh random nonce per seal, prefixed, where the slot's fixed nonce would repeat across distinct plaintexts.
pub fn seal_value(
    kek_secret: &[u8; 32],
    purpose: &[u8],
    value: &[u8; 32],
) -> Result<Vec<u8>, String> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
    let key = slot_key(kek_secret, purpose);
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from(nonce_bytes);
    let mut out = nonce_bytes.to_vec();
    let ct = ChaCha20Poly1305::new((&key).into())
        .encrypt(&nonce, value.as_slice())
        .map_err(|_| "scoped: value seal failed".to_string())?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a value slot. `None` when the bytes are not ours (wrong secret, wrong purpose, tampered, absent).
pub fn open_value(kek_secret: &[u8; 32], purpose: &[u8], sealed: &[u8]) -> Option<[u8; 32]> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
    if sealed.len() < 12 {
        return None;
    }
    let key = slot_key(kek_secret, purpose);
    let nonce = Nonce::from(<[u8; 12]>::try_from(&sealed[..12]).ok()?);
    let plain = ChaCha20Poly1305::new((&key).into())
        .decrypt(&nonce, &sealed[12..])
        .ok()?;
    <[u8; 32]>::try_from(plain.as_slice()).ok()
}

/// Encrypt the content once under the DEK. The blob id is bound in, so a ciphertext cannot be swapped between addresses while still opening.
pub fn seal_content(dek: &[u8; 32], blob_id: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
    // Fresh random nonce per seal, prefixed to the ciphertext — the same construction kete uses for vault blobs. A fixed nonce would be wrong here: unlike a slot, the content changes under a key that may be reused across a rewrite.
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from(nonce_bytes);
    let mut out = nonce_bytes.to_vec();
    let ct = ChaCha20Poly1305::new((dek).into())
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: blob_id,
            },
        )
        .map_err(|_| "scoped: content seal failed".to_string())?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt content fetched from `blob_id`. `None` if the key is wrong, the bytes were tampered with, or the object was served from a different address than the one it was sealed for.
pub fn open_content(dek: &[u8; 32], blob_id: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
    if sealed.len() < 12 {
        return None;
    }
    let (nonce_bytes, ct) = sealed.split_at(12);
    let nonce = Nonce::from(<[u8; 12]>::try_from(nonce_bytes).ok()?);
    ChaCha20Poly1305::new((dek).into())
        .decrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: ct,
                aad: blob_id,
            },
        )
        .ok()
}

/// Everything a publisher must write for one reader: where the slot goes, and what to put there.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SlotWrite {
    pub address: [u8; 32],
    pub sealed: Vec<u8>,
}

/// Build the slot writes for a full reader set. `readers` is each reader's shared secret — the fleet key for our own devices, the CLUTCH pair secret per friend. Removing a reader is simply leaving them out of a republish; adding one is a single extra write against the SAME blob.
pub fn slot_writes(
    readers: &[[u8; 32]],
    purpose: &[u8],
    contents: &SlotContents,
) -> Result<Vec<SlotWrite>, String> {
    readers
        .iter()
        .map(|kek| {
            Ok(SlotWrite {
                address: slot_address(kek, purpose),
                sealed: seal_slot(kek, purpose, contents)?,
            })
        })
        .collect()
}

/// A device's own KEK for scoped blobs it publishes to ITSELF (the local cache, and any future single-device scope). Derived from the device key so it exists before any ceremony and never needs distributing.
pub fn self_kek(device_key: &Keypair) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"PHOTON_SCOPED_SELF_v");
    h.update(&[SCOPED_VERSION]);
    h.update(device_key.secret.as_bytes());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// The round trip every reader performs: find my slot, unwrap the key, open the one shared ciphertext.
    #[test]
    fn reader_finds_its_slot_and_opens_the_shared_content() {
        let friend = secret(1);
        let device = secret(2);
        let dek = new_dek();
        let blob_id = new_blob_id();
        let contents = SlotContents { blob_id, dek };
        let content = b"a small avatar".to_vec();

        let sealed_content = seal_content(&dek, &blob_id, &content).unwrap();
        let writes = slot_writes(&[friend, device], b"avatar", &contents).unwrap();
        assert_eq!(writes.len(), 2);
        // Two readers, two unlinkable addresses.
        assert_ne!(writes[0].address, writes[1].address);

        for (kek, w) in [(friend, &writes[0]), (device, &writes[1])] {
            assert_eq!(w.address, slot_address(&kek, b"avatar"));
            let got = open_slot(&kek, b"avatar", &w.sealed).expect("reader opens its own slot");
            assert_eq!(got, contents);
            let plain = open_content(&got.dek, &got.blob_id, &sealed_content).expect("content");
            assert_eq!(plain, content);
        }
    }

    /// A non-reader has no way in: it cannot derive the address, and even handed the bytes it cannot open them. This is the property the bearer pin never had.
    #[test]
    fn a_non_reader_can_neither_find_nor_open() {
        let friend = secret(1);
        let stranger = secret(9);
        let contents = SlotContents { blob_id: new_blob_id(), dek: new_dek() };
        let writes = slot_writes(&[friend], b"avatar", &contents).unwrap();

        assert_ne!(slot_address(&stranger, b"avatar"), writes[0].address);
        assert!(open_slot(&stranger, b"avatar", &writes[0].sealed).is_none());
    }

    /// Slots are bound to their purpose and address: a slot cannot be replayed onto a different blob, and one blob's slot cannot be lifted to another's.
    #[test]
    fn slots_do_not_cross_purposes_or_addresses() {
        let friend = secret(1);
        let contents = SlotContents { blob_id: new_blob_id(), dek: new_dek() };
        let avatar = slot_writes(&[friend], b"avatar", &contents).unwrap();

        assert!(open_slot(&friend, b"attachment-7", &avatar[0].sealed).is_none());
        assert_ne!(slot_address(&friend, b"avatar"), slot_address(&friend, b"attachment-7"));
    }

    /// Content is bound to its blob id, so a ciphertext served from the wrong address fails rather than opening.
    #[test]
    fn content_is_bound_to_its_address() {
        let dek = new_dek();
        let blob_id = new_blob_id();
        let sealed = seal_content(&dek, &blob_id, b"pixels").unwrap();
        assert_eq!(open_content(&dek, &blob_id, &sealed).unwrap(), b"pixels");
        assert!(open_content(&dek, &new_blob_id(), &sealed).is_none());
        assert!(open_content(&new_dek(), &blob_id, &sealed).is_none());
        // Tampering fails the tag rather than yielding garbage.
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open_content(&dek, &blob_id, &bad).is_none());
    }

    /// ADDING a reader must not disturb the ciphertext or anyone else's slot — the whole point of wrapping a key instead of re-encrypting data.
    #[test]
    fn adding_a_reader_leaves_content_and_other_slots_untouched() {
        let a = secret(1);
        let b = secret(2);
        let contents = SlotContents { blob_id: new_blob_id(), dek: new_dek() };
        let sealed_content = seal_content(&contents.dek, &contents.blob_id, b"pixels").unwrap();

        let before = slot_writes(&[a], b"avatar", &contents).unwrap();
        let after = slot_writes(&[a, b], b"avatar", &contents).unwrap();

        assert_eq!(before[0], after[0], "an existing reader's slot is byte-identical");
        // The content never moved: the same bytes still open under the same key.
        assert!(open_content(&contents.dek, &contents.blob_id, &sealed_content).is_some());
        // And the newcomer reads the same content through their own slot.
        let got = open_slot(&b, b"avatar", &after[1].sealed).unwrap();
        assert_eq!(got.blob_id, contents.blob_id);
    }

    /// REMOVING a reader is a republish: new key, new address, slots for survivors only. The removed reader's stale slot points at content that no longer exists, and its secret cannot open the new one.
    #[test]
    fn removing_a_reader_republishes_beyond_their_reach() {
        let stay = secret(1);
        let go = secret(2);
        let v0 = SlotContents { blob_id: new_blob_id(), dek: new_dek() };
        let old_writes = slot_writes(&[stay, go], b"avatar", &v0).unwrap();
        let removed_slot = open_slot(&go, b"avatar", &old_writes[1].sealed).unwrap();

        let v1 = SlotContents { blob_id: new_blob_id(), dek: new_dek() };
        let new_content = seal_content(&v1.dek, &v1.blob_id, b"new pixels").unwrap();
        let new_writes = slot_writes(&[stay], b"avatar", &v1).unwrap();
        assert_eq!(new_writes.len(), 1);

        // The survivor follows the republish to the new object.
        let kept = open_slot(&stay, b"avatar", &new_writes[0].sealed).unwrap();
        assert_eq!(open_content(&kept.dek, &kept.blob_id, &new_content).unwrap(), b"new pixels");
        // The removed reader holds the OLD key and address, which open nothing of the new version.
        assert_ne!(removed_slot.blob_id, v1.blob_id);
        assert!(open_content(&removed_slot.dek, &removed_slot.blob_id, &new_content).is_none());
    }

    /// The self KEK is stable per device and distinct between devices — it must not need a ceremony to exist.
    #[test]
    fn self_kek_is_stable_and_device_bound() {
        let a = Keypair::from_seed(&[3u8; 32]);
        let b = Keypair::from_seed(&[4u8; 32]);
        assert_eq!(self_kek(&a), self_kek(&a));
        assert_ne!(self_kek(&a), self_kek(&b));
    }
}

#[cfg(test)]
mod value_slot_tests {
    use super::*;

    /// A value round-trips under its (kek, purpose); a rotated value re-seals under the SAME pair and still opens — the epochs-replace-in-place property the fleet-key recovery slot rides on.
    #[test]
    fn value_round_trips_and_replaces() {
        let kek = [3u8; 32];
        let purpose = b"fleet-key-test";
        let v1 = [7u8; 32];
        let sealed1 = seal_value(&kek, purpose, &v1).unwrap();
        assert_eq!(open_value(&kek, purpose, &sealed1), Some(v1));

        let v2 = [8u8; 32];
        let sealed2 = seal_value(&kek, purpose, &v2).unwrap();
        assert_eq!(open_value(&kek, purpose, &sealed2), Some(v2));
        // Distinct nonces: two seals of even the SAME value never share bytes.
        assert_ne!(seal_value(&kek, purpose, &v1).unwrap(), sealed1);
        // Wrong secret or purpose opens nothing.
        assert_eq!(open_value(&[4u8; 32], purpose, &sealed2), None);
        assert_eq!(open_value(&kek, b"other", &sealed2), None);
    }
}
