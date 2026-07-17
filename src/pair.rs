//! Pairing — device-ADD ceremony word logic (docs/pairing-v2.md, words-first redesign 2026-07-13).
//!
//! The NEW device DISPLAYS its device pubkey as 23 voca words, MASKED to its fleet ([`masked_device_words`]); the user types them into an EXISTING device, whose matcher screens them against the binding-request registry live, keystroke by keystroke.
//! The words carry a public value headed for the public chain anyway — disclosure is inert: nothing can be bound without a request signed by that device's own key (`fleet::bindreq_signing_bytes`), and the mask makes the words meaningless outside the fleet they were minted for.
//! 256 bits because the words ARE the selector: a full exact match against a verified request is the bind decision, no shorter code to grind against.
//!
//! This module is the word codec + spell-check + the mask; the request signing-bytes live in `fleet` (the fold verifies consent there, and the worker folds without this module's feature).
//!
//! The BLE transport (lock word + proximity beacon, below) delivers candidates by radio instead of by eyes — same ceremony, different selector; it ships later.

use vsf::VsfType;

/// NFC instant-add commitment: the keyed hash the PUBLIC binding request carries so the sponsor can verify the 32-byte secret `S` served over the tap. Bound to (device_pubkey, t) INSIDE the hash — a relay can't transplant it onto another candidate, because the sponsor recomputes with each candidate's own pubkey+stamp. `S` must be 32 random bytes: the hash is public, so a small preimage space would be brute-forceable offline and void the proximity gate.
pub fn nfc_secret_hash(secret: &[u8; 32], device_pubkey: &[u8; 32], t: i64) -> [u8; 32] {
    let key = blake3::derive_key("photon nfc pair v0", secret);
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(device_pubkey);
    h.update(&t.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Fixed word count for a 256-bit value: voca's FULL base is 3177 (~11.63 bits/word), and 22 words is 255.94 bits — just short — so 23 covers every key. Fixed-width (leading-zero-padded) so the typing side always knows when the entry is complete. The ~11 spare bits in the 23rd word stay spare (future versioning); no checksum — the live matcher subsumes typo detection.
pub const PAIR_WORD_COUNT: usize = 23;

/// The handle-scoped word mask: a key derived from the identity seed, XORed over the device pubkey before word-encoding. Both ends compute it (new device: from the typed handle; old device: from its session), so the same physical words resolve ONLY inside this fleet — two families pairing in one room can't cross-pollinate, and a transcribed word list is noise everywhere else. Against an attacker who holds the handle the mask is decoration (they can derive it); the security is the request's signatures.
pub fn word_mask(identity_seed: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("photon pair words v1", identity_seed)
}

/// The 23 words a NEW device displays: its device pubkey, masked to this fleet. The OLD device computes the same string per registry candidate and prefix-matches the typed entry against them — no decode, no comparison for a human to lazy-glance.
pub fn masked_device_words(device_pubkey: &[u8; 32], identity_seed: &[u8; 32]) -> String {
    let mask = word_mask(identity_seed);
    let mut masked = *device_pubkey;
    for (b, m) in masked.iter_mut().zip(mask.iter()) {
        *b ^= m;
    }
    pair_words(&masked)
}

/// The zero word (digit 0), capitalised to match voca's camelCase encode — the left-pad for keys with leading zeros, so the word count never shrinks and the completeness check stays exact.
fn zero_word() -> String {
    let w = std::str::from_utf8(voca::FULL.alphabet[0]).expect("voca words are ASCII");
    let mut s = String::with_capacity(w.len());
    let mut chars = w.chars();
    if let Some(c) = chars.next() {
        s.push(c.to_ascii_uppercase());
        s.extend(chars);
    }
    s
}

/// The pairing pubkey as EXACTLY `PAIR_WORD_COUNT` camelCase words, left-padded with the zero word. Positional base-3177: leading zero-digits don't change the decoded value, so padding is free.
pub fn pair_words(pairing_pubkey: &[u8; 32]) -> String {
    let encoded = voca::encode(num_bigint::BigUint::from_bytes_be(pairing_pubkey));
    let have = pair_word_tokens(&encoded);
    let mut s = String::new();
    for _ in have..PAIR_WORD_COUNT {
        s.push_str(&zero_word());
    }
    s.push_str(&encoded);
    s
}

/// Count the words in a typed string, mirroring voca's tokenizer: whitespace-separated if any whitespace, else camelCase boundaries. Drives the live n/23 counter and the completeness gate.
pub fn pair_word_tokens(s: &str) -> usize {
    let t = s.trim();
    if t.is_empty() {
        return 0;
    }
    if t.bytes().any(|b| b.is_ascii_whitespace()) {
        return t.split_ascii_whitespace().count();
    }
    let mut count = 1;
    for c in t.chars().skip(1) {
        if c.is_ascii_uppercase() {
            count += 1;
        }
    }
    count
}

/// Lazy index over the voca FULL alphabet for live spell-checking: a hash set for exact membership plus a sorted copy for prefix tests. Built once, ~3177 entries.
static WORD_INDEX: std::sync::OnceLock<(
    std::collections::HashSet<&'static [u8]>,
    Vec<&'static [u8]>,
)> = std::sync::OnceLock::new();
fn word_index() -> &'static (std::collections::HashSet<&'static [u8]>, Vec<&'static [u8]>) {
    WORD_INDEX.get_or_init(|| {
        let set: std::collections::HashSet<_> = voca::FULL.alphabet.iter().copied().collect();
        let mut sorted: Vec<_> = voca::FULL.alphabet.to_vec();
        sorted.sort_unstable();
        (set, sorted)
    })
}

/// The typed entry's tokens, lowercased, split exactly the way [`pair_word_tokens`] counts them: whitespace-separated if the entry contains any whitespace, else camelCase boundaries.
pub fn pair_word_list(s: &str) -> Vec<String> {
    let t = s.trim();
    if t.is_empty() {
        return Vec::new();
    }
    if t.bytes().any(|b| b.is_ascii_whitespace()) {
        return t.split_ascii_whitespace().map(|w| w.to_ascii_lowercase()).collect();
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in t.chars() {
        if c.is_ascii_uppercase() && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Live spell-check of a (possibly partial) pairing entry against the voca FULL list. Every completed word must be an exact list member; the final, still-being-typed word passes while it's still a PREFIX of some list word, so nothing flashes red mid-word — but the instant it can't become any list word ("contrav…", "spontani…") it's flagged, and a full 23-word entry (or a trailing space) demands exactness from every token. Case-insensitive. Returns the first offender for the status line.
pub fn first_bad_pair_word(s: &str) -> Option<String> {
    let words = pair_word_list(s);
    if words.is_empty() {
        return None;
    }
    let (set, sorted) = word_index();
    // The last token is "complete" (must match exactly) only once a separator follows it — a full-width count is NOT completion, because the 23rd token exists from its first typed character (an "at 23 words check everything" rule would flag the last word mid-type). A valid full word passes the prefix test anyway (exact match is its own prefix), so the lenient last-token rule never rejects a correct entry.
    let last_complete = s != s.trim_end();
    let n = words.len();
    for (i, w) in words.iter().enumerate() {
        let wb = w.as_bytes();
        let ok = if i + 1 < n || last_complete {
            set.contains(wb)
        } else {
            let idx = sorted.partition_point(|&cand| cand < wb);
            idx < sorted.len() && sorted[idx].starts_with(wb)
        };
        if !ok {
            return Some(w.clone());
        }
    }
    None
}

/// Parse a hub-pushed pairing event — section `pair_evt` {k: kind, hp} — into (kind, handle_proof). Returns `None` for every other frame: the hub also carries dashboard-capsule broadcasts, which subscribers skip cheaply on the header/section decode. Kinds today: "request" (a binding request was posted or withdrawn — the matcher refetches) and "fleet" (the membership chain extended — the joining device re-checks its lamp).
pub fn parse_pair_event(bytes: &[u8]) -> Option<(String, [u8; 32])> {
    // Verified read (hp + hb | signature) — hub frames are worker-built and always carry an anchor; anything unverifiable is skipped, not parsed.
    let (header, header_end) = vsf::verification::read_verified(bytes, None).ok()?;
    // primary_section resolves the near-form name from the header TOC. The old bare VsfSection::parse left `name` EMPTY for near-form frames, so the check below rejected EVERY real pair_evt — the hub push accelerator never fired and the poll cadence silently carried the whole ceremony (the observed "bind landed but the device sat minutes on the old timeout").
    let section = header.primary_section(bytes, header_end).ok()?;
    if section.name != "pair_evt" {
        return None;
    }
    let kind = match section.get_field("k").and_then(|f| f.values.first()) {
        // `a` is what the worker sends (its vsf build has no `text` feature, so `x` would panic there); accept `x` too for forward-compat.
        Some(VsfType::a(s)) | Some(VsfType::x(s)) => s.clone(),
        _ => return None,
    };
    let hp = match section.get_field("hp").and_then(|f| f.values.first()) {
        Some(VsfType::hP(b)) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            a
        }
        _ => return None,
    };
    Some((kind, hp))
}

/// True when the entry is fully typed: exactly `PAIR_WORD_COUNT` tokens and EVERY token an exact list member. This is the completeness gate for the network match-check: a bare token count trips on the 23rd word's first character (the token exists from its first letter), firing a decode that then complains "unrecognised word" about a word the user simply hasn't finished typing.
pub fn pair_entry_complete(s: &str) -> bool {
    let words = pair_word_list(s);
    words.len() == PAIR_WORD_COUNT && {
        let (set, _) = word_index();
        words.iter().all(|w| set.contains(w.as_bytes()))
    }
}

/// Decode a complete word entry back to the pairing pubkey. Strict: exactly `PAIR_WORD_COUNT` words, value < 2^256. A wrong word fails the decode; the right words of the wrong device fail the match downstream.
pub fn words_to_pair_pubkey(words: &str) -> Result<[u8; 32], String> {
    if pair_word_tokens(words) != PAIR_WORD_COUNT {
        return Err(format!("expected {PAIR_WORD_COUNT} words"));
    }
    let n = voca::decode(words.trim()).map_err(|e| format!("unrecognised word: {e:?}"))?;
    let bytes = n.to_bytes_be();
    if bytes.len() > 32 {
        return Err("words don't decode to a key".into());
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

/// Two-word voca pseudonym for an arbitrary 32-byte public id — the rendering for any identity that hasn't granted you a name (docs/identity-profile.md): contact party ids pre-grant, unknown knockers, strangers in a future phonebook. Public-derivable by design (the id is public); it is a LABEL, never trust. camelCase per the voca display convention.
pub fn keyed_pseudonym(id: &[u8; 32]) -> String {
    let mut input = Vec::with_capacity(21 + 32);
    input.extend_from_slice(b"PHOTON_PSEUDONYM_v1");
    input.extend_from_slice(id);
    let digest = blake3::hash(&input);
    let mut n8 = [0u8; 8];
    n8.copy_from_slice(&digest.as_bytes()[..8]);
    let base = voca::FULL.alphabet.len() as u64;
    let n = u64::from_le_bytes(n8) % (base * base);
    let encoded = voca::encode(num_bigint::BigUint::from(n));
    let mut s = String::new();
    for _ in pair_word_tokens(&encoded)..2 {
        s.push_str(&zero_word());
    }
    s.push_str(&encoded);
    s
}

/// Deterministic default device label: exactly TWO voca words derived one-way from the device PUBLIC key AND the fleet's identity seed. Keying on the pubkey (not the secret) makes the label FLEET-CONSISTENT — every device knows every other device's pubkey, so all devices compute the same name for a given device (a secret-keyed label could only be computed by the device itself, which is why the fleet list and the pairing screen used to disagree). Folding in `identity_seed` makes the label FLEET-SCOPED — the same physical device gets a distinct name in each owner's fleet, so a handed-off device shows a fresh name to its new owner rather than inheriting the old one, and only that fleet (which shares the seed) can compute the name. Both the pubkey and the seed are stable per-(device, identity), so the label still survives a wipe-and-reinstall ("same device, same name"). Label space is 3177² ≈ 10.1 M, so even a 12-device fleet collides with p ≈ 7×10⁻⁶. camelCase per the voca display convention. The owner-edited override (devices page) supersedes this — it is only the shipped default.
pub fn device_name_default(device_pubkey: &[u8; 32], identity_seed: &[u8; 32]) -> String {
    let mut input = Vec::with_capacity(24 + 64);
    input.extend_from_slice(b"PHOTON_DEVICE_NAME_v1");
    input.extend_from_slice(device_pubkey);
    input.extend_from_slice(identity_seed);
    let digest = blake3::hash(&input);
    let mut n8 = [0u8; 8];
    n8.copy_from_slice(&digest.as_bytes()[..8]);
    let base = voca::FULL.alphabet.len() as u64;
    let n = u64::from_le_bytes(n8) % (base * base);
    let encoded = voca::encode(num_bigint::BigUint::from(n));
    // Left-pad to exactly two words (a value < base encodes as one) — fixed width like pair_words, so the label always reads as a two-word name.
    let mut s = String::new();
    for _ in pair_word_tokens(&encoded)..2 {
        s.push_str(&zero_word());
    }
    s.push_str(&encoded);
    s
}

// ── Pairing v2 — lock word + beacon (photon docs/pairing-v2.md). The candidate device pubkey travels by proximity beacon ONLY (never the relay); one fresh voca word typed old→new authenticates the candidate; a second valid proof at any moment is proof of attack and aborts the ceremony. v1 above retires at phase 3. ──

/// Truncated MAC length in the proof beacon: 96 bits guards proof-forgery-without-the-word; it cannot guard the ~11.6-bit word itself (offline-brutable from any aired proof by design), which is why the single-valid-proof abort rule exists.
pub const WORD_MAC_LEN: usize = 12;

/// A fresh lock word for ONE ceremony, minted on the OLD device and typed into the new one. Fresh randomness each time, so holding the handle buys an attacker nothing; rerolled on every abort. Lowercase — the entry side lowercases anyway.
pub fn lock_word() -> String {
    let base = voca::FULL.alphabet.len() as u64;
    // u64 modulo bias over a 3177-word base is ~1e-16 — noise against an 11.6-bit secret.
    let idx = (rand::random::<u64>() % base) as usize;
    String::from_utf8_lossy(voca::FULL.alphabet[idx]).into_owned()
}

/// Exact-member spell check for the lock word entry (case/whitespace tolerant), reusing the pairing word index.
pub fn is_lock_word(s: &str) -> bool {
    let w = s.trim().to_ascii_lowercase();
    !w.is_empty() && word_index().0.contains(w.as_bytes())
}

/// The proof the NEW device beacons once the user typed the lock word: a keyed MAC over its device pubkey under a key derived from (word, handle_proof). The word is canonicalised (trim + lowercase) so display case and stray whitespace never break the ceremony. Word freshness is the replay guard — an old ceremony's proof verifies against nothing.
pub fn word_mac(word: &str, handle_proof: &[u8; 32], device_pubkey: &[u8; 32]) -> [u8; WORD_MAC_LEN] {
    let w = word.trim().to_ascii_lowercase();
    let mut material = Vec::with_capacity(w.len() + 32);
    material.extend_from_slice(w.as_bytes());
    material.extend_from_slice(handle_proof);
    let key = blake3::derive_key("fgtw pair v2 lock word", &material);
    let mac = blake3::keyed_hash(&key, device_pubkey);
    let mut out = [0u8; WORD_MAC_LEN];
    out.copy_from_slice(&mac.as_bytes()[..WORD_MAC_LEN]);
    out
}

/// OLD-device check of an aired proof against the word it displayed. Timing-safe comparison is pointless here — the word is offline-brutable from the proof by design; the abort-on-second-valid-proof rule is the actual defence.
pub fn verify_word_mac(word: &str, handle_proof: &[u8; 32], device_pubkey: &[u8; 32], proof: &[u8]) -> bool {
    proof.len() == WORD_MAC_LEN && word_mac(word, handle_proof, device_pubkey) == proof
}

// ── Proximity beacon: one 128-bit BLE service UUID = keyed hash of the published binding offer ──
//
// The carrier is a *service UUID* (not manufacturer data) for one blunt reason: it's the only advertising payload Apple's CoreBluetooth lets an app emit, so it's the single format that works on Linux, Android, Windows AND macOS — one codec, every platform, no fork.
// The entire 16 bytes are `keyed_hash(handle_key, device_pubkey ‖ eagle_time)` — no magic, no nonce, no carried plaintext. `eagle_time` is the NEW device's PUBLISHED binding-request stamp (`BindRequest::t`), the same value the sponsor reads back off the WWW broadcast — so the beacon is a function of real, signed, published offer state, not invented entropy. It rolls every ~3.5-min repost (fresh stamp ⇒ fresh id), so it's also an unlinkable, indistinguishable-from-noise service UUID at rest.
// Roles: the NEW device advertises `beacon_id(hp, me, my_published_eagle_time)`; the SPONSOR walks its full public candidate list and, for each entry, recomputes `beacon_id(hp, entry.device_pubkey, entry.t)` under OUR handle key and asks "did I hear that id?". A hit ⇒ that candidate is in proximity. That match IS the filter: a beacon with no matching gated registry entry hashes to nothing the sponsor computes, so it's silently dropped — and forging a matching entry needs the identity key, not just the handle.

/// Total beacon bytes: exactly one 128-bit service UUID.
pub const BEACON_UUID_LEN: usize = 16;

/// Per-fleet beacon subkey: a domain-separated derivation of `handle_proof`, so the raw proof is never a MAC key directly. The new device (typed the handle) and every sponsor (fleet member) derive the same key; no one else can — this is the "within the handle" scoping.
fn beacon_key(handle_proof: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("photon ble beacon v1", handle_proof)
}

/// The 16-byte beacon id a NEW device advertises: `keyed_hash(handle_key, device_pubkey ‖ eagle_time)`, where `eagle_time` is this device's PUBLISHED binding-offer stamp (`BindRequest::t`, oscillations). Derived entirely from the published offer — no randomness. Rolls per repost, so it's unlinkable across ceremonies and indistinguishable from any random service UUID to anyone without the handle key.
pub fn beacon_id(
    handle_proof: &[u8; 32],
    device_pubkey: &[u8; 32],
    eagle_time: i64,
) -> [u8; BEACON_UUID_LEN] {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(device_pubkey);
    material[32..].copy_from_slice(&eagle_time.to_le_bytes());
    let hash = blake3::keyed_hash(&beacon_key(handle_proof), &material);
    let mut out = [0u8; BEACON_UUID_LEN];
    out.copy_from_slice(&hash.as_bytes()[..BEACON_UUID_LEN]);
    out
}

/// SPONSOR-side match: is `device_pubkey`, which posted the offer stamped `eagle_time`, the one advertising this heard beacon? Recomputes the id under OUR handle key from the PUBLIC-LIST entry's own `(pubkey, eagle_time)` — no clock, no coupling beyond re-reading the list — and compares. A miss is the common case (room noise); a hit can't mis-BIND (the WAN registry re-verifies the full key + consent sig and the human green-confirm is the final gate), so the worst case is a transient mis-highlight among the few devices in tap range.
pub fn beacon_matches(
    uuid: &[u8; BEACON_UUID_LEN],
    handle_proof: &[u8; 32],
    device_pubkey: &[u8; 32],
    eagle_time: i64,
) -> bool {
    *uuid == beacon_id(handle_proof, device_pubkey, eagle_time)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HP: [u8; 32] = [0xab; 32];

    #[test]
    fn live_word_check_flags_typos_but_tolerates_prefixes() {
        // A real entry (generated words) passes at every truncation point.
        let words = pair_words(&[0xA5; 32]);
        assert_eq!(first_bad_pair_word(&words), None);
        for cut in 1..words.len() {
            if words.is_char_boundary(cut) {
                assert_eq!(first_bad_pair_word(&words[..cut]), None, "prefix at {cut} flagged");
            }
        }
        // Classic misspellings flag as soon as they're impossible prefixes, in either entry mode.
        assert_eq!(first_bad_pair_word("contraversy "), Some("contraversy".into()));
        assert_eq!(first_bad_pair_word("SpontaniousAble"), Some("spontanious".into()));
        // An in-progress word that is still a valid prefix stays green.
        let first = std::str::from_utf8(voca::FULL.alphabet[100]).unwrap();
        assert_eq!(first_bad_pair_word(&first[..2]), None);
        // Completeness gate: a full generated entry is complete; the same entry cut mid-last-word is NOT, even tho the token count already reads 23.
        assert!(pair_entry_complete(&words));
        let cut = words.len() - 2;
        assert!(!pair_entry_complete(&words[..cut]));
        assert_eq!(pair_word_tokens(&words[..cut]), PAIR_WORD_COUNT);
    }

    #[test]
    fn device_name_default_is_two_stable_words() {
        let seed = [3u8; 32];
        let a = device_name_default(&[7u8; 32], &seed);
        assert_eq!(a, device_name_default(&[7u8; 32], &seed), "deterministic");
        assert_eq!(pair_word_tokens(&a), 2, "always exactly two words: {a}");
        assert_ne!(a, device_name_default(&[8u8; 32], &seed), "distinct device, distinct name");
        // Same device, DIFFERENT fleet identity → distinct name (fleet-scoped): a handed-off device gets a fresh name in the new owner's fleet.
        assert_ne!(a, device_name_default(&[7u8; 32], &[9u8; 32]), "same device, distinct fleet, distinct name");
    }

    #[test]
    fn pair_words_fixed_width_round_trip() {
        // A normal key, an all-zero key (maximum padding), and a leading-zero key (partial padding) all render EXACTLY PAIR_WORD_COUNT words and decode back byte-identical.
        let mut leading_zero = [0x42u8; 32];
        leading_zero[0] = 0;
        leading_zero[1] = 0;
        for key in [[0x9au8; 32], [0u8; 32], leading_zero, rand::random()] {
            let words = pair_words(&key);
            assert_eq!(pair_word_tokens(&words), PAIR_WORD_COUNT, "fixed width");
            assert_eq!(words_to_pair_pubkey(&words).unwrap(), key, "round trip");
        }
        // The counter mirrors voca's tokenizer for both entry styles.
        let words = pair_words(&[7u8; 32]);
        let spaced: Vec<String> = {
            let mut v = Vec::new();
            let mut cur = String::new();
            for c in words.chars() {
                if c.is_ascii_uppercase() && !cur.is_empty() {
                    v.push(std::mem::take(&mut cur));
                }
                cur.push(c);
            }
            v.push(cur);
            v
        };
        assert_eq!(spaced.len(), PAIR_WORD_COUNT);
        assert_eq!(pair_word_tokens(&spaced.join(" ")), PAIR_WORD_COUNT);
        assert_eq!(words_to_pair_pubkey(&spaced.join(" ")).unwrap(), [7u8; 32]);
    }

    #[test]
    fn words_to_pair_pubkey_rejects_bad_entries() {
        // Wrong word count (incomplete entry) is rejected before any decode.
        assert!(words_to_pair_pubkey("justOneWord").is_err());
        // 23 copies of the LAST alphabet word decode above 2^256 — a valid-looking entry that isn't a key.
        let last = std::str::from_utf8(voca::FULL.alphabet[voca::FULL.base() - 1]).unwrap();
        let too_big = vec![last; PAIR_WORD_COUNT].join(" ");
        assert!(words_to_pair_pubkey(&too_big).is_err());
        // A garbage token fails the decode loudly.
        let mut words = pair_words(&[1u8; 32]);
        words.push_str("Zzzqx");
        assert!(words_to_pair_pubkey(&words).is_err());
    }

    #[test]
    fn lock_word_is_a_list_member() {
        for _ in 0..8 {
            let w = lock_word();
            assert!(is_lock_word(&w), "minted word must spell-check: {w}");
            assert_eq!(w, w.to_ascii_lowercase(), "minted lowercase: {w}");
        }
        // Case/whitespace tolerance, on a word actually in the list.
        let real = std::str::from_utf8(voca::FULL.alphabet[100]).unwrap();
        let mut dressed = String::from(" ");
        dressed.push(real.chars().next().unwrap().to_ascii_uppercase());
        dressed.push_str(&real[1..]);
        dressed.push(' ');
        assert!(is_lock_word(&dressed), "entry check is case/whitespace tolerant: {dressed:?}");
        assert!(!is_lock_word("zzzqx"));
        assert!(!is_lock_word(""));
    }

    #[test]
    fn word_mac_binds_word_identity_and_device() {
        let pk_a = [7u8; 32];
        let proof = word_mac("apple", &HP, &pk_a);
        // Verifies for the exact (word, hp, pubkey) triple, tolerant of display case and stray whitespace.
        assert!(verify_word_mac("apple", &HP, &pk_a, &proof));
        assert!(verify_word_mac(" Apple ", &HP, &pk_a, &proof));
        // Any changed leg fails: wrong word, wrong identity, wrong device, truncated proof.
        assert!(!verify_word_mac("orange", &HP, &pk_a, &proof));
        assert!(!verify_word_mac("apple", &[9u8; 32], &pk_a, &proof));
        assert!(!verify_word_mac("apple", &HP, &[8u8; 32], &proof));
        assert!(!verify_word_mac("apple", &HP, &pk_a, &proof[..WORD_MAC_LEN - 1]));
    }

    #[test]
    fn beacon_id_matches_only_the_right_fleet_device_and_stamp() {
        let pk = [0x42u8; 32];
        let other_pk = [0x43u8; 32];
        let et: i64 = 0x0011_2233_4455_6677;
        let uuid = beacon_id(&HP, &pk, et);
        assert_eq!(uuid.len(), BEACON_UUID_LEN);
        // The sponsor recomputes the id from the public-list entry's own (pubkey, eagle_time) under our key.
        assert!(beacon_matches(&uuid, &HP, &pk, et));
        // Wrong device, wrong fleet, wrong stamp, and flipped noise all fail closed.
        assert!(!beacon_matches(&uuid, &HP, &other_pk, et));
        let other_hp = [0xcd; 32];
        assert!(!beacon_matches(&uuid, &other_hp, &pk, et));
        assert!(!beacon_matches(&uuid, &HP, &pk, et + 1));
        let mut noise = uuid;
        noise[0] ^= 0xFF;
        assert!(!beacon_matches(&noise, &HP, &pk, et));
        // Fresh repost stamp ⇒ a different beacon for the same device (per-repost unlinkability).
        assert_ne!(beacon_id(&HP, &pk, et + 1), uuid);
    }

    #[test]
    fn masked_words_are_fleet_scoped_and_deterministic() {
        let device = [0x42u8; 32];
        let seed_a = [1u8; 32];
        let seed_b = [2u8; 32];
        let words_a = masked_device_words(&device, &seed_a);
        // Deterministic, fixed width, and the mask round-trips thru the word codec.
        assert_eq!(words_a, masked_device_words(&device, &seed_a));
        assert_eq!(pair_word_tokens(&words_a), PAIR_WORD_COUNT);
        let decoded = words_to_pair_pubkey(&words_a).unwrap();
        let mask = word_mask(&seed_a);
        let unmasked: Vec<u8> = decoded.iter().zip(mask.iter()).map(|(b, m)| b ^ m).collect();
        assert_eq!(unmasked.as_slice(), &device);
        // A different fleet's mask yields entirely different words — the same device is unrecognisable across fleets.
        assert_ne!(words_a, masked_device_words(&device, &seed_b));
    }
}
