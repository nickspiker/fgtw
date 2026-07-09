//! Pairing v1 — device-ADD ceremony word logic.
//!
//! The NEW device generates a fresh 256-bit pairing keypair and DISPLAYS its public half as words; the user types them into an EXISTING device, which matches them against the posted request and binds.
//! The words are a public key, not a bearer secret: the request is SIGNED by the pairing private key, so a shoulder-surfer who reads the words can find the request but can never forge a rival one for their own device — stealing the invite requires stealing the new device itself.
//! 256-bit because the value is matched on the network: birthday-bounded to 128-bit security, per the count that matters.
//!
//! This module is the word codec + spell-check + signing-bytes; the FGTW relay transport (post/fetch the request, post/poll the matched flag) is the client's job — it signs with the bytes defined here.

use crate::keys::Keypair;
use vsf::VsfType;

/// Fixed word count for a 256-bit pairing key: voca's FULL base is 3177 (~11.63 bits/word), and 22 words is 255.94 bits — just short — so 23 covers every key. Fixed-width (leading-zero-padded) so the typing side always knows when the entry is complete.
pub const PAIR_WORD_COUNT: usize = 23;

/// Fresh pairing identity for one add attempt (the seed IS the 256-bit value the words carry — the keypair is derived from it).
pub fn new_pairing_id() -> Keypair {
    Keypair::from_seed(&rand::random::<[u8; 32]>())
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

/// Parse a hub-pushed pairing event — section `pair_evt` {k: kind, hp} — into (kind, handle_proof). Returns `None` for every other frame: the hub also carries dashboard-capsule broadcasts, which subscribers skip cheaply on the header/section decode. Kinds today: "matched" (a member posted the matched flag) and "fleet" (the membership chain extended).
pub fn parse_pair_event(bytes: &[u8]) -> Option<(String, [u8; 32])> {
    // Verified read (hp + hb | signature) — hub frames are worker-built and always carry an anchor; anything unverifiable is skipped, not parsed.
    let (_, header_end) = vsf::verification::read_verified(bytes, None).ok()?;
    let mut ptr = header_end;
    let section = vsf::VsfSection::parse(bytes, &mut ptr).ok()?;
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

/// Deterministic default device label: exactly TWO voca words derived one-way from the device PUBLIC key. Keying on the pubkey (not the secret) is what makes the label FLEET-CONSISTENT — every device knows every other device's pubkey, so all devices compute the same name for a given device (a secret-keyed label could only be computed by the device itself, which is why the fleet list and the pairing screen used to disagree). The pubkey is fingerprint-deterministic just like the secret, so the label still survives a wipe-and-reinstall ("same device, same name"). Label space is 3177² ≈ 10.1 M, so even a 12-device fleet collides with p ≈ 7×10⁻⁶. camelCase per the voca display convention. The owner-edited override (devices page) supersedes this — it is only the shipped default.
pub fn device_name_default(device_pubkey: &[u8; 32]) -> String {
    let mut input = Vec::with_capacity(24 + 32);
    input.extend_from_slice(b"PHOTON_DEVICE_NAME_v1");
    input.extend_from_slice(device_pubkey);
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

/// A pairing request the existing device matched against the typed words: the device to bind, proven owned by the pairing key the words name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairRequest {
    pub pairing_pubkey: [u8; 32],
    pub device_pubkey: [u8; 32],
}

/// The exact bytes a pairing request signs: the pairing key attests it owns `device_pubkey` for `handle_proof` at time `t`. The client transport signs these with the pairing key and verifies them under the request's own pairing pubkey.
pub fn pair_request_signing_bytes(handle_proof: &[u8; 32], device_pubkey: &[u8; 32], t: i64) -> Vec<u8> {
    let mut v = Vec::with_capacity(24 + 64 + 8);
    v.extend_from_slice(b"PHOTON_PAIR_REQ_v1");
    v.extend_from_slice(handle_proof);
    v.extend_from_slice(device_pubkey);
    v.extend_from_slice(&t.to_le_bytes());
    v
}

/// The exact bytes a "matched" flag signs: a member device attests it matched `pairing_pubkey` for `handle_proof` at time `t`. Signed by the member device, verified by the new device against the current member set.
pub fn pair_matched_signing_bytes(handle_proof: &[u8; 32], pairing_pubkey: &[u8; 32], t: i64) -> Vec<u8> {
    let mut v = Vec::with_capacity(28 + 64 + 8);
    v.extend_from_slice(b"PHOTON_PAIR_MATCHED_v1");
    v.extend_from_slice(handle_proof);
    v.extend_from_slice(pairing_pubkey);
    v.extend_from_slice(&t.to_le_bytes());
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    const HP: [u8; 32] = [0xab; 32];

    fn key(seed: u8) -> Keypair {
        Keypair::from_seed(&[seed; 32])
    }
    fn pk(k: &Keypair) -> [u8; 32] {
        k.public.to_bytes()
    }

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
        let a = device_name_default(&[7u8; 32]);
        assert_eq!(a, device_name_default(&[7u8; 32]), "deterministic");
        assert_eq!(pair_word_tokens(&a), 2, "always exactly two words: {a}");
        assert_ne!(a, device_name_default(&[8u8; 32]), "distinct secrets, distinct names");
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
    fn pair_request_and_matched_signatures_verify_and_bind() {
        use ed25519_dalek::Verifier;
        let pairing = new_pairing_id();
        let member = key(4);
        let dk = pk(&key(5));
        let t = 12345i64;
        // Ownership proof: verifies under the pairing pubkey, breaks under a different device or identity.
        let sig = pairing.sign(&pair_request_signing_bytes(&HP, &dk, t));
        let vk = VerifyingKey::from_bytes(&pairing.public.to_bytes()).unwrap();
        assert!(vk.verify(&pair_request_signing_bytes(&HP, &dk, t), &sig).is_ok());
        assert!(vk.verify(&pair_request_signing_bytes(&HP, &pk(&key(6)), t), &sig).is_err());
        assert!(vk.verify(&pair_request_signing_bytes(&[9u8; 32], &dk, t), &sig).is_err());
        // Matched flag: verifies under the member's device key, breaks for a different pairing pubkey.
        let pp = pairing.public.to_bytes();
        let msig = member.sign(&pair_matched_signing_bytes(&HP, &pp, t));
        let mvk = VerifyingKey::from_bytes(&pk(&member)).unwrap();
        assert!(mvk.verify(&pair_matched_signing_bytes(&HP, &pp, t), &msig).is_ok());
        assert!(mvk.verify(&pair_matched_signing_bytes(&HP, &[8u8; 32], t), &msig).is_err());
    }
}
