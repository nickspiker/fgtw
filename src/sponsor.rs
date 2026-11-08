//! The sponsor's half of the device-ADD ceremony and the approver's half of a departure (photon docs/pairing-v2.md), for every client of a fleet: Photon on desktop and Android, ferros's identity service, any other app. One implementation, many callers; what moves bytes (UDP, HTTP, BLE, NFC) stays each caller's.
//!
//! The ceremony, sponsor side:
//! 0. **Candidates.** The newcomer's binding request reaches the sponsor two ways with one stamp: the seed's registry ([`crate::client::bindreq_list`], member-gated, every row re-verified) and the LAN (`bind_req` frames, checked here by [`check_lan_request`] exactly as a registry row is). [`merge_requests`] keeps the newest per device key; [`candidates`] precomputes each one's name, word tokens, and whether it is heard nearby (its BLE beacon id recomputed from its own key and stamp, [`crate::pair::beacon_matches`], or its request handed over the LAN).
//! 1. **Selection**, three ways: the person types the newcomer's 23 words ([`match_words`]: a full exact match against one verified request IS the selection, and the confirmation); the person taps the newcomer's NFC tag and the secret read matches the request's commitment ([`nfc_match`]); or the person picks a candidate heard nearby.
//! 2. **The Add** ([`bind_device_held`]): the consent-carrying Add appended to the chain held (refreshed from the seed when it answers), held, and published to the seed as a mirror. A plate this fleet locked out is refused first ([`plate_locked`]).
//! 3. **The key** ([`crate::held::fanout_grow_held`]): the fan-out grown to the member set including the newcomer, under the SAME key. A words match grows at once; a nearby pick waits behind the person's confirm that the newcomer left its words screen (two-phase: a wrong pick stays a keyless ledger entry).
//! 4. **The hand-over** is the caller's: the extended chain (`fleet_resp`) and the grown fan-out (`fanout_resp`) to the siblings and to the newcomer at the address its LAN request came from; the newcomer also finds both on the seed.
//!
//! Departure, approver side: a sibling's `depart_req` is checked on receipt ([`depart_receipt_valid`]); the person types the three words the leaver shows ([`depart_words_match`] against the request's commitment), and [`approve_departure`] countersigns and publishes the consented Remove, releasing the device's brand when the leaver asked for a new owner.
//!
//! Moved from photon src/ui/photon_app/devices.rs and src/network/fgtw/fleet.rs (2026-11-08), behaviour unchanged.

use crate::client::{self, FgtwTransport};
use crate::fleet::{BindRequest, MembershipBlob, BINDREQ_FRESH_OSC};
use crate::held::ChainHold;
use crate::pq::FleetSigner;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// One device asking to join, as the sponsor's screen shows it: its request, its name in this fleet, its 23 expected word tokens (precomputed so the per-keystroke matcher is a plain walk), and whether it is heard nearby.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub req: BindRequest,
    /// The two-word name every device of this fleet computes for it ([`crate::pair::device_name_default`]).
    pub name: String,
    pub tokens: Vec<String>,
    /// Its BLE beacon heard right now (the keyed id recomputed from its own key and stamp).
    pub heard_ble: bool,
    /// Its request handed to this sponsor over the LAN recently.
    pub heard_lan: bool,
}

impl Candidate {
    /// Heard nearby by either radio: only these are offered as a pick (a flooded registry never populates a pickable row).
    pub fn nearby(&self) -> bool {
        self.heard_ble || self.heard_lan
    }
}

/// The requests from both sources merged by device key, the newest stamp winning. Each was verified where it came in.
pub fn merge_requests(registry: &[BindRequest], lan: &[BindRequest]) -> Vec<BindRequest> {
    let mut reqs: Vec<BindRequest> = Vec::new();
    for req in registry.iter().chain(lan.iter()) {
        match reqs.iter_mut().find(|r| r.device_pubkey == req.device_pubkey) {
            Some(have) => {
                if req.t > have.t {
                    *have = req.clone();
                }
            }
            None => reqs.push(req.clone()),
        }
    }
    reqs
}

/// Drop the LAN requests whose stamp has lapsed (the registry's own freshness, [`BINDREQ_FRESH_OSC`]).
pub fn retain_fresh(lan: &mut Vec<BindRequest>, now: i64) {
    lan.retain(|r| now.abs_diff(r.t) <= BINDREQ_FRESH_OSC as u64);
}

/// The candidate rows: each request with its name, its word tokens, and whether it is heard nearby. `heard_ble` are the beacon ids the scanner heard; `heard_lan` the device keys whose requests came over the LAN recently.
pub fn candidates(reqs: Vec<BindRequest>, identity_seed: &[u8; 32], handle_proof: &[u8; 32], heard_ble: &[[u8; crate::pair::BEACON_UUID_LEN]], heard_lan: &[[u8; 32]]) -> Vec<Candidate> {
    reqs.into_iter()
        .map(|req| {
            let words = crate::pair::masked_device_words(&req.device_pubkey, identity_seed);
            Candidate {
                name: crate::pair::device_name_default(&req.device_pubkey, identity_seed),
                tokens: crate::pair::pair_word_list(&words),
                heard_ble: heard_ble.iter().any(|u| crate::pair::beacon_matches(u, handle_proof, &req.device_pubkey, req.t)),
                heard_lan: heard_lan.contains(&req.device_pubkey),
                req,
            }
        })
        .collect()
}

/// Why a binding request handed over the LAN was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanRefusal {
    /// Its stamp is outside the registry's freshness window.
    Stale,
    /// Its signatures do not verify for this fleet (the device's consent, or the identity's co-signature).
    Unverified,
}

/// A binding request handed to this sponsor directly (`bind_req`), checked exactly as a registry row is: the stamp fresh, both signatures under this fleet's identity key.
pub fn check_lan_request(req: &BindRequest, handle_proof: &[u8; 32], identity_seed: &[u8; 32], now: i64) -> Result<(), LanRefusal> {
    if now.abs_diff(req.t) > BINDREQ_FRESH_OSC as u64 {
        return Err(LanRefusal::Stale);
    }
    let identity_pubkey = ed25519_dalek::SigningKey::from_bytes(identity_seed).verifying_key().to_bytes();
    if !req.verify(handle_proof, &identity_pubkey) {
        return Err(LanRefusal::Unverified);
    }
    Ok(())
}

/// What offering a checked LAN request to the held set did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Offered {
    /// A request at least as new from this device is held already.
    Unchanged,
    /// A newer stamp replaced the device's held request.
    Updated,
    /// A device not asking before.
    New,
}

/// Keep a checked LAN request: the newest per device key.
pub fn offer_lan(lan: &mut Vec<BindRequest>, req: BindRequest) -> Offered {
    match lan.iter_mut().find(|r| r.device_pubkey == req.device_pubkey) {
        Some(have) if have.t >= req.t => Offered::Unchanged,
        Some(have) => {
            *have = req;
            Offered::Updated
        }
        None => {
            lan.push(req);
            Offered::New
        }
    }
}

/// Where the words typed so far stand against the candidates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WordMatch {
    /// No candidate to match against yet; the voca spell-check's first bad word, if any, still catches finger trouble while the registry answers.
    NoCandidates { typo: Option<String> },
    /// Nothing typed; how many devices are asking.
    Nothing { asking: usize },
    /// All 23 words, exact, against candidate `.0`: the selection is made.
    Full(usize),
    /// The words left every candidate at this word.
    NoMatch(String),
    /// Still matching exactly one candidate (its index).
    One(usize),
    /// Still matching this many.
    Many(usize),
}

/// The live matcher (docs/pairing-v2.md). Per candidate: every completed typed token must equal the expected token exactly; the still-being-typed last token passes while it is a prefix of the candidate's next word. The last typed token is complete (must match exactly) only once a separator follows it, so nothing flashes red mid-word. Divergence names the exact word.
pub fn match_words(text: &str, cands: &[Candidate]) -> WordMatch {
    let tokens = crate::pair::pair_word_list(text);
    if cands.is_empty() {
        // The spell-check needs the sorted word index, which only std builds keep; without it no typo is named until a candidate arrives.
        #[cfg(feature = "std")]
        let typo = crate::pair::first_bad_pair_word(text);
        #[cfg(not(feature = "std"))]
        let typo = None;
        return WordMatch::NoCandidates { typo };
    }
    if tokens.is_empty() {
        return WordMatch::Nothing { asking: cands.len() };
    }
    let last_complete = text != text.trim_end();
    let n = tokens.len();
    let mut full_match: Option<usize> = None;
    let mut alive = 0usize;
    let mut alive_idx = 0usize;
    let mut deepest = 0usize;
    for (ci, cand) in cands.iter().enumerate() {
        let mut depth = 0usize;
        let mut ok = n <= cand.tokens.len();
        if ok {
            for (i, t) in tokens.iter().enumerate() {
                let is_last = i + 1 == n;
                let hit = if !is_last || last_complete { &cand.tokens[i] == t } else { cand.tokens[i].starts_with(t.as_str()) };
                if hit {
                    depth += 1;
                } else {
                    ok = false;
                    break;
                }
            }
        }
        // WHY the max: the deepest any candidate got is where the entry left them all, the word to name in red.
        deepest = deepest.max(depth);
        if ok {
            alive += 1;
            alive_idx = ci;
            if n == crate::pair::PAIR_WORD_COUNT && tokens[n - 1] == cand.tokens[n - 1] {
                full_match = Some(ci);
            }
        }
    }
    if let Some(ci) = full_match {
        return WordMatch::Full(ci);
    }
    match alive {
        // `deepest < n` here: a candidate that matched all `n` tokens stayed alive, and one with fewer tokens than typed matched none, so with none alive every depth stopped short of `n`.
        0 => WordMatch::NoMatch(tokens[deepest].clone()),
        1 => WordMatch::One(alive_idx),
        k => WordMatch::Many(k),
    }
}

/// A secret read off a newcomer's NFC tag: the candidate whose published commitment it opens ([`crate::pair::nfc_secret_hash`] over the secret, its key and its stamp), if any. A request with no commitment (all zero) never matches.
pub fn nfc_match(secret: &[u8; 32], cands: &[Candidate]) -> Option<usize> {
    cands.iter().position(|c| c.req.nfc_hash != [0u8; 32] && crate::pair::nfc_secret_hash(secret, &c.req.device_pubkey, c.req.t) == c.req.nfc_hash)
}

/// Whether the joiner's plate is one this fleet locked out (the held chain's locked plates): a device the owner locked out, wiped and brought back under a fresh key is the same hardware, and words matching does not readmit it.
pub fn plate_locked(h: &impl ChainHold, handle_proof: &[u8; 32], req: &BindRequest) -> bool {
    let Some(plate) = req.plate else { return false };
    h.held(handle_proof).and_then(|c| c.locked_plates().ok()).unwrap_or_default().contains(&plate)
}

/// The Add, SEED-OPTIONAL: append the consent-carrying Add for a verified request to the chain held (refreshed from the seed when it answers), hold the result, and publish it to the seed as a mirror. A seed that cannot be reached does not fail the add: the chain reaches the fleet and the newcomer over the peer frames (`fleet_resp`). Returns the extended chain for the caller to hand out. A seed `stale` answer (a sibling extended first) re-fetches and re-applies.
pub fn bind_device_held<T: FgtwTransport>(t: &T, h: &impl ChainHold, signer: &impl FleetSigner, handle_proof: &[u8; 32], req: &BindRequest) -> Result<MembershipBlob, String> {
    let me = signer.keypair().public.to_bytes();
    for _attempt in 0..4 {
        let mut blob = crate::held::fetch(t, h, handle_proof)?.ok_or("no fleet to add to — attest this identity first")?;
        let members = blob.fold().map_err(|e| format!("stored fleet invalid: {e:?}"))?;
        if !members.contains(&me) {
            return Err("this device isn't a fleet member, so it can't add another".into());
        }
        if members.contains(&req.device_pubkey) {
            return Ok(blob); // already in — idempotent
        }
        // The joiner's bundle and plate ride its own signed request onto the Add; the stamp never precedes the tip (security audit FGTW-03).
        let at = client::stamp_after(&blob);
        blob.add_with(signer, req.device_pubkey, at, req.t, req.device_sig.clone(), req.bundle.clone(), req.plate, req.plate_kind);
        match crate::held::publish(t, h, &blob) {
            Ok(()) => return Ok(blob),
            Err(e) if e.contains("stale") => continue,
            Err(e) => {
                crate::log(&format!("FLEET: add bound and held; the seed mirror failed ({}) — the chain reaches the fleet over the peer frames", e));
                return Ok(blob);
            }
        }
    }
    Err("fleet add: lost too many extension races".into())
}

/// A sibling's departure request on receipt, deliberately shallow: the consent blob parses and its Ed25519 egg verifies against the leaver's device key over this fleet's departure bytes. Enough to drop junk before it reaches a person; the PQ eggs are verified by the FOLD when the approver publishes the consented Remove (the chain holds the leaver's declared bundle and the floor).
pub fn depart_receipt_valid(handle_proof: &[u8; 32], leaver: &[u8; 32], consent_t: i64, consent_sig: &[u8]) -> bool {
    let msg = crate::fleet::departreq_signing_bytes(handle_proof, leaver, consent_t);
    crate::pq::eggs_from_bytes(consent_sig)
        .ok()
        .and_then(|eggs| eggs.into_iter().find(|e| e.scheme == crate::fleet::scheme::ED25519))
        .map(|e| crate::pq::verify_egg(crate::fleet::scheme::ED25519, leaver, &msg, &e.sig))
        .unwrap_or(false)
}

/// The approval words typed against the request's commitment: blake3 over the typed words, trimmed and lower-cased (the leaver commits to its words lower-cased, [`crate::protocol::depart_words_commit`]).
pub fn depart_words_match(typed: &str, commit: &[u8; 32]) -> bool {
    crate::protocol::depart_words_commit(typed.trim()) == *commit
}

/// What an approved departure did beyond the Remove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Approved {
    /// To the desk (or an older request stating no intent): the device's brand kept.
    BrandKept,
    /// To a new owner: the brand released too, or why the release failed (the countersign landed; the release is the retired row's retry).
    Released(Result<(), String>),
}

/// APPROVER: countersign a sibling's departure and publish the consented Remove; for a new-owner departure release its brand in the same breath (the approve finishes the hand-off). `intent` as the request stated it: 1 a new owner, anything else keeps the brand (a legacy desk request, or an ancient intent 0).
pub fn approve_departure<T: FgtwTransport>(t: &T, signer: &impl FleetSigner, handle_proof: &[u8; 32], leaver: &[u8; 32], consent_t: i64, consent_sig: &[u8], intent: u8) -> Result<Approved, String> {
    client::depart_device_consented(t, signer, handle_proof, leaver, consent_t, consent_sig)?;
    if intent == crate::protocol::DEPART_NEW_OWNER {
        Ok(Approved::Released(client::device_release(t, signer, handle_proof, leaver)))
    } else {
        Ok(Approved::BrandKept)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    fn req(dev: &Keypair, seed: &[u8; 32], hp: &[u8; 32], t: i64, nfc: &[u8; 32]) -> BindRequest {
        crate::protocol::bind_request(dev, seed, hp, t, nfc)
    }

    #[test]
    fn words_select_exactly_one_device() {
        let (seed, hp) = ([7u8; 32], [9u8; 32]);
        let a = Keypair::from_seed(&[1u8; 32]);
        let b = Keypair::from_seed(&[2u8; 32]);
        let now = crate::now_oscillations();
        let cands = candidates(vec![req(&a, &seed, &hp, now, &[0; 32]), req(&b, &seed, &hp, now, &[0; 32])], &seed, &hp, &[], &[]);
        assert_eq!(match_words("", &cands), WordMatch::Nothing { asking: 2 });
        let words = crate::pair::masked_device_words(&b.public.to_bytes(), &seed);
        assert_eq!(match_words(&words, &cands), WordMatch::Full(1));
        // The first word alone, still being typed, narrows to the candidates it prefixes.
        let first = cands[1].tokens[0].clone();
        match match_words(&first[..first.len() - 1], &cands) {
            WordMatch::One(1) | WordMatch::Many(2) => {}
            m => panic!("unexpected {m:?}"),
        }
        // A completed wrong word is named.
        assert_eq!(match_words("zzzz ", &cands), WordMatch::NoMatch("zzzz".into()));
        assert!(matches!(match_words("anything", &[]), WordMatch::NoCandidates { .. }));
    }

    #[test]
    fn lan_requests_are_checked_merged_and_tapped() {
        let (seed, hp) = ([7u8; 32], [9u8; 32]);
        let a = Keypair::from_seed(&[1u8; 32]);
        let now = crate::now_oscillations();
        let s = [5u8; 32];
        let r0 = req(&a, &seed, &hp, now - 10, &s);
        let r1 = req(&a, &seed, &hp, now, &s);
        assert_eq!(check_lan_request(&r1, &hp, &seed, now), Ok(()));
        assert_eq!(check_lan_request(&r1, &hp, &[8u8; 32], now), Err(LanRefusal::Unverified));
        assert_eq!(check_lan_request(&r1, &hp, &seed, now + 2 * BINDREQ_FRESH_OSC), Err(LanRefusal::Stale));
        let mut lan = Vec::new();
        assert_eq!(offer_lan(&mut lan, r0.clone()), Offered::New);
        assert_eq!(offer_lan(&mut lan, r1.clone()), Offered::Updated);
        assert_eq!(offer_lan(&mut lan, r0.clone()), Offered::Unchanged);
        let merged = merge_requests(&[r0], &lan);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].t, now);
        let id = crate::pair::beacon_id(&hp, &a.public.to_bytes(), now);
        let cands = candidates(merged, &seed, &hp, &[id], &[]);
        assert!(cands[0].heard_ble && !cands[0].heard_lan && cands[0].nearby());
        assert_eq!(nfc_match(&s, &cands), Some(0));
        assert_eq!(nfc_match(&[6u8; 32], &cands), None);
    }

    #[test]
    fn departure_words_and_receipt() {
        let hp = [9u8; 32];
        let leaver = Keypair::from_seed(&[3u8; 32]);
        let words = crate::protocol::depart_words(12345);
        let commit = crate::protocol::depart_words_commit(&words);
        assert!(depart_words_match(&format!("  {} ", words.to_lowercase()), &commit));
        assert!(!depart_words_match("wrong words here", &commit));
        let t = 42;
        let consent = crate::protocol::depart_consent(&leaver, &hp, t);
        assert!(depart_receipt_valid(&hp, &leaver.public.to_bytes(), t, &consent));
        assert!(!depart_receipt_valid(&hp, &leaver.public.to_bytes(), t + 1, &consent));
    }
}
