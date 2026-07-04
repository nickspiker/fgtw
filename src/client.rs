//! The FGTW client oracle — fetch-then-sign over an injected transport.
//!
//! The device is a blind, stateless signing oracle: it fetches a blob from FGTW, finds its own pubkey, signs, and posts.
//! ALL the protocol logic lives here (request framing, the 404/409/epoch rules, freshness + signature checks) — the app supplies only the raw HTTP and the roster AEAD, via [`FgtwTransport`] and [`FleetSealer`].
//! So photon rides its warm-TLS connection pool and its own error-message UX, the calendar can use a different HTTP client, and this crate stays reqwest-free.

use crate::fanout::{fanout_from_bytes, fanout_open, fanout_seal, fanout_to_bytes, new_fleet_key, FanoutWrap};
use crate::fleet::{et_to_osc, MembershipBlob};
use crate::fstate::{roster_from_bytes, roster_to_bytes, RosterEntry};
use crate::keys::Keypair;
use crate::pair::{pair_matched_signing_bytes, pair_request_signing_bytes, PairRequest};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use vsf::VsfType;

/// One HTTP response from FGTW: the status code and the body bytes.
/// The transport returns this for ANY status it managed to receive; it returns `Err` only when it couldn't reach FGTW at all — so the client here owns the 404/409/success interpretation.
pub struct FgtwResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The app's reach to FGTW: POST these request bytes, return the response.
/// The implementor owns the endpoint URL, timeouts, headers, connection pooling, and network-error phrasing; this crate owns everything above the wire.
pub trait FgtwTransport {
    fn post(&self, body: Vec<u8>) -> Result<FgtwResponse, String>;
}

/// The app's AEAD for fleet-shared state: seal/open a blob under the 32-byte fleet key.
/// Injected (rather than a crate dep) so the roster ciphertext stays byte-identical to whatever the app already uses (photon: `kete`), with no second AEAD implementation to keep in sync.
pub trait FleetSealer {
    fn seal(&self, plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String>;
    fn open(&self, sealed: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String>;
}

/// Pairing slots older than this are ignored (stale inbox). 5 minutes.
const PAIR_FRESH_OSC: i64 = 300 * vsf::OSCILLATIONS_PER_SECOND as i64;

// ── helpers ──

fn provenance_req(section: vsf::VsfSection) -> Result<Vec<u8>, String> {
    vsf::VsfBuilder::new()
        .creation_time_oscillations(vsf::eagle_time_oscillations())
        .provenance_only()
        .add_section_direct(section)
        .build()
        .map_err(|e| format!("fgtw request build: {e}"))
}

fn parse_section(bytes: &[u8]) -> Result<vsf::VsfSection, String> {
    let (_, header_end) = vsf::VsfHeader::decode(bytes).map_err(|e| format!("fgtw header: {e}"))?;
    let mut ptr = header_end;
    vsf::VsfSection::parse(bytes, &mut ptr).map_err(|e| format!("fgtw section: {e}"))
}

// ── Fleet chain oracle ──

/// Fetch the identity's stored fleet chain, or `None` if none exists yet (404). Parsed but NOT trusted until [`MembershipBlob::fold`].
pub fn fetch<T: FgtwTransport>(t: &T, handle_proof: &[u8; 32]) -> Result<Option<MembershipBlob>, String> {
    let mut section = vsf::VsfSection::new("fleet_get");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    let resp = t.post(provenance_req(section)?)?;
    if resp.status == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&resp.status) {
        return Err("FGTW rejected the lookup".to_string());
    }
    Ok(Some(MembershipBlob::from_vsf_bytes(&resp.body)?))
}

/// Publish a new (or extended) chain. The worker accepts it only as a forward extension of what it holds; a stale post gets 409, surfaced as `"fleet: 409"` so the retry loop can match on it.
pub fn publish<T: FgtwTransport>(t: &T, blob: &MembershipBlob) -> Result<(), String> {
    let resp = t.post(blob.to_vsf_bytes()?)?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else if resp.status == 409 {
        Err("fleet: 409".to_string())
    } else {
        Err("FGTW rejected the fleet update".to_string())
    }
}

/// Ensure this device is a CURRENT member before an authorised write.
/// No fleet yet → claim it with a first-come, identity-co-signed genesis. Already a member → nothing to do. A fleet exists without this device → it must be enrolled from an existing device first.
pub fn ensure_member<T: FgtwTransport>(
    t: &T,
    device_key: &Keypair,
    handle_proof: &[u8; 32],
    identity_seed: &[u8; 32],
) -> Result<(), String> {
    let me = device_key.public.to_bytes();
    if let Some(blob) = fetch(t, handle_proof)? {
        return if blob.fold().map(|m| m.contains(&me)).unwrap_or(false) {
            Ok(())
        } else {
            Err("this device is not in the fleet — enroll it from an existing device first".into())
        };
    }
    let blob =
        MembershipBlob::genesis(device_key, *handle_proof, identity_seed, vsf::eagle_time_oscillations());
    let _ = publish(t, &blob);
    // Trust the network, not ourselves: re-fetch the canonical chain and accept ONLY if it names this device. The fleet slot has no compare-and-set, so two devices racing a fresh handle's genesis both "publish" but the slot settles on ONE — the loser re-reads here, finds it isn't a member, and fails cleanly instead of announcing as a phantom founder.
    match fetch(t, handle_proof)? {
        Some(b) if b.fold().map(|m| m.contains(&me)).unwrap_or(false) => Ok(()),
        Some(_) => {
            Err("this device is not in the fleet — enroll it from an existing device first".into())
        }
        None => Err("failed to establish fleet membership for this device".into()),
    }
}

/// The current device-pubkey member set (empty if no fleet yet).
pub fn current_members<T: FgtwTransport>(t: &T, handle_proof: &[u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    match fetch(t, handle_proof)? {
        Some(b) => b.fold().map_err(|e| format!("stored fleet invalid: {e:?}")),
        None => Ok(Vec::new()),
    }
}

/// Existing-device side of device-ADD: add `new_pubkey`, signed by this (member) device.
/// `new_pubkey` must have arrived over the proximity channel (NFC / words screen-to-screen), so the signature binds to the device in hand, not to anyone who knows the (public) handle.
pub fn bind_device<T: FgtwTransport>(
    t: &T,
    member_key: &Keypair,
    handle_proof: &[u8; 32],
    new_pubkey: [u8; 32],
) -> Result<(), String> {
    let me = member_key.public.to_bytes();
    for _attempt in 0..4 {
        let mut blob = fetch(t, handle_proof)?
            .ok_or("no fleet to add to — attest this identity first")?;
        let members = blob.fold().map_err(|e| format!("stored fleet invalid: {e:?}"))?;
        if !members.contains(&me) {
            return Err("this device isn't a fleet member, so it can't add another".into());
        }
        if members.contains(&new_pubkey) {
            return Ok(()); // already in — idempotent
        }
        blob.add(member_key, new_pubkey, vsf::eagle_time_oscillations());
        match publish(t, &blob) {
            Ok(()) => return Ok(()),
            Err(e) if e.contains("409") => continue, // someone else extended; re-fetch + retry
            Err(e) => return Err(e),
        }
    }
    Err("fleet add: lost too many extension races".into())
}

/// Existing-device side of device removal: remove `target_pubkey`, signed by this (member) device.
pub fn unbind_device<T: FgtwTransport>(
    t: &T,
    member_key: &Keypair,
    handle_proof: &[u8; 32],
    target_pubkey: [u8; 32],
) -> Result<(), String> {
    let me = member_key.public.to_bytes();
    for _attempt in 0..4 {
        let mut blob = fetch(t, handle_proof)?.ok_or("no fleet to modify")?;
        let members = blob.fold().map_err(|e| format!("stored fleet invalid: {e:?}"))?;
        if !members.contains(&me) {
            return Err("this device isn't a fleet member, so it can't remove another".into());
        }
        if !members.contains(&target_pubkey) {
            return Ok(()); // already gone — idempotent
        }
        blob.remove(member_key, target_pubkey, vsf::eagle_time_oscillations());
        match publish(t, &blob) {
            Ok(()) => return Ok(()),
            Err(e) if e.contains("409") => continue,
            Err(e) => return Err(e),
        }
    }
    Err("fleet remove: lost too many extension races".into())
}

// ── Pairing transport (FGTW is a dumb relay; the pairing key's signature authenticates ownership, the member's signature authenticates the match). ──

fn field32(section: &vsf::VsfSection, name: &str) -> Option<[u8; 32]> {
    match section.get_field(name).and_then(|f| f.values.first()) {
        Some(VsfType::ke(b)) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            Some(a)
        }
        _ => None,
    }
}

/// NEW device: post its pairing request — `{device_pubkey, pairing_pubkey, t, sig}` where `sig` is the PAIRING key signing the (identity, device, time) tuple.
pub fn post_pairing_request<T: FgtwTransport>(
    t: &T,
    pairing: &Keypair,
    new_device_pubkey: &[u8; 32],
    handle_proof: &[u8; 32],
) -> Result<(), String> {
    let now = vsf::eagle_time_oscillations();
    let sig = pairing.sign(&pair_request_signing_bytes(handle_proof, new_device_pubkey, now));
    let mut section = vsf::VsfSection::new("pair_put");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    section.add_field("dk", VsfType::ke(new_device_pubkey.to_vec()));
    section.add_field("pp", VsfType::ke(pairing.public.to_bytes().to_vec()));
    section.add_field("t", VsfType::e(vsf::types::EtType::e6(now)));
    section.add_field("sig", VsfType::ge(sig.to_bytes().to_vec()));
    let resp = t.post(provenance_req(section)?)?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(format!("pair_put http {}", resp.status))
    }
}

/// EXISTING device: fetch the pending pairing request, validating freshness and the pairing key's ownership signature. `None` when there's no fresh valid request.
pub fn fetch_pairing_request<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
) -> Result<Option<PairRequest>, String> {
    let mut section = vsf::VsfSection::new("pair_get");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    let resp = t.post(provenance_req(section)?)?;
    if resp.status == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("pair_get http {}", resp.status));
    }
    let stored = parse_section(&resp.body)?;
    let (Some(device_pubkey), Some(pairing_pubkey)) = (field32(&stored, "dk"), field32(&stored, "pp"))
    else {
        return Ok(None);
    };
    let ts = match stored.get_field("t").and_then(|f| f.values.first()) {
        Some(VsfType::e(et)) => et_to_osc(et),
        _ => return Ok(None),
    };
    let sig = match stored.get_field("sig").and_then(|f| f.values.first()) {
        Some(VsfType::ge(s)) if s.len() == 64 => Signature::from_bytes(s.as_slice().try_into().unwrap()),
        _ => return Ok(None),
    };
    if (vsf::eagle_time_oscillations() - ts) > PAIR_FRESH_OSC {
        return Ok(None);
    }
    let Ok(vk) = VerifyingKey::from_bytes(&pairing_pubkey) else {
        return Ok(None);
    };
    if vk.verify(&pair_request_signing_bytes(handle_proof, &device_pubkey, ts), &sig).is_err() {
        return Ok(None);
    }
    Ok(Some(PairRequest { pairing_pubkey, device_pubkey }))
}

/// EXISTING device: after the typed words matched, post the signed "matched" flag so the new device's screen flips to ready. Signed by this (member) device.
pub fn post_pair_matched<T: FgtwTransport>(
    t: &T,
    member_key: &Keypair,
    handle_proof: &[u8; 32],
    pairing_pubkey: &[u8; 32],
) -> Result<(), String> {
    let now = vsf::eagle_time_oscillations();
    let sig = member_key.sign(&pair_matched_signing_bytes(handle_proof, pairing_pubkey, now));
    let mut section = vsf::VsfSection::new("pack_put");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    section.add_field("pp", VsfType::ke(pairing_pubkey.to_vec()));
    section.add_field("dk", VsfType::ke(member_key.public.to_bytes().to_vec()));
    section.add_field("t", VsfType::e(vsf::types::EtType::e6(now)));
    section.add_field("sig", VsfType::ge(sig.to_bytes().to_vec()));
    let resp = t.post(provenance_req(section)?)?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(format!("pack_put http {}", resp.status))
    }
}

/// NEW device: has an existing member matched OUR words? True only for a fresh flag naming OUR pairing pubkey, signed by a device in `members` — so a stranger can't flip the ready light.
pub fn poll_pair_matched<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
    pairing_pubkey: &[u8; 32],
    members: &[[u8; 32]],
) -> Result<bool, String> {
    let mut section = vsf::VsfSection::new("pack_get");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    let resp = t.post(provenance_req(section)?)?;
    if resp.status == 404 {
        return Ok(false);
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("pack_get http {}", resp.status));
    }
    let stored = parse_section(&resp.body)?;
    let (Some(pp), Some(dk)) = (field32(&stored, "pp"), field32(&stored, "dk")) else {
        return Ok(false);
    };
    let ts = match stored.get_field("t").and_then(|f| f.values.first()) {
        Some(VsfType::e(et)) => et_to_osc(et),
        _ => return Ok(false),
    };
    let sig = match stored.get_field("sig").and_then(|f| f.values.first()) {
        Some(VsfType::ge(s)) if s.len() == 64 => Signature::from_bytes(s.as_slice().try_into().unwrap()),
        _ => return Ok(false),
    };
    if pp != *pairing_pubkey
        || (vsf::eagle_time_oscillations() - ts) > PAIR_FRESH_OSC
        || !members.contains(&dk)
    {
        return Ok(false);
    }
    let Ok(vk) = VerifyingKey::from_bytes(&dk) else {
        return Ok(false);
    };
    Ok(vk.verify(&pair_matched_signing_bytes(handle_proof, &pp, ts), &sig).is_ok())
}

// ── Fan-out transport + rotation ──

/// Publish a fan-out to the always-online slot. Device-signed envelope (ke/ge) so FGTW checks the writer against the folded fleet chain; the epoch inside the blob drives the worker's monotonic guard.
pub fn post_fanout<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
    device_key: &Keypair,
    epoch: u64,
    wraps: &[FanoutWrap],
) -> Result<(), String> {
    let mut section = vsf::VsfSection::new("fanout_put");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    section.add_field("bl", VsfType::ge(fanout_to_bytes(epoch, wraps)));
    let unsigned = vsf::VsfBuilder::new()
        .creation_time_oscillations(vsf::eagle_time_oscillations())
        .signed_only(VsfType::ke(device_key.public.to_bytes().to_vec()))
        .add_section_direct(section)
        .build()
        .map_err(|e| format!("fanout_put build: {e}"))?;
    let signed = vsf::verification::sign_file(unsigned, device_key.secret.as_bytes())
        .map_err(|e| format!("fanout_put sign: {e}"))?;
    let resp = t.post(signed)?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(format!("fanout_put http {}", resp.status))
    }
}

/// Fetch the current fan-out (epoch + wraps), or None if none published yet.
pub fn fetch_fanout<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
) -> Result<Option<(u64, Vec<FanoutWrap>)>, String> {
    let mut section = vsf::VsfSection::new("fanout_get");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    let resp = t.post(provenance_req(section)?)?;
    if resp.status == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("fanout_get http {}", resp.status));
    }
    let stored = parse_section(&resp.body)?;
    match stored.get_field("bl").and_then(|f| f.values.first()) {
        Some(VsfType::ge(b)) => Ok(Some(fanout_from_bytes(b)?)),
        _ => Ok(None),
    }
}

/// Rotate (or first-establish) the fleet key: mint a FRESH key, seal it to `members`, publish at `stored_epoch + 1`. One operation for both genesis-establish and every membership-change rotation — a removed device just isn't in `members`.
pub fn rotate_fleet_key<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
    device_key: &Keypair,
    members: &[[u8; 32]],
) -> Result<(u64, [u8; 32]), String> {
    let current = fetch_fanout(t, handle_proof)?.map(|(e, _)| e).unwrap_or(0);
    let epoch = current + 1;
    let key = new_fleet_key();
    let wraps = fanout_seal(handle_proof, epoch, &key, members)?;
    post_fanout(t, handle_proof, device_key, epoch, &wraps)?;
    Ok((epoch, key))
}

/// Recover the current fleet key from the always-online fan-out with this device's key alone (no live sibling). None if this device isn't in the current member set, or no fan-out exists yet.
pub fn recover_fleet_key<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
    device_key: &Keypair,
) -> Result<Option<[u8; 32]>, String> {
    match fetch_fanout(t, handle_proof)? {
        Some((epoch, wraps)) => Ok(fanout_open(handle_proof, epoch, &wraps, device_key)),
        None => Ok(None),
    }
}

/// Recover the current fleet key, or ESTABLISH epoch 1 if no fan-out exists yet (the genesis founder). Handles the establish race: if another device published epoch 1 first, recover theirs instead.
pub fn recover_or_establish_fleet_key<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
    device_key: &Keypair,
) -> Result<Option<[u8; 32]>, String> {
    if let Some(k) = recover_fleet_key(t, handle_proof, device_key)? {
        return Ok(Some(k));
    }
    let members = current_members(t, handle_proof)?;
    if members.is_empty() {
        return Ok(None);
    }
    match rotate_fleet_key(t, handle_proof, device_key, &members) {
        Ok((_, k)) => Ok(Some(k)),
        Err(_) => recover_fleet_key(t, handle_proof, device_key),
    }
}

// ── Fleet roster transport ──

/// Publish the fleet roster: seal it under the fleet key and PUT it to the membership-gated slot. The envelope is device-signed (ke/ge header) so FGTW checks the writer against the folded fleet chain — any fleet device may write.
pub fn push_roster<T: FgtwTransport, S: FleetSealer>(
    t: &T,
    s: &S,
    handle_proof: &[u8; 32],
    device_key: &Keypair,
    fleet_key: &[u8; 32],
    entries: &[RosterEntry],
) -> Result<(), String> {
    let sealed = s.seal(&roster_to_bytes(entries), fleet_key)?;
    let mut section = vsf::VsfSection::new("fstate_put");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    section.add_field("bl", VsfType::ge(sealed));
    section.add_field("t", VsfType::e(vsf::types::EtType::e6(vsf::eagle_time_oscillations())));
    let unsigned = vsf::VsfBuilder::new()
        .creation_time_oscillations(vsf::eagle_time_oscillations())
        .signed_only(VsfType::ke(device_key.public.to_bytes().to_vec()))
        .add_section_direct(section)
        .build()
        .map_err(|e| format!("fstate_put build: {e}"))?;
    let signed = vsf::verification::sign_file(unsigned, device_key.secret.as_bytes())
        .map_err(|e| format!("fstate_put sign: {e}"))?;
    let resp = t.post(signed)?;
    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(format!("fstate_put http {}", resp.status))
    }
}

/// Fetch + open the fleet roster (None if none published yet). The GET is unauthenticated — the payload is ciphertext only fleet members can open — so the pull just needs the fleet key.
pub fn pull_roster<T: FgtwTransport, S: FleetSealer>(
    t: &T,
    s: &S,
    handle_proof: &[u8; 32],
    fleet_key: &[u8; 32],
) -> Result<Option<Vec<RosterEntry>>, String> {
    let mut section = vsf::VsfSection::new("fstate_get");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    let resp = t.post(provenance_req(section)?)?;
    if resp.status == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("fstate_get http {}", resp.status));
    }
    let stored = parse_section(&resp.body)?;
    let sealed = match stored.get_field("bl").and_then(|f| f.values.first()) {
        Some(VsfType::ge(b)) => b.clone(),
        _ => return Ok(None),
    };
    let plaintext = s.open(&sealed, fleet_key)?;
    Ok(Some(roster_from_bytes(&plaintext)?))
}
