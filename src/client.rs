//! The FGTW client oracle — fetch-then-sign over an injected transport.
//!
//! The device is a blind, stateless signing oracle: it fetches a blob from FGTW, finds its own pubkey, signs, and posts.
//! ALL the protocol logic lives here (request framing, the `error`-frame reason rules, freshness + signature checks) — the app supplies only the raw HTTP and the roster AEAD, via [`FgtwTransport`] and [`FleetSealer`].
//! So photon rides its warm-TLS connection pool and its own error-message UX, the calendar can use a different HTTP client, and this crate stays reqwest-free.

use crate::fanout::{fanout_from_bytes, fanout_open, fanout_seal, fanout_to_bytes, new_fleet_key, FanoutWrap};
use crate::fleet::{bindreq_signing_bytes, et_to_osc, BindRequest, MembershipBlob, BINDREQ_FRESH_OSC};
use crate::fstate::{fstate_from_bytes, fstate_to_bytes, FleetState};
use crate::keys::Keypair;
use vsf::VsfType;

/// One HTTP response from FGTW: the status code and the body bytes.
/// The transport returns this for ANY status it managed to receive; it returns `Err` only when it couldn't reach FGTW at all. The worker now answers every failure with a VSF `error` frame at HTTP 200, so the client branches on the frame's `reason` label; `status` is kept only as an infra-error fallback (a CloudFlare 5xx that never reached the worker).
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

// ── helpers ──

fn unsigned_req(section: vsf::VsfSection) -> Result<Vec<u8>, String> {
    // Default build carries hp + hb, so even unsigned requests are verifiable documents.
    vsf::VsfBuilder::new()
        .creation_time_oscillations(vsf::eagle_time_oscillations())
        .add_section_direct(section)
        .build()
        .map_err(|e| format!("fgtw request build: {e}"))
}

fn parse_section(bytes: &[u8]) -> Result<(String, vsf::VsfSection), String> {
    // Verified read (hp + hb | signature) before the section is touched — every worker response carries an anchor, so an unverifiable body is noise or tampering, never data.
    let (header, header_end) = vsf::verification::read_verified(bytes, None)
        .map_err(|e| format!("fgtw response verification: {e}"))?;
    // primary_section resolves the anonymous near-form name from the header TOC AND reads header-only sections (acks, empty registries) as zero-field sections — that knowledge lives in the vsf crate now, not here.
    let section = header
        .primary_section(bytes, header_end)
        .map_err(|e| format!("fgtw section: {e}"))?;
    Ok((section.name.clone(), section))
}

/// If `body` is an FGTW `error` frame, return its `(reason, detail)`. The worker answers every
/// failure with one of these at HTTP 200 — VSF is the wire — so callers branch on the stable
/// `reason` label (`not_found`, `stale`, `bad_signature`, …), never an HTTP status. Both frame
/// shapes parse here: plain (hp + hb) and FGTW-header-signed (ke/ge, canonical scheme).
pub fn error_frame(body: &[u8]) -> Option<(String, String)> {
    let (name, section) = parse_section(body).ok()?;
    if name != "error" {
        return None;
    }
    let text = |n: &str| {
        section
            .get_field(n)
            .and_then(|f| f.values.first())
            .and_then(|v| match v {
                VsfType::a(s) | VsfType::x(s) => Some(s.clone()),
                _ => None,
            })
    };
    Some((text("reason")?, text("detail").unwrap_or_default()))
}

/// True if `body` is an FGTW `error` frame carrying exactly `reason`.
pub fn is_error(body: &[u8], reason: &str) -> bool {
    error_frame(body).map_or(false, |(r, _)| r == reason)
}

// ── Fleet chain oracle ──

/// Fetch the identity's stored fleet chain, or `None` if none exists yet (`not_found`). Parsed but NOT trusted until [`MembershipBlob::fold`].
pub fn fetch<T: FgtwTransport>(t: &T, handle_proof: &[u8; 32]) -> Result<Option<MembershipBlob>, String> {
    let mut section = vsf::VsfSection::new("fleet_get");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    let resp = t.post(unsigned_req(section)?)?;
    if is_error(&resp.body, "not_found") {
        return Ok(None);
    }
    if let Some((reason, detail)) = error_frame(&resp.body) {
        return Err(format!("fgtw fleet_get {reason}: {detail}"));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("FGTW transport {}", resp.status));
    }
    Ok(Some(MembershipBlob::from_vsf_bytes(&resp.body)?))
}

/// Publish a new (or extended) chain. The worker accepts it only as a forward extension of what it holds; a stale post gets the `stale` reason frame, surfaced as `"fleet: stale"` so the retry loop can match on it.
pub fn publish<T: FgtwTransport>(t: &T, blob: &MembershipBlob) -> Result<(), String> {
    let resp = t.post(blob.to_vsf_bytes()?)?;
    if is_error(&resp.body, "stale") {
        return Err("fleet: stale".to_string());
    }
    if let Some((reason, detail)) = error_frame(&resp.body) {
        return Err(format!("fgtw fleet_put {reason}: {detail}"));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("FGTW transport {}", resp.status));
    }
    Ok(())
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
    // A fold ERROR is indeterminate (corrupt/stale-format chain), NOT "not a member" — the two used to collapse into the same enroll-from-another-device message, hiding the real fault.
    let member_of = |blob: &MembershipBlob| -> Result<bool, String> {
        blob.fold()
            .map(|m| m.contains(&me))
            .map_err(|e| format!("stored fleet chain does not fold: {e:?}"))
    };
    // FLAG-DAY (v0→v1, 2026-07-13): a stored chain that no longer parses or folds under current rules is dead-format state — fall thru to the genesis attempt below; the worker applies the same supersession rule and adjudicates. Scoped to THIS genesis path only (contact-chain consumers still surface the error). Remove once no v0 chain can plausibly remain.
    let stored = match fetch(t, handle_proof) {
        Ok(s) => s,
        Err(e) if e.contains("fleet op:") || e.contains("fleet section:") || e.contains("fleet chain verification") => None,
        Err(e) => return Err(e),
    };
    if let Some(blob) = stored {
        match member_of(&blob) {
            Ok(true) => return Ok(()),
            Ok(false) => {
                return Err("this device is not in the fleet — enroll it from an existing device first".into())
            }
            Err(_) => {} // fold-dead v0 chain — flag-day supersession, genesis below
        }
    }
    let blob =
        MembershipBlob::genesis(device_key, *handle_proof, identity_seed, vsf::eagle_time_oscillations());
    // A rejected publish is NOT fatal by itself (a racing sibling may have won the slot), but it must not vanish either — the refetch below adjudicates, and the publish error rides along if that also comes up empty.
    let publish_err = publish(t, &blob).err();
    // Trust the network, not ourselves: re-fetch the canonical chain and accept ONLY if it names this device. The fleet slot has no compare-and-set, so two devices racing a fresh handle's genesis both "publish" but the slot settles on ONE — the loser re-reads here, finds it isn't a member, and fails cleanly instead of announcing as a phantom founder.
    match fetch(t, handle_proof)? {
        Some(b) => {
            if member_of(&b)? {
                Ok(())
            } else {
                Err("this device is not in the fleet — enroll it from an existing device first".into())
            }
        }
        None => Err(match publish_err {
            // The one-owner gate: say what actually blocked the claim, not plumbing (the bare wrap read as noise on a live device, 2026-07-17).
            Some(e) if e.contains("device_owned") => "this device is still enrolled in another identity's fleet \u{2014} wipe it (Settings \u{2192} Security), or remove it from that fleet, before claiming a new name".into(),
            Some(e) => format!("failed to establish fleet membership: {e}"),
            None => "failed to establish fleet membership for this device".into(),
        }),
    }
}

/// The current device-pubkey member set (empty if no fleet yet).
pub fn current_members<T: FgtwTransport>(t: &T, handle_proof: &[u8; 32]) -> Result<Vec<[u8; 32]>, String> {
    match fetch(t, handle_proof)? {
        Some(b) => b.fold().map_err(|e| format!("stored fleet invalid: {e:?}")),
        None => Ok(Vec::new()),
    }
}

/// The current device-pubkey member set for OUR OWN fleet, refusing any chain whose genesis is not co-signed by `Ed25519(identity_seed)`. `fold()` proves the chain is internally consistent; only this check pins it to OUR identity — without it, a relay that served the real chain once can swap in a structurally-valid foreign chain later (the probe-time-only TOCTOU). Every own-fleet fetch that feeds a trust decision (join loop, bind polling, fanout recovery) belongs here; `current_members` stays for CONTACT chains, where the peer-side genesis check lives in the caller.
pub fn current_members_verified<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
    identity_seed: &[u8; 32],
) -> Result<Vec<[u8; 32]>, String> {
    match fetch(t, handle_proof)? {
        Some(b) => {
            let members = b.fold().map_err(|e| format!("stored fleet invalid: {e:?}"))?;
            if !b.genesis_identity_matches(identity_seed) {
                return Err("fleet chain is not rooted in this identity — refusing it".into());
            }
            Ok(members)
        }
        None => Ok(Vec::new()),
    }
}

/// The current member set plus the chain-tip eagle time — a monotonic freshness guard. A consumer adopts a fold only when its tip is `>=` the last one adopted, so a stale (pre-removal) read served by R2 eventual consistency can't overwrite a fresh post-removal set. No fleet yet ⇒ `(empty, 0)`.
pub fn current_members_with_ts<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
) -> Result<(Vec<[u8; 32]>, i64), String> {
    match fetch(t, handle_proof)? {
        Some(b) => b.fold_with_ts().map_err(|e| format!("stored fleet invalid: {e:?}")),
        None => Ok((Vec::new(), 0)),
    }
}

/// The full fold read for a contact refresh: member set + chain-tip eagle time + the GENERATION id (the genesis hash — the pin that renders a re-claimant of a freed name as a stranger; photon docs/lifecycle.md) + whether a chain existed at all. Absent chain ⇒ `(empty, 0, zero, false)` — the CALLER distinguishes "ended" from "never existed" by whether it ever adopted a fold.
pub fn current_members_full<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
) -> Result<(Vec<[u8; 32]>, i64, [u8; 32], bool), String> {
    match fetch(t, handle_proof)? {
        Some(b) => {
            let (m, ts) = b.fold_with_ts().map_err(|e| format!("stored fleet invalid: {e:?}"))?;
            Ok((m, ts, b.genesis_hash().unwrap_or([0u8; 32]), true))
        }
        None => Ok((Vec::new(), 0, [0u8; 32], false)),
    }
}

/// Existing-device side of device-ADD: bind the device a verified binding request names, signed by this (member) device and carrying the request's device signature as the consent egg. `req` must have been screened by the matcher (full word match + `BindRequest::verify`) — the fold re-verifies the consent regardless, so a garbage request can't enter the chain even if a caller skips the screen.
pub fn bind_device<T: FgtwTransport>(
    t: &T,
    member_key: &Keypair,
    handle_proof: &[u8; 32],
    req: &BindRequest,
) -> Result<(), String> {
    let me = member_key.public.to_bytes();
    for _attempt in 0..4 {
        let mut blob = fetch(t, handle_proof)?
            .ok_or("no fleet to add to — attest this identity first")?;
        let members = blob.fold().map_err(|e| format!("stored fleet invalid: {e:?}"))?;
        if !members.contains(&me) {
            return Err("this device isn't a fleet member, so it can't add another".into());
        }
        if members.contains(&req.device_pubkey) {
            return Ok(()); // already in — idempotent
        }
        blob.add(member_key, req.device_pubkey, vsf::eagle_time_oscillations(), req.t, req.device_sig.clone());
        match publish(t, &blob) {
            Ok(()) => return Ok(()),
            Err(e) if e.contains("stale") => continue, // someone else extended; re-fetch + retry
            Err(e) => return Err(e),
        }
    }
    Err("fleet add: lost too many extension races".into())
}

/// This device's own departure — the ONLY chain remove that exists (self-signed; expelling another device is not a verb). Idempotent: already gone folds as success. Not yet wired to any UI; the self-retire flow arrives with the device-trust bundle.
pub fn depart_device<T: FgtwTransport>(
    t: &T,
    device_key: &Keypair,
    handle_proof: &[u8; 32],
) -> Result<(), String> {
    let me = device_key.public.to_bytes();
    for _attempt in 0..4 {
        let mut blob = fetch(t, handle_proof)?.ok_or("no fleet to depart from")?;
        let members = blob.fold().map_err(|e| format!("stored fleet invalid: {e:?}"))?;
        if !members.contains(&me) {
            return Ok(()); // already out — idempotent
        }
        blob.depart(device_key, vsf::eagle_time_oscillations());
        match publish(t, &blob) {
            Ok(()) => return Ok(()),
            Err(e) if e.contains("stale") => continue,
            Err(e) => return Err(e),
        }
    }
    Err("fleet depart: lost too many extension races".into())
}

// ── Binding-request registry (docs/pairing-v2.md): keyed per (hp, device), dual-signed at write, member-gated at read, author-withdrawn or stamp-lapsed — the worker NEVER consumes an entry. ──

/// Build + POST a device-signed envelope (ke/ge header, canonical scheme) around `section` — the shape the worker's signature-gated ops verify.
fn signed_req<T: FgtwTransport>(t: &T, device_key: &Keypair, section: vsf::VsfSection, what: &str) -> Result<FgtwResponse, String> {
    let unsigned = vsf::VsfBuilder::new()
        .creation_time_oscillations(vsf::eagle_time_oscillations())
        .signed_only(VsfType::ke(device_key.public.to_bytes().to_vec()))
        .add_section_direct(section)
        .build()
        .map_err(|e| format!("{what} build: {e}"))?;
    let signed = vsf::verification::sign_file(unsigned, device_key.secret.as_bytes())
        .map_err(|e| format!("{what} sign: {e}"))?;
    t.post(signed)
}

/// NEW device: post (or refresh) its binding request — "I, `device_key`, consent to join fleet `handle_proof`" — signed by the device key AND co-signed by `Ed25519(identity_seed)` (the registry write gate; the worker checks it against the chain's genesis identity pubkey). Re-post at ~3.5 min while the words screen is up; the stamp lapses at 5.
/// Returns the `eagle_time` (oscillations) this call stamped and published — the SAME value the sponsor reads back in [`bindreq_list`], so the caller can derive the proximity beacon ([`beacon_id`]) from the exact published offer state.
pub fn bindreq_put<T: FgtwTransport>(
    t: &T,
    device_key: &Keypair,
    identity_seed: &[u8; 32],
    handle_proof: &[u8; 32],
    nfc_secret: &[u8; 32],
) -> Result<i64, String> {
    use ed25519_dalek::Signer;
    let now = vsf::eagle_time_oscillations();
    let me = device_key.public.to_bytes();
    // NFC commitment computed HERE because it binds the stamp this call mints (all-zero secret = no NFC offered → zero hash).
    let nfc_hash = if *nfc_secret == [0u8; 32] {
        [0u8; 32]
    } else {
        crate::pair::nfc_secret_hash(nfc_secret, &me, now)
    };
    let msg = bindreq_signing_bytes(handle_proof, &me, now);
    let identity_key = ed25519_dalek::SigningKey::from_bytes(identity_seed);
    let mut section = vsf::VsfSection::new("bindreq_put");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    section.add_field("dk", VsfType::ke(me.to_vec()));
    section.add_field("t", VsfType::e(vsf::types::EtType::e6(now)));
    section.add_field("ds", VsfType::ge(device_key.sign(&msg).to_bytes().to_vec()));
    section.add_field("is", VsfType::ge(identity_key.sign(&msg).to_bytes().to_vec()));
    // NFC commitment (all-zero = none) — outside the signing bytes by design (see BindRequest::nfc_hash).
    section.add_field("nh", VsfType::hb(nfc_hash.to_vec()));
    let resp = t.post(unsigned_req(section)?)?;
    if is_error(&resp.body, "device_owned") {
        // The one-owner gate at the request door (2026-07-17): the joiner learns the truth NOW instead of a sponsor-side bind bouncing forever.
        return Err("this device is still enrolled in another identity's fleet \u{2014} wipe it (Settings \u{2192} Security), or remove it from that fleet, before joining a different one".to_string());
    }
    if let Some((reason, detail)) = error_frame(&resp.body) {
        return Err(format!("fgtw bindreq_put {reason}: {detail}"));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("FGTW transport {}", resp.status));
    }
    Ok(now)
}

/// NEW device: withdraw its own request — the author's exit act (on green, or on ceremony cancel). Signed envelope: the worker deletes exactly the signer's own entry, nobody else's. Best-effort; an unreachable worker just means the stamp lapses instead.
pub fn bindreq_withdraw<T: FgtwTransport>(
    t: &T,
    device_key: &Keypair,
    handle_proof: &[u8; 32],
) -> Result<(), String> {
    let mut section = vsf::VsfSection::new("bindreq_withdraw");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    let resp = signed_req(t, device_key, section, "bindreq_withdraw")?;
    if let Some((reason, detail)) = error_frame(&resp.body) {
        return Err(format!("fgtw bindreq_withdraw {reason}: {detail}"));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("FGTW transport {}", resp.status));
    }
    Ok(())
}

/// OWNER frees a retired device's hardware brand — the second signature of the two-signature retire (the first was the device's own departure). `member_key` must be a CURRENT fleet member; the worker refuses a release of a device still in the fold (membership only ever ends by the device's own hand) and a brand held by a different identity. Idempotent: already-free acks.
pub fn device_release<T: FgtwTransport>(
    t: &T,
    member_key: &Keypair,
    handle_proof: &[u8; 32],
    released_pubkey: &[u8; 32],
) -> Result<(), String> {
    let mut section = vsf::VsfSection::new("device_release");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    section.add_field("rd", VsfType::ke(released_pubkey.to_vec()));
    let resp = signed_req(t, member_key, section, "device_release")?;
    if let Some((reason, detail)) = error_frame(&resp.body) {
        return Err(format!("fgtw device_release {reason}: {detail}"));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("FGTW transport {}", resp.status));
    }
    Ok(())
}

/// EXISTING device: the pending binding requests for OUR fleet — the matcher's candidate set. Member-gated at the worker (signed envelope, signer must fold as a current member); every returned request is re-verified HERE too (freshness + both signatures against `Ed25519(identity_seed)`), so a compromised relay can inject nothing.
pub fn bindreq_list<T: FgtwTransport>(
    t: &T,
    member_key: &Keypair,
    handle_proof: &[u8; 32],
    identity_seed: &[u8; 32],
) -> Result<Vec<BindRequest>, String> {
    let identity_pubkey = ed25519_dalek::SigningKey::from_bytes(identity_seed).verifying_key().to_bytes();
    let mut section = vsf::VsfSection::new("bindreq_list");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    let resp = signed_req(t, member_key, section, "bindreq_list")?;
    if is_error(&resp.body, "not_found") {
        return Ok(Vec::new());
    }
    if let Some((reason, detail)) = error_frame(&resp.body) {
        return Err(format!("fgtw bindreq_list {reason}: {detail}"));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("FGTW transport {}", resp.status));
    }
    let (_, stored) = parse_section(&resp.body)?;
    let now = vsf::eagle_time_oscillations();
    let mut out = Vec::new();
    for field in stored.get_fields("req") {
        // Positional: [ke device_pubkey, e6 t, ge device_sig, ge identity_sig] — mirror of the worker's build.
        let v = &field.values;
        let (Some(VsfType::ke(dk)), Some(VsfType::e(et)), Some(VsfType::ge(ds)), Some(VsfType::ge(is))) =
            (v.first(), v.get(1), v.get(2), v.get(3))
        else {
            continue; // malformed entry — skip, never fail the healthy ones
        };
        if dk.len() != 32 {
            continue;
        }
        let mut device_pubkey = [0u8; 32];
        device_pubkey.copy_from_slice(dk);
        // Optional 5th value: the NFC commitment (older/absent rows read as zero = no NFC).
        let nfc_hash: [u8; 32] = match v.get(4) {
            Some(VsfType::hb(h)) if h.len() == 32 => h.as_slice().try_into().unwrap(),
            _ => [0u8; 32],
        };
        let req = BindRequest { device_pubkey, t: et_to_osc(et), device_sig: ds.clone(), identity_sig: is.clone(), nfc_hash };
        if (now - req.t).abs() > BINDREQ_FRESH_OSC {
            continue; // lapsed — expiry is the only deletion pending records get
        }
        if !req.verify(handle_proof, &identity_pubkey) {
            continue; // relay noise or forgery — invisible
        }
        out.push(req);
    }
    Ok(out)
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
    if let Some((reason, detail)) = error_frame(&resp.body) {
        return Err(format!("fgtw fanout_put {reason}: {detail}"));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("FGTW transport {}", resp.status));
    }
    Ok(())
}

/// Fetch the current fan-out (epoch + wraps), or None if none published yet.
pub fn fetch_fanout<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
) -> Result<Option<(u64, Vec<FanoutWrap>)>, String> {
    let mut section = vsf::VsfSection::new("fanout_get");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    let resp = t.post(unsigned_req(section)?)?;
    if is_error(&resp.body, "not_found") {
        return Ok(None);
    }
    if let Some((reason, detail)) = error_frame(&resp.body) {
        return Err(format!("fgtw fanout_get {reason}: {detail}"));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("FGTW transport {}", resp.status));
    }
    let (_, stored) = parse_section(&resp.body)?;
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

/// Recover the current fleet key, or ESTABLISH epoch 1 if NO fan-out exists yet (the genesis founder). Handles the establish race: if another device published epoch 1 first, recover theirs instead.
/// A fan-out that EXISTS but holds no wrap for us is NOT an establish case — that's a freshly-bound device whose wrap arrives with the sponsor's green-confirm rotation, and self-rotating in here would hand it the key before the human confirmed (voiding the two-phase gate: any member may rotate, so the gate is only real if the joiner never rotates itself in). Wait: return None and let the next sync recover the confirmed epoch.
pub fn recover_or_establish_fleet_key<T: FgtwTransport>(
    t: &T,
    handle_proof: &[u8; 32],
    device_key: &Keypair,
) -> Result<Option<[u8; 32]>, String> {
    match fetch_fanout(t, handle_proof)? {
        Some((epoch, wraps)) => Ok(fanout_open(handle_proof, epoch, &wraps, device_key)),
        None => {
            let members = current_members(t, handle_proof)?;
            if members.is_empty() {
                return Ok(None);
            }
            match rotate_fleet_key(t, handle_proof, device_key, &members) {
                Ok((_, k)) => Ok(Some(k)),
                Err(_) => recover_fleet_key(t, handle_proof, device_key),
            }
        }
    }
}

// ── Fleet state transport ──

/// Publish the fleet-shared state (roster + settings layers): seal it under the fleet key and PUT it to the membership-gated slot. The envelope is device-signed (ke/ge header) so FGTW checks the writer against the folded fleet chain — any fleet device may write.
pub fn push_fstate<T: FgtwTransport, S: FleetSealer>(
    t: &T,
    s: &S,
    handle_proof: &[u8; 32],
    device_key: &Keypair,
    fleet_key: &[u8; 32],
    state: &FleetState,
) -> Result<(), String> {
    let sealed = s.seal(&fstate_to_bytes(state), fleet_key)?;
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
    if let Some((reason, detail)) = error_frame(&resp.body) {
        return Err(format!("fgtw fstate_put {reason}: {detail}"));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("FGTW transport {}", resp.status));
    }
    Ok(())
}

/// Fetch + open the fleet-shared state (None if none published yet; an old roster-only blob reads as settings-empty). The GET is unauthenticated — the payload is ciphertext only fleet members can open — so the pull just needs the fleet key.
pub fn pull_fstate<T: FgtwTransport, S: FleetSealer>(
    t: &T,
    s: &S,
    handle_proof: &[u8; 32],
    fleet_key: &[u8; 32],
) -> Result<Option<FleetState>, String> {
    let mut section = vsf::VsfSection::new("fstate_get");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    let resp = t.post(unsigned_req(section)?)?;
    if is_error(&resp.body, "not_found") {
        return Ok(None);
    }
    if let Some((reason, detail)) = error_frame(&resp.body) {
        return Err(format!("fgtw fstate_get {reason}: {detail}"));
    }
    if !(200..300).contains(&resp.status) {
        return Err(format!("FGTW transport {}", resp.status));
    }
    let (_, stored) = parse_section(&resp.body)?;
    let sealed = match stored.get_field("bl").and_then(|f| f.values.first()) {
        Some(VsfType::ge(b)) => b.clone(),
        _ => return Ok(None),
    };
    let plaintext = s.open(&sealed, fleet_key)?;
    Ok(Some(fstate_from_bytes(&plaintext)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Near-form sections are anonymous on the wire (name only in the header TOC) — error_frame must still recognize them. This was broken from the v9 near-form change until 2026-07-06: section.name came back empty, every error frame went unrecognized, and callers parsed error frames as data (the "chain unverifiable: Empty" class).
    #[test]
    fn error_frame_recognizes_anonymous_near_form() {
        let body = vsf::VsfBuilder::new()
            .add_section(
                "error",
                vec![
                    ("reason".to_string(), VsfType::a("not_found".to_string())),
                    ("detail".to_string(), VsfType::a("no fleet".to_string())),
                ],
            )
            .build()
            .unwrap();
        let (reason, detail) = error_frame(&body).expect("frame must be recognized");
        assert_eq!(reason, "not_found");
        assert_eq!(detail, "no fleet");
        assert!(is_error(&body, "not_found"));
        assert!(!is_error(&body, "stale"));
        // Non-error frames must NOT read as errors.
        let data = vsf::VsfBuilder::new()
            .add_section("fleet", vec![("x".to_string(), VsfType::u(1, false))])
            .build()
            .unwrap();
        assert!(error_frame(&data).is_none());
    }
}
