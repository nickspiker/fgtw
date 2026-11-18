//! The relay pipe — sans-io codec for the seed's live per-device WebSocket relay.
//!
//! A device opens `wss://<seed>/pipe?dev=<hex>[&svc=<tag>]` as its receive socket, and sends by pushing a signed relay envelope either up that same socket (full-duplex, the worker forwards it) or as an HTTPS POST.
//! The seed binds the socket to the device only after the device answers its first frame, a seed-signed challenge, with a frame signed by its own key ([`challenge`], [`open_answer`], [`check_answer`]); an unproven socket carries nothing for the device (outside the seed's dated window for released clients) and never displaces a proven one.
//! The envelope is a whole signed VSF — section `relay` `{recipient, payload[, svc]}`, signed by the sender's device key — so the receiver learns "via relay, from device X" from authenticated bytes.
//!
//! **Service tags.** Two apps sharing one device key (photon and the rustdesk fork share the fleet identity on purpose) must not share a pipe: the worker names the hub `<hex>` for a svc-less pipe (photon, unchanged) and `<hex>:<svc>` otherwise, so the two pipes have independent lifecycles — closing photon to update it can never drop the rustdesk session doing the updating — and a frame addressed to a service can only land on that service's socket.
//!
//! **This module is sans-io** like [`crate::traverse`]: envelope build/peel and the stream frame codec live here with tests; the socket pump (tokio/tungstenite) is each app's concern, so `fgtw` stays free of async deps.

use crate::fleet::Egg;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use vsf::types::VsfType;

/// The rustdesk fork's service tag.
/// Worker rule: 1–8 chars, `[a-z0-9]`.
pub const SVC_RUSTDESK: &str = "rd";

/// The pipe URL for a device's receive socket on `seed_host` (e.g. `fgtw.org`).
pub fn pipe_url(seed_host: &str, device_pubkey: &[u8; 32], svc: Option<&str>) -> String {
    let dev = hex_lower(device_pubkey);
    match svc {
        Some(svc) => format!("wss://{seed_host}/pipe?dev={dev}&svc={svc}"),
        None => format!("wss://{seed_host}/pipe?dev={dev}"),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a signed relay envelope addressed to `recipient` (optionally to its `svc` hub).
///
/// Wire shape is the one the worker verifies and photon sends: header `signed_only_eggs(ke)` carrying every scheme the sender holds at the envelope tier (Ed25519 + Falcon; vsf anchors on the Ed25519 egg, the receiver holds the rest to its chain's floor), section `relay` with `recipient` (`kx`), `payload` (`v'r'`), and — new, optional, ignored by pre-svc workers' HTTPS path and refused-if-garbled by current ones — `svc` (`d`).
pub fn build_relay_envelope(
    device_key: &(impl crate::pq::FleetSigner + ?Sized),
    recipient: &[u8; 32],
    svc: Option<&str>,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if payload.is_empty() {
        return Err("relay envelope: empty payload".into());
    }
    let mut fields = vec![
        ("recipient".to_string(), VsfType::kx(recipient.to_vec())),
        ("payload".to_string(), VsfType::v(b'r', payload.to_vec())),
    ];
    if let Some(svc) = svc {
        fields.push(("svc".to_string(), VsfType::d(vsf::Ascii::new(svc).map_err(|e| format!("relay envelope svc: {e}"))?)));
    }
    let unsigned = vsf::VsfBuilder::new()
        .creation_time_oscillations(crate::now_oscillations())
        .signed_only_eggs(VsfType::ke(device_key.keypair().public.to_bytes().to_vec()), &crate::pq::reserve_eggs(crate::pq::envelope_mask(device_key)))
        .add_section("relay", fields)
        .build()
        .map_err(|e| format!("relay envelope build: {e}"))?;
    crate::pq::sign_envelope(unsigned, device_key)
}

/// Peel a relay envelope received over the pipe: verify the sender's whole-file signature, then return `(sender_device_key, inner_payload)`.
/// `None` on any structural/parse/verify failure — a malformed or unsigned frame off the pipe is dropped, never injected.
///
/// Ported verbatim from photon (which now delegates here): `verify_file_signature`, NOT `read_verified` — the signature covers the entire file (authorship + integrity), only the content-hp self-attestation is waived, same as every CLUTCH/chat parser.
/// And the section resolves via `primary_section`, not a bare body parse: the section NAME lives in the header TOC (near-form), so a body parse sees `name == ""` and a `== "relay"` check silently fails — the trap that black-holed the pipe data plane once already.
pub fn peel_relay_envelope(bytes: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    peel_relay_envelope_eggs(bytes).map(|(k, p, _, _)| (k, p))
}

/// `peel_relay_envelope`, also handing back the header's egg list and the file hash they sign, so a receiver that knows the sender's declared bundle can hold the frame to its fleet's floor with `pq::verify_eggs` — vsf checks only the Ed25519 anchor. The sender is not known until the anchor has been checked, which is why the tier check cannot live here.
pub fn peel_relay_envelope_eggs(bytes: &[u8]) -> Option<([u8; 32], Vec<u8>, Vec<Egg>, [u8; 32])> {
    peel_relay_section(bytes).map(|(k, p, e, h, _)| (k, p, e, h))
}

/// [`peel_relay_envelope`], also holding the envelope to its signed address (security audit FGTW-05): `None` unless the signed `recipient` is `our_device_pubkey` and the signed `svc` is exactly `svc` (`None` = an envelope that carries no `svc`, the photon shape).
/// The plain peel checks who SENT a frame but not whom it was FOR, so a relay or any peer holding a frame signed to one device could hand it to another, or move a rustdesk frame onto a photon pipe; the signature covers the whole file, so checking the two fields closes that.
/// Replay of a frame to the device it was addressed to is still the caller's to refuse: the header's creation time is signed and readable, but what window a payload tolerates is the payload's business.
pub fn peel_relay_envelope_for(bytes: &[u8], our_device_pubkey: &[u8; 32], svc: Option<&str>) -> Option<([u8; 32], Vec<u8>)> {
    peel_relay_envelope_eggs_for(bytes, our_device_pubkey, svc).map(|(k, p, _, _)| (k, p))
}

/// [`peel_relay_envelope_eggs`] with [`peel_relay_envelope_for`]'s recipient and service check, for a receiver that also holds the frame to its fleet's floor.
pub fn peel_relay_envelope_eggs_for(bytes: &[u8], our_device_pubkey: &[u8; 32], svc: Option<&str>) -> Option<([u8; 32], Vec<u8>, Vec<Egg>, [u8; 32])> {
    let (sender_key, payload, eggs, file_hash, section) = peel_relay_section(bytes)?;
    let recipient = section.get_field("recipient").and_then(|f| f.values.first()).and_then(|v| match v {
        VsfType::kx(k) => Some(k.as_slice()),
        _ => None,
    })?;
    if recipient != our_device_pubkey.as_slice() {
        return None;
    }
    // A `svc` of any other type is not a service name, and matches no expected one.
    let signed_svc = match section.get_field("svc").and_then(|f| f.values.first()) {
        None => None,
        Some(VsfType::d(s)) => Some(s.as_str()),
        Some(_) => return None,
    };
    if signed_svc != svc {
        return None;
    }
    Some((sender_key, payload, eggs, file_hash))
}

/// The one peel: the Ed25519 anchor over the whole file, then the `relay` section and its non-empty payload.
fn peel_relay_section(bytes: &[u8]) -> Option<([u8; 32], Vec<u8>, Vec<Egg>, [u8; 32], vsf::VsfSection)> {
    use vsf::file_format::VsfHeader;

    let (sender_key, eggs, file_hash) = vsf::verification::header_eggs(bytes).ok()?;
    let (header, header_end) = VsfHeader::decode(bytes).ok()?;
    let section = header.primary_section(bytes, header_end).ok()?;
    let payload = section
        .get_field("payload")
        .and_then(|f| f.values.first())
        .and_then(|v| match v {
            VsfType::v(_, data) => Some(data.clone()),
            _ => None,
        })?;
    if payload.is_empty() {
        return None;
    }
    Some((sender_key, payload, eggs, file_hash, section))
}

// ── the open handshake: a pipe is bound only to the device that proves its key ──
//
// The seed's first frame on a fresh pipe is a [`Challenge`] it signs with its own key: a fresh nonce, the seed's Eagle time, and the device and service the socket was opened for.
// The device answers with [`open_answer`], a device-signed envelope whose one field commits to the domain [`OPEN_DOMAIN`] and the challenge's exact bytes.
// The seed binds the pipe only when the answer's signer IS the device the pipe is named for and the commitment matches the challenge it sent on that socket.
// A socket that never answers is unproven: it never displaces a proven pipe, and it carries no frame for the device (beyond the worker's dated window for released clients that open unsigned).

/// The domain the answer commits to, so a pipe answer is never mistaken for any other signature the device key makes.
pub const OPEN_DOMAIN: &str = "photon pipe open";
/// The challenge's section name.
pub const CHALLENGE_SECTION: &str = "pipe_challenge";
/// The answer's section name.
pub const OPEN_SECTION: &str = "pipe_open";

/// A challenge as the device reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Fresh random material, one per socket.
    pub nonce: [u8; 32],
    /// The seed's Eagle time when it issued the challenge, in oscillations.
    pub time: i64,
    /// The device the pipe was opened for.
    pub dev: [u8; 32],
    /// The service hub the pipe was opened for (`None` = the photon hub).
    pub svc: Option<String>,
}

/// The seed's challenge for a pipe opened for `dev` (and `svc`), signed with the seed's Ed25519 secret.
/// `nonce` must be fresh for every socket; the worker draws it from the platform's random source.
pub fn challenge(seed_secret: &[u8; 32], dev: &[u8; 32], svc: Option<&str>, nonce: &[u8; 32], time: i64) -> Result<Vec<u8>, String> {
    let seed_public = ed25519_dalek::SigningKey::from_bytes(seed_secret).verifying_key().to_bytes();
    let mut fields = vec![("nonce".to_string(), VsfType::hR(nonce.to_vec())), ("dev".to_string(), VsfType::ke(dev.to_vec()))];
    if let Some(svc) = svc {
        fields.push(("svc".to_string(), VsfType::d(vsf::Ascii::new(svc).map_err(|e| format!("pipe challenge svc: {e}"))?)));
    }
    let unsigned = vsf::VsfBuilder::new()
        .creation_time_oscillations(time)
        .signed_only(VsfType::ke(seed_public.to_vec()))
        .add_section(CHALLENGE_SECTION, fields)
        .build()
        .map_err(|e| format!("pipe challenge build: {e}"))?;
    vsf::verification::sign_file(unsigned, seed_secret)
}

/// Read a challenge off the pipe, verified under the seed's pinned key `seed_public`.
/// `None` for anything else: a relay envelope, a frame signed by any other key, a malformed one.
pub fn read_challenge(bytes: &[u8], seed_public: &[u8; 32]) -> Option<Challenge> {
    // Every relay frame passes through here first, so anything that does not even claim to be the seed's challenge is turned away before a signature is hashed.
    let (claimed, claimed_end) = vsf::file_format::VsfHeader::decode(bytes).ok()?;
    let seed_signed = matches!(&claimed.signer_pubkey, Some(VsfType::ke(k)) if k.as_slice() == seed_public.as_slice());
    if !seed_signed || !claimed.primary_section(bytes, claimed_end).is_ok_and(|s| s.name == CHALLENGE_SECTION) {
        return None;
    }
    let (header, end) = vsf::verification::read_verified(bytes, Some(*seed_public)).ok()?;
    let section = header.primary_section(bytes, end).ok()?;
    if section.name != CHALLENGE_SECTION {
        return None;
    }
    let time = match &header.creation_time {
        Some(VsfType::e(et)) => crate::fleet::try_et_to_osc(et)?,
        _ => return None,
    };
    let nonce = match section.get_field("nonce").and_then(|f| f.values.first()) {
        Some(VsfType::hR(b)) if b.len() == 32 => b.as_slice().try_into().ok()?,
        _ => return None,
    };
    let dev = match section.get_field("dev").and_then(|f| f.values.first()) {
        Some(VsfType::ke(b)) if b.len() == 32 => b.as_slice().try_into().ok()?,
        _ => return None,
    };
    let svc = match section.get_field("svc").and_then(|f| f.values.first()) {
        None => None,
        Some(VsfType::d(s)) => Some(s.as_str().to_string()),
        Some(_) => return None,
    };
    Some(Challenge { nonce, time, dev, svc })
}

/// The commitment an answer carries: BLAKE3 in derive-key mode under [`OPEN_DOMAIN`] over the challenge's exact bytes.
/// The whole challenge is committed (nonce, time, device, service and the seed's signature), so an answer fits the one socket it was asked on and no other.
pub fn open_binding(challenge_bytes: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key(OPEN_DOMAIN).update(challenge_bytes).finalize().as_bytes()
}

/// The device's answer to `challenge_bytes`: a signed frame (`pipe_open` `{ch}`) under the device key, stamped `time`.
pub fn open_answer(challenge_bytes: &[u8], device_key: &(impl crate::pq::FleetSigner + ?Sized), time: i64) -> Result<Vec<u8>, String> {
    let mut section = vsf::VsfSection::new(OPEN_SECTION);
    section.add_field("ch", VsfType::hb(open_binding(challenge_bytes).to_vec()));
    crate::pq::signed_frame(section, device_key, time)
}

/// The seed's check of an answer: `Some(signer)` when it is a well-signed `pipe_open` whose commitment is `binding`.
/// The caller still holds the signer to the device the pipe is named for; this returns it rather than taking it so a refusal can say which half failed.
pub fn check_answer(bytes: &[u8], binding: &[u8; 32]) -> Option<[u8; 32]> {
    let (section, signer) = crate::pq::open_frame(bytes).ok()?;
    if section.name != OPEN_SECTION {
        return None;
    }
    match section.get_field("ch").and_then(|f| f.values.first()) {
        Some(VsfType::hb(b)) if b.as_slice() == binding.as_slice() => Some(signer),
        _ => None,
    }
}

/// Whether a frame names itself an answer (its primary section is `pipe_open`), read without verifying, so the seed can route it before paying for a signature check.
pub fn is_open_answer(bytes: &[u8]) -> bool {
    let Ok((header, end)) = vsf::file_format::VsfHeader::decode(bytes) else { return false };
    header.primary_section(bytes, end).is_ok_and(|s| s.name == OPEN_SECTION)
}

// ── the rustdesk stream frame ──
//
// The envelope's inner payload for SVC_RUSTDESK is a byte-stream segment, NOT a VSF file: this is the per-video-frame hot path, the bytes are opaque to every relay hop (only the two rustdesk ends read them, and rustdesk's own session encryption rides inside), so a fixed 29-byte header beats a parse.
// Layout, all fixed offsets:
//
//   "RDS1"  ‖  conn:16  ‖  seq:8 BE  ‖  flags:1  ‖  data…
//
// `conn` is a random per-connection id (the guest mints it; the host demuxes on it), `seq` is a per-connection monotonic counter.
// The pipe preserves order end-to-end (WS ordered, DO input gates serialize, WS ordered) — `seq` exists so the receiver can PROVE that and heal/flag if it ever stops being true, not because reordering is expected.

/// Frame magic — "RDS1" (RustDesk Stream v1).
pub const RD_MAGIC: [u8; 4] = *b"RDS1";
/// First frame of a connection (guest → host).
/// Carries the first data bytes too.
pub const RD_FLAG_SYN: u8 = 1;
/// Orderly close; no data after this frame.
pub const RD_FLAG_FIN: u8 = 2;
/// Retransmit request: `seq` names the frame the sender must send again, and `data` is empty. The relay is live-only with no mailbox, so a frame in flight while the recipient's pipe reconnects is simply dropped; the receiver notices the gap and asks for it rather than stalling on a byte stream that can never resync.
pub const RD_FLAG_NACK: u8 = 4;
/// The frame carries a [`CandidateOffer`], not stream bytes: the two ends telling each other where to aim a hole punch. Signalling rides the relay pipe because it is the one channel that already works before any direct path exists — which is exactly the bootstrap problem.
pub const RD_FLAG_PUNCH: u8 = 8;
/// Fixed header length.
pub const RD_HEADER_LEN: usize = 4 + 16 + 8 + 1;

/// One stream segment as it rides inside a relay envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdFrame {
    pub conn: [u8; 16],
    pub seq: u64,
    pub flags: u8,
    pub data: Vec<u8>,
}

impl RdFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RD_HEADER_LEN + self.data.len());
        out.extend_from_slice(&RD_MAGIC);
        out.extend_from_slice(&self.conn);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push(self.flags);
        out.extend_from_slice(&self.data);
        out
    }

    /// `None` for anything that isn't a well-formed RDS1 frame (wrong magic, short).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        // WHY/PROOF: frame bytes arrive off the relay from a peer and may be shorter than the header — the fixed slices below would panic.
        if bytes.len() < RD_HEADER_LEN || bytes[0..4] != RD_MAGIC {
            return None;
        }
        let mut conn = [0u8; 16];
        conn.copy_from_slice(&bytes[4..20]);
        let mut seq8 = [0u8; 8];
        seq8.copy_from_slice(&bytes[20..28]);
        Some(Self {
            conn,
            seq: u64::from_be_bytes(seq8),
            flags: bytes[28],
            data: bytes[RD_HEADER_LEN..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::derive_device_keypair;

    fn kp(tag: u8) -> crate::keys::Keypair {
        derive_device_keypair(&[tag; 16])
    }

    const SEED_SECRET: [u8; 32] = [0x5e; 32];

    fn seed_public() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&SEED_SECRET).verifying_key().to_bytes()
    }

    /// The device reads the seed's challenge back exactly, and only under the seed's own key.
    #[test]
    fn a_challenge_reads_back_under_the_seed_key_only() {
        let dev = kp(10).public.to_bytes();
        let ch = challenge(&SEED_SECRET, &dev, Some(SVC_RUSTDESK), &[3u8; 32], 1 << 40).unwrap();
        let read = read_challenge(&ch, &seed_public()).expect("reads under the seed key");
        assert_eq!(read, Challenge { nonce: [3u8; 32], time: 1 << 40, dev, svc: Some(SVC_RUSTDESK.to_string()) });
        assert!(read_challenge(&ch, &kp(11).public.to_bytes()).is_none(), "another key's challenge is not the seed's");
        let photon = challenge(&SEED_SECRET, &dev, None, &[4u8; 32], 1 << 40).unwrap();
        assert_eq!(read_challenge(&photon, &seed_public()).unwrap().svc, None);
        let mut tampered = ch.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(read_challenge(&tampered, &seed_public()).is_none(), "a tampered challenge is refused");
    }

    /// A relay envelope is never read as a challenge, and a challenge is never peeled as a relay frame (so a released client that cannot answer drops it harmlessly).
    #[test]
    fn a_challenge_and_a_relay_frame_never_pass_for_each_other() {
        let dev = kp(12);
        let ch = challenge(&SEED_SECRET, &dev.public.to_bytes(), None, &[5u8; 32], 1 << 40).unwrap();
        assert!(peel_relay_envelope(&ch).is_none());
        let env = build_relay_envelope(&dev, &[9u8; 32], None, b"x").unwrap();
        assert!(read_challenge(&env, &dev.public.to_bytes()).is_none());
        assert!(!is_open_answer(&env));
        assert!(!is_open_answer(&ch));
    }

    /// The seed accepts the device's answer to the challenge it sent and names the device that signed it.
    #[test]
    fn an_answer_names_its_signer_and_fits_only_its_own_challenge() {
        let dev = kp(13);
        let ch = challenge(&SEED_SECRET, &dev.public.to_bytes(), None, &[6u8; 32], 1 << 40).unwrap();
        let answer = open_answer(&ch, &dev, (1 << 40) + 1).unwrap();
        assert!(is_open_answer(&answer));
        assert_eq!(check_answer(&answer, &open_binding(&ch)), Some(dev.public.to_bytes()));
        // An answer to one socket's challenge is refused on any other socket's.
        let other = challenge(&SEED_SECRET, &dev.public.to_bytes(), None, &[7u8; 32], 1 << 40).unwrap();
        assert!(check_answer(&answer, &open_binding(&other)).is_none());
        // A claimant without the key can only sign as itself: the seed reads the impostor as the signer, never as the device.
        let impostor = open_answer(&ch, &kp(14), (1 << 40) + 1).unwrap();
        assert_eq!(check_answer(&impostor, &open_binding(&ch)), Some(kp(14).public.to_bytes()));
        let mut tampered = answer.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(check_answer(&tampered, &open_binding(&ch)).is_none());
    }

    /// The commitment carries the domain: the bare BLAKE3 of the challenge is not it.
    #[test]
    fn the_binding_is_domain_separated() {
        let ch = challenge(&SEED_SECRET, &[1u8; 32], None, &[8u8; 32], 1 << 40).unwrap();
        assert_ne!(open_binding(&ch), *blake3::hash(&ch).as_bytes());
    }

    #[test]
    fn envelope_round_trips_and_names_the_sender() {
        let sender = kp(1);
        let recipient = kp(2);
        let env = build_relay_envelope(
            &sender,
            &recipient.public.to_bytes(),
            Some(SVC_RUSTDESK),
            b"hello stream",
        )
        .unwrap();
        let (from, payload) = peel_relay_envelope(&env).expect("must peel");
        assert_eq!(from, sender.public.to_bytes());
        assert_eq!(payload, b"hello stream");
    }

    /// The checked peel takes an envelope only at the device and service it was signed to (security audit FGTW-05).
    #[test]
    fn the_checked_peel_holds_the_envelope_to_its_signed_address() {
        let sender = kp(6);
        let me = kp(7).public.to_bytes();
        let other = kp(8).public.to_bytes();
        let rd = build_relay_envelope(&sender, &me, Some(SVC_RUSTDESK), b"for my rustdesk").unwrap();
        assert_eq!(peel_relay_envelope_for(&rd, &me, Some(SVC_RUSTDESK)), Some((sender.public.to_bytes(), b"for my rustdesk".to_vec())));
        assert!(peel_relay_envelope_for(&rd, &other, Some(SVC_RUSTDESK)).is_none(), "another device's frame");
        assert!(peel_relay_envelope_for(&rd, &me, None).is_none(), "a rustdesk frame on the photon pipe");
        let photon = build_relay_envelope(&sender, &me, None, b"for my photon").unwrap();
        assert!(peel_relay_envelope_for(&photon, &me, None).is_some());
        assert!(peel_relay_envelope_for(&photon, &me, Some(SVC_RUSTDESK)).is_none(), "a photon frame on the rustdesk pipe");
        let (from, payload, eggs, _) = peel_relay_envelope_eggs_for(&photon, &me, None).unwrap();
        assert_eq!((from, payload.as_slice()), (sender.public.to_bytes(), b"for my photon".as_slice()));
        assert!(!eggs.is_empty());
        // The plain peel is unchanged: it still names the sender of any well-signed envelope.
        assert!(peel_relay_envelope(&rd).is_some());
    }

    #[test]
    fn envelope_without_svc_still_round_trips() {
        // The legacy (photon) shape — no svc field at all.
        let sender = kp(3);
        let env = build_relay_envelope(&sender, &[9u8; 32], None, b"x").unwrap();
        assert!(peel_relay_envelope(&env).is_some());
    }

    #[test]
    fn a_tampered_envelope_is_refused() {
        let sender = kp(4);
        let mut env =
            build_relay_envelope(&sender, &[9u8; 32], Some(SVC_RUSTDESK), b"payload").unwrap();
        let last = env.len() - 1;
        env[last] ^= 0x01;
        assert!(peel_relay_envelope(&env).is_none(), "signature must not survive tampering");
    }

    #[test]
    fn garbage_and_empty_are_refused_not_faulted() {
        assert!(peel_relay_envelope(b"").is_none());
        assert!(peel_relay_envelope(b"not a vsf at all").is_none());
    }

    #[test]
    fn rd_frames_round_trip_including_empty_data() {
        for (flags, data) in [
            (RD_FLAG_SYN, b"first bytes".to_vec()),
            (0, vec![0u8; 100_000]),
            (RD_FLAG_FIN, Vec::new()),
            (RD_FLAG_NACK, Vec::new()),
        ] {
            let f = RdFrame { conn: [7u8; 16], seq: 42, flags, data };
            assert_eq!(RdFrame::decode(&f.encode()), Some(f));
        }
    }

    #[test]
    fn short_or_wrong_magic_frames_are_refused() {
        assert_eq!(RdFrame::decode(b"RDS1short"), None);
        let mut f = RdFrame { conn: [0u8; 16], seq: 0, flags: 0, data: vec![] }.encode();
        f[0] = b'X';
        assert_eq!(RdFrame::decode(&f), None);
    }

    #[test]
    fn a_frame_survives_the_envelope_end_to_end() {
        // The composition the wire actually carries: RdFrame inside a signed envelope.
        let sender = kp(5);
        let frame = RdFrame { conn: [1u8; 16], seq: 7, flags: RD_FLAG_SYN, data: b"raw stream bytes".to_vec() };
        let env = build_relay_envelope(&sender, &[2u8; 32], Some(SVC_RUSTDESK), &frame.encode()).unwrap();
        let (_, inner) = peel_relay_envelope(&env).unwrap();
        assert_eq!(RdFrame::decode(&inner), Some(frame));
    }
}


use core::net::SocketAddr;

/// The addresses a peer can be punched at, offered over the relay pipe.
///
/// Both ends send one as soon as a session starts, then probe every address the other listed. A probe's ack carries the responder's view of our source address, so the exchange doubles as reflexive discovery — no STUN server, and nothing the seed has to be able to do (Cloudflare Workers cannot speak UDP at all, so a worker-side echo was never an option).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CandidateOffer {
    pub addrs: Vec<SocketAddr>,
}

impl CandidateOffer {
    /// `count:u8 ‖ (len:u8 ‖ addr-bytes)*` — addresses use traverse's own encoding so the punch path has exactly one address format end to end.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.addrs.len() * 19);
        // The offer is our own gathered candidates (a handful of interfaces), far under the u8 count the wire carries.
        out.push(self.addrs.len() as u8);
        for a in &self.addrs {
            let b = crate::traverse::wire::socketaddr_to_bytes(a);
            out.push(b.len() as u8);
            out.extend_from_slice(&b);
        }
        out
    }

    /// Decode an offer. `None` on any malformed input — a peer that cannot be parsed simply gets no direct path, never a fault.
    /// An address no peer can be reached at is dropped, and at most [`phonebook::ADDRESS_SET_MAX`](crate::phonebook::ADDRESS_SET_MAX) are kept, the first listed (security audit FGTW-07): both ends probe every address the other offered.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&count, mut rest) = bytes.split_first()?;
        let mut addrs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (&len, tail) = rest.split_first()?;
            let len = len as usize;
            // WHY/PROOF: the per-address length byte is peer-supplied and may overrun the frame — split_at would panic.
            if tail.len() < len {
                return None;
            }
            let (body, tail) = tail.split_at(len);
            let addr = crate::traverse::wire::bytes_to_socketaddr(body)?;
            // WHY/PROOF: the offer is peer-supplied and every address in it is probed; the count byte allows 255 and the address may be one no host answers at (security audit FGTW-07).
            if !crate::traverse::gather::is_bogus_addr(&addr) && addrs.len() < crate::phonebook::ADDRESS_SET_MAX {
                addrs.push(addr);
            }
            rest = tail;
        }
        Some(Self { addrs })
    }
}

#[cfg(test)]
mod candidate_offer_tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn round_trips_v4_and_v6() {
        let offer = CandidateOffer {
            addrs: vec![
                sa("192.168.1.156:21118"),
                sa("203.0.113.7:41234"),
                sa("[2001:db8::1]:21118"),
            ],
        };
        assert_eq!(CandidateOffer::decode(&offer.encode()), Some(offer));
    }

    /// A peer's offer is held to the bogus gate and to ADDRESS_SET_MAX addresses, the first listed (security audit FGTW-07).
    #[test]
    fn an_offer_drops_bogus_addresses_and_stops_at_the_cap() {
        let mut addrs = vec![sa("0.0.0.0:0"), sa("224.0.0.1:4383"), sa("10.0.0.2:0")];
        for p in 0..200u16 {
            addrs.push(SocketAddr::new(sa("203.0.113.7:1").ip(), 1000 + p));
        }
        let back = CandidateOffer::decode(&CandidateOffer { addrs }.encode()).expect("decodes");
        assert_eq!(back.addrs.len(), crate::phonebook::ADDRESS_SET_MAX);
        assert_eq!(back.addrs[0], sa("203.0.113.7:1000"));
    }

    #[test]
    fn an_empty_offer_is_valid() {
        let offer = CandidateOffer::default();
        assert_eq!(CandidateOffer::decode(&offer.encode()), Some(offer));
    }

    #[test]
    fn truncated_input_decodes_to_nothing_rather_than_panicking() {
        let full = CandidateOffer { addrs: vec![sa("192.168.1.5:4383")] }.encode();
        for cut in 0..full.len() {
            let _ = CandidateOffer::decode(&full[..cut]); // must not panic
        }
        assert_eq!(CandidateOffer::decode(&[]), None);
    }

    #[test]
    fn a_punch_frame_is_not_mistaken_for_stream_bytes() {
        let offer = CandidateOffer { addrs: vec![sa("10.0.0.2:4383")] };
        let frame = RdFrame {
            conn: [7u8; 16],
            seq: 0,
            flags: RD_FLAG_PUNCH,
            data: offer.encode(),
        };
        let decoded = RdFrame::decode(&frame.encode()).expect("decodes");
        assert_eq!(decoded.flags & RD_FLAG_PUNCH, RD_FLAG_PUNCH);
        assert_eq!(CandidateOffer::decode(&decoded.data), Some(offer));
    }
}
