//! The fleet's frames between devices — the generic half of photon's `protocol.rs` (MIGRATION.md step 5, the fleet and pairing slice, 2026-10-31): the LAN beacon, the binding request and its `bind_req` envelope, the departure request, and the membership chain and fan-out handed device to device (`fleet_req`, `fleet_resp`, `fanout_resp`).
//! One codec for every client — photon, ferros, any app on the fleet — so the bytes a joiner sends and a sponsor reads are the same code on both ends, not copies pinned against each other.
//! The messaging frames (chat, CLUTCH, PT, waves) stay in photon: that split rides the messaging rework.
//!
//! Every builder takes the signer and the time: a host passes its clock, a bare-metal client its own (no OS clock here).
//! Envelopes are device-signed VSF documents: the header reserves one egg per scheme at the envelope tier (`pq::envelope_mask`), `pq::sign_envelope` fills them over the file hash, and the reader verifies the anchor egg (`vsf::verification::read_verified`) before reading a field.
//! The wire format is the one photon shipped; moving it here changed no byte.

use crate::fleet::{scheme, BindRequest};
use crate::pq::{eggs_from_bytes, eggs_to_bytes, envelope_mask, reserve_eggs, sign_envelope, FleetSigner, KeyBundle};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use vsf::file_format::{VsfHeader, VsfSection};
use vsf::{VsfBuilder, VsfType};

/// The frame port and the beacon port the apps listen on.
pub const PORT: u16 = 4383;
pub const BEACON_PORT: u16 = 4384;
/// The LAN beacon groups: IPv4 multicast 239.104.199.144 and IPv6 ff02::68c7:9014.
pub const BEACON_V4: [u8; 4] = [239, 104, 199, 144];
pub const BEACON_V6: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0xc7, 0x90, 0x14];

// ── The LAN beacon ──

/// The LAN discovery beacon (`pt_disc`): the handle proof as the header's provenance (no registry lookup needed to know whose fleet is beaconing), the frame port, and the device key (so a receiver can tell which fleet device it is, and drop its own looped-back beacon). Unsigned, provenance only: a one-shot broadcast.
pub fn beacon(handle_proof: [u8; 32], port: u16, device_pubkey: [u8; 32], time: i64) -> Vec<u8> {
    VsfBuilder::new()
        .creation_time_oscillations(time)
        .provenance_hash(handle_proof)
        .provenance_only()
        .add_section("pt_disc", vec![("port".to_string(), VsfType::u(port as usize, false)), ("ke".to_string(), VsfType::ke(device_pubkey.to_vec()))])
        .build()
        .unwrap_or_default()
}

/// A beacon's (handle proof, frame port, device key); None for anything that is not one. The device key is None on beacons from builds that predate it.
/// The section is resolved through the header's table of contents (`primary_section`), never a bare section parse: the name lives in the TOC, and a body parse reads an empty name — the 2026-08-11 trap that rejected every beacon fleet-wide.
/// The port is read width-agnostic: a writer may auto-size, and a port under 256 legitimately encodes narrow.
pub fn parse_beacon(bytes: &[u8]) -> Option<([u8; 32], u16, Option<[u8; 32]>)> {
    let (header, end) = VsfHeader::decode(bytes).ok()?;
    let hp: [u8; 32] = match &header.provenance_hash {
        VsfType::hp(b) if b.len() == 32 => b.as_slice().try_into().ok()?,
        _ => return None,
    };
    let section = header.primary_section(bytes, end).ok()?;
    if section.name != "pt_disc" {
        return None;
    }
    let port = section.get_field("port").and_then(|f| f.values.first()).and_then(|v| v.as_u64()).and_then(|n| u16::try_from(n).ok())?;
    let ke = section.get_field("ke").and_then(|f| f.values.first()).and_then(|v| match v {
        VsfType::ke(b) if b.len() == 32 => b.as_slice().try_into().ok(),
        _ => None,
    });
    Some((hp, port, ke))
}

// ── Envelopes ──

/// A device-signed envelope around `section`, stamped `time`.
pub fn signed_frame(section: VsfSection, signer: &(impl FleetSigner + ?Sized), time: i64) -> Result<Vec<u8>, String> {
    let ke = signer.keypair().public.to_bytes();
    let unsigned = VsfBuilder::new()
        .creation_time_oscillations(time)
        .signed_only_eggs(VsfType::ke(ke.to_vec()), &reserve_eggs(envelope_mask(signer)))
        .add_section_direct(section)
        .build()
        .map_err(|e| alloc::format!("frame build: {e}"))?;
    sign_envelope(unsigned, signer)
}

/// Verify a device-signed envelope and read its section: (the section, the signing device). Fails unless the anchor egg verifies under the header's own `ke`.
pub fn open_frame(bytes: &[u8]) -> Result<(VsfSection, [u8; 32]), String> {
    let (header, end) = vsf::verification::read_verified(bytes, None).map_err(|e| alloc::format!("frame verification failed: {e}"))?;
    let signer = vsf::verification::extract_signer_pubkey(bytes)?;
    let section = header.primary_section(bytes, end).map_err(|e| alloc::format!("frame section: {e}"))?;
    Ok((section, signer))
}

/// `open_frame` for one expected section name.
fn open_named(bytes: &[u8], name: &str) -> Result<(VsfSection, [u8; 32]), String> {
    let (section, signer) = open_frame(bytes).map_err(|e| alloc::format!("{name}: {e}"))?;
    if section.name != name {
        return Err(alloc::format!("Expected '{name}' section, got '{}'", section.name));
    }
    Ok((section, signer))
}

/// A 32-byte handle proof field: `hP`, the fgtw sections' type for it (`hp` and `hb` accepted too).
pub fn field_handle_proof(section: &VsfSection, name: &str) -> Option<[u8; 32]> {
    section.get_field(name).and_then(|f| f.values.first()).and_then(|v| match v {
        VsfType::hP(b) | VsfType::hp(b) | VsfType::hb(b) if b.len() == 32 => b.as_slice().try_into().ok(),
        _ => None,
    })
}

/// A byte-string field (`ge`), as the envelopes carry chains, blobs and egg lists.
pub fn field_ge(section: &VsfSection, name: &str) -> Option<Vec<u8>> {
    section.get_field(name).and_then(|f| f.values.first()).and_then(|v| match v {
        VsfType::ge(b) => Some(b.clone()),
        _ => None,
    })
}

// ── Joining: the binding request ──

/// This device's binding request for fleet `handle_proof`, stamped `t`: "I consent to join", signed by the device with one egg per scheme it holds (its bundle rides along), co-signed by `Ed25519(identity_seed)` (the registry's handle-knowledge gate). `nfc_secret` is the tap's secret S when the device serves one: the request then commits to it (`pair::nfc_secret_hash` over this device and `t`); all zero = no tap offered.
/// Built once and sent two ways with the same stamp — to the seed's registry and as a `bind_req` frame to sponsors heard on the LAN — so `t` is the Add's `consent_t` and the BLE beacon's stamp alike.
pub fn bind_request(signer: &(impl FleetSigner + ?Sized), identity_seed: &[u8; 32], handle_proof: &[u8; 32], t: i64, nfc_secret: &[u8; 32]) -> BindRequest {
    bind_request_plated(signer, identity_seed, handle_proof, t, nfc_secret, None, crate::fleet::plate::UNSTATED)
}

/// [`bind_request`] with the joiner's plate (see `fleet::FleetOp::plate`): both signatures then cover the plate (`fleet::bindreq_signing_bytes_plated`), so the sponsor puts it on the Add as the joiner's own word.
pub fn bind_request_plated(signer: &(impl FleetSigner + ?Sized), identity_seed: &[u8; 32], handle_proof: &[u8; 32], t: i64, nfc_secret: &[u8; 32], plate: Option<[u8; 32]>, plate_kind: u8) -> BindRequest {
    use ed25519_dalek::Signer;
    let me = signer.keypair().public.to_bytes();
    let nfc_hash = if *nfc_secret == [0u8; 32] { [0u8; 32] } else { crate::pair::nfc_secret_hash(nfc_secret, &me, t) };
    let msg = crate::fleet::bindreq_signing_bytes_plated(handle_proof, &me, t, plate.as_ref(), plate_kind);
    let bundle = signer.bundle();
    let mask = bundle.as_ref().map(|b| b.mask()).unwrap_or(scheme::MASK_BASE);
    let identity_key = ed25519_dalek::SigningKey::from_bytes(identity_seed);
    BindRequest { device_pubkey: me, t, device_sig: signer.eggs(&msg, mask), bundle, identity_sig: identity_key.sign(&msg).to_bytes().to_vec(), plate, plate_kind, nfc_hash }
}

/// The `bind_req` frame: the request's fields (hp, dk, t, ds consent eggs, is identity co-sign, kb bundle, nh NFC commitment) for fleet `hp`, in an envelope signed by the request's own device. A sponsor verifies the request exactly as a registry row (`BindRequest::verify` + freshness).
pub fn bind_req(req: &BindRequest, handle_proof: &[u8; 32], signer: &(impl FleetSigner + ?Sized), time: i64) -> Result<Vec<u8>, String> {
    let mut section = VsfSection::new("bind_req");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    section.add_field("dk", VsfType::ke(req.device_pubkey.to_vec()));
    section.add_field("t", VsfType::e(vsf::types::EtType::e6(req.t)));
    section.add_field("ds", VsfType::ge(eggs_to_bytes(&req.device_sig)));
    section.add_field("is", VsfType::ge(req.identity_sig.clone()));
    if let Some(b) = &req.bundle {
        section.add_field("kb", VsfType::ge(b.to_bytes()));
    }
    if let Some(p) = &req.plate {
        section.add_field("pl", VsfType::hb(p.to_vec()));
    }
    if req.plate_kind != crate::fleet::plate::UNSTATED {
        section.add_field("pk", VsfType::u(req.plate_kind as usize, false));
    }
    section.add_field("nh", VsfType::hb(req.nfc_hash.to_vec()));
    signed_frame(section, signer, time)
}

/// Read a `bind_req`: (handle proof, the request, the sending device). The envelope signer must be the request's device; the request's own signatures are the receiver's to check (`BindRequest::verify` needs the identity key). A request without `nh` reads as no tap offered.
pub fn parse_bind_req(bytes: &[u8]) -> Result<([u8; 32], BindRequest, [u8; 32]), String> {
    let (section, sender) = open_named(bytes, "bind_req")?;
    let hp = field_handle_proof(&section, "hp").ok_or("bind_req missing hp")?;
    let first = |name: &str| section.get_field(name).and_then(|f| f.values.first());
    let device_pubkey: [u8; 32] = match first("dk") {
        Some(VsfType::ke(b)) if b.len() == 32 => b.as_slice().try_into().map_err(|_| "bind_req dk")?,
        _ => return Err("bind_req missing dk".into()),
    };
    if device_pubkey != sender {
        return Err("bind_req envelope signer is not the request's device".into());
    }
    let t = section.eagle("t").ok_or("bind_req missing t")?;
    let device_sig = match first("ds") {
        Some(VsfType::ge(b)) => eggs_from_bytes(b)?,
        _ => return Err("bind_req missing ds".into()),
    };
    let identity_sig = field_ge(&section, "is").ok_or("bind_req missing is")?;
    let bundle = match first("kb") {
        Some(VsfType::ge(b)) => Some(KeyBundle::from_bytes(b)?),
        _ => None,
    };
    let nfc_hash: [u8; 32] = match first("nh") {
        Some(VsfType::hb(h)) if h.len() == 32 => h.as_slice().try_into().map_err(|_| "bind_req nh")?,
        _ => [0u8; 32],
    };
    let plate: Option<[u8; 32]> = match first("pl") {
        Some(VsfType::hb(p)) if p.len() == 32 => Some(p.as_slice().try_into().map_err(|_| "bind_req pl")?),
        _ => None,
    };
    let plate_kind = match first("pk") {
        Some(v) => {
            use vsf::schema::FromVsfType;
            u8::from_vsf_type(v).map_err(|_| "bind_req pk")?
        }
        None => crate::fleet::plate::UNSTATED,
    };
    Ok((hp, BindRequest { device_pubkey, t, device_sig, bundle, identity_sig, plate, plate_kind, nfc_hash }, sender))
}

// ── Leaving: the departure request ──

/// A departure's intent: the leaving device going to a new owner (the approver countersigns and releases the brand) or to the desk (brand kept, the retired row is inventory). Absent on the wire from pre-intent builds, which the approver treats as desk.
pub const DEPART_NEW_OWNER: u8 = 1;
pub const DEPART_DESK: u8 = 2;

/// The departure request's fields, in wire order (the order the signature covers).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DepartReq {
    /// The consent stamp the leaver's signature covers.
    pub t: i64,
    /// The leaver's signature over `fleet::departreq_signing_bytes(hp, device, t)`.
    pub consent_sig: Vec<u8>,
    /// `DEPART_NEW_OWNER`, `DEPART_DESK`, or 0 for a pre-intent build (none on the wire).
    pub intent: u8,
    /// The approval words' commitment (`depart_words_commit`): the leaver's screen shows the words, the approver types them — proof of live contact with the departing device's screen. The words never ride the wire.
    pub words_commit: Option<[u8; 32]>,
}

/// The approval words' commitment: BLAKE3 of the words, lowercased.
pub fn depart_words_commit(words: &str) -> [u8; 32] {
    *blake3::hash(words.to_lowercase().as_bytes()).as_bytes()
}

/// The `depart_req` frame — the LEAVING device's request to a sibling (bilateral removal, the mirror of the add ceremony): fields t, cs, it, wc, signed by the leaving device. A surviving member's user approves by typing the words, and that device countersigns and publishes the consented Remove.
pub fn depart_req(req: &DepartReq, signer: &(impl FleetSigner + ?Sized), time: i64) -> Result<Vec<u8>, String> {
    let mut section = VsfSection::new("depart_req");
    section.add_field("t", VsfType::e(vsf::types::EtType::e6(req.t)));
    section.add_field("cs", VsfType::ge(req.consent_sig.clone()));
    if req.intent != 0 {
        section.add_field("it", VsfType::u(req.intent as usize, false));
    }
    if let Some(wc) = &req.words_commit {
        section.add_field("wc", VsfType::hp(wc.to_vec()));
    }
    signed_frame(section, signer, time)
}

/// Read a `depart_req`: (the request, the leaving device = the envelope's signer). A missing intent reads 0, a missing commitment None.
pub fn parse_depart_req(bytes: &[u8]) -> Result<(DepartReq, [u8; 32]), String> {
    let (section, sender) = open_named(bytes, "depart_req")?;
    let t = section.eagle("t").ok_or("depart_req missing t")?;
    let consent_sig = field_ge(&section, "cs").ok_or("depart_req missing cs")?;
    let intent = section.get_field("it").and_then(|f| f.values.first()).and_then(|v| v.as_u64()).and_then(|n| u8::try_from(n).ok()).unwrap_or(0);
    let words_commit = section.get_field("wc").and_then(|f| f.values.first()).and_then(|v| match v {
        VsfType::hp(b) if b.len() == 32 => b.as_slice().try_into().ok(),
        _ => None,
    });
    Ok((DepartReq { t, consent_sig, intent, words_commit }, sender))
}

/// The leaver's consent for a departure from fleet `handle_proof` stamped `t`: its eggs over `fleet::departreq_signing_bytes`, one per scheme it holds, as an egg-list blob — the Remove op's `consent_sig`. The fold verifies them against the bundle the chain holds for this device and demands the floor, so a consent is never weaker than the device's declared set.
pub fn depart_consent(signer: &(impl FleetSigner + ?Sized), handle_proof: &[u8; 32], t: i64) -> Vec<u8> {
    let me = signer.keypair().public.to_bytes();
    let msg = crate::fleet::departreq_signing_bytes(handle_proof, &me, t);
    let mask = signer.bundle().map(|b| b.mask()).unwrap_or(scheme::MASK_BASE);
    eggs_to_bytes(&signer.eggs(&msg, mask))
}

/// The three approval words the leaving device shows, from `nonce` (the caller's randomness: this crate has no RNG on bare metal): the nonce reduced to three voca words' worth, encoded, and left-padded with the capitalised zero word to exactly three.
pub fn depart_words(nonce: u64) -> String {
    let base = voca::FULL.alphabet().len() as u64;
    let mut words = voca::encode(num_bigint::BigUint::from(nonce % base.pow(3)));
    while crate::pair::pair_word_tokens(&words) < 3 {
        let w0 = core::str::from_utf8(voca::FULL.alphabet()[0]).expect("voca words are ASCII");
        let mut z = String::new();
        let mut cs = w0.chars();
        if let Some(c) = cs.next() {
            z.push(c.to_ascii_uppercase());
            z.extend(cs);
        }
        words = alloc::format!("{z}{words}");
    }
    words
}

// ── The membership chain and the fan-out over the mesh ──

/// The `fleet_req` frame: "send me the membership chain of handle `hp`". The answerer gates on knowing the asking device (the chain is public, but a 10–50 KB answer is amplification bait).
pub fn fleet_req(handle_proof: &[u8; 32], signer: &(impl FleetSigner + ?Sized), time: i64) -> Result<Vec<u8>, String> {
    let mut section = VsfSection::new("fleet_req");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    signed_frame(section, signer, time)
}

/// Read a `fleet_req`: (the handle proof asked for, the asking device).
pub fn parse_fleet_req(bytes: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let (section, sender) = open_named(bytes, "fleet_req")?;
    Ok((field_handle_proof(&section, "hp").ok_or("fleet_req missing hp")?, sender))
}

/// The `fleet_resp` frame: the membership chain of handle `hp` (`MembershipBlob::to_vsf_bytes`, a complete VSF document in the `ch` field) — the answer to a `fleet_req`, or a sponsor's push after extending the chain. The chain verifies itself; the carrier earns no trust.
pub fn fleet_resp(handle_proof: &[u8; 32], chain: &[u8], signer: &(impl FleetSigner + ?Sized), time: i64) -> Result<Vec<u8>, String> {
    let mut section = VsfSection::new("fleet_resp");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    section.add_field("ch", VsfType::ge(chain.to_vec()));
    signed_frame(section, signer, time)
}

/// Read a `fleet_resp`: (handle proof, the chain's bytes, the sending device). The chain is not folded here: the receiver folds it against its own roots.
pub fn parse_fleet_resp(bytes: &[u8]) -> Result<([u8; 32], Vec<u8>, [u8; 32]), String> {
    let (section, sender) = open_named(bytes, "fleet_resp")?;
    Ok((field_handle_proof(&section, "hp").ok_or("fleet_resp missing hp")?, field_ge(&section, "ch").ok_or("fleet_resp missing ch")?, sender))
}

/// The `fanout_resp` frame: a fan-out blob (`fanout_to_bytes`) for fleet `hp`, handed by the device that sealed it to the newcomer it was grown for and to the siblings. Each opens it with its own ira; a header the recovered key does not reproduce is refused.
pub fn fanout_resp(handle_proof: &[u8; 32], blob: &[u8], signer: &(impl FleetSigner + ?Sized), time: i64) -> Result<Vec<u8>, String> {
    let mut section = VsfSection::new("fanout_resp");
    section.add_field("hp", VsfType::hP(handle_proof.to_vec()));
    section.add_field("bl", VsfType::ge(blob.to_vec()));
    signed_frame(section, signer, time)
}

/// Read a `fanout_resp`: (handle proof, the blob, the sending device).
pub fn parse_fanout_resp(bytes: &[u8]) -> Result<([u8; 32], Vec<u8>, [u8; 32]), String> {
    let (section, sender) = open_named(bytes, "fanout_resp")?;
    Ok((field_handle_proof(&section, "hp").ok_or("fanout_resp missing hp")?, field_ge(&section, "bl").ok_or("fanout_resp missing bl")?, sender))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::Egg;
    use crate::keys::Keypair;

    /// The departure request's section is byte-identical to photon's hand codec (photon protocol.rs `depart_req_derive_is_byte_identical_and_round_trips`), and the signed frame round-trips with intent and commitment, and a pre-intent request reads desk-less (0, None).
    #[test]
    fn depart_req_matches_the_hand_codec_and_round_trips() {
        let mut hand = VsfSection::new("depart_req");
        hand.add_field("t", VsfType::e(vsf::types::EtType::e6(9_999)));
        hand.add_field("cs", VsfType::ge(vec![7u8; 64]));
        hand.add_field("it", VsfType::u(1, false));
        hand.add_field("wc", VsfType::hp(vec![3u8; 32]));
        let req = DepartReq { t: 9_999, consent_sig: vec![7u8; 64], intent: 1, words_commit: Some([3u8; 32]) };
        let kp = Keypair::from_seed(&[0x5Au8; 32]);
        let frame = depart_req(&req, &kp, 42).unwrap();
        let (section, signer) = open_frame(&frame).unwrap();
        assert_eq!(section.encode(), hand.encode(), "the section must be the hand codec's bytes");
        assert_eq!(parse_depart_req(&frame).unwrap(), (req, kp.public.to_bytes()));
        let legacy = depart_req(&DepartReq { t: 5, consent_sig: vec![1u8; 64], intent: 0, words_commit: None }, &kp, 42).unwrap();
        let (back, _) = parse_depart_req(&legacy).unwrap();
        assert_eq!((back.intent, back.words_commit), (0, None));
        assert_eq!(signer, kp.public.to_bytes());
    }

    #[test]
    fn bind_req_fleet_and_fanout_frames_round_trip() {
        let kp = Keypair::from_seed(&[0x55u8; 32]);
        let hp = [0x66u8; 32];
        let req = BindRequest { device_pubkey: kp.public.to_bytes(), t: 123_456, device_sig: vec![Egg { scheme: scheme::ED25519, sig: vec![9u8; 64] }], bundle: None, identity_sig: vec![8u8; 64], plate: Some([5u8; 32]), plate_kind: crate::fleet::plate::WIDEVINE, nfc_hash: [7u8; 32] };
        let frame = bind_req(&req, &hp, &kp, 1).unwrap();
        assert_eq!(parse_bind_req(&frame).unwrap(), (hp, req, kp.public.to_bytes()));
        assert_eq!(parse_fleet_req(&fleet_req(&hp, &kp, 1).unwrap()).unwrap(), (hp, kp.public.to_bytes()));
        let chain = vec![0xABu8; 2000];
        assert_eq!(parse_fleet_resp(&fleet_resp(&hp, &chain, &kp, 1).unwrap()).unwrap(), (hp, chain, kp.public.to_bytes()));
        let blob = vec![0xCDu8; 3000];
        assert_eq!(parse_fanout_resp(&fanout_resp(&hp, &blob, &kp, 1).unwrap()).unwrap(), (hp, blob, kp.public.to_bytes()));
        // A frame of one kind never parses as another.
        assert!(parse_fleet_req(&frame).is_err());
    }

    #[test]
    fn bind_request_commits_to_the_tap_secret_only_when_given() {
        let kp = Keypair::from_seed(&[0x11u8; 32]);
        let (seed, hp) = ([0x22u8; 32], [0x33u8; 32]);
        let none = bind_request(&kp, &seed, &hp, 77, &[0u8; 32]);
        assert_eq!(none.nfc_hash, [0u8; 32]);
        let s = [0x44u8; 32];
        let tap = bind_request(&kp, &seed, &hp, 77, &s);
        assert_eq!(tap.nfc_hash, crate::pair::nfc_secret_hash(&s, &kp.public.to_bytes(), 77));
        assert_ne!(tap.nfc_hash, crate::pair::nfc_secret_hash(&s, &kp.public.to_bytes(), 78), "the stamp is inside the commitment");
    }

    #[test]
    fn beacon_round_trips() {
        let b = beacon([0x77u8; 32], PORT, [0x88u8; 32], 5);
        assert_eq!(parse_beacon(&b), Some(([0x77u8; 32], PORT, Some([0x88u8; 32]))));
        assert_eq!(parse_beacon(&[1, 2, 3]), None);
    }
}
