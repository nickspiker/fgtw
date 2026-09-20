//! The relay pipe — sans-io codec for the seed's live per-device WebSocket relay.
//!
//! A device opens `wss://<seed>/pipe?dev=<hex>[&svc=<tag>]` as its receive socket, and sends by pushing a signed relay envelope either up that same socket (full-duplex, the worker forwards it) or as an HTTPS POST.
//! The envelope is a whole signed VSF — section `relay` `{recipient, payload[, svc]}`, signed by the sender's device key — so the receiver learns "via relay, from device X" from authenticated bytes.
//!
//! **Service tags.** Two apps sharing one device key (photon and the rustdesk fork share the fleet identity on purpose) must not share a pipe: the worker names the hub `<hex>` for a svc-less pipe (photon, unchanged) and `<hex>:<svc>` otherwise, so the two pipes have independent lifecycles — closing photon to update it can never drop the rustdesk session doing the updating — and a frame addressed to a service can only land on that service's socket.
//!
//! **This module is sans-io** like [`crate::traverse`]: envelope build/peel and the stream frame codec live here with tests; the socket pump (tokio/tungstenite) is each app's concern, so `fgtw` stays free of async deps.

use crate::fleet::Egg;
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
    device_key: &impl crate::pq::FleetSigner,
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
        fields.push(("svc".to_string(), VsfType::d(svc.to_string())));
    }
    let unsigned = vsf::VsfBuilder::new()
        .creation_time_oscillations(vsf::eagle_time_oscillations())
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
    Some((sender_key, payload, eggs, file_hash))
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


use std::net::SocketAddr;

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
        out.push(self.addrs.len().min(u8::MAX as usize) as u8);
        for a in self.addrs.iter().take(u8::MAX as usize) {
            let b = crate::traverse::wire::socketaddr_to_bytes(a);
            out.push(b.len() as u8);
            out.extend_from_slice(&b);
        }
        out
    }

    /// Decode an offer. `None` on any malformed input — a peer that cannot be parsed simply gets no direct path, never a fault.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&count, mut rest) = bytes.split_first()?;
        let mut addrs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (&len, tail) = rest.split_first()?;
            let len = len as usize;
            if tail.len() < len {
                return None;
            }
            let (body, tail) = tail.split_at(len);
            addrs.push(crate::traverse::wire::bytes_to_socketaddr(body)?);
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
