//! The punch wire format — the two messages traversal puts on the socket.
//!
//! This is the single encoder for both consumers. Photon's `FgtwMessage::PunchProbe` /
//! `PunchProbeAck` arms delegate here rather than carrying their own copy, so the format
//! cannot drift between the two implementations.
//!
//! # Why the golden-bytes tests exist
//!
//! Photon has a shipped fleet punching with this exact encoding right now. VSF headers carry
//! a table of contents and a total length, so a reordered field or a renamed section shifts
//! bytes in places you would not predict by reading the diff — and the failure mode is not a
//! compile error, it is two deployed versions that silently stop being able to punch to each
//! other. The fixtures below were captured from the pre-extraction encoder and pin the format
//! byte-for-byte. **If you change this file and a golden test fails, you have broken
//! compatibility with every deployed build — fix the code, do not update the fixture.**
//!
//! # Shape
//!
//! Both messages carry their crypto in the VSF header (timestamp, signer pubkey, provenance
//! hash, ed25519 signature). The probe is header-only — a name-only TOC entry with no body,
//! the minimal wire form. The ack adds one `obs` field carrying the address the responder saw
//! the probe arrive from, which is what makes an ack double as a reflexive-address echo.

use std::net::{IpAddr, SocketAddr};

use vsf::file_format::VsfHeader;
use vsf::types::VsfType;
use vsf::VsfBuilder;

use super::DevicePubkey;

/// Section name for a probe — header-only.
const SECTION_PROBE: &str = "punch";
/// Section name for an ack — header plus the `obs` field.
const SECTION_ACK: &str = "punch_ack";
/// Field name carrying the observed address in an ack.
const FIELD_OBSERVED: &str = "obs";

/// A punch message on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchMessage {
    /// A hole-punch probe fired at one candidate address.
    Probe {
        timestamp: i64,
        sender_pubkey: DevicePubkey,
        provenance_hash: [u8; 32],
        signature: [u8; 64],
    },
    /// The reply to a [`PunchMessage::Probe`]. Echoes the probe's provenance so the prober can
    /// match which candidate round-tripped, and carries `observed_addr` so the ack doubles as
    /// a reflexive echo.
    ProbeAck {
        timestamp: i64,
        responder_pubkey: DevicePubkey,
        provenance_hash: [u8; 32],
        signature: [u8; 64],
        observed_addr: SocketAddr,
    },
}

impl PunchMessage {
    /// Encode to a full VSF file (magic included).
    pub fn to_vsf_bytes(&self) -> Result<Vec<u8>, String> {
        let builder = VsfBuilder::new();
        match self {
            PunchMessage::Probe {
                timestamp,
                sender_pubkey,
                provenance_hash,
                signature,
            } => builder
                .creation_time_oscillations(*timestamp)
                .provenance_hash(*provenance_hash)
                .signature_ed25519(*sender_pubkey, *signature)
                .add_section(SECTION_PROBE, vec![])
                .build(),
            PunchMessage::ProbeAck {
                timestamp,
                responder_pubkey,
                provenance_hash,
                signature,
                observed_addr,
            } => builder
                .creation_time_oscillations(*timestamp)
                .provenance_hash(*provenance_hash)
                .signature_ed25519(*responder_pubkey, *signature)
                .add_section(
                    SECTION_ACK,
                    vec![(
                        FIELD_OBSERVED.to_string(),
                        VsfType::hb(socketaddr_to_bytes(observed_addr)),
                    )],
                )
                .build(),
        }
    }

    /// Decode a punch message. `Ok(None)` means "a valid VSF file, but not one of ours" — the
    /// caller should pass it to its own dispatch rather than treating it as an error, which is
    /// what lets photon share one socket across several message families.
    pub fn from_vsf_bytes(bytes: &[u8]) -> Result<Option<Self>, String> {
        if bytes.len() < 4 || &bytes[0..3] != "RÅ".as_bytes() || bytes[3] != b'<' {
            return Err("not a VSF file (invalid magic)".to_string());
        }
        let (header, header_end) =
            VsfHeader::decode(bytes).map_err(|e| format!("failed to parse VSF header: {e}"))?;
        let section = header
            .primary_section(bytes, header_end)
            .map_err(|e| format!("failed to parse section: {e}"))?;

        match section.name.as_str() {
            SECTION_PROBE => Ok(Some(PunchMessage::Probe {
                timestamp: header_timestamp(&header)?,
                sender_pubkey: header_pubkey(&header)?,
                provenance_hash: header_provenance(&header)?,
                signature: header_signature(&header)?,
            })),
            SECTION_ACK => {
                let timestamp = header_timestamp(&header)?;
                let responder_pubkey = header_pubkey(&header)?;
                let provenance_hash = header_provenance(&header)?;
                let signature = header_signature(&header)?;
                let observed_addr = section
                    .fields
                    .iter()
                    .find(|f| f.name == FIELD_OBSERVED)
                    .and_then(|f| match f.values.first() {
                        Some(VsfType::hb(b)) => bytes_to_socketaddr(b),
                        _ => None,
                    })
                    .ok_or_else(|| format!("{SECTION_ACK} missing observed_addr"))?;
                Ok(Some(PunchMessage::ProbeAck {
                    timestamp,
                    responder_pubkey,
                    provenance_hash,
                    signature,
                    observed_addr,
                }))
            }
            _ => Ok(None),
        }
    }
}

/// A socket address as bytes: IPv4 → 4 + 2 (port, big-endian) = 6; IPv6 → 16 + 2 = 18.
pub fn socketaddr_to_bytes(addr: &SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::new();
    match addr.ip() {
        IpAddr::V4(v4) => bytes.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => bytes.extend_from_slice(&v6.octets()),
    }
    bytes.extend_from_slice(&addr.port().to_be_bytes());
    bytes
}

/// Inverse of [`socketaddr_to_bytes`]; `None` on any length other than 6 or 18.
pub fn bytes_to_socketaddr(bytes: &[u8]) -> Option<SocketAddr> {
    match bytes.len() {
        6 => {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            ));
            Some(SocketAddr::new(
                ip,
                u16::from_be_bytes([bytes[4], bytes[5]]),
            ))
        }
        18 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[0..16]);
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
            Some(SocketAddr::new(
                ip,
                u16::from_be_bytes([bytes[16], bytes[17]]),
            ))
        }
        _ => None,
    }
}

fn header_timestamp(header: &VsfHeader) -> Result<i64, String> {
    use vsf::types::EtType;
    match &header.creation_time {
        Some(VsfType::e(EtType::e6(v))) => Ok(*v),
        _ => Err("invalid header timestamp".to_string()),
    }
}

fn header_provenance(header: &VsfHeader) -> Result<[u8; 32], String> {
    match &header.provenance_hash {
        VsfType::hp(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            Ok(a)
        }
        _ => Err("invalid or missing header provenance hash".to_string()),
    }
}

fn header_pubkey(header: &VsfHeader) -> Result<DevicePubkey, String> {
    match header.signer_pubkey.as_ref() {
        Some(VsfType::ke(b)) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            Ok(a)
        }
        _ => Err("invalid or missing header signer pubkey".to_string()),
    }
}

fn header_signature(header: &VsfHeader) -> Result<[u8; 64], String> {
    match header.signature.as_ref() {
        Some(VsfType::ge(b)) if b.len() == 64 => {
            let mut a = [0u8; 64];
            a.copy_from_slice(b);
            Ok(a)
        }
        _ => Err("invalid or missing header signature".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from photon's FgtwMessage encoder BEFORE this module existed. These pin the
    // format that every deployed photon build is punching with right now.
    const GOLDEN_PROBE: &str = "52c3853c7a33097933096233b46c33b4653600000000000030396870331f09090909090909090909090909090909090909090909090909090909090909096b65331f07070707070707070707070707070707070707070707070707070707070707076765333f030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303036e33012864330570756e6368293e";
    const GOLDEN_ACK_V4: &str = "52c3853c7a33097933096233c46c33d9653600000000000030396870331f09090909090909090909090909090909090909090909090909090909090909096b65331f07070707070707070707070707070707070707070707070707070707070707076765333f030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303036e33012864330970756e63685f61636b3a6f33c42c6233152c6e3301293e5b286433036f62733a68623305cb007109111f295d";
    const GOLDEN_ACK_V6: &str = "52c3853c7a33097933096233c46c33e5653600000000000030396870331f09090909090909090909090909090909090909090909090909090909090909096b65331f07070707070707070707070707070707070707070707070707070707070707076765333f030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303036e33012864330970756e63685f61636b3a6f33c42c6233212c6e3301293e5b286433036f62733a6862331120010db8000000000000000000000001111f295d";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn probe() -> PunchMessage {
        PunchMessage::Probe {
            timestamp: 12345,
            sender_pubkey: [7u8; 32],
            provenance_hash: [9u8; 32],
            signature: [3u8; 64],
        }
    }

    fn ack(addr: &str) -> PunchMessage {
        PunchMessage::ProbeAck {
            timestamp: 12345,
            responder_pubkey: [7u8; 32],
            provenance_hash: [9u8; 32],
            signature: [3u8; 64],
            observed_addr: addr.parse().unwrap(),
        }
    }

    /// If this fails, deployed photon builds can no longer punch with this one. Fix the code,
    /// not the fixture.
    #[test]
    fn probe_matches_the_deployed_wire_format() {
        assert_eq!(hex(&probe().to_vsf_bytes().unwrap()), GOLDEN_PROBE);
    }

    #[test]
    fn ack_matches_the_deployed_wire_format() {
        assert_eq!(hex(&ack("203.0.113.9:4383").to_vsf_bytes().unwrap()), GOLDEN_ACK_V4);
        assert_eq!(hex(&ack("[2001:db8::1]:4383").to_vsf_bytes().unwrap()), GOLDEN_ACK_V6);
    }

    #[test]
    fn every_message_round_trips() {
        for m in [probe(), ack("203.0.113.9:4383"), ack("[2001:db8::1]:4383")] {
            let bytes = m.to_vsf_bytes().unwrap();
            assert_eq!(PunchMessage::from_vsf_bytes(&bytes).unwrap(), Some(m));
        }
    }

    #[test]
    fn a_probe_is_a_full_vsf_file() {
        assert!(probe().to_vsf_bytes().unwrap().starts_with(b"R\xC3\x85"));
    }

    /// A valid VSF file that isn't a punch message is not an error — photon shares one socket
    /// across several message families and must pass non-punch traffic to its own dispatch.
    #[test]
    fn a_foreign_section_decodes_to_none_rather_than_erroring() {
        let other = VsfBuilder::new()
            .creation_time_oscillations(1)
            .add_section("pong", vec![])
            .build()
            .unwrap();
        assert_eq!(PunchMessage::from_vsf_bytes(&other).unwrap(), None);
    }

    #[test]
    fn non_vsf_input_is_rejected() {
        assert!(PunchMessage::from_vsf_bytes(b"nope").is_err());
        assert!(PunchMessage::from_vsf_bytes(&[]).is_err());
    }

    #[test]
    fn socketaddr_bytes_round_trip_both_families() {
        for s in ["203.0.113.9:4383", "[2001:db8::1]:4383", "0.0.0.0:0"] {
            let a: SocketAddr = s.parse().unwrap();
            assert_eq!(bytes_to_socketaddr(&socketaddr_to_bytes(&a)), Some(a));
        }
        assert_eq!(socketaddr_to_bytes(&"1.2.3.4:80".parse().unwrap()).len(), 6);
        assert_eq!(socketaddr_to_bytes(&"[::1]:80".parse().unwrap()).len(), 18);
        assert_eq!(bytes_to_socketaddr(&[0u8; 7]), None);
    }
}
