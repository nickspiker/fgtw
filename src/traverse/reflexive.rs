//! Reflexive (public) address discovery — the peer-echoed STUN primitive.
//!
//! A node cannot see its own public address directly: NAT rewrites the source of every outbound datagram.
//! It learns that address by asking another node "what source did you see me at?" — and that answer, echoed on the *same UDP socket the data flows over*, is the correct reflexive address (unlike fgtw.org's `cf-connecting-ip`, which reflects the TLS flow and is thus only right for cone NATs).
//!
//! Two channels feed this: a friend's signed pong (`observed_addr`, trusted — the pong is contact-gated, so it comes from someone in our fleet/contacts) and an open `ReflectResponse` from any directory-serving node (untrusted — corroborated by quorum before adoption, so a single lying peer can't poison the address we then publish). See the traversal plan, P0.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

/// Distinct untrusted sources that must agree on an address before we adopt it.
/// Trusted sources (a contact's pong, or the bootstrap seed) bypass this.
const QUORUM: usize = 2;

/// This node's own reflexive address, per family, with a quorum buffer for untrusted claims.
///
/// Separate v4/v6 slots because a dual-stack node has both and learning one must not clobber the other.
/// The adopted address feeds `PhotonApp.our_reflexive`, which candidate gathering and the FGTW announce consume.
#[derive(Default)]
pub struct ReflexiveState {
    v4: Option<SocketAddr>,
    v6: Option<SocketAddr>,
    /// Untrusted observations awaiting corroboration: address → distinct source device pubkeys.
    votes: HashMap<SocketAddr, HashSet<[u8; 32]>>,
}

impl ReflexiveState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a signed reflexive observation of `observed`, echoed by device `from`.
    ///
    /// `trusted` = the observation came from a contact's pong or the bootstrap seed → adopt immediately.
    /// Otherwise the address must be seen from [`QUORUM`] distinct sources before adoption (anti-poison).
    ///
    /// Returns `Some(addr)` when this observation *changed* the adopted address for its family (the caller should then update `PhotonApp.our_reflexive` and re-announce), else `None`.
    pub fn record(
        &mut self,
        observed: SocketAddr,
        from: [u8; 32],
        trusted: bool,
    ) -> Option<SocketAddr> {
        // A pong that arrived over the RELAY carries the `RELAY_ADDR` sentinel (0.0.0.0:0) as its observed address -- the pipe has no peer address to report. Adopting that as OUR reflexive address is actively harmful: it is what `publish_self_peer_record` signs, so the mesh gets handed a record saying we are unreachable, and the seed-from-ack fallback then declines to correct it because a value is technically present. Observed live: a first-ever published record carrying 0.0.0.0:0 while the FGTW ack was reporting a perfectly good v6 address.
        //
        // The inbound-DATA path already refuses the sentinel for the same reason (see photon_app's "storing the sentinel as contact.ip would poison direct sends"); this is the missing half.
        if super::gather::is_bogus_addr(&observed) {
            return None;
        }
        let adopt = if trusted {
            true
        } else {
            let voters = self.votes.entry(observed).or_default();
            voters.insert(from);
            voters.len() >= QUORUM
        };
        if !adopt {
            return None;
        }

        let slot = if observed.is_ipv4() {
            &mut self.v4
        } else {
            &mut self.v6
        };
        if *slot == Some(observed) {
            return None; // already adopted — no change, no re-announce
        }
        *slot = Some(observed);
        // Clear this address's pending votes; leave others (a different pending address may still be racing).
        self.votes.remove(&observed);
        Some(observed)
    }

    pub fn v4(&self) -> Option<SocketAddr> {
        self.v4
    }

    pub fn v6(&self) -> Option<SocketAddr> {
        self.v6
    }

    /// This node's adopted public IP (prefers v4, falls back to v6). Currently informational; kept for candidate gathering and any future same-NAT/hairpin use (the old `Contact::best_addr` path was dead and removed — `race_addrs` already covers same-NAT by racing the LAN candidate).
    pub fn public_ip(&self) -> Option<IpAddr> {
        self.v4.map(|a| a.ip()).or_else(|| self.v6.map(|a| a.ip()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn trusted_source_adopts_immediately() {
        let mut r = ReflexiveState::new();
        assert_eq!(
            r.record(v4("1.2.3.4:4383"), [1u8; 32], true),
            Some(v4("1.2.3.4:4383"))
        );
        assert_eq!(r.v4(), Some(v4("1.2.3.4:4383")));
    }

    #[test]
    fn untrusted_needs_quorum() {
        let mut r = ReflexiveState::new();
        // First untrusted claim: no adoption yet.
        assert_eq!(r.record(v4("1.2.3.4:4383"), [1u8; 32], false), None);
        assert_eq!(r.v4(), None);
        // Same address, a second distinct source → quorum reached, adopted.
        assert_eq!(
            r.record(v4("1.2.3.4:4383"), [2u8; 32], false),
            Some(v4("1.2.3.4:4383"))
        );
        assert_eq!(r.v4(), Some(v4("1.2.3.4:4383")));
    }

    #[test]
    fn same_source_twice_does_not_reach_quorum() {
        let mut r = ReflexiveState::new();
        assert_eq!(r.record(v4("1.2.3.4:4383"), [1u8; 32], false), None);
        assert_eq!(r.record(v4("1.2.3.4:4383"), [1u8; 32], false), None); // duplicate voter
        assert_eq!(r.v4(), None);
    }

    #[test]
    fn re_adopting_same_address_reports_no_change() {
        let mut r = ReflexiveState::new();
        assert_eq!(
            r.record(v4("1.2.3.4:4383"), [1u8; 32], true),
            Some(v4("1.2.3.4:4383"))
        );
        assert_eq!(r.record(v4("1.2.3.4:4383"), [9u8; 32], true), None); // unchanged
    }

    #[test]
    fn v4_and_v6_do_not_clobber() {
        let mut r = ReflexiveState::new();
        let v6a: SocketAddr = "[2001:db8::1]:4383".parse().unwrap();
        r.record(v4("1.2.3.4:4383"), [1u8; 32], true);
        r.record(v6a, [1u8; 32], true);
        assert_eq!(r.v4(), Some(v4("1.2.3.4:4383")));
        assert_eq!(r.v6(), Some(v6a));
    }

    /// The RELAY sentinel must never become our reflexive address.
    ///
    /// A pong injected off the relay pipe reports `0.0.0.0:0` -- the pipe has no peer address to give. That used to be adopted verbatim and then SIGNED into our published peer record, telling the whole mesh we were unreachable. Worse, it was sticky: the seed-from-ack fallback only fills when nothing is present, so a garbage value blocked the good address FGTW was reporting all along.
    #[test]
    fn the_relay_sentinel_is_never_adopted_as_our_address() {
        let mut r = ReflexiveState::new();
        let sentinel: SocketAddr = "0.0.0.0:0".parse().unwrap();

        // Even "trusted" (a signature-verified friend's pong) must not get the sentinel through.
        assert_eq!(
            r.record(sentinel, [1u8; 32], true),
            None,
            "sentinel refused even from a trusted echo"
        );
        assert_eq!(r.v4(), None, "nothing adopted");

        // A real address still works, and is not blocked by the refused one.
        let real: SocketAddr = "203.0.113.9:4383".parse().unwrap();
        assert_eq!(
            r.record(real, [1u8; 32], true),
            Some(real),
            "a genuine address still adopts"
        );
        assert_eq!(r.v4(), Some(real));
    }
}
