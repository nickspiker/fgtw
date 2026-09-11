//! Candidate gathering — turning known addresses into a [`CandidateSet`].
//!
//! Two directions:
//! - [`gather_peer_candidates`] builds the set of addresses at which a *peer* might be
//!   reachable (where we send probes).
//! - [`gather_own_candidates`] builds the set of *our* addresses to advertise to a peer so
//!   they can punch back at us.
//!
//! The peer-side gather takes a plain [`PeerEndpoint`] slice rather than any caller's contact type. Photon's `Contact` and rustdesk's phonebook `Record` both flatten into that, so neither shape leaks in here — photon's two former entry points differed only in whether a peer's LAN address had to share our `/24`, which is now the explicit [`LanPolicy`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::candidate::{Candidate, CandidateKind, CandidateSet};

/// True for a LAN IPv4 worth trying at all — excludes loopback, link-local, the unspecified address, and the `192.0.0.0/24` service-continuity block (the 464XLAT CLAT address, which is never a reachable peer LAN address).
pub fn is_usable_lan_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let is_service_continuity = o[0] == 192 && o[1] == 0 && o[2] == 0; // 192.0.0.0/24
    !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() && !is_service_continuity
}

/// True for the RFC 1918 private ranges (10/8, 172.16/12, 192.168/16) — the addresses only reachable on a shared LAN. Decides whether a peer's v4 candidate is a routable public address (send freely) or a private one only worth trying on the SAME subnet (see
/// [`is_foreign_peer_lan`]).
pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

/// Classify a peer public address: a v6 public address is a direct host (no NAT rewriting v6,
/// so no punch needed); a v4 public address is reached by hole-punch → reflexive-class.
pub fn public_kind(addr: &SocketAddr) -> CandidateKind {
    if addr.is_ipv6() {
        CandidateKind::HostV6
    } else {
        CandidateKind::Reflexive
    }
}

/// True for an address that must NEVER enter the candidate set: the unspecified `0.0.0.0` /
/// `::`, which is the relay sentinel a relayed message carries. If it leaks in, the punch
/// "validates" a path to `0.0.0.0` (it round-trips locally), which then poisons all addressing: sends go nowhere while the path looks `Some`.
pub fn is_bogus_addr(addr: &SocketAddr) -> bool {
    addr.ip().is_unspecified()
}

/// The Wi-Fi Direct group subnet Android's group owner always uses (192.168.49.0/24).
pub fn is_wfd_subnet(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 192 && o[1] == 168 && o[2] == 49
}

/// Would a peer's private IPv4 plausibly be reachable from us, given OUR own LAN v4?
///
/// A peer's private address is only reachable when we share its subnet — otherwise it is a
/// FOREIGN LAN address that we would retransmit into a black hole, wasting the direct-path budget and masking that the relay is the real path. This is common in practice because default home routers all hand out the same `192.168.0.*` block, so two unrelated peers routinely carry colliding-but-unreachable private addresses.
///
/// "Same subnet" is approximated as a shared `/24` — the common home-LAN mask. A wider real mask only makes us slightly conservative (fall back to public/relay), never sending to an unreachable address. With no known LAN of our own we can't vouch for any peer LAN.
pub fn peer_lan_reachable(peer_v4: Ipv4Addr, our_v4: Option<Ipv4Addr>) -> bool {
    match our_v4 {
        Some(ours) => {
            let (a, b) = (peer_v4.octets(), ours.octets());
            a[0] == b[0] && a[1] == b[1] && a[2] == b[2]
        }
        None => false,
    }
}

/// True if `peer` is a private IPv4 NOT on our `/24` (a foreign LAN we can't reach) — the exact address a caller holding our-LAN should refuse to send to directly. A public/global v4 is never foreign.
pub fn is_foreign_peer_lan(peer: &SocketAddr, our_v4: Option<Ipv4Addr>) -> bool {
    match peer.ip() {
        // The reserved Wi-Fi Direct subnet: an address here only enters state via a live group-up (cleared at teardown), so it is vouched by group membership rather than by sharing our infra /24. Punch validation still gates actual path adoption.
        IpAddr::V4(v4) if is_wfd_subnet(v4) => false,
        IpAddr::V4(v4) if is_private_ipv4(v4) => !peer_lan_reachable(v4, our_v4),
        _ => false,
    }
}

/// How strictly to admit a peer's LAN address as a candidate.
#[derive(Debug, Clone, Copy)]
pub enum LanPolicy {
    /// Keep any usable LAN v4, without checking whether it is on our subnet. The right choice when the caller has no our-LAN context; a foreign address merely fails to validate.
    AnyUsable,
    /// Keep a peer LAN v4 only when it shares our `/24`. The right choice wherever the caller does know our LAN, so we never burn the direct-path budget on a black hole.
    SameSubnetAs(Option<Ipv4Addr>),
}

impl LanPolicy {
    fn admits(&self, v4: Ipv4Addr) -> bool {
        if !is_usable_lan_ipv4(v4) {
            return false;
        }
        match self {
            LanPolicy::AnyUsable => true,
            LanPolicy::SameSubnetAs(our_v4) => peer_lan_reachable(v4, *our_v4),
        }
    }
}

/// One place a peer might be reachable, as the directory knows it. Callers flatten their own contact/record type into these.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerEndpoint {
    /// The peer's public/reflexive address (v4 punched, or a v6 host).
    pub public: Option<SocketAddr>,
    /// The peer's LAN address, for same-subnet reach.
    pub lan: Option<SocketAddr>,
}

/// The addresses at which a peer might be reachable — the set we punch toward, and (via
/// [`CandidateSet::best_pair`]) the send order.
///
/// Scanning every endpoint rather than just the active one is what surfaces a peer's global
/// IPv6 when its active address happens to be v4 — so the v6 host, priority-first, is tried before a v4 LAN address that may be on a foreign network.
///
/// `p2p` is a live Wi-Fi Direct group address: group membership vouches reachability, so it bypasses the LAN policy entirely.
pub fn gather_peer_candidates(
    endpoints: &[PeerEndpoint],
    p2p: Option<SocketAddr>,
    policy: LanPolicy,
) -> CandidateSet {
    let mut set = CandidateSet::new();

    for ep in endpoints {
        if let Some(pub_addr) = ep.public {
            if !is_bogus_addr(&pub_addr) {
                // A PRIVATE v4 in the public slot is a LAN address whatever column it arrived in — a device that learned its reflexive from a same-LAN observer publishes exactly this (field 2026-09-11: a phone on cellular aimed a wave at 192.168.1.163 because it sat in the peer's PUBLIC field). It joins only under the LAN policy, never as a public candidate.
                match pub_addr.ip() {
                    IpAddr::V4(v4) if is_private_ipv4(v4) => {
                        if policy.admits(v4) {
                            set.add(Candidate::new(pub_addr, CandidateKind::HostV4Lan));
                        }
                    }
                    _ => set.add(Candidate::new(pub_addr, public_kind(&pub_addr))),
                }
            }
        }
        if let Some(lan_addr) = ep.lan {
            if let IpAddr::V4(v4) = lan_addr.ip() {
                if policy.admits(v4) {
                    set.add(Candidate::new(lan_addr, CandidateKind::HostV4Lan));
                }
            }
        }
    }

    if let Some(p2p) = p2p {
        if !is_bogus_addr(&p2p) {
            set.add(Candidate::new(p2p, CandidateKind::HostV4P2p));
        }
    }

    set
}

/// Our own addresses to advertise so a peer can punch back at us: our learned reflexive address (public, from peer-echoed reflection) and our LAN address on the port we listen on.
pub fn gather_own_candidates(
    our_reflexive: Option<SocketAddr>,
    local_v4: Option<Ipv4Addr>,
    port: u16,
) -> CandidateSet {
    let mut set = CandidateSet::new();

    if let Some(refl) = our_reflexive {
        let kind = if refl.is_ipv6() {
            CandidateKind::HostV6
        } else {
            CandidateKind::Reflexive
        };
        set.add(Candidate::new(refl, kind));
    }

    if let Some(v4) = local_v4 {
        if is_usable_lan_ipv4(v4) {
            set.add(Candidate::new(
                SocketAddr::new(IpAddr::V4(v4), port),
                CandidateKind::HostV4Lan,
            ));
        }
    }

    set
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }
    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn the_relay_sentinel_never_becomes_a_candidate() {
        assert!(is_bogus_addr(&a("0.0.0.0:0")));
        assert!(is_bogus_addr(&a("[::]:4383")));
        assert!(!is_bogus_addr(&a("203.0.113.7:4383")));

        let set = gather_peer_candidates(
            &[PeerEndpoint {
                public: Some(a("0.0.0.0:0")),
                lan: None,
            }],
            None,
            LanPolicy::AnyUsable,
        );
        assert!(set.is_empty(), "sentinel must not enter the candidate set");
    }

    #[test]
    fn the_clat_service_continuity_block_is_not_a_usable_lan() {
        assert!(!is_usable_lan_ipv4(v4("192.0.0.4")));
        assert!(!is_usable_lan_ipv4(v4("127.0.0.1")));
        assert!(!is_usable_lan_ipv4(v4("169.254.1.1")));
        assert!(is_usable_lan_ipv4(v4("192.168.1.2")));
    }

    #[test]
    fn private_ranges_are_classified_per_rfc1918() {
        assert!(is_private_ipv4(v4("10.0.0.1")));
        assert!(is_private_ipv4(v4("172.16.0.1")));
        assert!(is_private_ipv4(v4("172.31.255.254")));
        assert!(!is_private_ipv4(v4("172.32.0.1")));
        assert!(is_private_ipv4(v4("192.168.1.1")));
        assert!(!is_private_ipv4(v4("203.0.113.7")));
    }

    #[test]
    fn a_peer_lan_is_reachable_only_on_our_own_slash24() {
        assert!(peer_lan_reachable(v4("192.168.1.5"), Some(v4("192.168.1.9"))));
        assert!(!peer_lan_reachable(
            v4("192.168.2.5"),
            Some(v4("192.168.1.9"))
        ));
        // Unknown own-LAN can vouch for nothing.
        assert!(!peer_lan_reachable(v4("192.168.1.5"), None));
    }

    #[test]
    fn a_colliding_but_foreign_home_subnet_is_refused() {
        // The common real-world failure: two unrelated peers both on 192.168.0.*.
        assert!(is_foreign_peer_lan(
            &a("192.168.0.5:4383"),
            Some(v4("192.168.1.9"))
        ));
        assert!(!is_foreign_peer_lan(
            &a("192.168.1.5:4383"),
            Some(v4("192.168.1.9"))
        ));
        // A public address is never foreign.
        assert!(!is_foreign_peer_lan(
            &a("203.0.113.7:4383"),
            Some(v4("192.168.1.9"))
        ));
        // Wi-Fi Direct is vouched by group membership, not by subnet.
        assert!(!is_foreign_peer_lan(&a("192.168.49.5:4383"), None));
    }

    #[test]
    fn lan_policy_is_the_only_difference_between_the_two_gathers() {
        let eps = [PeerEndpoint {
            public: Some(a("203.0.113.7:4383")),
            lan: Some(a("192.168.9.5:4383")),
        }];

        // Subnet-agnostic: the foreign LAN address is kept.
        let loose = gather_peer_candidates(&eps, None, LanPolicy::AnyUsable);
        assert_eq!(loose.sorted().len(), 2);

        // Subnet-gated against a different /24: the LAN address is dropped.
        let strict =
            gather_peer_candidates(&eps, None, LanPolicy::SameSubnetAs(Some(v4("192.168.1.9"))));
        assert_eq!(strict.sorted().len(), 1);
        assert_eq!(strict.sorted()[0].kind, CandidateKind::Reflexive);

        // Subnet-gated against the matching /24: kept, and it outranks the public address.
        let same =
            gather_peer_candidates(&eps, None, LanPolicy::SameSubnetAs(Some(v4("192.168.9.9"))));
        assert_eq!(same.best_pair().unwrap().0, a("192.168.9.5:4383"));
    }

    #[test]
    fn a_v6_endpoint_outranks_a_v4_lan_even_when_listed_later() {
        let eps = [
            PeerEndpoint {
                public: None,
                lan: Some(a("192.168.1.5:4383")),
            },
            PeerEndpoint {
                public: Some(a("[2001:db8::1]:4383")),
                lan: None,
            },
        ];
        let set = gather_peer_candidates(&eps, None, LanPolicy::SameSubnetAs(Some(v4("192.168.1.9"))));
        assert_eq!(set.best_pair().unwrap().0, a("[2001:db8::1]:4383"));
    }

    #[test]
    fn our_own_candidates_advertise_reflexive_and_lan() {
        let set = gather_own_candidates(Some(a("203.0.113.7:4383")), Some(v4("192.168.1.9")), 4383);
        let addrs: Vec<_> = set.sorted().iter().map(|c| c.addr).collect();
        assert!(addrs.contains(&a("203.0.113.7:4383")));
        assert!(addrs.contains(&a("192.168.1.9:4383")));
    }

    #[test]
    fn our_own_candidates_skip_an_unusable_lan() {
        let set = gather_own_candidates(None, Some(v4("192.0.0.4")), 4383);
        assert!(set.is_empty());
    }
}

/// How a direct path reaches a peer, best first. One ladder shared by every app in the fleet,
/// so a colour means the same thing in photon's presence ring and rustdesk's fleet tile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathTier {
    /// No router at all: a Wi-Fi Direct group or a link-local pair. Nothing in the middle.
    NoRouter,
    /// A local network — reachable without any internet, on the building's own wiring.
    Lan,
    /// Direct across the internet, e.g. a punched path.
    Wan,
    /// Frames ride the seed's pipe; every one pays a WAN round trip.
    Relay,
}

/// Classify a validated direct path to `peer`, given our own LAN v4.
///
/// The same-subnet check is the whole point and cannot be skipped: judging "local" from the address SHAPE calls every RFC-1918 address same-room, and carrier CGNAT hands cellular devices 10.x — so a carrier-internal path to a peer hundreds of miles away rings LAN (photon field bug, 2026-08-30). Private-but-foreign is a real direct path, but it is WAN.
pub fn classify_path(peer: &SocketAddr, our_v4: Option<Ipv4Addr>) -> PathTier {
    match peer.ip() {
        IpAddr::V4(v4) => {
            // The reserved Wi-Fi Direct subnet is vouched by group membership, not by sharing our infra /24 — and CGNAT never hands it out, so the shape check is safe here.
            if is_wfd_subnet(v4) || v4.is_link_local() {
                PathTier::NoRouter
            } else if is_private_ipv4(v4) && peer_lan_reachable(v4, our_v4) {
                PathTier::Lan
            } else {
                PathTier::Wan
            }
        }
        IpAddr::V6(v6) => {
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                PathTier::NoRouter // link-local: no router ever assigned this
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                PathTier::Lan // ULA — site-local by construction
            } else {
                PathTier::Wan
            }
        }
    }
}

#[cfg(test)]
mod tier_tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }
    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn wfd_and_link_local_are_router_free() {
        assert_eq!(classify_path(&sa("192.168.49.1:4383"), None), PathTier::NoRouter);
        assert_eq!(classify_path(&sa("169.254.3.4:4383"), None), PathTier::NoRouter);
    }

    #[test]
    fn private_on_our_subnet_is_lan() {
        let ours = Some(v4("192.168.1.161"));
        assert_eq!(classify_path(&sa("192.168.1.156:21118"), ours), PathTier::Lan);
    }

    /// The 2026-08-30 field bug: carrier CGNAT hands out 10.x, so a private address off our own subnet is a real direct path but emphatically not "same room".
    #[test]
    fn private_but_foreign_is_wan_not_lan() {
        let ours = Some(v4("192.168.1.161"));
        assert_eq!(classify_path(&sa("10.172.215.102:4383"), ours), PathTier::Wan);
    }

    #[test]
    fn without_our_lan_no_private_address_can_claim_same_room() {
        assert_eq!(classify_path(&sa("192.168.1.156:21118"), None), PathTier::Wan);
    }

    #[test]
    fn public_is_wan() {
        let ours = Some(v4("192.168.1.161"));
        assert_eq!(classify_path(&sa("203.0.113.7:4383"), ours), PathTier::Wan);
    }

    #[test]
    fn a_better_tier_sorts_first() {
        let mut v = vec![PathTier::Relay, PathTier::Wan, PathTier::NoRouter, PathTier::Lan];
        v.sort();
        assert_eq!(v[0], PathTier::NoRouter);
        assert_eq!(v[3], PathTier::Relay);
    }
}

#[cfg(test)]
mod public_slot_tests {
    use super::*;

    fn ep(public: &str) -> PeerEndpoint {
        PeerEndpoint { public: Some(public.parse().unwrap()), lan: None }
    }

    /// A private v4 published as a "public" address is a LAN address in disguise: gated by the LAN policy like any other.
    #[test]
    fn a_private_v4_in_the_public_slot_obeys_the_lan_policy() {
        let none = gather_peer_candidates(&[ep("192.168.1.163:4383")], None, LanPolicy::SameSubnetAs(None));
        assert!(none.sorted().is_empty(), "off-LAN (our address unknown) it is no route at all");
        let foreign = gather_peer_candidates(&[ep("192.168.1.163:4383")], None, LanPolicy::SameSubnetAs(Some("100.91.131.105".parse().unwrap())));
        assert!(foreign.sorted().is_empty(), "a carrier-NAT phone cannot reach a home LAN");
        let same = gather_peer_candidates(&[ep("192.168.1.163:4383")], None, LanPolicy::SameSubnetAs(Some("192.168.1.161".parse().unwrap())));
        let got = same.sorted();
        assert_eq!(got.len(), 1);
        assert!(matches!(got[0].kind, CandidateKind::HostV4Lan), "on the same /24 it is a LAN candidate, never a public one");
        let public = gather_peer_candidates(&[ep("97.186.10.184:4383")], None, LanPolicy::SameSubnetAs(None));
        assert_eq!(public.sorted().len(), 1, "a real public address is untouched by the policy");
    }
}
