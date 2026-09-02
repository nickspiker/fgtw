//! Connection candidates and their priority ordering.
//!
//! A candidate is one address at which a peer might be reachable. Traversal gathers a set per peer (their LAN address, their reflexive/public address, an IPv6 host address) and punches toward all of them; the first to round-trip wins. Priority orders which we *prefer* when several validate, and lets [`CandidateSet::best_pair`] reproduce the exact `(primary, alt)` shape `Contact::race_addrs` returns today, so the transport contract downstream is unchanged.
//!
//! Ordering, best first:
//! 1. **Global IPv6 host** — no NAT in the path at all, so it needs no hole-punch; just works when both ends have v6.
//! 2. **IPv6 reflexive** — v6 seen from outside (rare; behind a v6 firewall).
//! 3. **IPv4 LAN host** — same-subnet / hairpin: avoids the router's often-broken hairpin and AP isolation.
//! 4. **IPv4 reflexive** — the punched-thru public v4 address; the common WAN path.

use std::net::SocketAddr;

/// What kind of address a candidate is — determines its priority and how it was learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    /// A global (routable, non-ULA, non-link-local) IPv6 address — reachable directly, no NAT.
    HostV6,
    /// A usable IPv4 LAN address (a peer's `local_ip`) — for same-subnet / hairpin reach.
    HostV4Lan,
    /// A Wi-Fi Direct group address (192.168.49.x) — group membership vouches reachability, so it skips the foreign-LAN `/24` gate; below LAN (infra WiFi is cheaper) but above the punched WAN path when we're stranded.
    HostV4P2p,
    /// A reflexive address (our own learned public address, or a peer's public address from the phonebook) — reached by hole-punch.
    Reflexive,
}

/// One candidate address plus its kind and computed priority (higher = more preferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    pub addr: SocketAddr,
    pub kind: CandidateKind,
    pub priority: u32,
}

impl Candidate {
    pub fn new(addr: SocketAddr, kind: CandidateKind) -> Self {
        Self {
            addr,
            kind,
            priority: priority(kind, &addr),
        }
    }
}

/// Priority of a candidate (higher = tried/preferred first). See the module ordering.
pub fn priority(kind: CandidateKind, addr: &SocketAddr) -> u32 {
    match kind {
        CandidateKind::HostV6 => 100,
        CandidateKind::Reflexive if addr.is_ipv6() => 80,
        CandidateKind::HostV4Lan => 60,
        CandidateKind::HostV4P2p => 50,
        CandidateKind::Reflexive => 40, // v4 reflexive
    }
}

/// A peer's gathered candidate addresses, deduplicated and priority-sorted.
#[derive(Debug, Clone, Default)]
pub struct CandidateSet {
    candidates: Vec<Candidate>,
}

impl CandidateSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a candidate, ignoring exact-address duplicates (keeping the higher-priority kind on collision).
    pub fn add(&mut self, c: Candidate) {
        if let Some(existing) = self.candidates.iter_mut().find(|e| e.addr == c.addr) {
            if c.priority > existing.priority {
                *existing = c;
            }
            return;
        }
        self.candidates.push(c);
    }

    /// All candidates, sorted by priority (best first).
    pub fn sorted(&self) -> Vec<Candidate> {
        let mut v = self.candidates.clone();
        v.sort_by(|a, b| b.priority.cmp(&a.priority));
        v
    }

    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// The `(primary, alternate)` pair for the transport, matching `Contact::race_addrs`'s contract: primary = highest-priority candidate, alternate = next distinct-address candidate (or `None`). PT races both and locks onto whichever ACKs first. This drives the actual send order via `race_addrs` — a global IPv6 host outranks everything (no NAT, no punch), then IPv6 reflexive, then IPv4 LAN, then IPv4 reflexive — so v6 is tried first whenever both ends have it.
    pub fn best_pair(&self) -> Option<(SocketAddr, Option<SocketAddr>)> {
        let sorted = self.sorted();
        let primary = sorted.first()?.addr;
        let alt = sorted.iter().map(|c| c.addr).find(|a| *a != primary);
        Some((primary, alt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv6_host_outranks_everything() {
        assert!(
            priority(CandidateKind::HostV6, &a("[2001:db8::1]:4383"))
                > priority(CandidateKind::HostV4Lan, &a("192.168.1.2:4383"))
        );
        assert!(
            priority(CandidateKind::HostV4Lan, &a("192.168.1.2:4383"))
                > priority(CandidateKind::Reflexive, &a("203.0.113.7:4383"))
        );
    }

    #[test]
    fn lan_is_primary_public_is_alt_matching_race_addrs() {
        // The current race_addrs behaviour: LAN primary, public alternate.
        let mut set = CandidateSet::new();
        set.add(Candidate::new(
            a("203.0.113.7:4383"),
            CandidateKind::Reflexive,
        ));
        set.add(Candidate::new(
            a("192.168.1.2:4383"),
            CandidateKind::HostV4Lan,
        ));
        assert_eq!(
            set.best_pair(),
            Some((a("192.168.1.2:4383"), Some(a("203.0.113.7:4383"))))
        );
    }

    #[test]
    fn public_only_has_no_alternate() {
        let mut set = CandidateSet::new();
        set.add(Candidate::new(
            a("203.0.113.7:4383"),
            CandidateKind::Reflexive,
        ));
        assert_eq!(set.best_pair(), Some((a("203.0.113.7:4383"), None)));
    }

    #[test]
    fn ipv6_host_wins_when_present() {
        let mut set = CandidateSet::new();
        set.add(Candidate::new(
            a("192.168.1.2:4383"),
            CandidateKind::HostV4Lan,
        ));
        set.add(Candidate::new(
            a("203.0.113.7:4383"),
            CandidateKind::Reflexive,
        ));
        set.add(Candidate::new(
            a("[2001:db8::1]:4383"),
            CandidateKind::HostV6,
        ));
        let (primary, _) = set.best_pair().unwrap();
        assert_eq!(primary, a("[2001:db8::1]:4383"));
    }

    #[test]
    fn duplicate_address_keeps_higher_priority_kind() {
        let mut set = CandidateSet::new();
        set.add(Candidate::new(
            a("203.0.113.7:4383"),
            CandidateKind::Reflexive,
        ));
        set.add(Candidate::new(a("203.0.113.7:4383"), CandidateKind::HostV6)); // same addr, higher kind
        assert_eq!(set.sorted().len(), 1);
        assert_eq!(set.sorted()[0].kind, CandidateKind::HostV6);
    }

    #[test]
    fn p2p_sits_between_lan_and_v4_reflexive() {
        let p2p = priority(CandidateKind::HostV4P2p, &a("192.168.49.5:4383"));
        assert!(priority(CandidateKind::HostV4Lan, &a("192.168.1.2:4383")) > p2p);
        assert!(p2p > priority(CandidateKind::Reflexive, &a("203.0.113.7:4383")));
    }

    #[test]
    fn empty_set_has_no_pair() {
        assert_eq!(CandidateSet::new().best_pair(), None);
    }
}
