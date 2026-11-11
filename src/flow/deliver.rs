//! Deliver one frame to every live member until each has it (owner 2026-11-10).
//! A device that has not taken it is handed it again each time it shows it is reachable (a Pong, its beacon, a frame from it) or a network comes up; nothing is resent on a timer.
//! A member never reached at all (no Sent comes back for it, or none maps to its key) is covered the same way: its first beacon or Pong hands it the frame.

use alloc::vec::Vec;

use super::{Action, Key, To};

/// How far one target has got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hand {
    /// Handed to the app; no word back yet.
    Out,
    /// It arrived.
    Took,
    /// The app gave up; hand it again at the next chance.
    Again,
}

/// One frame on its way to a set of devices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deliver {
    frame: Vec<u8>,
    targets: Vec<(Key, Hand)>,
    /// The app reports every send's outcome ([`super::Event::Sent`]): a send with no word back is in flight, not lost. An app that reports none (Photon today) has each reachable edge hand it again.
    reports_sent: bool,
}

impl Deliver {
    /// Start delivering `frame` to `targets`: one send each.
    pub fn new(frame: Vec<u8>, targets: &[Key], reports_sent: bool, out: &mut Vec<Action>) -> Self {
        let mut d = Deliver { frame, targets: Vec::new(), reports_sent };
        for k in targets {
            d.add(*k, out);
        }
        d
    }

    /// A device that should have it too (a member that joined while this was under way).
    pub fn add(&mut self, k: Key, out: &mut Vec<Action>) {
        if self.targets.iter().any(|(t, _)| *t == k) {
            return;
        }
        self.targets.push((k, Hand::Out));
        out.push(Action::Send { to: To::Device(k), frame: self.frame.clone() });
    }

    /// A device that should have it, handed at the next [`Deliver::resume`], reachable edge or new network (a restart rebuilding the target list).
    pub fn owe(&mut self, k: Key) {
        if !self.targets.iter().any(|(t, _)| *t == k) {
            self.targets.push((k, Hand::Again));
        }
    }

    /// Keep only targets still in `live` (a member that left or was locked needs nothing).
    pub fn retain(&mut self, live: &[Key]) {
        self.targets.retain(|(k, _)| live.contains(k));
    }

    /// The app's word on a send.
    pub fn on_sent(&mut self, to: Key, ok: bool) {
        if let Some((_, h)) = self.targets.iter_mut().find(|(k, _)| *k == to) {
            if *h != Hand::Took {
                *h = if ok { Hand::Took } else { Hand::Again };
            }
        }
    }

    /// `from` answered the frame itself (a deny, an approval): it has it.
    pub fn answered(&mut self, from: Key) {
        if let Some((_, h)) = self.targets.iter_mut().find(|(k, _)| *k == from) {
            *h = Hand::Took;
        }
    }

    /// `from` showed it is reachable: hand it the frame if its send gave up or it was never handed it; a send still in flight is not sent again (ferros 2026-11-10: a beacon every 3 s would start a duplicate transfer each time). Where the app reports no send outcomes, a send with no word back is handed again.
    pub fn on_reachable(&mut self, from: Key, out: &mut Vec<Action>) {
        let again_in_flight = !self.reports_sent;
        if let Some((_, h)) = self.targets.iter_mut().find(|(k, _)| *k == from) {
            if *h == Hand::Again || (*h == Hand::Out && again_in_flight) {
                *h = Hand::Out;
                out.push(Action::Send { to: To::Device(from), frame: self.frame.clone() });
            }
        }
    }

    /// A network came up: hand it again to every device whose send gave up.
    pub fn on_link_up(&mut self, out: &mut Vec<Action>) {
        for (k, h) in self.targets.iter_mut() {
            if *h == Hand::Again {
                *h = Hand::Out;
                out.push(Action::Send { to: To::Device(*k), frame: self.frame.clone() });
            }
        }
    }

    /// Every target has it.
    pub fn done(&self) -> bool {
        self.targets.iter().all(|(_, h)| *h == Hand::Took)
    }

    /// After a restart nothing is known about the sends: hand it to every target that has not taken it.
    pub fn resume(&mut self, out: &mut Vec<Action>) {
        for (k, h) in self.targets.iter_mut() {
            if *h != Hand::Took {
                *h = Hand::Out;
                out.push(Action::Send { to: To::Device(*k), frame: self.frame.clone() });
            }
        }
    }

    /// The frame being delivered.
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }
}
