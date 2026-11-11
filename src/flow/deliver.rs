//! Deliver one frame to every live member until each has it (owner 2026-11-10).
//! A send the app gave up on is handed again at that device's next Pong, or when a network comes up; nothing is resent on a timer.

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
}

impl Deliver {
    /// Start delivering `frame` to `targets`: one send each.
    pub fn new(frame: Vec<u8>, targets: &[Key], out: &mut Vec<Action>) -> Self {
        let mut d = Deliver { frame, targets: Vec::new() };
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

    /// A device that should have it, handed at the next [`Deliver::resume`], Pong or new network (a restart rebuilding the target list).
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

    /// `from` is reachable again: hand it the frame if its last send gave up.
    pub fn on_pong(&mut self, from: Key, out: &mut Vec<Action>) {
        if let Some((_, h)) = self.targets.iter_mut().find(|(k, _)| *k == from) {
            if *h == Hand::Again {
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
