//! Joining a fleet, the new device's side (FLOWS.md stage 4; the owner's rules of 2026-11-22), written once for every app.
//! The person types the handle once and taps attest; the app runs the memory-hard proof and the look-up (a question that rings nobody) and tells the machine what it found ([`Event::Looked`]).
//! Only when the identity has a fleet and this device is unbound does the machine ask "are you sure?", and only the person's yes ([`UserOp::Confirm`]) lets anything out: before it no binding request is minted, nothing is handed to a fleet device, no tap secret is served, no BLE beacon is aired, no LAN beacon goes out under the handle, no words are shown and fgtw.org is not posted to.
//! After the yes the request goes to the person's devices first: a beacon on this network (each fleet device that answers is handed the request), NFC and BLE.
//! fgtw.org's registry is the last rung: it gets the request only on the edge "no fleet device heard on this network" ([`UNHEARD_OSC`] after the yes), or at once when the person asks for the words ([`UserOp::ShowWords`], "Not in range?").
//! The words are shown only behind that press (shoulder surfing).
//! The machine keeps no state on disk: it holds the identity seed (a root), so a restart asks the question again.
//! Its acts are its own enum ([`Do`]), not the members' [`super::Action`]: a joiner is not a member yet, and what it does (mint, beacon, post to the registry) is nothing a member does.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::{Event, Key, UserOp, Wake};
use crate::fleet::BINDREQ_FRESH_OSC;

/// One second in Eagle oscillations.
const OSC: i64 = vsf::OSCILLATIONS_PER_SECOND as i64;

/// How long after the yes the joiner listens for a fleet device on this network before fgtw.org's registry gets the request: 4¼ s.
/// WHY this wait: "no fleet device heard" is an edge only silence can mark, and silence needs a window.
/// A Photon fleet device answers the joiner's beacon at once (a LAN round trip, milliseconds), and a ferros one beacons every 3 s on its own, so a window past one ferros beacon period with a second of margin hears every fleet device on this network; ferros's identity service waits 2^22 µs (about 4.2 s) for the same reason.
/// It is one deadline, taken once per yes, never a poll.
pub const UNHEARD_OSC: i64 = (OSC << 2) + (OSC >> 2);

/// When a minted binding request is minted again: three quarters into its freshness ([`BINDREQ_FRESH_OSC`], the registry's and every sponsor's), so a fleet device never holds a stale one.
/// The request's own lifetime is the protocol's clock, the one sanctioned deadline here besides [`UNHEARD_OSC`].
pub const REMINT_OSC: i64 = BINDREQ_FRESH_OSC - (BINDREQ_FRESH_OSC >> 2);

/// Why a join stopped before it started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// This device is bound to another identity (the device-busy gate).
    Busy,
    /// fgtw.org says this device belongs to another identity's fleet: only that fleet can release it.
    Owned,
}

/// Where the join stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// The look-up runs: the proof and the question, which ring nobody.
    Looking,
    /// Not a join: the handle has no fleet (a fresh identity) or this device is already a member (attest goes on). The machine has nothing to do.
    NotJoining,
    /// The identity has a fleet and this device is unbound: "are you sure?" is asked. Nothing has left the device.
    Confirm,
    /// Refused: see [`Refusal`].
    Refused(Refusal),
    /// The person said yes: the request is out to the fleet's devices (on this network, NFC, BLE), and to fgtw.org once the edge says so.
    Asking,
    /// This device is in the fleet.
    Joined,
}

/// What the joiner should be told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinNote {
    /// Ask "are you sure?" (`text::Msg::JoinConfirmPrompt`, the button `text::Msg::JoinConfirmYes`).
    Confirm,
    /// This device is bound to another identity: refused.
    Busy,
    /// The request is out: tell the person how to finish (`text::Msg::JoinTogether`; the words only behind `text::Msg::JoinShowWords`).
    Asking,
    /// No fleet device was heard on this network: the request went to fgtw.org's registry, the last rung.
    Unheard,
    /// fgtw.org says this device belongs to another identity's fleet: refused.
    Owned,
    /// fgtw.org did not take the request (a network failure, not a verdict); the fleet's devices nearby still have it.
    PostFailed(String),
    /// The request could not be minted.
    MintFailed(String),
    /// A device of the fleet picked this one: it should turn green.
    Selected { by: Key },
    /// This device is in the fleet.
    Joined,
    /// The person backed out: the request is withdrawn.
    Withdrawn,
}

/// What the joiner asks the app to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Do {
    /// Mint and sign this device's binding request with a fresh stamp (and the tap secret this join serves), off the machine; answer [`Event::Minted`].
    Mint,
    /// Hand the request (a `bind_req` frame) to this fleet device, heard on this network: the app reaches it at the address it heard it from.
    Hand { to: Key, frame: Vec<u8> },
    /// Beacon under the handle on this network once: every fleet device that hears it answers, and each answer comes back as [`Event::LanHeard`].
    LanBeacon,
    /// Air the BLE join beacon for this request stamp (`pair::beacon_id`), or stop.
    Ble(Option<i64>),
    /// Serve this tap secret by NFC, or stop.
    Nfc(Option<[u8; 32]>),
    /// Post the request as minted to fgtw.org's registry (the last rung); answer [`Event::Posted`].
    PostRegistry,
    /// Withdraw the request posted to fgtw.org.
    Withdraw,
    /// Watch for the green: chains and picks handed to this device over the mesh, and fgtw.org's copy of the chain when `registry` (only once the request went there).
    Watch { registry: bool },
    /// Stop watching.
    Unwatch,
    /// Tell the person.
    Note(JoinNote),
}

/// A step's result: the acts in order, and at most one deadline.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Step {
    pub actions: Vec<Do>,
    pub wake: Option<(i64, Wake)>,
}

impl Step {
    fn push(&mut self, d: Do) {
        self.actions.push(d);
    }
}

/// What the joiner's screen shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub phase: Phase,
    /// The pairing words: only after "Not in range?" while asking.
    pub words: Option<String>,
    /// This device's name as the fleet will list it.
    pub name: String,
    /// The fleet device that picked this one, while asking.
    pub selected_by: Option<Key>,
    /// fgtw.org's registry holds the request.
    pub posted: bool,
    /// Fleet devices heard on this network since the yes.
    pub heard: usize,
}

/// One joining device.
#[derive(Clone, Debug)]
pub struct Join {
    me: Key,
    /// The identity seed (a root): the words and the name come from it. Never saved.
    seed: [u8; 32],
    phase: Phase,
    nfc: Option<[u8; 32]>,
    /// The request as minted: its frame and stamp.
    frame: Option<Vec<u8>>,
    t: Option<i64>,
    minting: bool,
    /// Fleet devices heard on this network since the yes, and those handed the current stamp.
    heard: Vec<Key>,
    handed: Vec<Key>,
    /// When the window for hearing a fleet device closes; None once decided.
    unheard_at: Option<i64>,
    /// The registry is wanted (the edge fired or the words were asked for); `posted` is the stamp it holds.
    registry: bool,
    posted: Option<i64>,
    posting: bool,
    words: bool,
    selected_by: Option<Key>,
    remint_at: Option<i64>,
}

impl Join {
    /// A join for device `me` with the identity seed derived from the handle typed. The look-up runs; tell it [`Event::Looked`] when it answers.
    pub fn new(me: Key, seed: [u8; 32]) -> Self {
        Join { me, seed, phase: Phase::Looking, nfc: None, frame: None, t: None, minting: false, heard: Vec::new(), handed: Vec::new(), unheard_at: None, registry: false, posted: None, posting: false, words: false, selected_by: None, remint_at: None }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The screen as it stands.
    pub fn view(&self) -> View {
        let asking = self.phase == Phase::Asking;
        View {
            phase: self.phase,
            words: (asking && self.words).then(|| crate::pair::masked_device_words(&self.me, &self.seed)),
            name: crate::pair::device_name_default(&self.me, &self.seed),
            selected_by: self.selected_by.filter(|_| asking),
            posted: self.posted.is_some(),
            heard: self.heard.len(),
        }
    }

    /// The one deadline: the hearing window while it is open, else the request's re-mint.
    fn wake(&self) -> Option<(i64, Wake)> {
        if self.phase != Phase::Asking {
            return None;
        }
        match (self.unheard_at, self.remint_at) {
            (Some(u), Some(r)) if r < u => Some((r, Wake::Remint)),
            (Some(u), _) => Some((u, Wake::Unheard)),
            (None, Some(r)) => Some((r, Wake::Remint)),
            (None, None) => None,
        }
    }

    /// One event. `now` is Eagle time in oscillations.
    pub fn step(&mut self, ev: Event, now: i64) -> Step {
        let mut s = Step::default();
        match ev {
            Event::Looked { has_fleet, member, busy } if self.phase == Phase::Looking => {
                // The device-busy gate first: a device bound to another identity is never asked, and never sends.
                if busy {
                    self.phase = Phase::Refused(Refusal::Busy);
                    s.push(Do::Note(JoinNote::Busy));
                } else if member || !has_fleet {
                    self.phase = Phase::NotJoining;
                } else {
                    self.phase = Phase::Confirm;
                    s.push(Do::Note(JoinNote::Confirm));
                }
            }
            Event::User(UserOp::Confirm { nfc_secret }) if self.phase == Phase::Confirm => self.confirm(nfc_secret, now, &mut s),
            Event::User(UserOp::ShowWords) if self.phase == Phase::Asking => {
                // The explicit edge: the words for a fleet device not in range, and the registry where that device finds the request by them.
                self.words = true;
                self.unheard_at = None;
                self.want_registry(&mut s);
            }
            Event::User(UserOp::Back) if self.phase == Phase::Asking => {
                self.stop(&mut s);
                self.phase = Phase::Confirm;
                s.push(Do::Note(JoinNote::Withdrawn));
            }
            Event::Minted { t, result } if self.phase == Phase::Asking && self.minting => {
                self.minting = false;
                match result {
                    Ok(frame) => self.minted(t, frame, &mut s),
                    Err(e) => {
                        self.stop(&mut s);
                        self.phase = Phase::Confirm;
                        s.push(Do::Note(JoinNote::MintFailed(e.to_string())));
                    }
                }
            }
            Event::LanHeard { device } if self.phase == Phase::Asking && device != self.me => {
                if !self.heard.contains(&device) {
                    self.heard.push(device);
                }
                // A fleet device on this network: the hearing window has its answer, and the device gets the request (once per stamp).
                self.unheard_at = None;
                self.hand(device, &mut s);
            }
            Event::LinkUp if self.phase == Phase::Asking => s.push(Do::LanBeacon),
            Event::Wake { reason: Wake::Unheard } if self.phase == Phase::Asking => {
                if self.unheard_at.is_some_and(|at| now >= at) {
                    self.unheard_at = None;
                    if self.heard.is_empty() {
                        s.push(Do::Note(JoinNote::Unheard));
                        self.want_registry(&mut s);
                    }
                }
            }
            Event::Wake { reason: Wake::Remint } if self.phase == Phase::Asking => {
                if self.remint_at.is_some_and(|at| now >= at) && !self.minting {
                    self.remint_at = None;
                    self.minting = true;
                    s.push(Do::Mint);
                }
            }
            Event::Posted { result } if self.posting => {
                self.posting = false;
                match result {
                    Ok(()) => {
                        self.posted = self.t;
                        s.push(Do::Watch { registry: true });
                    }
                    // The one-owner verdict is final: this device stays its owner's until that fleet lets it go.
                    Err(e) if e.starts_with("device_owned") => {
                        self.stop(&mut s);
                        self.phase = Phase::Refused(Refusal::Owned);
                        s.push(Do::Note(JoinNote::Owned));
                    }
                    Err(e) => s.push(Do::Note(JoinNote::PostFailed(e.to_string()))),
                }
            }
            Event::Picked { by } if self.phase == Phase::Asking => {
                self.selected_by = Some(by);
                s.push(Do::Note(JoinNote::Selected { by }));
            }
            Event::InFleet if self.phase == Phase::Asking => {
                self.stop(&mut s);
                self.phase = Phase::Joined;
                s.push(Do::Note(JoinNote::Joined));
            }
            _ => {}
        }
        s.wake = self.wake();
        s
    }

    /// The yes: the request goes out, to the person's devices first.
    fn confirm(&mut self, nfc_secret: [u8; 32], now: i64, s: &mut Step) {
        self.phase = Phase::Asking;
        self.nfc = Some(nfc_secret);
        self.minting = true;
        self.unheard_at = Some(now + UNHEARD_OSC);
        s.push(Do::Nfc(Some(nfc_secret)));
        s.push(Do::Mint);
        s.push(Do::LanBeacon);
        s.push(Do::Watch { registry: false });
        s.push(Do::Note(JoinNote::Asking));
    }

    fn minted(&mut self, t: i64, frame: &[u8], s: &mut Step) {
        let first = self.frame.is_none();
        self.frame = Some(frame.to_vec());
        self.t = Some(t);
        self.remint_at = Some(t + REMINT_OSC);
        self.handed.clear();
        s.push(Do::Ble(Some(t)));
        // A fresh stamp is announced again on this network, so a fleet device that came up since hears it: the beacon persists on the request's own edges, never on a cadence.
        if !first {
            s.push(Do::LanBeacon);
        }
        for k in self.heard.clone() {
            self.hand(k, s);
        }
        if self.registry {
            self.post(s);
        }
    }

    fn hand(&mut self, to: Key, s: &mut Step) {
        let Some(frame) = self.frame.as_ref() else { return };
        if self.handed.contains(&to) {
            return;
        }
        self.handed.push(to);
        s.push(Do::Hand { to, frame: frame.clone() });
    }

    fn want_registry(&mut self, s: &mut Step) {
        self.registry = true;
        self.post(s);
    }

    /// Post the current stamp to the registry, when there is one minted and it is not there yet.
    fn post(&mut self, s: &mut Step) {
        if self.posting || self.frame.is_none() || self.posted == self.t {
            return;
        }
        self.posting = true;
        s.push(Do::PostRegistry);
    }

    /// Everything the yes started, stopped: radios, the watch, and the registry's copy withdrawn.
    fn stop(&mut self, s: &mut Step) {
        s.push(Do::Nfc(None));
        s.push(Do::Ble(None));
        s.push(Do::Unwatch);
        if self.posted.is_some() || self.posting {
            s.push(Do::Withdraw);
        }
        self.nfc = None;
        self.frame = None;
        self.t = None;
        self.minting = false;
        self.heard.clear();
        self.handed.clear();
        self.unheard_at = None;
        self.registry = false;
        self.posted = None;
        self.posting = false;
        self.words = false;
        self.selected_by = None;
        self.remint_at = None;
    }
}
