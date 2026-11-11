//! The fleet flows as machines (FLOWS.md): what happens when a device asks to leave, is added, joins, is locked, written once so every TOKEN app behaves alike.
//! A machine is pure: it takes an [`Event`] and returns a [`Step`] of [`Action`]s, and never does I/O, reads a clock, draws randomness, blocks or signs.
//! The app carries the actions out with its own radios, sockets, vault and screen, and reports what happened as the next events.
//! Nothing here runs on a timer: a machine asks for at most one deadline ([`Step::wake`]) and says why.

use alloc::string::String;
use alloc::vec::Vec;

use crate::pq::FleetSigner;

pub mod add;
pub mod deliver;
pub mod depart;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod add_tests;

/// A device key (Ed25519 public key).
pub type Key = [u8; 32];

/// Where a frame goes: a device by key, which the app reaches by the owner's ladder (BLE, then the local network, then the internet, then fgtw.org last), or one address the app was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum To {
    Device(Key),
    Addr(core::net::SocketAddr),
}

/// A frame for the app to build and sign with the device's signer (all its eggs), outside any step; the bytes come back as [`Event::Built`].
/// Signing is the app's because it can take seconds (SLH-DSA), and a machine never waits on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// This device asks its fleet to let it go.
    DepartReq { hp: Key, t: i64, intent: u8, salt: [u8; 32] },
    /// This device's person said Deny to `leaver`'s request.
    DepartDeny { hp: Key, leaver: Key, salt: [u8; 32], t: i64 },
    /// Tell a device picked on the sponsor's screen that it was picked, so it can turn green.
    BindSelect { hp: Key, joiner: Key },
    /// The fleet key's fan-out, grown to include a new member.
    FanoutResp { hp: Key, blob: Vec<u8> },
}

/// Build and sign `frame`: the one place a [`Frame`] becomes bytes, so every app signs the same thing. `time` is the document's stamp.
pub fn build(frame: &Frame, signer: &(impl FleetSigner + ?Sized), time: i64) -> Result<Vec<u8>, String> {
    match frame {
        Frame::DepartReq { hp, t, intent, salt } => {
            let consent_sig = crate::protocol::depart_consent(signer, hp, *t);
            crate::protocol::depart_req(&crate::protocol::DepartReq { t: *t, consent_sig, intent: *intent, salt: *salt }, signer, time)
        }
        Frame::DepartDeny { hp, leaver, salt, t } => crate::protocol::depart_deny(hp, leaver, salt, *t, signer, time),
        Frame::BindSelect { hp, joiner } => crate::protocol::bind_select(hp, joiner, signer, time),
        Frame::FanoutResp { hp, blob } => crate::protocol::fanout_resp(hp, blob, signer, time),
    }
}

/// Slow or effectful work the app runs off the machine and answers with an event.
#[derive(Clone, Debug, PartialEq)]
pub enum Job {
    /// Countersign `leaver`'s departure and publish the consented Remove; for intent 1 release its hardware too (`sponsor::approve_departure`). Answered by [`Event::Approved`].
    Approve { leaver: Key, t: i64, consent_sig: Vec<u8>, intent: u8 },
    /// Read fgtw.org's binding requests for our fleet (`client::bindreq_list`), and which of them belong to another fleet. Answered by [`Event::Listed`].
    ListRequests,
    /// Add this device to the fleet (`sponsor::bind_device_held`; a plate the fleet locked out is refused there too). Answered by [`Event::Bound`].
    Bind { req: crate::fleet::BindRequest },
    /// Grow the fan-out to `members` (the machine leaves locked devices out) with the key held now (`held::fanout_grow_held`). Answered by [`Event::Grown`].
    Grow { device: Key, members: Vec<Key> },
}

/// What the person should be told. The app chooses the words (`text::Msg`), the device names and where it shows: a toast, a notification, the Fleet page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Note {
    /// This is the identity's last device (or its members are not known yet): it cannot ask to leave.
    LastDevice,
    /// Our departure request is out; the other devices are asked.
    DepartAsking,
    /// Our departure request could not be built.
    DepartNotSent(String),
    /// A device denied our request; this device stays.
    DepartDenied { by: Key },
    /// Our departure is done: we are out of the fleet (a [`Action::Wipe`] follows).
    DepartDone,
    /// `leaver` asks to leave; Approve or Deny.
    DepartAsked { leaver: Key },
    /// Denied here.
    DepartDeniedHere { leaver: Key },
    /// `leaver`'s request was denied on another device and is cleared here.
    DepartDeniedElsewhere { leaver: Key, by: Key },
    /// `leaver`'s request was settled elsewhere (it is no longer in the fleet).
    DepartSettled { leaver: Key },
    /// `leaver` withdrew its request.
    DepartWithdrawn { leaver: Key },
    /// Approved here: the Remove is published; what happened to the hardware.
    DepartApproved { leaver: Key, outcome: crate::sponsor::Approved },
    /// The approval did not publish; the request stays for another try.
    DepartApproveFailed { leaver: Key, reason: String },
    /// This device holds no fleet key, so it cannot add a device (nothing was written).
    AddNoFleetKey,
    /// A device on this network is asking to join (LAN only; a request seen only on fgtw.org notifies nowhere).
    AsksToJoin { device: Key },
    /// A device was picked: it should turn green on its own screen.
    Picked { device: Key },
    /// The picked device could not be reached on this network: add it by its words.
    PickUnreachable { device: Key },
    /// Another add is under way.
    AddBusy,
    /// This device is one the fleet locked out.
    AddLockedOut { device: Key },
    /// This device belongs to another fleet.
    AddOwnedElsewhere { device: Key },
    /// The add started: the screen goes back to the Fleet page.
    Adding { device: Key },
    /// The device is in and holds the fleet key.
    Added { device: Key },
    /// The add stopped.
    AddFailed { device: Key, reason: String },
    /// fgtw.org's requests could not be read; the rows already shown stay.
    ListFailed { reason: String },
}

/// What a machine asks the app to do.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Send these bytes; the app reports [`Event::Sent`] when it knows whether they arrived.
    Send { to: To, frame: Vec<u8> },
    /// A frame from `device` came from `addr`: the app may reach it there (it learns addresses from frames as well as beacons).
    Seen { device: Key, addr: core::net::SocketAddr },
    /// Build and sign this frame ([`build`]) and answer [`Event::Built`] with the same `id`.
    Build { id: u32, frame: Frame },
    /// Run this job and answer with its event.
    Job(Job),
    /// Serve this secret by NFC (a tap of another fleet device reads it), or stop serving.
    NfcServe(Option<[u8; 32]>),
    /// The machine's state changed: write [`depart::Depart::to_section`] (or the machine's own) to the vault now.
    Persist,
    /// Remember this denied request in the fleet-shared settings, so every device refuses it.
    RecordDenied { leaver: Key, salt: [u8; 32], t: i64 },
    /// Remember that this device's hardware was released.
    RecordReleased { device: Key },
    /// Send our fleet chain as it stands now (`fleet_resp`) to this device.
    PushChain { to: Key },
    /// Our chain changed by our hand: send it to every device of ours, every contact's devices, and `extra` (a device not in the fold yet, the newcomer).
    ChainNews { extra: Option<Key> },
    /// The radios the sponsor's screen needs, as a whole state (idempotent: the app sets both, and sets them again after a driver restart).
    Radios { ble_scan: bool, nfc_reader: bool },
    /// The fleet chain changed by our hand: fetch or refold it now.
    RefreshChain,
    /// Tell the person.
    Note(Note),
    /// This device has left the fleet: wipe it.
    Wipe,
}

/// Why a machine wants to be woken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wake {
    /// A request heard on the LAN or a device heard nearby lapses then (the add screen's candidates change by time alone).
    Lapse,
}

/// A step's result: the actions in order, and at most one deadline.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Step {
    pub actions: Vec<Action>,
    pub wake: Option<(i64, Wake)>,
}

impl Step {
    fn push(&mut self, a: Action) {
        self.actions.push(a);
    }
}

/// The person's choices a machine reacts to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserOp {
    /// Ask the fleet to let this device go. `salt` is 32 fresh random bytes from the app (a machine draws no randomness).
    Leave { intent: u8, salt: [u8; 32] },
    /// Forget our own request.
    GiveUp,
    /// Approve the request shown.
    Approve,
    /// Deny the request shown.
    Deny,
    /// Touch a device's row on the add screen: pick it.
    Touch { device: Key },
    /// Yes, the picked device is bright green: add it.
    Yes,
    /// No: drop the pick.
    No,
    /// "Not nearby? Look through fgtw.org", or opening "type its words": read fgtw.org's requests once.
    LookFarther,
}

/// What the app tells a machine.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Event<'a> {
    /// The fleet as folded now: every member (this device among them) and the locked ones. Sent at start and on every change.
    Members { members: &'a [Key], locked: &'a [Key] },
    /// A frame arrived, from this address when the app knows it (the machine opens it, checks its signer, and reports the pair as [`Action::Seen`]).
    Frame { bytes: &'a [u8], from: Option<core::net::SocketAddr> },
    /// A send finished: it arrived (`ok`) or the app gave up on it.
    Sent { to: Key, ok: bool },
    /// A device showed it is reachable: it answered a ping, its beacon was heard, or a frame came from it. A good moment to hand it what it has not taken.
    Reachable { from: Key },
    /// A network came up: hand again whatever did not arrive.
    LinkUp,
    /// The frame asked for with [`Action::Build`].
    Built { id: u32, result: Result<&'a [u8], &'a str> },
    /// The answer to [`Job::Approve`].
    Approved { leaver: Key, result: Result<&'a crate::sponsor::Approved, &'a str> },
    /// Denied requests the fleet-shared settings hold (every device's list, merged).
    DeniedKnown { denied: &'a [(Key, [u8; 32], i64)] },
    /// The leaving device withdrew the request stamped `t` (its frame, or the identity space showing the entry gone).
    GaveUp { leaver: Key, t: i64 },
    /// An NFC tap read this secret.
    NfcRead { secret: [u8; 32] },
    /// The Fleet page is shown (the add flow opens) or gone (it closes).
    Page { shown: bool },
    /// Whether this device holds the fleet key now.
    FleetKey { held: bool },
    /// The plates this fleet locked out.
    LockedPlates { plates: &'a [[u8; 32]] },
    /// A binding request's BLE beacon id heard.
    BeaconHeard { id: [u8; crate::pair::BEACON_UUID_LEN] },
    /// An own-handle LAN beacon from this device key heard.
    LanHeard { device: Key },
    /// The answer to [`Job::ListRequests`]: the requests read, and the devices among them owned by another fleet.
    Listed { reqs: &'a [crate::fleet::BindRequest], owned_elsewhere: &'a [Key] },
    /// The answer to [`Job::Bind`].
    Bound { device: Key, result: Result<(), &'a str> },
    /// The answer to [`Job::Grow`]: the grown fan-out blob.
    Grown { device: Key, result: Result<&'a [u8], &'a str> },
    /// The words typed so far on the add screen.
    Words { text: &'a str },
    /// A deadline a step asked for ([`Step::wake`]) has come.
    Wake { reason: Wake },
    /// [`Job::ListRequests`] failed: the rows read before stay.
    ListFailed { reason: &'a str },
    /// The person chose.
    User(UserOp),
}
