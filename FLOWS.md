# Fleet flows move into fgtw

Status: **plan, 2026-11-10; the owner's decisions are in (below).** Nothing here is built yet. `fgtw::text` (the shared wording, 8b0f48e) has landed and Photon uses it (photon 06e10e1d).

## Why

Owner, 2026-11-10: everything FGTW moves out of Photon.
Photon becomes a messenger: on ferros it has no fleet page (the OS owns identity and fleet), and on Linux, macOS, Windows and Android it only hosts the FGTW/TOKEN screens.

Today fgtw holds the primitives (chain and fold, bind, grow, frames, word and NFC matching, the attest verdict) but no flow.
Each app drives its own sequences: Photon in `ui/photon_app/devices.rs` (3430 lines) plus arms in `protocol.rs`, `status.rs`, `driver.rs`, `launch.rs` and `settings.rs`; ferros in `payloads/fgtw/src/main.rs` (2863 lines) with hand-numbered phases.
The two copies have already split, and each has a bug the other fixed:

| Behaviour | Photon | ferros |
|---|---|---|
| The last device cannot ask to leave | yes | **no** |
| A depart_req lost to a failed send is handed again | **no** | yes (PT give-up, re-hand at the next Pong) |
| The grow leaves locked devices out | yes | **no** (cached member list) |
| bindreq_put built by `client::bindreq_put` | yes | **no** (hand-built fields) |
| Mint errors read from typed values | yes | **no** (matches error text) |

Tonight's Yes/No step and the departure wording were each written twice.

## The shape

One module, `fgtw::flow`, behind a feature `flow` (on top of `protocol`), **no_std + alloc**.
The rest of the crate keeps its current std/no_std split; this supersedes the July 2026 "fgtw stays std until ferros" note for this module only, since ferros is here.

Each flow is a machine:

```rust
pub struct Step {
    pub actions: Vec<Action>,
    /// The one deadline this machine needs, and why (a resend, a request's expiry). Never a polling interval.
    pub wake: Option<(EagleTime, Wake)>,
}

impl AddMachine {
    pub fn step(&mut self, ev: Event, now: EagleTime) -> Step;
    pub fn to_vsf(&self) -> VsfSection;              // the state rests in the app's vault
    pub fn from_vsf(s: &VsfSection) -> Result<Self, FlowError>;
}
```

- **Pure.** No I/O, no clock read, no RNG, no blocking, no signing inside `step`. Anything slow or effectful is an Action whose result comes back as an Event.
- **No timers.** Edges drive it; a machine asks for at most one deadline, with a reason.
- **State is VSF**, so a departure under way survives a restart (ferros keeps it in the vault; Photon too).
- **Wording** comes from `fgtw::text` (the ferros-side `text` branch): actions name a `Msg`, each app draws it.

### Events (what the app tells a machine)

- a frame received: bytes, from-address, signer
- a beacon heard (key, address, port), a BLE beacon id heard, an NFC tag secret read
- `fleet_req` received; a Pong from a known device
- a send finished: ok or given up (to which address)
- a result: signed (purpose, signature), a seed call answered, a chain or fan-out adopted, the space generation changed
- randomness, when a step needs it (a departure salt arrives with the Leave op)
- the link came up or went down (Wi-Fi or cellular): a new network beacons again, and pending sends retry on it
- the roots handed (the attest screen) or forgotten: they start and end Join and Attest
- a radio's own answer: the NFC or Bluetooth driver refused or is absent, so the screen can say so
- the Fleet page shown or gone: Add opens and closes on it (the owner's rule that adding needs the page open)
- the person: touch a row, Yes, No, words typed, approve, deny, leave, give up, lock, unlock

### Actions (what the app carries out)

- `Send { to: Device(pk) | Addr, frame }`: the app walks the owner's ladder, BLE, then LAN, then WAN, then fgtw.org last; ferros has no WAN or relay today and does LAN only
- `Beacon4384 { frame, scope }`: multicast v4/v6, subnet broadcast, or unicast
- `Seed { call }`: an fgtw.org request, last resort only; its answer returns as an Event
- `Radios { ble_id, nfc_secret, ble_scan, nfc_reader }`
- `Sign { bytes, purpose }`: all eggs; ferros runs it pinned to the big cores, outside any call another process waits on
- `Persist { key, bytes }` and `Forget { key }`
- `Show { screen, msg }` and `Notify { msg }` (doorbell or OS notification)
- `Members { joined, left, locked }`: the membership edge Photon uses to keep its sibling rows (CLUTCH, lanes and history still need them until stage 8)
- `Wipe`: the leaver's departure completed

### One delivery helper

`Deliver`: send this frame to every live member until each acks or answers; a member whose send gave up is handed again at its next Pong.
It replaces ferros's depart resend and gives Photon one; Add, Depart, Lock and chain news all use it.

## The machines

| Machine | Today in Photon | Today in ferros | The owner's rules it carries |
|---|---|---|---|
| **Add** (sponsor) | `open_add_device_flow`, `select_candidate`, `add_in_background`, `spawn_bind_device`, `spawn_confirm_add`, the Bound/Rotated arms | `open_add`, `sponsor_step`, `select`, `bind_picked`, `grow_for_newcomer` | add only with the Fleet page open; NFC match or typed words bind and grow at once; a touch on a row selects (`bind_select`, green, "Is your new device bright green?" Yes / No, No = Back); the sponsor must hold the fleet key; one add at a time; contention shuts the network path |
| **Join** (new device) | `submit_join_step` (one 330-line thread), `end_join_flow`, the JoinUpdate arms | `mint_request`, `beacon`, `join_check`, `select_from` | join notices are LAN only; fgtw.org's mailbox only after "ask through fgtw.org"; green when a chain folds us in; Selected only from a live unlocked member of a genesis-matched chain |
| **Depart** (leaver and approver) | `request_fleet_departure`, `complete_departure_approval`, `approve/deny_pending_departure`, the depart arms | `leave`, `depart_hand`, `on_depart_req`, `answer_depart`, `approve_now` | the last device cannot leave; Approve frees the hardware; a denied salt is refused for good; the leaver wipes when de-folded |
| **Lock** (lock, revoke, reinstate) | `revoke_device`, `reinstate_fleet_device`, `apply_locked_set`, the tombstone ack-quorum | (not built) | arm then confirm; the last other live unlocker is warned |
| **Chain** (news, refold, adoption) | `chain_news`, `refold_own_chain`, `ask_siblings_for_chain`, the fold drain's adoption table | `on_frame` FleetResp, `hold_chain` | peers first, fgtw.org only when nobody answers; genesis pinned; adopt only by extension; a new head is passed on once |
| **State** (fleet settings, roster, key heal) | `spawn_settings_push`, `merge_into_slot`, the roster pull retry/park/breaker, `fanout_needs_rotation`, the checkpoint spine | space push/want | siblings first, fgtw.org as compare-and-set backup |
| **Attest** | `submit_handle`, `on_query_result`, the post-attest list | `lookup`, `mint` | the verdict is `fgtw::attest::attest_verdict` (already shared); held and peer chains go in (ferros passes none today) |

The network leftovers in Photon (`network/fgtw/`: held-chain statics, the fstate compare-and-set, the device signer, `phonebook_client`, `peer_store`, `node`, `bootstrap` announce, `blob`, `octopus`, `doorbell`, and `relay.rs`, which duplicates `fgtw::pipe`) move behind small traits (`FleetStore` for the vault, an async transport for HTTP), in the stage that first needs them.

Photon's 16 fleet-frame dispatch arms in `network/status.rs` collapse onto one `fgtw::protocol::parse_fleet_frame -> FleetFrame`, and `STRANGER_SECTIONS` comes from fgtw.

## Stages

Green at every step (MIGRATION.md's rule): Photon, the worker and ferros build, and the wire format does not change.
Each stage lands in fgtw with its tests, then Photon adopts it (Photon's code becomes an executor of actions), then ferros adopts it (the ferros session).

0. **This plan**, the owner's decisions below, and `photon/docs/one-identity.md` corrected ("Photon keeps ... fleet" is superseded).
1. **Scaffold**: `flow` feature, Event / Action / Step / Wake, the VSF state codec, `Deliver`, and a test harness that wires two or three machines together in memory (frames passed by hand, sends failing on demand). Delete Photon's `relay.rs` copy of `fgtw::pipe`.
2. **Depart**: with `Deliver` (Photon gains the resend, ferros gains the last-device gate). First, because both bugs are live on the owner's devices and it is the smaller machine to prove the scaffold on.
3. **Add**: the most duplicated. Port the union of both apps' behaviour, fix the divergences above, tests for every owner rule.
4. **Join**.
5. **Lock**.
6. **Chain** and the fleet-frame parser (`parse_fleet_frame`, `STRANGER_SECTIONS` from fgtw); the held-chain statics move into fgtw.
7. **State** (settings, roster, key heal, checkpoint spine) and the `FleetStore` trait. Beside it, **Profile** (owner 2026-11-10: the You page's content managed in ferros too): the person's preferred name, avatar pin and contact details as records signed by their owner with a revision; any holder of a newer signed copy passes it on (to the owner's devices when theirs is older or missing, to anyone showing it as Pending), and a device with none asks the people and devices it knows, fgtw.org last. "Pending" then means no copy anywhere it asked. Today's Pending names and avatars are being traced first.
8. **Attest** (`photon/docs/one-identity.md` item 1), then people and devices: Photon's own devices stop being contacts; per-device links (lane, CLUTCH) keyed by device key, the same shape for a friend's devices and the owner's.
9. **The rest of the network substrate** (phonebook client and store, routing, announce, blobs, octopus, doorbell), with the `FgtwMessage` split (MIGRATION.md step 5).

Who builds: Photon's session builds each machine in fgtw and Photon's adoption; the ferros session reviews each machine against its loop before it lands, then adopts it in ferros. One fgtw branch at a time.

## Decided (owner, 2026-11-10)

0. **Friendship-chain replication between the owner's own devices** (`chain_sync`, the checkpoint spine): Photon keeps the conversation content; fgtw gives it `Deliver` to the owner's devices and the epoch keys.
1. **no_std for `fgtw::flow` only**; the rest of fgtw unchanged.
2. **Both timers go**: Photon refolds its own chain every 45 s while a Settings page is open, and ferros lists fgtw.org's bind requests every 8 s while adding. The machines would drop both: chain refresh on edges (a Pong, a frame, a page opening, the link coming up); the registry read only on the person's edges (once when they open "type its words", and again when the words typed so far match no known candidate), plus a hub poke where the app has one (ferros has none: plain HTTP only). That covers the one case the registry matters, a remote joiner reached by words; nearby devices come by BLE and LAN.
3. **Order**: left to the builders; Depart first (stage 2), then Add.
4. **The key that signs kists and the kist directory** is undecided ("governed by the FGTW kaitiakitanga"); nothing here bakes one in.

## Review

ferros session, 2026-11-10: fits ferros's single loop; every Event and Action above can be produced or carried out (Leave's randomness from kernel entropy, `Members` drives its Fleet list); the four ferros rows of the divergence table checked against its code.
The State machine's scope includes what already rides the identity space sync: the zone fact (ZONE) and the kist list (KIST, ANSWER, PLACE), not a new path.
