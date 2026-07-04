# fgtw crate — migration plan

Extract the generic FGTW client substrate out of `photon/src/network/fgtw/` into this crate, so photon, the calendar, any TOKEN app, **and** the worker all share one source of truth.
This is a "holy refactor" — the rule is **photon and the worker stay green at every step**, one module at a time, commit per move.

## The boundary — generic (moves here) vs messaging (stays in photon)

| Photon file | Lines | Destination |
|---|---|---|
| `fleet.rs` | 1992 | **split**: fold/verify → `fgtw::fleet` **[DONE]**; fan-out + roster codec + pairing words → `fgtw::fanout`; the HTTP oracle (fetch/publish/pairing/fstate) → `fgtw::client` |
| `fingerprint.rs` `Keypair` | — | `fgtw::keys` **[DONE, moved alongside the fleet core]**; the oracle read (`derive_device_keypair`/`get_machine_fingerprint`/`FgtwPaths`) stays in photon until the `tohu` reconcile |
| `protocol.rs` | 2402 | **split**: generic msgs (announce/challenge/fleet ops/avatar/blob) → `fgtw::protocol`; photon msgs (chat, CLUTCH, PT) **stay** |
| `bootstrap.rs` | 618 | `fgtw::client` (announce, load_bootstrap_peers) |
| `blob.rs` | 381 | `fgtw::blob` |
| `node.rs` / `peer_store.rs` / `relay.rs` | 781 | `fgtw` DHT modules (generic Kademlia) |
| `fingerprint.rs` | 90 | `fgtw` (device-key derivation) — reconcile overlap with `tohu` first |
| **stays in photon** | | `status.rs` (presence + CLUTCH orchestration), `pt/` (Photon Transfer), `handle_query.rs` (attest orchestration — app glue), contacts/conversations |

The current client/worker duplication — photon `fleet.rs` fold ↔ `fgtw-bootstrap/src/fleet.rs` "kept in lockstep via a known-answer test" — collapses in step 2: one `fgtw::fleet`, no lockstep, nothing to keep in sync.

## Order (green at each step; commit per move)

0. **[DONE] Scaffold** — crate exists, compiles, publishes clean at 0.0.0.
1. **[DONE] Path dep, unpublished.**
   During the migration `fgtw` is a **path** dep for photon and the worker (unpublished beyond the 0.0.0 reservation).
   Real crates.io publish waits until `vsf`/`spirix` publish (they're path-locked at 0.9.1 / 0.1.1) — its deps must be published at matching versions first.
2. **[DONE] `fgtw::keys` + `fgtw::fleet` (fold/verify + VSF codec + builders).**
   Moved `Keypair` (`fgtw::keys`) and the fleet core (`FleetOp`, `MembershipBlob`, `fold`, `extends`, `is_member`, the VSF op codec, the device-signed builders) into the crate.
   Re-pointed photon `fleet.rs` (thin re-export + the client half) and the worker (`pub use fgtw::fleet::*`, mirror deleted); the known-answer test moved into `fgtw::fleet`.
   Highest value (dedup) + self-contained. photon + worker green.
3. **`fgtw::fanout` (behind the `fanout` feature).**
   Seal/open + roster codec + pairing words + the scoped-key bundle model (`docs/fleet-vault-security.md` in photon).
   Two no_std-friendly refactors (BTreeMap roster merge, sorted-Vec word index) so a wasm signer can enable `fanout` without `client`.
   Re-point.
4. **`fgtw::client` (behind the `client` feature) + `fgtw::fstate`.**
   The std HTTP oracle (fetch/publish/pairing/fan-out transport/roster push-pull) via trait injection (photon supplies the reqwest transport + `kete` sealer).
   Re-point.
5. **`fgtw::protocol`.**
   SPLIT `protocol.rs` — generic codec here, photon msgs stay.
   This is the fiddliest; do it after the fleet/fanout/fstate types it references have moved.
6. **`fgtw::blob`** + DHT (`node`/`peer_store`/`relay`) + finish `fingerprint` (reconcile with `tohu`).
   Re-point.
7. **Worker depends on `fgtw`; photon depends on `fgtw`.**
   Photon's `network/fgtw/` shrinks to the messaging layer + thin re-exports.

## Invariants during the move

- Each step compiles **photon** (`scripts/dev.sh` / `cargo check --features development`) AND the **worker** (`cargo check --target wasm32-unknown-unknown` in `/fgtw-bootstrap`) before commit.
- The crate is **`std` for now** — its only consumers (photon, and the worker, a wasm32 cdylib) are both `std`, and the `vsf` codec it rides pulls `std` via `crypto`/`inspect` in every real build. A `#![no_std]` core is deferred until a genuinely `no_std` consumer exists; the `fanout` feature keeps its extra crypto deps `alloc`-friendly so that door stays open.
- The wire format does not change — this is a code move, not a protocol change.
  A mid-migration photon must still talk to the deployed worker.
