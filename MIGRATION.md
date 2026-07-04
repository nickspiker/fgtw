# fgtw crate — migration plan

Extract the generic FGTW client substrate out of `photon/src/network/fgtw/` into this crate, so photon, the calendar, any TOKEN app, **and** the worker all share one source of truth.
This is a "holy refactor" — the rule is **photon and the worker stay green at every step**, one module at a time, commit per move.

## The boundary — generic (moves here) vs messaging (stays in photon)

| Photon file | Lines | Destination |
|---|---|---|
| `fleet.rs` | 1992 | **split**: fold/verify + fan-out + fstate → `fgtw::{fleet,fanout,fstate}` (no_std core); the HTTP oracle (fetch/publish/pairing) → `fgtw::client` |
| `protocol.rs` | 2402 | **split**: generic msgs (announce/challenge/fleet ops/avatar/blob) → `fgtw::protocol`; photon msgs (chat, CLUTCH, PT) **stay** |
| `bootstrap.rs` | 618 | `fgtw::client` (announce, load_bootstrap_peers) |
| `blob.rs` | 381 | `fgtw::blob` |
| `node.rs` / `peer_store.rs` / `relay.rs` | 781 | `fgtw` DHT modules (generic Kademlia) |
| `fingerprint.rs` | 90 | `fgtw` (device-key derivation) — reconcile overlap with `tohu` first |
| **stays in photon** | | `status.rs` (presence + CLUTCH orchestration), `pt/` (Photon Transfer), `handle_query.rs` (attest orchestration — app glue), contacts/conversations |

The current client/worker duplication — photon `fleet.rs` fold ↔ `fgtw-bootstrap/src/fleet.rs` "kept in lockstep via a known-answer test" — collapses in step 2: one `fgtw::fleet`, no lockstep, nothing to keep in sync.

## Order (green at each step; commit per move)

0. **[DONE] Scaffold** — crate exists, compiles no_std + std, publishes clean at 0.0.0.
1. **Publish-deps prerequisite.**
   To publish `fgtw` beyond a dep-free 0.0.0, its real deps (`vsf`, `ihi`, `blake3`, `ed25519-dalek`, …) must be published at matching versions.
   `vsf`/`spirix` are currently path-locked (0.9.1 / 0.1.1) and unpublished — so either publish them, or keep `fgtw` path-only + unpublished until the code lands and the deps are cut.
   (0.0.0 name-reservation publishes today because it's dep-free.)
2. **`fgtw::fleet` (fold/verify).**
   Move the no_std core (`FleetOp`, `MembershipBlob`, `fold`, `extends`, `is_member`).
   Re-point photon `fleet.rs` and worker `fleet.rs` to it; delete the worker mirror.
   Highest value (dedup) + self-contained.
   Build photon + worker green.
3. **`fgtw::fanout`.**
   Seal/open + the scoped-key bundle model (`docs/fleet-vault-security.md` in photon).
   Re-point.
4. **`fgtw::fstate`.**
   Sealed shared-state slot + the worker's `fstate_put/get`.
   Re-point.
5. **`fgtw::protocol`.**
   SPLIT `protocol.rs` — generic codec here, photon msgs stay.
   This is the fiddliest; do it after the fleet/fanout/fstate types it references have moved.
6. **`fgtw::blob`** + **`fgtw::client`** (bootstrap/announce/oracle) + DHT + fingerprint.
   Re-point.
7. **Worker depends on `fgtw`; photon depends on `fgtw`.**
   Photon's `network/fgtw/` shrinks to the messaging layer + thin re-exports.

## Invariants during the move

- Each step compiles **photon** (`scripts/dev.sh` / `cargo check --features development`) AND the **worker** (`cargo check --target wasm32-unknown-unknown` in `/fgtw-bootstrap`) before commit.
- no_std core must not pull std (the worker is WASM).
  Keep std behind the `client` feature.
- The wire format does not change — this is a code move, not a protocol change.
  A mid-migration photon must still talk to the deployed worker.
