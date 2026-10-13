# The pulse — FGTW's anchored time

Status: **design, 2026-10-12.** Nothing here is built.
This note specifies the pulse, how it wires into this crate and the worker, and which existing pieces of photon and the other TOKEN apps it reuses.

## What it is

The pulse is a value the whole FGTW network agrees on for every span of Eagle time.
It is unknowable before its span closes, fixed forever after, and computable by anyone holding that span's contributions.
It is owned by nobody: no blockchain, no fees, no external chain or calendar server.

It is the "previous modular state" `M_n(t−1)` in the node state of the TOKEN patent's FGTW appendix (`TOKEN/patent/appendix/fgtw_proofs.tex:30-36`), which names that slot without specifying it.

It is **anchoring**, the complement of **acquisition**.
Acquisition answers "what time is it now": nunc's interval intersection over nonce-selected witnesses (the patent's `consensus` claim, `/mnt/Harbor/Code/nunc`).
Anchoring answers "when did this exist": the pulse.
Together they are the mechanism behind the patent's `temporal` claim, proving when an event occurred.

Three uses:

- **Not before.** Anything that includes a closed window's root provably postdates that window.
- **Not after.** Anything whose hash is in a window's tree provably predates that window's close.
- **Ordering of revocations.** A key revoked in window R: everything it anchored before R stands, anything after R is suspect, and nothing can be anchored into the past.

## Vocabulary

| term | meaning |
|---|---|
| stamp | an instant, as a `u64` count of Eagle oscillations since the Eagle epoch (about 704 ps each) |
| level k | spans of `2^k` oscillations; the level-k span containing stamp `t` is `t >> k` |
| time tree | one binary tree over stamps: every level-k node commits to every contribution in its span |
| window | the level `W` at which the network reconciles and closes; window `w` is the level-W span `w` |
| window root | `R_w`, the chained root of window `w`: its subtree root bound to `R_{w−1}` |
| contribution | a 32-byte commitment some device wants anchored, with its stamp and framing (below) |
| beacon | a public random value derived one-way from `R_w` |
| root answer | a node's signed statement of the root it computed for a window or a higher level |
| inclusion path | the sibling hashes proving a contribution is in a span |

## Time and its levels

There are no epochs of seconds, minutes or days.
Time is the Eagle oscillation count itself, and every grouping of it is a power of two of oscillations, so every level is a bit shift with no division and no calendar.
This follows the stack's grid doctrine (`photon/docs/lock.md` §1.2): names are exact integers, stamps are measurements.
Stamps use the legacy Eagle scale already decided for stamps (`photon/docs/lock.md:469`).

| level | span | role |
|---|---|---|
| 2¹⁰ | ≈ 0.72 µs | |
| 2²⁰ | ≈ 0.74 ms | |
| 2³⁰ | ≈ 0.76 s | |
| **2³⁶** | **≈ 48 s** | **the window (proposed)** |
| 2³⁷ | ≈ 97 s | the alternative window |
| 2⁴⁰ | ≈ 13 min | the lowest level a phone keeps |
| 2⁴⁵ | ≈ 6.9 h | |
| 2⁴⁷ | ≈ 27.5 h | |
| 2⁵⁵ | ≈ 294 days | |

**Granularity is selectable by reading a different level of the same tree.**
A use case that needs microseconds reads level 10; one that needs days reads level 47; the tree, the hashing and the proofs are the same, and a proof's length is set by the levels it spans.

**The window is a separate number from the resolution.**
The network cannot agree on a root every microsecond: reconciliation, root answers and signatures have a cost per closing, and propagation (mobile, satellite) takes seconds.
So the network reconciles and closes once per window, for that window's whole subtree, while contributions keep their own stamps at full resolution inside it.
The window can be changed later without changing the tree's shape or any existing proof.

A contribution's **window** is `stamp >> W`.
A node accepts it until that window's **close**: the window's end plus a grace period `G` (default two windows), during which nodes reconcile their sets.
A contribution arriving after the close is refused; its author resubmits it with a current stamp.
A closed window never reopens.

## Contributions

A contribution is a VSF record:

| field | content |
|---|---|
| `commit` | the 32-byte commitment being anchored |
| `stamp` | its claimed instant, `u64` oscillations |
| `unc` | the uncertainty of that claim, in oscillations (as tukutahi marks carry `unc_ns`) |
| `signer` | the signing key (see Privacy) |
| `sig` | an egg list over the record (`vsf::eggs`, multi-scheme) |

A stamp outside the window being reconciled, beyond its uncertainty, is refused, and so is a stamp in the future of the receiving node (its local floor, as `PeerRecord.local_seen` floors `last_seen`, `photon/src/network/fgtw/protocol.rs:180-190`).

Its **key** is the stamp followed by `spaghettify(DOMAIN_CONTRIB ‖ commit ‖ signer)`: the stamp places it in time, the hash separates contributions at the same instant, and two signers anchoring the same commitment are two leaves.
The leaf value is the hash of the full record, so the signature is committed too.

**Batching.** A device contributes at most one record per window: the Merkle root of every event it wants anchored in that window (photos, message heads, fleet ops), stamped with the window's last event.
That bounds load, hides how many events a device had, and gives each event an inclusion path of two parts: event → device batch root, batch root → time tree.
lumis's run chain fits the same shape: one contribution for a whole offline run, the run's Merkle root, made when the device reconnects.

## The time tree

One binary tree over keys: the 64 bits of the stamp first, then the 256 bits of the contribution hash.
Above the window level it is a dense binary tree over windows; below it, each window's subtree is sparse and stored compressed: only branch points are materialized, so a window with `n` contributions has about `n` internal nodes.
Inclusion and non-inclusion proofs both exist, and a range of time is proven by the handful of nodes that cover it.

Hashing follows the conventions already in `ihi/src/keyring.rs` and `vsf/src/tukutahi.rs`, domain-separated by a leading byte, with **spaghettify** as the hash (`ihi/SPAGHETTIFY.md` §5.3):

```
leaf      = spaghettify(0x00 ‖ key ‖ value)
node      = spaghettify(0x01 ‖ level ‖ left ‖ right)      -- inside a window subtree
empty     = the per-level zero hashes, as keyring.rs precomputes them
```

The compressed form collapses single-child paths, and the level byte keeps the result canonical: every node holding the same set computes the same root, bit for bit.
Order of arrival is irrelevant by construction.

## Chained roots and the levels above the window

```
R_w       = spaghettify(0x02 ‖ w ‖ subtree_root_w ‖ R_{w−1})     -- one per window, chained
U_k,j     = spaghettify(0x03 ‖ k ‖ U_{k−1,2j} ‖ U_{k−1,2j+1})   -- level k > W; U_W,w = R_w
B_w       = spaghettify(0x06 ‖ R_w)                             -- the public beacon
```

Chaining makes the history linear at the window level; the binary levels above make it short.
A verifier who trusts any high-level node needs only one hash per level to reach a window, and the window's subtree path to reach a contribution: from a stamp to level 2⁴⁰ is about 70 hashes, near 2 KB, carried by the anchored item itself.
The structure is the one tukutahi uses for media marks (`Mark.root`, `Mark.prev`, `vsf/src/tukutahi.rs:213-284`), one level up.

## What a level proves

The tree records stamps at oscillation resolution, but the pulse network **proves** bounds only at its own scale: about the window plus the grace period, tens of seconds.
Inside a window, a contribution's stamp is its contributor's claim (from its clock, nunc-checked, with `unc`), committed and ordered but not independently confirmed.

The not-before side has the same limit: a capture can include only roots that exist, and the newest closed root is at least a window plus the grace period old.
For a not-before good to seconds, a capture includes instead a sampled node's signed digest of the **still-open** window: its LtHash of the contributions so far, which is just as unpredictable, backed by that node's signature rather than a closed root.

## Fine time: local chains

Ordering at microsecond scale (permission grants, order books, matching engines, any system where who-was-first matters) needs a witness at the place where the events happen.
The pattern:

1. **The venue keeps a high-rate hash chain.** Each event is stamped at oscillation resolution with its uncertainty and chained to the previous one, as tukutahi marks and braid lanes already are. It proves order and fine time on the venue's authority, and it cannot be reordered or edited after the fact.
2. **The venue contributes its chain head to the pulse every window.** That binds the whole sequence to network time: every fine stamp in the batch must fall inside the pulse's bounds for it, or the venue is caught lying.
3. **Venues weave each other's heads into their chains** (the braid pattern), which orders events across venues down to the latency between them.

Physics sets the floor, as the patent's `locality` claim already uses: two events at different places, closer in time than their distance divided by the speed of light, have no order every observer agrees on (New York to London is about 19 ms).
Microsecond ordering is meaningful only within one place, which is where the venue's chain sits; across places the honest resolution is the light-travel time, which the cross-venue braid reaches.

So the layering is: fine time and order from local chains, at whatever resolution the venue's clock supports; absolute, tamper-evident time from the pulse, at the window; both held in the one oscillation-keyed tree, read at whatever level a use case needs.

## Dispersion

Contributions spread by gossip, deduplicated by contribution key, rate-limited per signer.
**Pulse gossip is open**, by the phonebook doctrine (`photon/docs/peers-are-fgtw.md:14`), unlike today's contact-gated gossip (`photon/src/network/status.rs:3938-3944`), which stays as it is for everything else.

During the grace period nodes reconcile their sets for the closing window:

- an **LtHash** running digest of the set (1024 × u16 lanes, wrapping add) lets two nodes test equality in one exchange and supports removal; it replaces, for the pulse, the order-free XOR digest of `SyncRecord` (`photon/src/network/fgtw/protocol.rs:199-202`), which detects a mismatch but cannot locate it;
- on mismatch, a set-reconciliation sketch (IBLT or minisketch) locates the differing contributions; nothing in the stack provides one yet.

## Root answers and sampling

A node answers "what is your root for window w" with a signed record using the existing control-message template (`timestamp`, `sender_pubkey`, `provenance_hash`, egg signature; `protocol.rs:8-174`), carrying:

- the window and the root it computed (or a higher level and its root);
- the signer's own chain head at signing time;
- the hash of the answer itself, **contributed to the next window**.

The last item is what defeats a stolen key: a forged "old" answer was never included in the window after the one it claims, and cannot be inserted now without breaking every later root.
Quoting an old chain head proves nothing by itself; inclusion does.

Answers are signed by default (cheap) and become portable evidence: two conflicting signed answers for one window from one node prove it lied, and an anchored file can carry a handful of signed answers so anyone can check it offline.

**Sampling** follows the patent (`fgtw_proofs.tex:104-121`; `patent.typ` tiers of 42, 64, 128):

- derive 256 candidate keys as `spaghettify(nonce ‖ w ‖ i)` for `i < 256`, with `nonce` from OS entropy;
- map each to the phonebook record nearest it in keyspace (the phonebook is already BLAKE3-addressed, `src/phonebook.rs:1-20`);
- take the first 42 answers (64 or 128 for tighter consensus); accept the majority root; record the outliers.

Weighting against Sybils draws on what exists: diversity of network origin as nunc's sampler does (`nunc/src/pool.rs:36-93`), the one-owner-per-device index (`fgtw-bootstrap/src/lib.rs:3019`), and fleet age once it is provable (below).
Queries fetch ranges (a level-2⁴⁰ span of window roots) rather than one window, so a query does not reveal which minute the asker cares about.

## Revocation

The pulse is the global, time-ordered revocation log lumis's design asks for (`revoke(ira, at_block)`, `lumis/docs/provenance.md:243-245`), without a new log.
Fleet Lock, Remove and succession ops already live in the fleet chain (`src/fleet.rs:71-82`); contributing each op's `chain_hash` anchors it in a window.
A verifier fetches the fleet chain, finds the revoking op, reads its window from its inclusion proof, and applies the rule: anchored before, valid; after, suspect.

## Fleet age

Today a fleet's age is self-asserted (`FleetOp.eagle_time`, "not load-bearing for auth", `src/fleet.rs:110`).
Contributing `genesis_hash` (`src/fleet.rs:431`) at genesis makes it provable from then on: a fleet is at least as old as the window its genesis was anchored in.
That gives sampling the age signal it lacks, for every fleet created after the pulse exists.

## History

- **Each anchored item carries its own proof.** After the window closes, the contributor fetches its inclusion path and stores it with the item; a VSF file appends it as a generation, leaving the original generation's hash and signatures intact.
- **Full nodes keep every window root,** about 650,000 a year at 2³⁶, near 21 MB. **Phones keep levels from 2⁴⁰ up,** about 41,000 roots a year, near 1.3 MB, and anything finer travels with the item it proves.
- **Leaves are kept for a retention window** (default 30 days) so contributors can fetch paths; beyond that, full logs are a voluntary archive service, never needed for verification.
- **Partitions:** each side closes its own windows; when the sides rejoin, a merge window includes both roots, and a lookup over a split returns both rather than picking one.
- **Physical anchoring** is optional and independent of the network: publishing year roots in print (a newspaper notice, a national library) lets them outlive any infrastructure.

## Privacy

From the constraints the stack already holds (`photon/docs/braid.md`, `lanes.md:28`, `keyring.md`, `lumis/docs/provenance.md:151-157`):

- **Never contribute raw identifiers or values.** A commitment is `spaghettify(salt ‖ tag ‖ value)` with the salt kept by its owner and revealed only for disclosure.
- **Do not sign with a raw device key.** Per-window signing keys derived unlinkably from the device secret, so contributions do not reveal which devices are active or how many a fleet has; the owner proves authorship later by revealing the derivation.
- **Batch per device per window**, which hides event counts; optional cover contributions in idle windows hide activity itself, at a cost to be measured.
- Anti-spam without identity: open decision (see below).

## Wiring into this crate

| piece | where | notes |
|---|---|---|
| `fgtw::pulse` core | new module, `no_std + alloc` | level math, contribution codec, the time tree with compressed window subtrees, chained roots, proof verification, root-answer codec. Compiles to WASM, so the worker and every client run identical verification |
| `fgtw::pulse::node` | new, behind a `pulse-node` feature (std) | contribution pool, gossip handling, dedup and rate limits, LtHash digest, reconciliation, closing |
| `fgtw::client` | extend | contribute, fetch inclusion path, query roots by range, sample |
| messages | new `PulseMessage` family in VSF sections | kept out of `FgtwMessage`, so it does not wait on the deferred step-5 enum split |
| peer list and DHT | pulls MIGRATION step 6 forward | sampling needs `peer_store`; the pulse is the consumer step 6 was waiting for |
| dependencies | `ihi` (spaghettify), `vsf` (eggs, Eagle time, codecs) | both already path deps of the stack |

**The worker during the transition** is one node among many, never an authority (`fgtw-bootstrap`):

- new sections `pulse_put`, `pulse_root`, `pulse_proof`;
- windows closed by a Durable Object alarm (the hourly cron, `src/lib.rs:4576-4630`, is too coarse for a 48 s window);
- leaves in R2 for the retention window;
- a root-closed bump through `PeerUpdateHub`;
- every root answer signed with the pinned FGTW key, as `handle_challenge` already signs (`src/lib.rs:1340-1360`).

Sampling weights the worker like any other answer, so the network does not depend on it.

## What the TOKEN apps contribute

| app | contributes | gains |
|---|---|---|
| photon | per-window batch of lane heads (`SyncRecord.lane_heads`), fleet head, checkpoint `ckpt_commit`, wave frame-set roots (`docs/waves.md:94-112`), custodian succession attestations | anchored message history; succession attestations "nunc-timestamped" as `device-trust-and-recovery.md:70` asks |
| fleet chain (fgtw) | `genesis_hash`, every op's `chain_hash` | provable fleet age; revocation ordering |
| lumis | per-photo manifest hash; run roots on reconnect | the not-before / not-after envelope of `docs/provenance.md` without an external chain |
| opsin | generation manifest hashes for edits and IDT pastes | provable edit history |
| chameleon | calibration and scan hashes | proof an IDT existed before the photos it characterized |
| vsf logs | head of each `verichrome.*.log.vsf` | tamper-evident, time-bounded logs |
| custodes | recovery and succession attestations | time-locked recovery (`patent.typ` `timelockedrecovery`) |
| rustdesk fork | session start and end | auditable remote sessions |
| ferros | billing attestations | the patent's `locality` rejection has anchored times to compare |
| toka | published bytecode hashes | provable publication order |
| calendar (planned) | event commitments | provable scheduling history |

## What it reuses

| from | piece | used for |
|---|---|---|
| photon `protocol.rs:8-174` | signed control-message template | root requests and answers |
| photon `protocol.rs:180-190` | `PeerRecord.local_seen` floor | refusing future-dated contributions |
| photon `braid.md` §14 | total order `(eagle_time, content_hash, tag)`; "sealing is an idempotent pure function of the merged prefix" | deterministic tie-breaks; the convergence argument for closing |
| fgtw `fleet.rs` | `chain_hash`, `extends`, `genesis_hash`, Lock/Unlock | revocation and fleet-age contributions |
| fgtw `phonebook.rs` | BLAKE3-addressed keyspace | candidate selection for sampling |
| ihi `keyring.rs` | zero hashes, domain prefixes, verify loop | the window subtrees (re-keyed by stamp and hash, compressed) |
| ihi `spaghettify` | the hash | tree nodes, chained roots, beacon, sampling keys |
| vsf `tukutahi.rs` | chained `Mark` pattern; grid naming doctrine; `unc_ns` | chained roots, level naming, stamp uncertainty |
| vsf `eggs.rs` | multi-scheme signatures | contribution and answer signatures |
| nunc | diversity-weighted, nonce-seeded sampler | Sybil weighting |
| worker | signed challenge, `PeerUpdateHub`, R2 | transition node |

## Gaps to build

0. The time tree: binary levels over stamps, compressed window subtrees, inclusion and non-inclusion proofs, incremental update.
1. Window closing and acceptance rules.
2. Open contribution gossip with dedup and per-signer rate limits.
3. Set reconciliation: LtHash digest plus a sketch that locates differences.
4. The `PulseMessage` family: contributions, root requests and answers, proof requests.
5. Peer sampling with weighting (moves `peer_store` and the DHT into the crate).
6. The worker's window closer on a Durable Object alarm.
7. Unlinkable per-window signing keys and the contribution privacy rules.
8. Optional ingestion of external beacons (drand, NIST) as extra not-before sources.

Suggested order: 0 and 1 (pure, testable in core), then 4 and 6 (the worker as sole closer, so apps can start contributing), then 2, 3 and 5 (peers close windows too and the worker becomes one witness among many), with 7 before any app contributes real user events.

## Open decisions

- **Window level.** 2³⁶ (≈ 48 s) is proposed, 2³⁷ (≈ 97 s) the alternative; it can change later without touching the tree or existing proofs.
- **Anti-spam.** Contributions must be cheap for real devices and expensive in bulk, without revealing who contributed: a per-window proof of work, a fleet-membership token, or rate limits by network origin.
- **Leaf retention.** 30 days proposed.
- **Cover contributions.** Whether devices contribute in idle windows to hide activity, and at what cost.
- **Transition.** Whether the worker closes windows alone at first, and when peers take over.
- **The patent appendix.** Whether to update `fgtw_proofs.tex` to define `M_n(t−1)` as the chained window root.
