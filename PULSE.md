# The pulse — FGTW's anchored time

Status: **design, 2026-10-12.** Nothing here is built.
This note specifies the pulse, how it wires into this crate and the worker, and which existing pieces of photon and the other TOKEN apps it reuses.

## What it is

The pulse is a value the whole FGTW network agrees on for every epoch of Eagle time.
It is unknowable before its epoch closes, fixed forever after, and computable by anyone holding that epoch's contributions.
It is owned by nobody: no blockchain, no fees, no external chain or calendar server.

It is the "previous modular state" `M_n(t−1)` in the node state of the TOKEN patent's FGTW appendix (`TOKEN/patent/appendix/fgtw_proofs.tex:30-36`), which names that slot without specifying it.

It is **anchoring**, the complement of **acquisition**.
Acquisition answers "what time is it now": nunc's interval intersection over nonce-selected witnesses (the patent's `consensus` claim, `/mnt/Harbor/Code/nunc`).
Anchoring answers "when did this exist": the pulse.
Together they are the mechanism behind the patent's `temporal` claim, proving when an event occurred.

Three uses:

- **Not before.** Anything that includes epoch e's root provably postdates epoch e.
- **Not after.** Anything whose hash is in epoch e's tree provably predates the close of epoch e.
- **Ordering of revocations.** A key revoked in epoch R: everything it anchored before R stands, anything after R is suspect, and nothing can be anchored into the past.

## Vocabulary

| term | meaning |
|---|---|
| contribution | a 32-byte commitment some device wants anchored, plus its framing (below) |
| epoch | a fixed span of Eagle time; epoch `e` covers `[e·L, (e+1)·L)` oscillations |
| epoch tree | the sparse Merkle tree of one epoch's contributions, keyed by contribution hash |
| epoch root | `R_e`, the chained root of epoch `e`: its tree root bound to `R_{e−1}` |
| roll-up | the root of a fixed run of epoch roots (hour, day, year), recursively |
| beacon | a public random value derived one-way from `R_e` |
| root answer | a node's signed statement of the root it computed for an epoch |
| inclusion path | the sibling hashes proving a contribution is in an epoch tree |

## Epochs

Epoch numbering follows the stack's grid doctrine (`photon/docs/lock.md` §1.2): names are exact integers, stamps are measurements.
`e = floor(eagle_oscillations / L)`, on the legacy Eagle scale already decided for stamps (`photon/docs/lock.md:469`).
`L` defaults to one minute, `60 × 1_420_407_826` oscillations; it is a network constant, not per node.

A contribution names its epoch.
A node accepts it into that epoch until the epoch's **close**: `(e+1)·L + G`, with `G` a grace period (default two epochs) during which nodes reconcile their sets.
A contribution arriving after the close is refused for that epoch; its author resubmits it into the current one.
A closed epoch never reopens.

## Contributions

A contribution is a VSF record:

| field | content |
|---|---|
| `commit` | the 32-byte commitment being anchored |
| `epoch` | the epoch number it targets |
| `signer` | the signing key (see Privacy) |
| `sig` | an egg list over the record (`vsf::eggs`, multi-scheme) |

Its **key** in the epoch tree is `spaghettify(DOMAIN_CONTRIB ‖ commit ‖ signer)`, so two signers anchoring the same commitment are two leaves and a contribution's position is a pure function of its content.
The leaf value is the hash of the full record, so the signature is committed too.

**Batching.** A device contributes at most one record per epoch: the Merkle root of every event it wants anchored that epoch (photos, message heads, fleet ops).
That bounds load, hides how many events a device had, and gives each event an inclusion path of two parts: event → device batch root, batch root → epoch tree.
lumis's run chain fits the same shape: one contribution for a whole offline run, the run's Merkle root, made when the device reconnects.

## The epoch tree

A depth-256 sparse Merkle tree keyed by contribution key, stored compressed: only branch points are materialized, so a tree of `n` contributions has about `n` internal nodes.
Inclusion and non-inclusion proofs both exist.

Hashing follows the conventions already in `ihi/src/keyring.rs` and `vsf/src/tukutahi.rs`, domain-separated by a leading byte, with **spaghettify** as the hash (`ihi/SPAGHETTIFY.md` §5.3):

```
leaf   = spaghettify(0x00 ‖ key ‖ value)
node   = spaghettify(0x01 ‖ depth ‖ left ‖ right)
empty  = the per-depth zero hashes, as keyring.rs precomputes them
```

The compressed form needs a canonical rule for collapsed paths (the depth byte above), so that every node holding the same set computes the same root bit for bit.
Order of arrival is irrelevant by construction.

## Chained roots and roll-ups

```
R_e      = spaghettify(0x02 ‖ e ‖ tree_root_e ‖ R_{e−1})
hour_h   = merkle(0x03, R_e for the 60 epochs of hour h)
day_d    = merkle(0x04, hour roots of day d)
year_y   = merkle(0x05, day roots of year y)
B_e      = spaghettify(0x06 ‖ R_e)                         -- the public beacon
```

Hours, days and years are fixed spans of Eagle time (3,600 s, 86,400 s, 365 Eagle days), not civil calendar units.
Chaining makes the history linear; roll-ups make it short: a verifier who trusts a year root needs only a path down to one minute.
The structure is the same one tukutahi uses for media marks (`Mark.root`, `Mark.prev`, `vsf/src/tukutahi.rs:213-284`), one level up.

## Dispersion

Contributions spread by gossip, deduplicated by contribution key, rate-limited per signer.
**Pulse gossip is open**, by the phonebook doctrine (`photon/docs/peers-are-fgtw.md:14`), unlike today's contact-gated gossip (`photon/src/network/status.rs:3938-3944`), which stays as it is for everything else.

During the grace period nodes reconcile their sets for the closing epoch:

- an **LtHash** running digest of the set (1024 × u16 lanes, wrapping add) lets two nodes test equality in one exchange and supports removal; it replaces, for the pulse, the order-free XOR digest of `SyncRecord` (`photon/src/network/fgtw/protocol.rs:199-202`), which detects a mismatch but cannot locate it;
- on mismatch, a set-reconciliation sketch (IBLT or minisketch) locates the differing contributions; nothing in the stack provides one yet.

## Root answers and sampling

A node answers "what is your root for epoch e" with a signed record using the existing control-message template (`timestamp`, `sender_pubkey`, `provenance_hash`, egg signature; `protocol.rs:8-174`), carrying:

- the epoch and the root it computed (or roll-up level and root);
- the signer's own chain head at signing time;
- the hash of the answer itself, **contributed to the next epoch**.

The last item is what defeats a stolen key: a forged "old" answer was never included in the epoch after the one it claims, and cannot be inserted now without breaking every later root.
Quoting an old chain head proves nothing by itself; inclusion does.

Answers are signed by default (cheap) and become portable evidence: two conflicting signed answers for one epoch from one node prove it lied, and an anchored file can carry a handful of signed answers so anyone can check it offline.

**Sampling** follows the patent (`fgtw_proofs.tex:104-121`; `patent.typ` tiers of 42, 64, 128):

- derive 256 candidate keys as `spaghettify(nonce ‖ e ‖ i)` for `i < 256`, with `nonce` from OS entropy;
- map each to the phonebook record nearest it in keyspace (the phonebook is already BLAKE3-addressed, `src/phonebook.rs:1-20`);
- take the first 42 answers (64 or 128 for tighter consensus); accept the majority root; record the outliers.

Weighting against Sybils draws on what exists: diversity of network origin as nunc's sampler does (`nunc/src/pool.rs:36-93`), the one-owner-per-device index (`fgtw-bootstrap/src/lib.rs:3019`), and fleet age once it is provable (below).
Queries fetch ranges (an hour of roots) rather than one epoch, so a query does not reveal which minute the asker cares about.

## Revocation

The pulse is the global, time-ordered revocation log lumis's design asks for (`revoke(ira, at_block)`, `lumis/docs/provenance.md:243-245`), without a new log.
Fleet Lock, Remove and succession ops already live in the fleet chain (`src/fleet.rs:71-82`); contributing each op's `chain_hash` anchors its epoch.
A verifier fetches the fleet chain, finds the revoking op, reads its epoch from its inclusion proof, and applies the rule: anchored before, valid; after, suspect.

## Fleet age

Today a fleet's age is self-asserted (`FleetOp.eagle_time`, "not load-bearing for auth", `src/fleet.rs:110`).
Contributing `genesis_hash` (`src/fleet.rs:431`) at genesis makes it provable from then on: a fleet is at least as old as the epoch its genesis was anchored in.
That gives sampling the age signal it lacks, for every fleet created after the pulse exists.

## History

- **Each anchored item carries its own proof.** After the epoch closes, the contributor fetches its inclusion path and stores it with the item; a VSF file appends it as a generation, leaving the original generation's hash and signatures intact.
- **Every node keeps every epoch root,** 32 bytes a minute, about 17 MB a year.
- **Leaves are kept for a retention window** (default 30 days) so contributors can fetch paths; beyond that, full logs are a voluntary archive service, never needed for verification.
- **Partitions:** each side closes its own epochs; when the sides rejoin, a merge epoch includes both roots, and a lookup over a split returns both rather than picking one.
- **Physical anchoring** is optional and independent of the network: publishing year roots in print (a newspaper notice, a national library) lets them outlive any infrastructure.

## Privacy

From the constraints the stack already holds (`photon/docs/braid.md`, `lanes.md:28`, `keyring.md`, `lumis/docs/provenance.md:151-157`):

- **Never contribute raw identifiers or values.** A commitment is `spaghettify(salt ‖ tag ‖ value)` with the salt kept by its owner and revealed only for disclosure.
- **Do not sign with a raw device key.** Per-epoch signing keys derived unlinkably from the device secret, so contributions do not reveal which devices are active or how many a fleet has; the owner proves authorship later by revealing the derivation.
- **Batch per device per epoch**, which hides event counts; optional cover contributions in idle epochs hide activity itself, at a cost to be measured.
- Anti-spam without identity: open decision (see below).

## Wiring into this crate

| piece | where | notes |
|---|---|---|
| `fgtw::pulse` core | new module, `no_std + alloc` | epoch math, contribution codec, compressed SMT, chained roots, roll-ups, proof verification, root-answer codec. Compiles to WASM, so the worker and every client run identical verification |
| `fgtw::pulse::node` | new, behind a `pulse-node` feature (std) | contribution pool, gossip handling, dedup and rate limits, LtHash digest, reconciliation, closing |
| `fgtw::client` | extend | contribute, fetch inclusion path, query roots by range, sample |
| messages | new `PulseMessage` family in VSF sections | kept out of `FgtwMessage`, so it does not wait on the deferred step-5 enum split |
| peer list and DHT | pulls MIGRATION step 6 forward | sampling needs `peer_store`; the pulse is the consumer step 6 was waiting for |
| dependencies | `ihi` (spaghettify), `vsf` (eggs, Eagle time, codecs) | both already path deps of the stack |

**The worker during the transition** is one node among many, never an authority (`fgtw-bootstrap`):

- new sections `pulse_put`, `pulse_root`, `pulse_proof`;
- epochs closed by a Durable Object alarm (the hourly cron, `src/lib.rs:4576-4630`, is too coarse for one-minute epochs);
- leaves in R2 for the retention window;
- a root-closed bump through `PeerUpdateHub`;
- every root answer signed with the pinned FGTW key, as `handle_challenge` already signs (`src/lib.rs:1340-1360`).

Sampling weights the worker like any other answer, so the network does not depend on it.

## What the TOKEN apps contribute

| app | contributes | gains |
|---|---|---|
| photon | per-epoch batch of lane heads (`SyncRecord.lane_heads`), fleet head, checkpoint `ckpt_commit`, wave frame-set roots (`docs/waves.md:94-112`), custodian succession attestations | anchored message history; succession attestations "nunc-timestamped" as `device-trust-and-recovery.md:70` asks |
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
| ihi `keyring.rs` | zero hashes, domain prefixes, verify loop | the epoch tree (re-keyed, compressed) |
| ihi `spaghettify` | the hash | tree nodes, chained roots, beacon, sampling keys |
| vsf `tukutahi.rs` | chained `Mark` pattern; grid naming doctrine | roots and epoch numbering |
| vsf `eggs.rs` | multi-scheme signatures | contribution and answer signatures |
| nunc | diversity-weighted, nonce-seeded sampler | Sybil weighting |
| worker | signed challenge, `PeerUpdateHub`, R2 | transition node |

## Gaps to build

0. The compressed sparse Merkle tree keyed by hash, with inclusion and non-inclusion proofs and incremental update.
1. Epoch numbering and closing rules.
2. Open contribution gossip with dedup and per-signer rate limits.
3. Set reconciliation: LtHash digest plus a sketch that locates differences.
4. The `PulseMessage` family: contributions, root requests and answers, proof requests.
5. Peer sampling with weighting (moves `peer_store` and the DHT into the crate).
6. The worker's epoch closer on a Durable Object alarm.
7. Unlinkable per-epoch signing keys and the contribution privacy rules.
8. Optional ingestion of external beacons (drand, NIST) as extra not-before sources.

Suggested order: 0 and 1 (pure, testable in core), then 4 and 6 (the worker as sole closer, so apps can start contributing), then 2, 3 and 5 (peers close epochs too and the worker becomes one witness among many), with 7 before any app contributes real user events.

## Open decisions

- **Epoch length.** One minute is proposed; shorter tightens the envelope, longer cuts root count.
- **Anti-spam.** Contributions must be cheap for real devices and expensive in bulk, without revealing who contributed: a per-epoch proof of work, a fleet-membership token, or rate limits by network origin.
- **Leaf retention.** 30 days proposed.
- **Cover contributions.** Whether devices contribute in idle epochs to hide activity, and at what cost.
- **Transition.** Whether the worker closes epochs alone at first, and when peers take over.
- **The patent appendix.** Whether to update `fgtw_proofs.tex` to define `M_n(t−1)` as the chained epoch root.
