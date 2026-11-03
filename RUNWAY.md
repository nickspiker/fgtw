# FGTW Runway

Nov 2, 2026 · Nick Spiker

## Thesis

Carriers own people because they issue the credential. The IMSI and Ki on a SIM is the only identity a phone has, and the carrier mints it. Take issuance away from them and a carrier is a reseller of coverage, nothing more. (link to https://holdmyoscilloscope.com/log/sim/)

FGTW is the data utility that makes that real: a member-governed, at-cost, data-only network where service is granted to a human (a TOKEN handle), never to a SIM or a device. The carrier under it is a wholesale pipe. The identity above it belongs to the person and to nobody else.

This is year 4 of 42. The end state is not a product. It is a world where owning your own identity is ambient, like TLS: nobody thinks about it, and nobody can take it.

## Invariants

These are the rules the governing body cannot amend. Everything else is up for a vote.

1. **No compellable secret.** No component of FGTW, Photon or TOKEN may ever hold a secret that a court, a government or a thief could take and use. Full legal cooperation with any demand must yield zero actionable intelligence. The one exception is the carrier attach credential (Ki), which lives at the sponsor carrier, not with FGTW, and buys an attacker coverage, not identity. Ki is a Phase 1 and 2 artifact. Phase 3 is defined by its disappearance: once the handle is the attach credential, no carrier mints a secret for anyone.
2. **Attestations are never bearer instruments.** Reputation is non-transferable and multidimensional. A score can be sold; an attestation cannot. Nothing in the system may compress a human into a transferable token.
3. **Anyone can issue it, nobody can own it.** Custodians are elected by the user and portable. Attestations are indistinguishable by issuer at the verifier. Hardware secrets are provisioned by the owner, never a vendor.
4. **Service follows the human, not the device.** Access is granted to a handle. A SIM, an IMEI or a device is plumbing.
5. **Data only, no PSTN, ever.** FGTW never carries, markets, bundles or provisions voice or SMS. Wave and Beam are peer to peer between handles. The moment anything dials a phone number, every regime FGTW is built to avoid comes back.
6. **No owner.** No equity, no dividends, no founder clause. Surplus lowers next period's price. Nick is a member on the same terms as everyone else, or he is not a member.

## Where it stands

Each piece is labelled at its true confidence. Running means it works today on real hardware. Designed means the spec exists and nothing has been built. Bet means it depends on the world cooperating.

| Piece | What it is | Status |
| --- | --- | --- |
| TOKEN / passless | User-sovereign credential, no password, no account, no server | Running. Working demo, open code, 88-page spec. Provisional filed 24 Jun 2026 |
| Photon | Messaging, Wave (voice), Beam (video), bridge (remote access) over CLUTCH | Running. Live with real contacts since Jul 2026. Beam in progress. |
| CLUTCH | 8-primitive post-quantum key exchange | Running. Spec v3.0 draft |
| ferros | Capability OS, bare metal, modem as untrusted peripheral | Running on Pixel 8 Pro: display, touch, all cores, cameras, data-only eSIM. No GPU, no carrier voice |
| PIPE | 3-pin isolated enclave, owner-provisioned secret | Software only. Silicon Verilog bit-exact with the software. Provisional filed 17 Jun 2026 |
| Spirix | Two's complement floating point | Silicon-verified on FPGA. Non-provisional filed 14 May 2026, Track One |
| ISOMEM | Pageless memory protection | Provisional filed 16 May 2026 |
| FGTW network | Data-only utility, handle-gated, sponsor carrier underneath | Specification designed, scaffolding code written and deployed |
| Glyph | The full meal deal | Designed. Spec drafted Aug 2026. Years 9-12 hardware |
| Dumb watch | 3 mm e-ink notification watch, \~1 yr battery | Prototype works. Candidate hardware PIPE anchor for Pixels |
| Phase 3 and 4 | Carriers commoditize, sovereignty becomes ambient | Bet |

## Entities

FGTW is probably going to be born as a Wyoming nonprofit association. It likely starts as a UNA and becomes a DUNA at 100 members. Still in founding stages and pending legal evaluation.

| Entity | Form | Holds | Why this form |
| --- | --- | --- | --- |
| FGTW | Wyoming UNA, converting to DUNA at 100 members (W.S. 17-32) | Governing principles, the Rust governance program, the MVNE/sponsor contract, the PUD service-provider seat, domains | Statute says members are not owners, no dividends, governance may be read from a ledger. Separate legal entity for contracts and torts |
| DUMB PIPE Inc. | Corporation, state TBD | Patents (TOKEN, PIPE, ISOMEM, Spirix) once non-provisionals issue; fiat conversion; carrier billing in USD | Quarantines fiat, tax and regulatory contact away from the association. Nick assigns 100% of the patents here and owns zero |
| Kaitiakitanga | Not an entity. The recurring molecule of kaitiaki | Nothing | The founding cohort of the UNA and the people who hold the keys after handoff |

The PUDs (Kitsap, Grays Harbor) are partners, not entities FGTW can form. They supply open-access fibre backhaul and the legal ISP seat. The co-op is the language, not the wrapper: at cost, member governed, no owners.

## Membership

One human, one membership, no founder clause. Nick qualifies the same way everyone does.

**To become a member, all five:**

1. **Handle.** Membership is bound to a TOKEN handle. No handle, no membership. The network's Sybil resistance is the roll's Sybil resistance.
2. **Patron.** Active service on FGTW, paid at cost, for 30 days. You are served by it, so you govern it.
3. **Vouched.** Two existing members attest you are a person they know. Vouchers are on record. A captured member brings their vouchers' standing down with them.
4. **Consented.** You have signed the governing principles, invariants included. The handle proves which human signed.
5. **Seasoned.** Voting rights start 90 days after membership. Membership is immediate; power is not.

**To lose it, one of two:**

- Release. You leave. Bilateral, final, same as a device leaving a fleet.
- A member vote finds you broke the governing principles. No administrator can remove a member alone, Nick included.

**Founding exception.** At formation there are no lines and no members to vouch. The kaitiaki present at formation vouch for each other, once, on a dated record. That exception closes the day the record is signed. Anyone who later Releases and returns, Nick included, qualifies under the five rules.

## Governance and handoff

The keys leave Nick's hands the day the governing body is solid, and they do not come back. Until then he is the single point of failure, and fixing that is the first job of the kaitiaki.

**Order of authority.** The governing principles are the source of authority. The Rust governance program implements them. Where the program and the text disagree, the text wins and the program gets fixed. A court reads text.

**What members decide by vote:** price, sponsor, administrators, admission disputes, amendments to anything not in the invariants. Proposal, vote, timelock, then the program executes. No unilateral change-of-terms, ever.

**What administrators do:** operational tasks at the direction of the membership, as the statute puts it. They cannot admit, remove, or spend outside a passed proposal.

**Handoff, in order:**

1. Kaitiaki sign the governing principles and form the UNA.
2. A second person can run everything without Nick: repos, domains, Cloudflare, filings, a share of the recovery material. This is the bus test and it is cheap.
3. Recovery material for every FGTW secret is split across kaitiaki under the custodian model (x of y, custodians hold it, not Nick).
4. Membership crosses 100 and the UNA converts to a DUNA.
5. Press go. Nick's administrative keys are destroyed on a dated record. He is a member with one vote.

After step 5, decisions belong to the body. If the body decides wrong, that is the body's to fix, not Nick's to veto.

## Network plan

Use the SIM like they designed it. The eUICC is a certified secure element with a per-chip key, and the sponsor's HSS enforces one registration per IMSI. That is FGTW's Sybil defence for profiles, and the carrier runs it for free. FGTW has no lines: a handle has service, and its fleet carries as many profiles as it has devices.

**Sponsor.** FGTW is a light MVNO. A sponsor carrier or MVNE holds the HSS and Ki, runs the SM-DP+, and downloads profiles. FGTW holds nothing it could be compelled to hand over. A regional operator (Nomad in Kalispell is the type) is the first conversation, not T-Mobile. Wholesale is a sponsor-finding problem, not a technical one.

**Profiles.** Identical apart from per-device identity. Bind each profile in the fleet to the handle at enrollment. A cloned identity on a second device flaps, it does not get service. An eSIM swap at the carrier is a Revoke-and-reissue event on the handle, never something to recover thru.

**IMEI.** Use a certified cellular module and let its IMEI be the IMEI. A minted TAC is refused by the carrier EIR. FGTW's own TAC means GSMA membership and device certification, a Phase 2 cost.

**Device tiers.** Service follows the handle; the tier sets how much the backend trusts the device. Hidden domain separators let FGTW gate by tier without any verifier seeing issuer or level.

| Tier | Device | Identity root | Gets |
| --- | --- | --- | --- |
| Glyph | Portless sovereign phone | PIPE in silicon, owner-provisioned | Full FGTW service |
| Pixel + watch | Pixel 8 Pro on ferros, dumb watch with PIPE paired over Photon Transport | Hardware PIPE in the watch | Full FGTW service |
| Pixel | Pixel 8 Pro on ferros | Software PIPE | Photon, Wave, Beam. Bring your own data, or pilot service |

**Guests.** An identity is born only on ferros, Glyph or a PIPE, where the owner provisions the secret and the OS that takes the handle is the owner's. Everything else, a Photon on Android or on a desktop, is a guest of the fleet: a device key bound in by a sovereign device and revocable from one, able to message and be messaged, unable to mint, vouch, add devices or hold recovery material. A captured guest loses its own sessions and nothing else. Android on a ferros Pixel is the owner's choice (no restrictions, opt in after attest, never the default, supervised by the hypervisor and unsupported), and it is a guest like any other.

## Regulatory posture

Data only with no PSTN touch point drops roughly a dozen federal regimes to three filings and a label. Mobile broadband is an information service after the Sixth Circuit's January 2025 ruling, not a Title II common carrier service.

| Regime | Applies to FGTW | Why |
| --- | --- | --- |
| E911, text-to-911 | No | Attaches to CMRS voice and interconnected VoIP |
| CALEA build obligation | No | Falls on the facilities-based host carrier; an MVNO is not facilities-based. Put it in the sponsor contract |
| USF, TRS, per-line FCC fees | No | Broadband access revenue is not assessable. File 499-A, claim de minimis |
| Numbering, LNP, STIR/SHAKEN, robocall | No | No phone numbers |
| CPNI (s.222) | No | Telecom carrier rule. State privacy law and FTC still apply |
| Broadband consumer label | Yes | All BIAS providers. One plan, one label |
| WA net neutrality (RCW 19.385) | Yes | Unaffected by the Sixth Circuit. Handle gating must read as access control, not content discrimination. Counsel question |
| FCC 499-A registration, FRN | Yes | Even if exempt |
| Equipment authorization | Yes, Glyph only | Part 15/22/24/27, SAR. No HAC without voice |
| State sales tax | Yes | No 911 surcharge, which is per voice line in WA |
| Subpoenas, lawful process | Yes | Answered by the no-compellable-secret invariant, not by CALEA |

**Voice apps.** Google Voice or any VoIP app in Glyph's APK sandbox is that provider's regulatory problem. FGTW never markets, bundles or provisions it. Written policy, not just a fact.

**911 on Glyph.** It cannot dial 911 and no rule requires a data device to. Tell people plainly: Glyph is a data device like a tablet. Carry a phone or run a VoIP app with a registered address.

**Payments.** Tap to pay is EMV over NFC, and host card emulation needs no secure element and no Google: Visa and Mastercard issue device tokens to registered token requestors, which is how Curve, Garmin and the banks' own wallets pay without Google Wallet. The route is DUMB PIPE Inc. as a token requestor (the fiat entity, the one that signs contracts) and a wallet of ferros's own, keyed to the handle: keys issued the way the networks want them issued, on a device whose security argument they can read, bringing them transactions they do not have today. It is a certification and a contract, nothing else. Until it exists, the wallets that do not demand Google's integrity verdict are the ones to run as APKs on ferros. What FGTW never does: fake a Play Integrity verdict or a device attestation to obtain a token. Lying to a financial institution's security control to get a payment credential is a fraud question, not a terms-of-service one, and no ferros or hypervisor code hides root or spoofs a device for anyone (Nick, 2 Nov 2026: "if it means breaking the law, nope").

## Runway

&#91;embedded content: FGTW runway · 5 phases, 1 hard gate\]

The only hard-dated gate is the TOKEN non-provisional, 24 June 2027. Everything else is sequenced, not dated.

**Next twelve months, in order:**

1. Kaitiakitanga convenes (4 Nov 2026). Governing principles drafted from the invariants and membership rules above.
2. A second person can run everything. Repos, domains, Cloudflare, filings, recovery share.
3. Wyoming UNA formed by the kaitiaki. Governing principles signed on a dated record.
4. Sponsor conversation opened with a regional operator. The PUD service-provider seats taken.
5. TOKEN non-provisional filed. Funding for it resolved, by someone else paying or by Nick accepting the cost.
6. Fifty-Pixel pilot on software PIPE, three months. PIPE watch built in parallel.
7. First service on the sponsor network. (Seabrook CBRS, if ever, is a later and smaller thing.)
8. Membership crosses 100. UNA converts to DUNA. Press go: Nick's keys destroyed on a dated record.

Steps 1 to 3 need no money and no outside party. Steps 4 to 7 need a sponsor and a fiat float. Step 8 needs 100 humans who have passed the membership test.

## What is needed now

Ranked by what kills the plan if it is missing. The first three cost nothing but people.

| # | Need | Why it is first | Who at the table can move it |
| --- | --- | --- | --- |
| 1 | A second person who could run it | Nick is the single point of failure. Nobody else knows where the repos, domains, filings and recovery material are | Telecom PM or construction people: they run operations and are not developers |
| 2 | The entity | Without it there is no one to sign a sponsor contract, take a patent assignment or hold a PUD seat | Kaitiaki sign the UNA. Counsel reviews |
| 3 | An explanation that survives without Nick | Everyone who understands the plan learned it from him talking. A one-pager that a branch owner can repeat to a home office | This document, cut to one page |
| 4 | The TOKEN non-provisional, 24 Jun 2027 | Hard date. Attorney cost in the low five figures. Conflicts with the no-money principle and has to be resolved | Nobody at the table. Flag it |
| 5 | One verifier that is not Nick | Passless has a demo, code and spec, and zero third parties accepting it. | No idea |
| 6 | A sponsor conversation | FGTW needs an MVNE or regional operator willing to hold the HSS and download profiles | The Nomad (Kalispell) connection. Technical contact, not sales |
| 7 | Users outside the family | Fifty strangers on Photon who Nick does not support personally | Digital creator friends, not telecom people |

Not needed yet: Glyph hardware partners, carrier wholesale contracts, GSMA anything, a marketing firm. All of those wait on items 2 and 4.

## Open questions for counsel

None of this document is legal advice. These are the questions a lawyer earns their fee on.

- [ ] UNA to DUNA sequencing under W.S. 17-32, and what SF0022 (effective 1 Jul 2026) changed about distributions and winding up
- [ ] Whether the invariants can be made unamendable in the governing principles, or only amendable at a supermajority, and which a court will respect
- [ ] Can a Wyoming nonprofit association sign an MVNE wholesale contract and register as a service provider on a Washington PUD open-access network
- [ ] Washington net neutrality (RCW 19.385): does handle-based traffic gating read as access control or as discrimination between lawful content
- [ ] CALEA allocation in the sponsor contract: confirm the facilities-based host carries the intercept obligation
- [ ] 501(c)(12) fit, if ever: member-income test with global membership, and whether rate reduction counts as returning savings at cost
- [ ] Patent assignment path: Nick to DUMB PIPE Inc., and the patent non-assertion pledge for conforming passless implementations
- [ ] NZ absolute novelty: which Glyph details are unfiled and must not be disclosed at Kaitiakitanga before filing
- [ ] Token requestor registration with Visa (VTS) and Mastercard (MDES) by DUMB PIPE Inc.: eligibility, certification, PCI scope, and whether a wallet that only holds network tokens for the user's own cards is a money transmitter or an MSB
- [ ] The line between a terms breach and a crime when a device presents a false integrity verdict or attestation to a payment network, so the written policy (never) rests on counsel's words, not ours

**Sources**

- [Wyoming DUNA Act, W.S. 17-32 (enrolled SF0050, 2024)](https://www.wyoleg.gov/2024/Enroll/SF0050.pdf)
- [SF0022 (2026) DUNA amendments, summary](https://www.wyoleg.gov/2026/Summaries/SF0022.pdf)
- [WA PUD retail broadband laws, HB 1336 and SB 5383](https://www.wpuda.org/retail-broadband-laws-go-into-effect-july-25--2021)
- [Sixth Circuit vacates Title II order, Jan 2025](https://www.dwt.com/blogs/broadband-advisor/2025/01/6th-circuit-fcc-net-neutrality-order)
- [Grays Harbor PUD fibre expansion](https://communitynetworks.org/content/grays-harbor-pud-hits-phase-four-major-fiber-expansion)
