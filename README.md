<p align="center">
  <img src="fgtw.webp" alt="FGTW — Fractal Gradient Trust Web" width="360" />
</p>

# fgtw — Fractal Gradient Trust Web

The client substrate for **TOKEN identity**: one identity, many apps.

A calendar, a messenger, any TOKEN app rides the *same* fleet — same device keys, same membership chain, same per-member fan-out — and stores its own state in its own sealed scope.
This crate is that substrate, shared by every app and by the FGTW worker itself.

> **Status: `0.0.0` — name reservation + architecture scaffold.**
> The modules are stubs.
> Real code migrates in from an existing implementation (`photon`) module by module, keeping every consumer green at each step — see [`MIGRATION.md`](MIGRATION.md).
> Not usable yet; watch the version.

## What it is

Most systems bolt identity onto each app.
FGTW inverts that: your **fleet** — the set of devices you own, as a signed, hash-chained membership record — is the identity, and every app you run rides it.
Add a device once and every app gains it; revoke a device once and every app loses it.

Each app gets its own **sealed scope** in the fleet's shared state, so a calendar's events and a messenger's roster live side by side, each readable only by an authorized member device, never by the storage that holds them.

## Shape

- **core** (`no_std`) — the fleet membership chain (fold / verify / extend), the per-member fan-out of scoped keys, and the wire-protocol codec.
  Compiles to WASM, so the server worker and every client run the *same* verification logic — no client/server drift.
- **client** (feature, `std`) — the HTTP oracle: fetch-then-sign, announce, publish.
  Real apps enable it; the worker never does.

## What's here vs not

**Here (generic identity substrate):** device-key derivation, attestation/announce, fleet membership, the fan-out of scoped-key bundles, fleet-shared state, avatar/blob storage, the FGTW wire protocol.

**Not here (app-specific):** messaging (key exchange, transport, presence, conversations) stays in the app.
FGTW is *who you are across your devices*, not *how you talk*.

## Security model, honestly

- **Held everywhere, readable nowhere.** Peers and the backing store hold only ciphertext; keys are sealed per-device in the fan-out.
- **Integrity over availability.** State is fetched by newest signed epoch, so a query can be *denied* by unavailable or lying nodes but never *deceived* — one honest, reachable copy is enough, and the rest can be hostile.
- **Revocable at rest.** Because the vault-wrapping key is fetched from the fan-out rather than stored on the device, removing a device stops it decrypting even its *local* data — revocation reaches backward, not just forward.
- **The honest floor.** Live-RAM key extraction and hibernation are not closeable in userspace; those are the hardware-sealing (secure-element / PIPE) endgame.
  Software raises the bar a lot; silicon draws the floor.

## License

MIT OR Apache-2.0.
