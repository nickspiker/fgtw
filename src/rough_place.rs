//! A rough place from the network address a request arrives from — the seed call a GPS receiver asks before its first lock, so it can predict which satellites are overhead (ferros, branch gps-rough-fix).
//!
//! **fgtw.org is the last resort, and this call is acceptable only because it adds no new watcher.**
//! The ask carries no identity, no device key and no handle: one fresh nonce, nothing else.
//! The place is read from what Cloudflare already derives from the request's network address (`request.cf`: coordinates, city, region, ASN, country), so only Cloudflare sees where the request came from, exactly as it does for every other request.
//! The worker keeps nothing, logs nothing about the asker and stores nothing; the answer is computed and forgotten.
//!
//! **The device should ask this last.**
//! Its own last fix comes first, then its own devices' answers (a sibling in the same fleet that holds a fix), and only when neither exists this call.
//!
//! **Wire.**
//! The ask is a complete VSF document (hp + hb, unsigned) with one section, [`ASK_SECTION`], field `nonce` (`hR`, 32 fresh bytes).
//! The reply is a complete VSF document signed with the seed's Ed25519 key, the same key and the same canonical signing the pipe challenge uses, created at the seed's Eagle time, with one section [`REPLY_SECTION`]:
//! - `nonce` (`hR`): the ask's, echoed, so a reply fits the one ask it answers;
//! - `at` (`w`, WorldCoord): the place, on a grid of 2^-[`GRID_SHIFT`] degrees in latitude and longitude;
//! - `radius` (unsigned, metres): how far the true place may lie, [`RADIUS_CITY`] when Cloudflare names a city, [`RADIUS_REGION`] when it names only a region, [`RADIUS_COUNTRY`] when it names neither;
//! - `asn` (unsigned): the network's autonomous system number, absent when Cloudflare gives none;
//! - `country` (`a`): the two ISO 3166-1 letters, absent when Cloudflare gives none or a code that is not two letters (`T1`, Tor).
//!
//! When Cloudflare gives no coordinates the section carries `nonce` alone: a signed "unknown" bound to this ask, which [`verify_reply`] reads as `Ok(None)`.
//! The nonce rides in the unknown reply too, so a captured "unknown" cannot be replayed against a later ask.
//!
//! The ask's creation time is not read by the seed: a device with no clock yet still asks, and the reply's signed creation time ([`RoughPlace::time`]) is a rough clock as well.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use vsf::schema::{SectionBuilder, SectionSchema, TypeConstraint};
use vsf::types::{VsfType, WorldCoord};

/// The ask's section name, which the worker dispatches on.
pub const ASK_SECTION: &str = "rough_place_ask";
/// The reply's section name.
pub const REPLY_SECTION: &str = "rough_place";
/// The place's grid: 2^-7 degrees (about 870 m of latitude), coarse enough that the reply names an area and not a house.
pub const GRID_SHIFT: u32 = 7;
/// The radius when Cloudflare names a city: 2^15 m, about 33 km.
pub const RADIUS_CITY: u32 = 1 << 15;
/// The radius when Cloudflare names a region but no city: 2^19 m, about 524 km.
pub const RADIUS_REGION: u32 = 1 << 19;
/// The radius when Cloudflare gives coordinates but names neither a city nor a region (a country's centroid): 2^22 m, about 4,200 km.
pub const RADIUS_COUNTRY: u32 = 1 << 22;

/// The ask's schema.
fn ask_schema() -> SectionSchema {
    SectionSchema::new(ASK_SECTION).field("nonce", TypeConstraint::AnyHash)
}

/// The reply's schema.
/// VSF has no WorldCoord constraint, so `at` takes any value here and the reader matches the `w` marker itself.
fn reply_schema() -> SectionSchema {
    SectionSchema::new(REPLY_SECTION)
        .field("nonce", TypeConstraint::AnyHash)
        .field("at", TypeConstraint::Any)
        .field("radius", TypeConstraint::AnyUnsigned)
        .field("asn", TypeConstraint::AnyUnsigned)
        .field("country", TypeConstraint::AsciiText)
}

/// What the seed saw for an ask, already on the grid: the worker fills it from `request.cf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    /// Latitude in steps of 2^-[`GRID_SHIFT`] degrees.
    pub lat_steps: i32,
    /// Longitude in steps of 2^-[`GRID_SHIFT`] degrees.
    pub lon_steps: i32,
    /// Metres.
    pub radius: u32,
    /// `None` when Cloudflare gives no ASN.
    pub asn: Option<u32>,
    /// The two ISO 3166-1 letters, `None` when Cloudflare gives no two-letter code.
    pub country: Option<[u8; 2]>,
}

/// A verified rough place, as the device reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoughPlace {
    /// The place, on the 2^-[`GRID_SHIFT`] degree grid.
    pub at: WorldCoord,
    /// How far the true place may lie from `at`, in metres.
    pub radius: u32,
    pub asn: Option<u32>,
    pub country: Option<[u8; 2]>,
    /// The seed's Eagle time when it answered, in oscillations.
    pub time: i64,
}

/// The degrees a grid step count names.
pub fn steps_to_degrees(steps: i32) -> f64 {
    steps as f64 / (1u32 << GRID_SHIFT) as f64
}

/// The ask: the document to POST to the seed and the nonce its reply must echo.
/// The nonce comes from [`crate::random32`] (a `no_std` embedding registers its entropy with `set_entropy` first) and the creation time from [`crate::now_oscillations`].
pub fn ask() -> Result<(Vec<u8>, [u8; 32]), String> {
    let nonce = crate::random32();
    Ok((ask_with(&nonce, crate::now_oscillations())?, nonce))
}

/// [`ask`] with the nonce and time given.
pub fn ask_with(nonce: &[u8; 32], time: i64) -> Result<Vec<u8>, String> {
    let body = ask_schema()
        .build()
        .set("nonce", VsfType::hR(nonce.to_vec()))
        .and_then(|b| b.encode())
        .map_err(|e| format!("rough_place ask: {e:?}"))?;
    vsf::VsfBuilder::new()
        .creation_time_oscillations(time)
        .add_unboxed(ASK_SECTION, body)
        .build()
        .map_err(|e| format!("rough_place ask build: {e}"))
}

/// The seed's read of an ask: its nonce, after the document verifies.
pub fn read_ask(bytes: &[u8]) -> Result<[u8; 32], String> {
    let section = SectionBuilder::parse_document(ask_schema(), bytes, None).map_err(|e| format!("rough_place ask: {e:?}"))?;
    nonce_of(&section)
}

/// The nonce field of either section: exactly 32 bytes of `hR`.
fn nonce_of(section: &SectionBuilder) -> Result<[u8; 32], String> {
    // WHY/PROOF: the nonce arrives off the network; a value of any other length cannot be the 32 bytes the ask sent, and `try_into` is the length check that turns it into a refusal instead of a mismatch found later.
    match section.get("nonce").ok().and_then(|v| v.first()) {
        Some(VsfType::hR(b)) => b.as_slice().try_into().map_err(|_| "rough_place: nonce is not 32 bytes".to_string()),
        Some(_) => Err("rough_place: nonce is not hR".into()),
        None => Err("rough_place: no nonce".into()),
    }
}

/// The seed's reply to the ask carrying `nonce`, signed with `seed_secret` and stamped `time`.
/// `seen` is `None` when Cloudflare gave no coordinates: the reply is then the signed unknown.
pub fn reply(seed_secret: &[u8; 32], nonce: &[u8; 32], seen: Option<&Seen>, time: i64) -> Result<Vec<u8>, String> {
    let seed_public = ed25519_dalek::SigningKey::from_bytes(seed_secret).verifying_key().to_bytes();
    let mut b = reply_schema().build().set("nonce", VsfType::hR(nonce.to_vec())).map_err(|e| format!("rough_place reply: {e:?}"))?;
    if let Some(s) = seen {
        let at = WorldCoord::from_lat_lon(steps_to_degrees(s.lat_steps), steps_to_degrees(s.lon_steps));
        b = b
            .set("at", VsfType::w(at))
            .and_then(|b| b.set("radius", VsfType::u(s.radius as usize, false)))
            .map_err(|e| format!("rough_place reply: {e:?}"))?;
        if let Some(asn) = s.asn {
            b = b.set("asn", VsfType::u(asn as usize, false)).map_err(|e| format!("rough_place reply asn: {e:?}"))?;
        }
        if let Some(c) = s.country {
            if !is_country(&c) {
                return Err("rough_place reply: country is not two ISO letters".into());
            }
            let text = core::str::from_utf8(&c).map_err(|_| "rough_place reply: country is not text".to_string())?;
            b = b.set("country", VsfType::a(vsf::Ascii::new(text).map_err(|e| format!("rough_place reply country: {e}"))?)).map_err(|e| format!("rough_place reply country: {e:?}"))?;
        }
    }
    let body = b.encode().map_err(|e| format!("rough_place reply: {e:?}"))?;
    let unsigned = vsf::VsfBuilder::new()
        .creation_time_oscillations(time)
        .signed_only(VsfType::ke(seed_public.to_vec()))
        .add_unboxed(REPLY_SECTION, body)
        .build()
        .map_err(|e| format!("rough_place reply build: {e}"))?;
    vsf::verification::sign_file(unsigned, seed_secret)
}

/// Two ASCII capital letters, the ISO 3166-1 alpha-2 shape.
fn is_country(c: &[u8; 2]) -> bool {
    c.iter().all(|b| b.is_ascii_uppercase())
}

/// The device's read of the seed's reply to the ask that carried `nonce`, verified under the seed's pinned key.
/// `Ok(Some(place))` for a place, `Ok(None)` for the seed's signed unknown, `Err` for anything not to be trusted: another signer, a tampered or unsigned document, another ask's nonce, a malformed field.
pub fn verify_reply(bytes: &[u8], nonce: &[u8; 32], seed_public: &[u8; 32]) -> Result<Option<RoughPlace>, String> {
    let section = SectionBuilder::parse_document(reply_schema(), bytes, Some(*seed_public)).map_err(|e| format!("rough_place reply: {e:?}"))?;
    if nonce_of(&section)? != *nonce {
        return Err("rough_place reply: answers another ask".into());
    }
    let first = |name: &str| section.get(name).ok().and_then(|v| v.first());
    let at = match first("at") {
        None => return Ok(None),
        Some(VsfType::w(at)) => *at,
        Some(_) => return Err("rough_place reply: at is not a WorldCoord".into()),
    };
    // WHY/PROOF: `radius` and `asn` arrive off the network in any unsigned width; an `as u32` cast would silently drop the high bits of a wider value and name another radius, so a value past u32 is refused.
    let unsigned = |name: &str| -> Result<Option<u32>, String> {
        match first(name) {
            None => Ok(None),
            Some(v) => v.as_u64().and_then(|n| u32::try_from(n).ok()).map(Some).ok_or_else(|| format!("rough_place reply: {name} is not an unsigned u32")),
        }
    };
    let radius = unsigned("radius")?.ok_or("rough_place reply: a place with no radius")?;
    let asn = unsigned("asn")?;
    let country = match first("country") {
        None => None,
        Some(VsfType::a(t)) => {
            // WHY/PROOF: the text arrives off the network; anything but two bytes is not an ISO 3166-1 alpha-2 code, and `try_into` refuses it rather than slicing past its end.
            let c: [u8; 2] = t.as_str().as_bytes().try_into().map_err(|_| "rough_place reply: country is not two letters".to_string())?;
            if !is_country(&c) {
                return Err("rough_place reply: country is not two ISO letters".into());
            }
            Some(c)
        }
        Some(_) => return Err("rough_place reply: country is not text".into()),
    };
    let (header, _) = vsf::file_format::VsfHeader::decode(bytes).map_err(|e| format!("rough_place reply header: {e}"))?;
    let time = match &header.creation_time {
        Some(VsfType::e(et)) => crate::fleet::try_et_to_osc(et).ok_or("rough_place reply: creation time out of range")?,
        _ => return Err("rough_place reply: no creation time".into()),
    };
    Ok(Some(RoughPlace { at, radius, asn, country, time }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_SECRET: [u8; 32] = [0x5e; 32];

    fn seed_public() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&SEED_SECRET).verifying_key().to_bytes()
    }

    /// Austin, on the grid.
    fn austin() -> Seen {
        Seen { lat_steps: 3875, lon_steps: -12510, radius: RADIUS_CITY, asn: Some(7922), country: Some(*b"US") }
    }

    /// The device's ask reaches the seed with its nonce, the seed's reply reads back as the place it saw, on the grid and stamped with the seed's time.
    #[test]
    fn an_ask_and_its_reply_round_trip() {
        let (ask_bytes, nonce) = ask().unwrap();
        assert_eq!(read_ask(&ask_bytes).unwrap(), nonce);
        let header = vsf::verification::parse_full_header(&ask_bytes).unwrap();
        assert_eq!(header.fields.first().map(|f| f.name.as_str()), Some(ASK_SECTION), "the worker dispatches on the ask's first section");
        assert!(vsf::file_format::VsfHeader::decode(&ask_bytes).unwrap().0.signer_pubkey.is_none(), "the ask carries no key");

        let seen = austin();
        let r = reply(&SEED_SECRET, &nonce, Some(&seen), 1 << 40).unwrap();
        let place = verify_reply(&r, &nonce, &seed_public()).unwrap().expect("a place");
        assert_eq!(place.radius, RADIUS_CITY);
        assert_eq!(place.asn, Some(7922));
        assert_eq!(place.country, Some(*b"US"));
        assert_eq!(place.time, 1 << 40);
        let (lat, lon) = place.at.to_lat_lon();
        // WorldCoord's own error is millimetres, about 1e-7 degrees, far inside one grid step.
        let step = steps_to_degrees(1);
        assert!((lat - steps_to_degrees(seen.lat_steps)).abs() < step / 1024., "lat {lat}");
        assert!((lon - steps_to_degrees(seen.lon_steps)).abs() < step / 1024., "lon {lon}");
    }

    /// A place with no ASN and no country still reads back.
    #[test]
    fn asn_and_country_are_optional() {
        let nonce = [9u8; 32];
        let seen = Seen { asn: None, country: None, radius: RADIUS_REGION, ..austin() };
        let r = reply(&SEED_SECRET, &nonce, Some(&seen), 1 << 40).unwrap();
        let place = verify_reply(&r, &nonce, &seed_public()).unwrap().unwrap();
        assert_eq!((place.radius, place.asn, place.country), (RADIUS_REGION, None, None));
    }

    /// A reply to another ask, a reply signed by any other key, a tampered reply and an unsigned one are all refused.
    #[test]
    fn a_reply_that_is_not_this_asks_or_not_the_seeds_is_refused() {
        let nonce = [1u8; 32];
        let r = reply(&SEED_SECRET, &nonce, Some(&austin()), 1 << 40).unwrap();
        assert!(verify_reply(&r, &[2u8; 32], &seed_public()).is_err(), "another ask's nonce");

        let impostor = reply(&[0x77; 32], &nonce, Some(&austin()), 1 << 40).unwrap();
        assert!(verify_reply(&impostor, &nonce, &seed_public()).is_err(), "another signer");

        let mut tampered = r.clone();
        let last = tampered.len() - 2;
        tampered[last] ^= 1;
        assert!(verify_reply(&tampered, &nonce, &seed_public()).is_err(), "a tampered reply");

        let mut bad_sig = r.clone();
        let header = vsf::file_format::VsfHeader::decode(&r).unwrap().0;
        let Some(VsfType::ge(sig)) = header.signature else { panic!("the reply is ge-signed") };
        let at = r.windows(sig.len()).position(|w| w == sig.as_slice()).unwrap();
        bad_sig[at] ^= 1;
        assert!(verify_reply(&bad_sig, &nonce, &seed_public()).is_err(), "a bad signature");

        // The same section in an unsigned document is not the seed's word.
        let body = reply_schema().build().set("nonce", VsfType::hR(nonce.to_vec())).unwrap().encode().unwrap();
        let unsigned = vsf::VsfBuilder::new().creation_time_oscillations(1 << 40).add_unboxed(REPLY_SECTION, body).build().unwrap();
        assert!(verify_reply(&unsigned, &nonce, &seed_public()).is_err(), "an unsigned reply");
    }

    /// When Cloudflare gives no coordinates the reply is the seed's signed unknown, and it too is bound to the ask.
    #[test]
    fn the_no_coordinates_reply_is_a_signed_unknown() {
        let nonce = [3u8; 32];
        let r = reply(&SEED_SECRET, &nonce, None, 1 << 40).unwrap();
        assert_eq!(verify_reply(&r, &nonce, &seed_public()), Ok(None));
        assert!(verify_reply(&r, &[4u8; 32], &seed_public()).is_err(), "an unknown for another ask");
        let impostor = reply(&[0x77; 32], &nonce, None, 1 << 40).unwrap();
        assert!(verify_reply(&impostor, &nonce, &seed_public()).is_err(), "an unknown from another signer");
    }

    /// The seed refuses to sign a country that is not two capital letters.
    #[test]
    fn a_country_must_be_two_iso_letters() {
        let seen = Seen { country: Some(*b"T1"), ..austin() };
        assert!(reply(&SEED_SECRET, &[5u8; 32], Some(&seen), 1 << 40).is_err());
    }

    /// An ask whose nonce is not 32 bytes of random material is refused.
    #[test]
    fn a_malformed_ask_is_refused() {
        let body = ask_schema().build().set("nonce", VsfType::hR(vec![1u8; 16])).unwrap().encode().unwrap();
        let short = vsf::VsfBuilder::new().creation_time_oscillations(0).add_unboxed(ASK_SECTION, body).build().unwrap();
        assert!(read_ask(&short).is_err());
        let body = ask_schema().build().set("nonce", VsfType::hb(vec![1u8; 32])).unwrap().encode().unwrap();
        let wrong = vsf::VsfBuilder::new().creation_time_oscillations(0).add_unboxed(ASK_SECTION, body).build().unwrap();
        assert!(read_ask(&wrong).is_err());
    }
}
