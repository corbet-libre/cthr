//! Versioned plaintext frame of a room's MLS application message (P6c).
//!
//! WasHere facts ride piggyback on the room's ordinary application messages:
//! never sent alone, never delivered offline. The frame is the MLS plaintext:
//! one version byte, then the canonical Postcard encoding of the content and
//! the piggybacked facts. An unknown version is refused, never guessed.
//! Who may state a fact is decided by the receiver against the MLS-authenticated
//! sender ([`authenticated`]); the frame itself grants nothing.
use super::*;
use cgrp::WasHere;

/// The only frame version this build reads and writes.
pub const VISIT_FRAME_VERSION: u8 = 1;
/// Most facts one message may carry (one member opens few groups per bucket).
pub const MAX_VISITS: usize = 16;

#[derive(Serialize, Deserialize)]
struct Body {
    content: Vec<u8>,
    visits: Vec<WasHere>,
}

/// Frame `content` with the facts that ride on it.
pub fn encode(content: &[u8], visits: &[WasHere]) -> Result<Vec<u8>> {
    well_formed(visits)?;
    let body = Body {
        content: content.to_vec(),
        visits: visits.to_vec(),
    };
    let mut out = vec![VISIT_FRAME_VERSION];
    out.extend(postcard::to_allocvec(&body).map_err(|_| Error::Encoding)?);
    Ok(out)
}

/// Open a frame into its content and facts. Unknown versions, trailing bytes
/// and oversized fact lists are refused.
pub fn decode(plaintext: &[u8]) -> Result<(Vec<u8>, Vec<WasHere>)> {
    let (&version, rest) = plaintext.split_first().ok_or(Error::Encoding)?;
    if version != VISIT_FRAME_VERSION {
        return Err(Error::Unavailable);
    }
    let (body, tail): (Body, _) = postcard::take_from_bytes(rest).map_err(|_| Error::Encoding)?;
    if !tail.is_empty() {
        return Err(Error::Encoding);
    }
    well_formed(&body.visits)?;
    Ok((body.content, body.visits))
}

/// At most [`MAX_VISITS`] facts, each naming the start of a visit bucket.
fn well_formed(visits: &[WasHere]) -> Result<()> {
    if visits.len() > MAX_VISITS {
        return Err(Error::Limit);
    }
    if visits
        .iter()
        .any(|fact| fact.bucket_start % cgrp::BUCKET_TICKS != 0)
    {
        return Err(Error::Encoding);
    }
    Ok(())
}

/// Merge accepted facts into the room's stored set at `now` (unix seconds).
/// The store holds exactly the inputs of the warm derivation
/// ([`cgrp::warm_ends`]): facts whose bucket has begun and whose seat lifetime
/// (warm plus cooling) has not passed. Anything else is not state, so it is
/// neither kept nor added; duplicates collapse.
pub(crate) fn remember(stored: &mut Vec<WasHere>, accepted: &[WasHere], now: u64) {
    let now = now / cgrp::TICK_SECONDS;
    let horizon = cgrp::WARM_MAX_TICKS + cgrp::COOL_MAX_TICKS;
    let live = |fact: &WasHere| {
        fact.bucket_start <= now && fact.bucket_start.saturating_add(horizon) > now
    };
    stored.retain(live);
    for fact in accepted {
        if live(fact) && !stored.contains(fact) {
            stored.push(fact.clone());
        }
    }
}

/// A fact is accepted only when its member IS the MLS-authenticated sender and
/// it names this room; one foreign fact refuses the whole message.
pub fn authenticated(visits: &[WasHere], sender: &str, room: &[u8; 32]) -> Result<()> {
    if visits
        .iter()
        .all(|fact| fact.member == sender && fact.group == *room)
    {
        Ok(())
    } else {
        Err(Error::Authority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(member: &str) -> WasHere {
        WasHere {
            member: member.into(),
            group: [7; 32],
            bucket_start: 0,
        }
    }

    #[test]
    fn frame_round_trips_and_refuses_unknown_versions() {
        let wire = encode(b"hello", &[fact("a")]).expect("encodes");
        assert_eq!(wire[0], VISIT_FRAME_VERSION);
        assert_eq!(
            decode(&wire).expect("decodes"),
            (b"hello".to_vec(), vec![fact("a")])
        );
        let mut future = wire.clone();
        future[0] = VISIT_FRAME_VERSION + 1;
        assert!(matches!(decode(&future), Err(Error::Unavailable)));
        let mut long = wire.clone();
        long.push(0);
        assert!(matches!(decode(&long), Err(Error::Encoding)));
        assert!(matches!(decode(&[]), Err(Error::Encoding)));
        let many = vec![fact("a"); MAX_VISITS + 1];
        assert!(matches!(encode(b"x", &many), Err(Error::Limit)));
    }

    #[test]
    fn misaligned_buckets_are_malformed() {
        let mut odd = fact("a");
        odd.bucket_start = 1;
        assert!(matches!(encode(b"x", &[odd.clone()]), Err(Error::Encoding)));
        let mut wire = encode(b"x", &[fact("a")]).expect("encodes");
        // The bucket is the frame's last varint: 0 becomes 1.
        *wire.last_mut().unwrap() = 1;
        assert!(matches!(decode(&wire), Err(Error::Encoding)));
    }

    #[test]
    fn the_store_holds_exactly_the_derivation_inputs() {
        let bucket = cgrp::BUCKET_TICKS;
        let horizon = cgrp::WARM_MAX_TICKS + cgrp::COOL_MAX_TICKS;
        let at = |member: &str, bucket_start: u64| WasHere {
            bucket_start,
            ..fact(member)
        };
        let seconds = |ticks: u64| ticks * cgrp::TICK_SECONDS;
        let mut stored = vec![];
        remember(
            &mut stored,
            &[at("a", 0), at("a", 0), at("b", bucket)],
            seconds(10),
        );
        // The duplicate collapses; a bucket that has not begun is no input.
        assert_eq!(stored, vec![at("a", 0)]);
        remember(&mut stored, &[at("b", bucket)], seconds(bucket));
        assert_eq!(stored, vec![at("a", 0), at("b", bucket)]);
        // Past the seat lifetime a fact is neither kept nor added.
        remember(&mut stored, &[at("c", 0)], seconds(horizon));
        assert_eq!(stored, vec![at("b", bucket)]);
    }

    #[test]
    fn only_the_authenticated_sender_may_state_its_own_visit() {
        assert!(authenticated(&[fact("a")], "a", &[7; 32]).is_ok());
        assert!(authenticated(&[], "a", &[7; 32]).is_ok());
        assert!(matches!(
            authenticated(&[fact("a"), fact("b")], "a", &[7; 32]),
            Err(Error::Authority)
        ));
        assert!(matches!(
            authenticated(&[fact("a")], "a", &[8; 32]),
            Err(Error::Authority)
        ));
    }
}
