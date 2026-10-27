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
    if visits.len() > MAX_VISITS {
        return Err(Error::Limit);
    }
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
    if body.visits.len() > MAX_VISITS {
        return Err(Error::Limit);
    }
    Ok((body.content, body.visits))
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
