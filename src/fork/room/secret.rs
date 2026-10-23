//! Room secrets (row 14.5): a short secret that one member sends to the whole
//! room as a single MLS application message, such as the member's profile key
//! at the epoch where a newcomer is admitted. The message is authenticated by
//! the group: the sender is the pseudonym of the leaf credential that signed
//! it, certified through Keys like every other leaf.
//!
//! A secret never enters the accepted history: that history is what a later
//! newcomer may be given, and a key must not travel in it. Opening one advances
//! the MLS state (the secret-tree ratchet) and records an event without
//! content. The caller reads the plaintext from the returned [`RoomSecret`],
//! stores it under its own custody and commits both in one Store transaction
//! through [`Candidate::commit_room_secret`]; a candidate that is dropped
//! changes nothing.
use super::*;

/// Largest room secret in bytes (a profile-key hand-over is far below this).
pub const MAX_ROOM_SECRET: usize = 4096;

/// One secret opened from the room, with the facts MLS authenticated for it.
/// The plaintext is wiped when this is dropped.
pub struct RoomSecret {
    sender: String,
    epoch: u64,
    bytes: Zeroizing<Vec<u8>>,
}

impl RoomSecret {
    /// The pseudonym of the leaf that sent the message (MLS-authenticated).
    pub fn sender(&self) -> &str {
        &self.sender
    }
    /// The MLS epoch the message was sent in.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// The secret itself.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Threads {
    /// Seal `bytes` to the room in the current epoch. The candidate's single
    /// `Event::Ciphertext` carries the message; like every output it is
    /// released only after the checkpoint, and it never enters the history.
    /// Only a member of the room's current roster may send.
    pub async fn seal_room_secret(
        &self,
        keys: &mut impl Custody,
        source: &impl PolicySource,
        clock: &mut impl ckmg::Clock,
        bytes: &[u8],
    ) -> Result<Candidate> {
        if bytes.is_empty() || bytes.len() > MAX_ROOM_SECRET {
            return Err(Error::Limit);
        }
        let cert = self.local(keys).await?;
        let spec = self.snapshot.fork.clone().ok_or(Error::State)?;
        spec.current(&cert.binding, source, now(clock)?)?;
        if !spec.members.contains(cert.binding.member()) {
            return Err(Error::Authority);
        }
        let working = self.working()?;
        let mut group = self.group(&working)?;
        self.fork_roster(keys, &group, &cert, &spec).await?;
        let epoch = group.epoch().as_u64();
        let wire = keys
            .use_signer(|signer| {
                check_signer(&signer, &cert)?;
                group
                    .create_message(&working.0, &ScopedSigner(signer), bytes)
                    .map_err(crypto_error)?
                    .tls_serialize_detached()
                    .map_err(encoding_error)
            })
            .await?;
        bounded_wire(&wire)?;
        self.candidate(
            &working,
            Some(&group),
            cert,
            None,
            vec![Event::Ciphertext {
                id: *ckmg::hash(&wire).value(),
                epoch,
                bytes: wire,
            }],
        )
    }

    /// Open one room secret sent by another member of the roster. The sender
    /// is the certified leaf that signed it; a message from this device itself,
    /// from a non-member, or any MLS content other than an application message
    /// is refused, and an MLS message of an older epoch cannot be opened at all.
    pub async fn open_room_secret(
        &self,
        keys: &mut impl Custody,
        source: &impl PolicySource,
        clock: &mut impl ckmg::Clock,
        wire: &[u8],
    ) -> Result<(Candidate, RoomSecret)> {
        bounded_wire(wire)?;
        let cert = self.local(keys).await?;
        let spec = self.snapshot.fork.clone().ok_or(Error::State)?;
        spec.current(&cert.binding, source, now(clock)?)?;
        if !spec.members.contains(cert.binding.member()) {
            return Err(Error::Authority);
        }
        let message = parse(wire)?
            .try_into_protocol_message()
            .map_err(encoding_error)?;
        let working = self.working()?;
        let mut group = self.group(&working)?;
        self.fork_roster(keys, &group, &cert, &spec).await?;
        let processed = group
            .process_message(&working.0, message)
            .map_err(crypto_error)?;
        let sender = match processed.sender() {
            Sender::Member(index) => group.member_at(*index).ok_or(Error::Authority)?,
            _ => return Err(Error::Authority),
        };
        let sender = decode_credential(processed.credential(), &sender.signature_key)?;
        keys.verify(&sender).await?;
        let member = sender.binding.member();
        if member == cert.binding.member() || !spec.members.contains(member) {
            return Err(Error::Authority);
        }
        let epoch = group.epoch().as_u64();
        let bytes = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                Zeroizing::new(message.into_bytes())
            }
            _ => return Err(Error::Authority),
        };
        if bytes.is_empty() || bytes.len() > MAX_ROOM_SECRET {
            return Err(Error::Limit);
        }
        let secret = RoomSecret {
            sender: member.into(),
            epoch,
            bytes,
        };
        let candidate = self.candidate(
            &working,
            Some(&group),
            cert,
            None,
            vec![Event::RoomSecret { epoch }],
        )?;
        Ok((candidate, secret))
    }
}

impl Candidate {
    /// Commit a sealed or opened room secret with `companions` (the caller's own
    /// records, for example the adopted key) in ONE Store transaction. Keys and
    /// the signed policy are checked again, the room's roster must still be the
    /// one Groups holds, and the candidate must be one of the two secret
    /// candidates; nothing else commits through here.
    pub async fn commit_room_secret<B: Backend>(
        self,
        keys: &mut impl Custody,
        store: &mut Store<B>,
        operation: [u8; 32],
        source: &impl PolicySource,
        clock: &mut impl ckmg::Clock,
        companions: &[Change<'_>],
    ) -> Result<Committed> {
        if self.required_group
            || !matches!(
                self.events.as_slice(),
                [Event::RoomSecret { .. }] | [Event::Ciphertext { .. }]
            )
        {
            return Err(Error::State);
        }
        self.recheck(keys).await?;
        let spec = self.snapshot.fork.as_ref().ok_or(Error::State)?;
        if !spec.members.contains(self.snapshot.binding.member()) {
            return Err(Error::Authority);
        }
        spec.current(&self.snapshot.binding, source, now(clock)?)?;
        let held = store
            .read("cgrp", b"snapshot.v1")
            .map_err(storage_error)?
            .ok_or(Error::Authority)?;
        let held: cgrp::Snapshot = postcard::from_bytes(held).map_err(encoding_error)?;
        if held.community() != self.snapshot.binding.community()
            || held.members(&spec.group).map_err(authority_error)? != &spec.members
        {
            return Err(Error::Authority);
        }
        self.persist_now(store, operation, companions).await
    }
}
