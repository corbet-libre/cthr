//! Existing-member room transitions. Transport ordering belongs to Attend.
use super::*;
mod join;
mod secret;
pub use join::{MAX_HANDOVER, RoomAdmission, RoomJoin};
pub use secret::{MAX_ROOM_SECRET, RoomSecret};

impl Fork {
    fn room_successor(
        &self,
        binding: &Binding,
        slot: &[u8; 32],
        decision: &PreparedEffect<'_>,
        at: u64,
    ) -> Result<Self> {
        if !matches!(self.level, Level::Opening | Level::Public)
            || self.members != self.roster
            || at < self.last_time
        {
            return Err(Error::Authority);
        }
        let mut next = Self::from_decision(binding, slot, decision, at, true, true)?;
        if next.lineage != self.lineage
            || next.parents != self.parents
            || Some(next.revision) != self.revision.checked_add(1)
            || !next.members.is_subset(&self.members)
        {
            return Err(Error::Authority);
        }
        next.pace = self
            .pace
            .iter()
            .filter(|(member, _)| next.members.contains(*member))
            .map(|(member, value)| (member.clone(), *value))
            .collect();
        Ok(next)
    }
}

impl Threads {
    /// Prepare the exact remaining-member roster and canonical Groups context
    /// in a real encrypted MLS member commit. Additions/external joins use the
    /// separate two-commit protocol and are refused here. This lower capability
    /// supplies no Assembly order or complete Attend admission authority.
    pub async fn update_room<B: Backend>(
        &self,
        keys: &mut impl Custody,
        store: &Store<B>,
        decision: &PreparedEffect<'_>,
        clock: &mut impl ckmg::Clock,
    ) -> Result<Candidate> {
        let local = self.local(keys).await?;
        let at = now(clock)?;
        let next = self
            .snapshot
            .fork
            .as_ref()
            .ok_or(Error::State)?
            .room_successor(&local.binding, &self.snapshot.slot, decision, at)?;
        let working = self.working()?;
        let mut group = self.group(&working)?;
        self.room_base(keys, store, &group, &local, &next).await?;
        let removals = removed(&group, &next)?;
        let wire = keys
            .use_signer(|signer| {
                check_signer(&signer, &local)?;
                let bundle = group
                    .commit_builder()
                    .consume_proposal_store(false)
                    .propose_removals(removals)
                    .propose_group_context_extensions(group_context::extensions(
                        decision.group_state(),
                    )?)
                    .map_err(crypto_error)?
                    .load_psks(working.0.storage())
                    .map_err(crypto_error)?
                    .build(
                        working.0.rand(),
                        working.0.crypto(),
                        &ScopedSigner(signer),
                        |_| true,
                    )
                    .map_err(crypto_error)?
                    .stage_commit(&working.0)
                    .map_err(crypto_error)?;
                let wire = bundle
                    .commit()
                    .tls_serialize_detached()
                    .map_err(encoding_error)?;
                bounded_wire(&wire)?;
                group
                    .merge_pending_commit(&working.0)
                    .map_err(crypto_error)?;
                Ok(wire)
            })
            .await?;
        self.room_candidate(
            keys,
            &working,
            &group,
            (local, next, vec![Event::MembershipCommit { bytes: wire }]),
            decision,
            clock,
        )
        .await
    }

    /// Authenticate one member commit against this exact previously committed
    /// Groups/MLS state. Unexpected proposals, additions, skipped revisions and
    /// mismatching complete contexts never produce a candidate.
    pub async fn receive_room_update<B: Backend>(
        &self,
        keys: &mut impl Custody,
        store: &Store<B>,
        decision: &PreparedEffect<'_>,
        wire: &[u8],
        clock: &mut impl ckmg::Clock,
    ) -> Result<Candidate> {
        let message = parse(wire)?
            .try_into_protocol_message()
            .map_err(encoding_error)?;
        let local = self.local(keys).await?;
        let next = self
            .snapshot
            .fork
            .as_ref()
            .ok_or(Error::State)?
            .room_successor(&local.binding, &self.snapshot.slot, decision, now(clock)?)?;
        let working = self.working()?;
        let mut group = self.group(&working)?;
        self.room_base(keys, store, &group, &local, &next).await?;
        let expected = removed(&group, &next)?;
        let processed = group
            .process_message(&working.0, message)
            .map_err(crypto_error)?;
        let sender = match processed.sender() {
            Sender::Member(index) => group.member_at(*index).ok_or(Error::Authority)?,
            _ => return Err(Error::Authority),
        };
        let sender = decode_credential(processed.credential(), &sender.signature_key)?;
        if !next.members.contains(sender.binding.member()) {
            return Err(Error::Authority);
        }
        keys.verify(&sender).await?;
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(Error::Authority);
        };
        let mut actual = BTreeSet::new();
        let mut contexts = 0;
        for queued in staged.queued_proposals() {
            match queued.proposal() {
                Proposal::Remove(proposal) if actual.insert(proposal.removed()) => {}
                Proposal::GroupContextExtensions(_) => contexts += 1,
                _ => return Err(Error::Authority),
            }
        }
        if contexts != 1 || actual != expected.into_iter().collect() {
            return Err(Error::Authority);
        }
        group
            .merge_staged_commit(&working.0, *staged)
            .map_err(crypto_error)?;
        self.room_candidate(
            keys,
            &working,
            &group,
            (local, next, vec![Event::MembershipChanged]),
            decision,
            clock,
        )
        .await
    }

    async fn room_base<B: Backend>(
        &self,
        keys: &mut impl Custody,
        store: &Store<B>,
        group: &MlsGroup,
        local: &KeyCertificate,
        next: &Fork,
    ) -> Result<()> {
        if store.version().map_err(storage_error)? != self.expected {
            return Err(Error::Conflict);
        }
        let prior = cgrp::Snapshot::load(local.binding.community(), store)
            .map_err(storage_error)?
            .group_state(&self.snapshot.slot)
            .map_err(authority_error)?;
        let old = self.snapshot.fork.as_ref().ok_or(Error::State)?;
        if !old.matches_state(&prior) {
            return Err(Error::Authority);
        }
        group_context::verify(group, &prior)?;
        // Removed members need not retain a live device. Their identity is
        // authenticated by the old MLS checkpoint; every remaining device is
        // verified again under actual current Keys authority.
        let mut retained = next.clone();
        retained.roster = old.roster.clone();
        self.fork_roster(keys, group, local, &retained).await
    }

    async fn room_candidate(
        &self,
        keys: &mut impl Custody,
        working: &Working,
        group: &MlsGroup,
        parts: (KeyCertificate, Fork, Vec<Event>),
        decision: &PreparedEffect<'_>,
        clock: &mut impl ckmg::Clock,
    ) -> Result<Candidate> {
        let (local, mut next, events) = parts;
        group_context::verify(group, decision.group_state())?;
        if group.extensions() != &group_context::extensions(decision.group_state())? {
            return Err(Error::Authority);
        }
        self.fork_roster(keys, group, &local, &next).await?;
        let at = now(clock)?;
        if at < next.last_time || at >= next.preparation_until {
            return Err(Error::Authority);
        }
        next.last_time = at;
        let mut candidate = self.candidate(working, Some(group), local, None, events)?;
        candidate.snapshot.fork = Some(next);
        candidate.required_group = true;
        candidate.required_context = Some(
            decision
                .group_state()
                .commitment()
                .map_err(authority_error)?,
        );
        Ok(candidate)
    }
}

fn removed(group: &MlsGroup, next: &Fork) -> Result<Vec<LeafNodeIndex>> {
    group
        .members()
        .filter_map(
            |member| match decode_credential(&member.credential, &member.signature_key) {
                Ok(cert) if next.members.contains(cert.binding.member()) => None,
                Ok(_) => Some(Ok(member.index)),
                Err(error) => Some(Err(error)),
            },
        )
        .collect()
}
