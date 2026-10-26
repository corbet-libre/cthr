//! Ordered external room join (RFC 9420 section 12.4.3.2) as two commits: the
//! newcomer's external commit, then the member commit that installs the
//! canonical Groups context (an external commit cannot carry a
//! GroupContextExtensions proposal, section 12.2). Both stay one pending
//! operation in memory until the shared Groups/Threads checkpoint; a lost
//! operation is discarded and restarted, never resumed from a partial state.
//! Ordering belongs to Attend and Assembly; this file only produces and
//! authenticates the MLS evidence.
//!
//! Credentials: the newcomer's leaf holds exactly the scoped device certificate
//! for this community (community, member pseudonym, per-community device key,
//! purpose key). No other identifier enters a leaf.
use super::*;
use openmls::group::PublicGroup;
use openmls::messages::group_info::VerifiableGroupInfo;

/// Largest newcomer hand-over (profile keys, bounded history) per join.
pub const MAX_HANDOVER: usize = 256;

fn chain(candidate: Candidate) -> Threads {
    Threads {
        snapshot: candidate.snapshot,
        expected: candidate.expected,
        base: candidate.base,
    }
}

impl Fork {
    /// The decision after the current one adds exactly one new member.
    fn join_successor(
        &self,
        binding: &Binding,
        slot: &[u8; 32],
        decision: &PreparedEffect<'_>,
        at: u64,
    ) -> Result<(Self, String)> {
        if !matches!(self.level, Level::Opening | Level::Public)
            || self.members != self.roster
            || at < self.last_time
        {
            return Err(Error::Authority);
        }
        let mut next = Self::from_decision(binding, slot, decision, at, false, true)?;
        let added: Vec<_> = next.members.difference(&self.members).cloned().collect();
        if next.lineage != self.lineage
            || next.parents != self.parents
            || Some(next.revision) != self.revision.checked_add(1)
            || !self.members.is_subset(&next.members)
            || added.len() != 1
        {
            return Err(Error::Authority);
        }
        next.pace = self.pace.clone();
        Ok((next, added.into_iter().next().expect("one addition")))
    }
}

/// The newcomer's prepared external commit and the unpublished MLS state that
/// follows it. Dropping it publishes nothing.
pub struct RoomJoin {
    threads: Threads,
    next: Fork,
    commit: Vec<u8>,
    companion: Vec<u8>,
    epoch: u64,
}

/// The commit's authenticated data: binds the exact companion (the newcomer's
/// signed Groups `Join` request) to this group's external commit. An admitting
/// member recomputes it from the companion it received with the commit.
fn companion_binding(slot: &[u8; 32], companion: &[u8]) -> Vec<u8> {
    let mut bytes = b"cthr.room.join.companion.v1\0".to_vec();
    bytes.extend_from_slice(slot);
    bytes.extend_from_slice(companion);
    ckmg::hash(&bytes).value().to_vec()
}

impl RoomJoin {
    /// The external commit for the ordering link (a PublicMessage by RFC 9420).
    pub fn commit(&self) -> &[u8] {
        &self.commit
    }
    /// The companion the commit authenticates (ordered together with it).
    pub fn companion(&self) -> &[u8] {
        &self.companion
    }
    /// The MLS epoch this commit creates.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Authenticate the member commit that installs the canonical context and
    /// seal the newcomer's hand-over (profile keys etc.) to the room in the
    /// resulting epoch. Returns the candidate and the hand-over ciphertexts;
    /// the latter must not be released before the shared checkpoint commits.
    pub async fn finish(
        self,
        keys: &mut impl Custody,
        decision: &PreparedEffect<'_>,
        wire: &[u8],
        handover: &[Vec<u8>],
        clock: &mut impl ckmg::Clock,
    ) -> Result<(Candidate, Vec<Vec<u8>>)> {
        if handover.len() > MAX_HANDOVER
            || handover
                .iter()
                .any(|item| item.is_empty() || item.len() > MAX_WIRE / 2)
        {
            return Err(Error::Limit);
        }
        let local = self.threads.local(keys).await?;
        let message = parse(wire)?
            .try_into_protocol_message()
            .map_err(encoding_error)?;
        let working = self.threads.working()?;
        let mut group = self.threads.group(&working)?;
        apply_context(keys, &mut group, &working, &self.next, message).await?;
        let mut events = vec![Event::Joined];
        let mut sealed = vec![];
        for item in handover {
            let epoch = group.epoch().as_u64();
            let wire = keys
                .use_signer(|signer| {
                    check_signer(&signer, &local)?;
                    group
                        .create_message(&working.0, &ScopedSigner(signer), item)
                        .map_err(crypto_error)?
                        .tls_serialize_detached()
                        .map_err(encoding_error)
                })
                .await?;
            sealed.push(wire.clone());
            events.push(Event::Ciphertext {
                id: *ckmg::hash(&wire).value(),
                epoch,
                bytes: wire,
            });
        }
        let candidate = self
            .threads
            .room_candidate(
                keys,
                &working,
                &group,
                (local, self.next, events),
                decision,
                clock,
            )
            .await?;
        Ok((candidate, sealed))
    }
}

/// An existing member that processed the newcomer's ordered external commit and
/// now needs the member commit that installs the canonical context.
pub struct RoomAdmission {
    threads: Threads,
    next: Fork,
}

impl RoomAdmission {
    /// Produce the context-installing member commit (this member is the
    /// committer). The candidate's `Event::MembershipCommit` carries it.
    pub async fn commit_context(
        self,
        keys: &mut impl Custody,
        decision: &PreparedEffect<'_>,
        clock: &mut impl ckmg::Clock,
    ) -> Result<Candidate> {
        let local = self.threads.local(keys).await?;
        let working = self.threads.working()?;
        let mut group = self.threads.group(&working)?;
        let wire = keys
            .use_signer(|signer| {
                check_signer(&signer, &local)?;
                let bundle = group
                    .commit_builder()
                    .consume_proposal_store(false)
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
        self.threads
            .room_candidate(
                keys,
                &working,
                &group,
                (
                    local,
                    self.next,
                    vec![Event::MembershipCommit { bytes: wire }],
                ),
                decision,
                clock,
            )
            .await
    }

    /// Authenticate another member's context-installing commit.
    pub async fn receive_context(
        self,
        keys: &mut impl Custody,
        decision: &PreparedEffect<'_>,
        wire: &[u8],
        clock: &mut impl ckmg::Clock,
    ) -> Result<Candidate> {
        let local = self.threads.local(keys).await?;
        let message = parse(wire)?
            .try_into_protocol_message()
            .map_err(encoding_error)?;
        let working = self.threads.working()?;
        let mut group = self.threads.group(&working)?;
        apply_context(keys, &mut group, &working, &self.next, message).await?;
        self.threads
            .room_candidate(
                keys,
                &working,
                &group,
                (local, self.next, vec![Event::MembershipChanged]),
                decision,
                clock,
            )
            .await
    }
}

/// Process one member commit that must contain exactly one
/// GroupContextExtensions proposal and nothing else, from a member of the
/// resulting roster.
async fn apply_context(
    keys: &mut impl Custody,
    group: &mut MlsGroup,
    working: &Working,
    next: &Fork,
    message: ProtocolMessage,
) -> Result<()> {
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
    let mut contexts = 0;
    for queued in staged.queued_proposals() {
        match queued.proposal() {
            Proposal::GroupContextExtensions(_) => contexts += 1,
            _ => return Err(Error::Authority),
        }
    }
    if contexts != 1 {
        return Err(Error::Authority);
    }
    group
        .merge_staged_commit(&working.0, *staged)
        .map_err(crypto_error)
}

impl Threads {
    /// Newcomer, before anything is prepared, signed or sent: authenticate the
    /// delivered Groups state against the MLS evidence. The state's commitment
    /// must be the one carried in the GroupInfo's authenticated context (same
    /// group id, same epoch: the GroupInfo is signed for exactly one epoch), and
    /// every certified device in the tree must match the state's roster. Writes
    /// nothing; the returned state is the only one a Join may then name as its
    /// parent.
    pub async fn verify_room_state(
        &self,
        keys: &mut impl Custody,
        evidence: &ParentEvidence,
    ) -> Result<cgrp::GroupState> {
        if self.snapshot.group.is_some() {
            return Err(Error::State);
        }
        bounded_wire(&evidence.group_info)?;
        bounded_wire(&evidence.ratchet_tree)?;
        let cert = self.local(keys).await?;
        Ok(self.verified_evidence(keys, &cert, evidence).await?.0)
    }

    async fn verified_evidence(
        &self,
        keys: &mut impl Custody,
        cert: &KeyCertificate,
        evidence: &ParentEvidence,
    ) -> Result<(cgrp::GroupState, VerifiableGroupInfo, RatchetTreeIn)> {
        let state = cgrp::GroupState::decode(&evidence.state).map_err(encoding_error)?;
        if state.id() != &self.snapshot.slot {
            return Err(Error::Authority);
        }
        let info = match parse(&evidence.group_info)?.extract() {
            MlsMessageBodyIn::GroupInfo(info) => info,
            _ => return Err(Error::Encoding),
        };
        let tree =
            RatchetTreeIn::tls_deserialize_exact(&evidence.ratchet_tree).map_err(encoding_error)?;
        let isolated = OpenMlsRustCrypto::default();
        let (imported, _) = PublicGroup::from_external(
            isolated.crypto(),
            isolated.storage(),
            tree.clone(),
            info.clone(),
            ProposalStore::new(),
        )
        .map_err(crypto_error)?;
        group_context::verify_context(imported.group_context(), &state)?;
        let mut roster = BTreeSet::new();
        for member in imported.members() {
            let certificate = decode_credential(&member.credential, &member.signature_key)?;
            if certificate.binding.community() != cert.binding.community()
                || certificate.binding == cert.binding
                || !roster.insert(certificate.binding.member().to_owned())
            {
                return Err(Error::Authority);
            }
            keys.verify(&certificate).await?;
        }
        if &roster != state.members() {
            return Err(Error::Authority);
        }
        Ok((state, info, tree))
    }
}

impl Threads {
    /// Newcomer: join the room by an external commit built from an existing
    /// member's `ParentEvidence`. The evidence is checked against the signed
    /// Groups join decision (exactly one added member, this one, on the next
    /// revision), the GroupInfo's authenticated context and every certified
    /// device in the tree. Nothing is accepted from the evidence's own claims.
    pub async fn prepare_room_join(
        &self,
        keys: &mut impl Custody,
        decision: &PreparedEffect<'_>,
        evidence: &ParentEvidence,
        companion: &[u8],
        source: &impl PolicySource,
        clock: &mut impl ckmg::Clock,
    ) -> Result<RoomJoin> {
        if self.snapshot.group.is_some() || companion.is_empty() {
            return Err(Error::State);
        }
        bounded_wire(&evidence.group_info)?;
        bounded_wire(&evidence.ratchet_tree)?;
        let cert = self.local(keys).await?;
        let at = now(clock)?;
        let next =
            Fork::from_decision(&cert.binding, &self.snapshot.slot, decision, at, true, true)?;
        let state = cgrp::GroupState::decode(&evidence.state).map_err(encoding_error)?;
        let mut before = next.members.clone();
        before.remove(cert.binding.member());
        if next.revision < 2
            || state.id() != &self.snapshot.slot
            || state.revision() + 1 != next.revision
            || state.members() != &before
            || state.level() != next.level
            || state.policy_epoch() != next.policy_epoch
        {
            return Err(Error::Authority);
        }
        next.current(&cert.binding, source, at)?;
        let (verified, info, tree) = self.verified_evidence(keys, &cert, evidence).await?;
        if verified.commitment().map_err(authority_error)?
            != state.commitment().map_err(authority_error)?
        {
            return Err(Error::Authority);
        }
        let working = self.working()?;
        let credential = credential(&cert)?;
        let (group, commit) = keys
            .use_signer(|signer| {
                check_signer(&signer, &cert)?;
                let signer = ScopedSigner(signer);
                let (group, bundle) = MlsGroup::external_commit_builder()
                    .with_aad(companion_binding(&self.snapshot.slot, companion))
                    .with_ratchet_tree(tree)
                    .with_config(config().join_config().clone())
                    .build_group(&working.0, info, credential)
                    .map_err(crypto_error)?
                    .leaf_node_parameters(
                        LeafNodeParameters::builder()
                            .with_capabilities(group_context::capabilities())
                            .build(),
                    )
                    .load_psks(working.0.storage())
                    .map_err(crypto_error)?
                    .build(working.0.rand(), working.0.crypto(), &signer, |_| true)
                    .map_err(crypto_error)?
                    .finalize(&working.0)
                    .map_err(crypto_error)?;
                let commit = bundle
                    .commit()
                    .tls_serialize_detached()
                    .map_err(encoding_error)?;
                bounded_wire(&commit)?;
                Ok((group, commit))
            })
            .await?;
        // The joined tree still carries the previous context until the member
        // commit follows, so only the roster is checked here.
        self.fork_roster(keys, &group, &cert, &next).await?;
        let epoch = group.epoch().as_u64();
        let mut candidate =
            self.candidate(&working, Some(&group), cert, None, vec![Event::Joined])?;
        candidate.snapshot.fork = Some(next.clone());
        Ok(RoomJoin {
            threads: chain(candidate),
            next,
            commit,
            companion: companion.to_vec(),
            epoch,
        })
    }

    /// Existing member, before any Groups decision: the leaf credential the
    /// newcomer's ordered external commit carries. The commit is processed on a
    /// throw-away working group (nothing is merged or stored) and must be a
    /// new-member commit that authenticates exactly `companion`. The returned
    /// certificate is UNTRUSTED: the caller reads the newcomer's lineage and
    /// verifies it through `Custody::verify` (as `receive_room_join` does again)
    /// before anything it states is believed.
    pub fn room_join_credential(&self, wire: &[u8], companion: &[u8]) -> Result<KeyCertificate> {
        if companion.is_empty() {
            return Err(Error::Authority);
        }
        let message = parse(wire)?
            .try_into_protocol_message()
            .map_err(encoding_error)?;
        let working = self.working()?;
        let mut group = self.group(&working)?;
        let processed = group
            .process_message(&working.0, message)
            .map_err(crypto_error)?;
        if !matches!(processed.sender(), Sender::NewMemberCommit)
            || processed.aad() != companion_binding(&self.snapshot.slot, companion)
        {
            return Err(Error::Authority);
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(Error::Authority);
        };
        let leaf = staged.update_path_leaf_node().ok_or(Error::Authority)?;
        decode_credential(leaf.credential(), leaf.signature_key().as_slice())
    }

    /// Existing member: authenticate the newcomer's ordered external commit
    /// against this member's exact committed Groups/MLS state. Only the
    /// external init, from the one added member with a certified community
    /// credential, is accepted; removals, other proposals and extensions refuse.
    pub async fn receive_room_join<B: Backend>(
        &self,
        keys: &mut impl Custody,
        store: &Store<B>,
        decision: &PreparedEffect<'_>,
        wire: &[u8],
        companion: &[u8],
        clock: &mut impl ckmg::Clock,
    ) -> Result<RoomAdmission> {
        if companion.is_empty() {
            return Err(Error::Authority);
        }
        let message = parse(wire)?
            .try_into_protocol_message()
            .map_err(encoding_error)?;
        let local = self.local(keys).await?;
        let (next, newcomer) = self
            .snapshot
            .fork
            .as_ref()
            .ok_or(Error::State)?
            .join_successor(&local.binding, &self.snapshot.slot, decision, now(clock)?)?;
        let working = self.working()?;
        let mut group = self.group(&working)?;
        self.room_base(keys, store, &group, &local, &next).await?;
        let processed = group
            .process_message(&working.0, message)
            .map_err(crypto_error)?;
        if !matches!(processed.sender(), Sender::NewMemberCommit)
            || processed.aad() != companion_binding(&self.snapshot.slot, companion)
        {
            return Err(Error::Authority);
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(Error::Authority);
        };
        for queued in staged.queued_proposals() {
            if !matches!(queued.proposal(), Proposal::ExternalInit(_)) {
                return Err(Error::Authority);
            }
        }
        let leaf = staged.update_path_leaf_node().ok_or(Error::Authority)?;
        let joined = decode_credential(leaf.credential(), leaf.signature_key().as_slice())?;
        if joined.binding.community() != local.binding.community()
            || joined.binding.member() != newcomer
        {
            return Err(Error::Authority);
        }
        keys.verify(&joined).await?;
        group
            .merge_staged_commit(&working.0, *staged)
            .map_err(crypto_error)?;
        self.fork_roster(keys, &group, &local, &next).await?;
        let mut candidate = self.candidate(
            &working,
            Some(&group),
            local,
            None,
            vec![Event::MembershipChanged],
        )?;
        candidate.snapshot.fork = Some(next.clone());
        Ok(RoomAdmission {
            threads: chain(candidate),
            next,
        })
    }
}
