//! Immutable MLS forks driven by genuine Groups decisions and signed policy.
use super::*;
mod room;
use cgrp::{Band, Effect, Level, PolicySource, PreparedEffect};
use governor::{
    Quota, RateLimiter,
    clock::Clock,
    middleware::NoOpMiddleware,
    nanos::Nanos,
    state::{NotKeyed, StateStore},
};
use std::{cell::Cell, collections::BTreeMap, num::NonZeroU32, rc::Rc};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fork {
    group: [u8; 32],
    lineage: [u8; 32],
    parents: Vec<[u8; 32]>,
    members: BTreeSet<String>,
    roster: BTreeSet<String>,
    level: Level,
    band: Band,
    policy_epoch: u64,
    policy_until: u64,
    preparation_until: u64,
    revision: u64,
    last_time: u64,
    pace: BTreeMap<String, u64>,
}
impl Fork {
    pub(super) fn matches_state(&self, state: &cgrp::GroupState) -> bool {
        self.members == self.roster
            && &self.members == state.members()
            && &self.group == state.id()
            && self.revision == state.revision()
            && self.policy_epoch == state.policy_epoch()
            && self.level == state.level()
    }
    pub(super) fn recipients(&self, owner: &str) -> Vec<&str> {
        self.members
            .iter()
            .map(String::as_str)
            .filter(|member| *member != owner)
            .collect()
    }
    fn from_decision(
        binding: &Binding,
        slot: &[u8; 32],
        decision: &PreparedEffect<'_>,
        now: u64,
        require_member: bool,
        room: bool,
    ) -> Result<Self> {
        let Effect::Membership {
            group,
            lineage,
            parents,
            members,
            level,
            policy_epoch,
            revision,
        } = decision.event()
        else {
            return Err(Error::Authority);
        };
        if decision.community() != binding.community()
            || group != slot
            || (require_member && !members.contains(binding.member()))
        {
            return Err(Error::Scope);
        }
        if !(if room {
            matches!(level, Level::Opening | Level::Public)
        } else {
            matches!(level, Level::Circle | Level::Ingroup)
        }) {
            return Err(Error::Unavailable);
        }
        if decision.valid_until() <= now {
            return Err(Error::Authority);
        }
        Ok(Self {
            group: *group,
            lineage: *lineage,
            parents: parents.clone(),
            members: members.clone(),
            roster: members.clone(),
            level: *level,
            band: decision.policy_band().clone(),
            policy_epoch: *policy_epoch,
            policy_until: decision.policy_valid_until(),
            preparation_until: decision.valid_until(),
            revision: *revision,
            last_time: now,
            pace: BTreeMap::new(),
        })
    }
    pub(super) fn current(
        &self,
        binding: &Binding,
        source: &impl PolicySource,
        now: u64,
    ) -> Result<()> {
        if now < self.last_time {
            return Err(Error::Clock);
        }
        if now >= self.policy_until {
            return Err(Error::Authority);
        }
        let policy = source
            .current(binding.community(), now)
            .map_err(authority_error)?;
        policy.validate(now).map_err(authority_error)?;
        if policy.epoch != self.policy_epoch || !policy.bands.contains(&self.band) {
            return Err(Error::Authority);
        }
        Ok(())
    }
    fn pace(&mut self, member: &str, now: u64) -> Result<()> {
        if !self.members.contains(member) {
            return Err(Error::Authority);
        }
        let nanos = now
            .checked_mul(1_000_000_000)
            .filter(|n| *n <= u64::MAX - 7_200_000_000_000)
            .ok_or(Error::Clock)?;
        let quota = Quota::per_hour(
            NonZeroU32::new(u32::from(self.band.posts_per_hour)).ok_or(Error::Authority)?,
        )
        .allow_burst(NonZeroU32::new(u32::from(self.band.burst)).ok_or(Error::Authority)?);
        // The zero origin is stable across checkpoint restore. Governor owns
        // GCRA arithmetic; only its opaque virtual-arrival scalar is persisted.
        let clock = PaceClock(Rc::new(Cell::new(Nanos::from(0))));
        let state = PaceStore(Cell::new(self.pace.get(member).copied().map(Nanos::from)));
        let limiter: RateLimiter<NotKeyed, PaceStore, PaceClock, NoOpMiddleware<Nanos>> =
            RateLimiter::new(quota, state, clock.clone());
        clock.0.set(nanos.into());
        limiter.check().map_err(|_| Error::Pace)?;
        let next = limiter
            .into_state_store()
            .0
            .get()
            .expect("accepted governor measurement stores state");
        self.pace.insert(member.into(), next.as_u64());
        self.last_time = now;
        Ok(())
    }
}
#[derive(Clone)]
struct PaceClock(Rc<Cell<Nanos>>);
impl Clock for PaceClock {
    type Instant = Nanos;
    fn now(&self) -> Nanos {
        self.0.get()
    }
}
struct PaceStore(Cell<Option<Nanos>>);
impl StateStore for PaceStore {
    type Key = NotKeyed;
    fn measure_and_replace<T, F, E>(&self, _: &NotKeyed, f: F) -> std::result::Result<T, E>
    where
        F: Fn(Option<Nanos>) -> std::result::Result<(T, Nanos), E>,
    {
        // This cell is private to one synchronous candidate operation. No user
        // callback or shared thread accesses it; cwst fences concurrent candidates.
        let (value, next) = f(self.0.get())?;
        self.0.set(Some(next));
        Ok(value)
    }
}
fn now(clock: &mut impl ckmg::Clock) -> Result<u64> {
    clock.now().map_err(|_| Error::Clock)
}
impl Threads {
    pub async fn create_fork(
        &self,
        keys: &mut impl Custody,
        decision: &PreparedEffect<'_>,
        packages: &[Vec<u8>],
        clock: &mut impl ckmg::Clock,
    ) -> Result<Candidate> {
        self.create_membership(keys, decision, packages, clock, false)
            .await
    }
    pub(super) async fn create_membership(
        &self,
        keys: &mut impl Custody,
        decision: &PreparedEffect<'_>,
        packages: &[Vec<u8>],
        clock: &mut impl ckmg::Clock,
        room: bool,
    ) -> Result<Candidate> {
        if self.snapshot.group.is_some() {
            return Err(Error::State);
        }
        let cert = self.local(keys).await?;
        let spec = Fork::from_decision(
            &cert.binding,
            &self.snapshot.slot,
            decision,
            now(clock)?,
            true,
            room,
        )?;
        // Later decisions must update the accepted MLS context, never create a
        // second genesis from a claimed current roster.
        if room && spec.revision != 1 {
            return Err(Error::Authority);
        }
        if packages.len() + 1 != spec.members.len() {
            return Err(Error::Authority);
        }
        let working = self.working()?;
        let mut validated = vec![];
        let mut roster = BTreeSet::from([cert.binding.member().to_owned()]);
        for wire in packages {
            bounded_wire(wire)?;
            let package = KeyPackageIn::tls_deserialize_exact(wire)
                .map_err(encoding_error)?
                .validate(working.0.crypto(), ProtocolVersion::Mls10)
                .map_err(crypto_error)?;
            let other = decode_credential(
                package.leaf_node().credential(),
                package.leaf_node().signature_key().as_slice(),
            )?;
            if other.binding.community() != cert.binding.community()
                || !spec.members.contains(other.binding.member())
                || !roster.insert(other.binding.member().into())
            {
                return Err(Error::Authority);
            }
            keys.verify(&other).await?;
            validated.push(package);
        }
        let credential = credential(&cert)?;
        let (group, commit, welcome) = keys
            .use_signer(|signer| {
                check_signer(&signer, &cert)?;
                let signer = ScopedSigner(signer);
                let mut group = MlsGroup::new_with_group_id(
                    &working.0,
                    &signer,
                    &group_context::config(decision.group_state())?,
                    GroupId::from_slice(&self.snapshot.slot),
                    credential,
                )
                .map_err(crypto_error)?;
                let (commit, welcome, _) = group
                    .add_members(&working.0, &signer, &validated)
                    .map_err(crypto_error)?;
                let commit = commit.tls_serialize_detached().map_err(encoding_error)?;
                let welcome = welcome.tls_serialize_detached().map_err(encoding_error)?;
                group
                    .merge_pending_commit(&working.0)
                    .map_err(crypto_error)?;
                Ok((group, commit, welcome))
            })
            .await?;
        let mut candidate = self.candidate(
            &working,
            Some(&group),
            cert,
            None,
            vec![Event::Invitation { commit, welcome }],
        )?;
        candidate.snapshot.fork = Some(spec);
        candidate.required_group = true;
        candidate.required_context = Some(
            decision
                .group_state()
                .commitment()
                .map_err(authority_error)?,
        );
        Ok(candidate)
    }
    pub async fn join_fork(
        &self,
        keys: &mut impl Custody,
        decision: &PreparedEffect<'_>,
        wire: &[u8],
        clock: &mut impl ckmg::Clock,
    ) -> Result<Candidate> {
        self.join_membership(keys, decision, wire, clock, false)
            .await
    }
    pub(super) async fn join_membership(
        &self,
        keys: &mut impl Custody,
        decision: &PreparedEffect<'_>,
        wire: &[u8],
        clock: &mut impl ckmg::Clock,
        room: bool,
    ) -> Result<Candidate> {
        if self.snapshot.group.is_some() {
            return Err(Error::State);
        }
        let cert = self.local(keys).await?;
        let spec = Fork::from_decision(
            &cert.binding,
            &self.snapshot.slot,
            decision,
            now(clock)?,
            true,
            room,
        )?;
        // Later decisions must update the accepted MLS context, never create a
        // second genesis from a claimed current roster.
        if room && spec.revision != 1 {
            return Err(Error::Authority);
        }
        let welcome = match parse(wire)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(Error::Encoding),
        };
        let working = self.working()?;
        let staged =
            StagedWelcome::new_from_welcome(&working.0, config().join_config(), welcome, None)
                .map_err(crypto_error)?;
        let sender = staged.welcome_sender().map_err(crypto_error)?;
        let sender = decode_credential(sender.credential(), sender.signature_key().as_slice())?;
        if sender.binding.community() != cert.binding.community()
            || !spec.members.contains(sender.binding.member())
        {
            return Err(Error::Authority);
        }
        keys.verify(&sender).await?;
        let group = staged.into_group(&working.0).map_err(crypto_error)?;
        group_context::verify(&group, decision.group_state())?;
        self.fork_roster(keys, &group, &cert, &spec).await?;
        let mut candidate =
            self.candidate(&working, Some(&group), cert, None, vec![Event::Joined])?;
        candidate.snapshot.fork = Some(spec);
        candidate.required_group = true;
        candidate.required_context = Some(
            decision
                .group_state()
                .commitment()
                .map_err(authority_error)?,
        );
        Ok(candidate)
    }
    pub(super) async fn fork_roster(
        &self,
        keys: &mut impl Custody,
        group: &MlsGroup,
        local: &KeyCertificate,
        spec: &Fork,
    ) -> Result<()> {
        if group.group_id().as_slice() != spec.group {
            return Err(Error::Scope);
        }
        let mut actual = BTreeSet::new();
        for member in group.members() {
            let cert = decode_credential(&member.credential, &member.signature_key)?;
            if cert.binding.community() != local.binding.community()
                || !actual.insert(cert.binding.member().to_owned())
            {
                return Err(Error::Authority);
            }
            if cert.binding == local.binding && cert != *local {
                return Err(Error::Authority);
            }
            if spec.members.contains(local.binding.member())
                && spec.members.contains(cert.binding.member())
            {
                keys.verify(&cert).await?;
            }
        }
        if actual != spec.roster {
            return Err(Error::Authority);
        }
        Ok(())
    }
    /// Apply an owner's immutable-fork departure/policy decision. The MLS tree
    /// remains unchanged; departed devices cease sending/receiving or fan-out.
    pub async fn update_fork(
        &self,
        keys: &mut impl Custody,
        decision: &PreparedEffect<'_>,
        clock: &mut impl ckmg::Clock,
    ) -> Result<Candidate> {
        let cert = self.local(keys).await?;
        let old = self.snapshot.fork.as_ref().ok_or(Error::State)?;
        let now = now(clock)?;
        if now < old.last_time {
            return Err(Error::Clock);
        }
        let mut spec = Fork::from_decision(
            &cert.binding,
            &self.snapshot.slot,
            decision,
            now,
            false,
            false,
        )?;
        if spec.lineage != old.lineage
            || spec.parents != old.parents
            || !spec.members.is_subset(&old.members)
            || spec.revision <= old.revision
        {
            return Err(Error::Authority);
        }
        spec.roster = old.roster.clone();
        spec.pace = old.pace.clone();
        let working = self.working()?;
        let group = self.group(&working)?;
        self.fork_roster(keys, &group, &cert, &spec).await?;
        let mut candidate = self.candidate(
            &working,
            Some(&group),
            cert,
            None,
            vec![Event::MembershipChanged],
        )?;
        candidate.snapshot.fork = Some(spec);
        candidate.required_group = true;
        Ok(candidate)
    }
    pub fn lineage(&self) -> Option<([u8; 32], &[[u8; 32]])> {
        self.snapshot
            .fork
            .as_ref()
            .map(|f| (f.lineage, f.parents.as_slice()))
    }
    pub fn notification(&self) -> Option<cgrp::Notification> {
        self.snapshot.fork.as_ref().map(|f| f.band.notification)
    }
    pub(super) fn contacts(&self, contacts: &ctcs::Contacts) -> Result<()> {
        if contacts.binding() != &self.snapshot.binding || contacts.version() != self.expected {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    pub async fn send_group(
        &self,
        keys: &mut impl Custody,
        contacts: &ctcs::Contacts,
        source: &impl PolicySource,
        clock: &mut impl ckmg::Clock,
        bytes: &[u8],
    ) -> Result<Candidate> {
        if bytes.is_empty() || bytes.len() > MAX_WIRE / 2 {
            return Err(Error::Limit);
        }
        self.contacts(contacts)?;
        let cert = self.local(keys).await?;
        let now = now(clock)?;
        let mut spec = self.snapshot.fork.clone().ok_or(Error::State)?;
        spec.current(&cert.binding, source, now)?;
        if !spec.members.contains(cert.binding.member()) {
            return Err(Error::Authority);
        }
        for peer in spec.recipients(cert.binding.member()) {
            if contacts.relation(peer).map_err(authority_error)?.state == ctcs::State::Blocked {
                return Err(Error::Authority);
            }
        }
        spec.pace(cert.binding.member(), now)?;
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
        let id = *ckmg::hash(&wire).value();
        let message = Message {
            id,
            sender: cert.binding.member().into(),
            epoch,
            bytes: bytes.to_vec(),
            accepted_at: now,
        };
        let mut candidate = self.candidate(
            &working,
            Some(&group),
            cert,
            None,
            vec![Event::Ciphertext {
                id,
                epoch,
                bytes: wire,
            }],
        )?;
        candidate.snapshot.fork = Some(spec);
        candidate.snapshot.pending.push(message);
        Ok(candidate)
    }
    pub async fn receive_group(
        &self,
        keys: &mut impl Custody,
        contacts: &ctcs::Contacts,
        source: &impl PolicySource,
        clock: &mut impl ckmg::Clock,
        wire: &[u8],
    ) -> Result<Candidate> {
        self.contacts(contacts)?;
        let cert = self.local(keys).await?;
        let now = now(clock)?;
        let mut spec = self.snapshot.fork.clone().ok_or(Error::State)?;
        spec.current(&cert.binding, source, now)?;
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
        if contacts
            .relation(sender.binding.member())
            .map_err(authority_error)?
            .state
            == ctcs::State::Blocked
        {
            return Err(Error::Authority);
        }
        spec.pace(sender.binding.member(), now)?;
        let bytes = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
            _ => return Err(Error::Unavailable),
        };
        if bytes.is_empty() || bytes.len() > MAX_WIRE / 2 {
            return Err(Error::Limit);
        }
        let message = Message {
            id: *ckmg::hash(wire).value(),
            sender: sender.binding.member().into(),
            epoch: group.epoch().as_u64(),
            bytes,
            accepted_at: now,
        };
        let mut candidate = self.candidate(
            &working,
            Some(&group),
            cert,
            None,
            vec![Event::Received {
                message: message.clone(),
            }],
        )?;
        candidate.snapshot.fork = Some(spec);
        candidate.snapshot.accepted.push(message);
        Ok(candidate)
    }
    /// Only local accepted history, selected under the authentic newcomer policy.
    /// Delivery inside a new MLS group belongs to the prepared join transaction.
    pub fn history_for(
        &self,
        decision: &PreparedEffect<'_>,
        clock: &mut impl ckmg::Clock,
    ) -> Result<Vec<Message>> {
        let now = now(clock)?;
        self.snapshot.fork.as_ref().ok_or(Error::State)?;
        let Effect::Membership {
            parents,
            members,
            level,
            ..
        } = decision.event()
        else {
            return Err(Error::Authority);
        };
        if decision.community() != self.snapshot.binding.community()
            || !parents.contains(&self.snapshot.slot)
            || !members.contains(self.snapshot.binding.member())
            || now >= decision.valid_until()
        {
            return Err(Error::Authority);
        }
        if *level == Level::Circle {
            return Ok(vec![]);
        }
        let band = decision.policy_band();
        let mut messages: Vec<_> = self
            .snapshot
            .accepted
            .iter()
            .filter(|message| cgrp::history_allowed(now, message.accepted_at, band))
            .rev()
            .take(usize::from(band.history_messages))
            .cloned()
            .collect();
        messages.reverse();
        Ok(messages)
    }
}
struct Transaction<'a, B: Backend> {
    candidate: Option<Candidate>,
    store: &'a mut Store<B>,
    operation: [u8; 32],
    committed: Option<Committed>,
}
impl<B: Backend> cgrp::Persistence for Transaction<'_, B> {
    fn commit<'a>(
        &'a mut self,
        expected: u64,
        snapshot: &'a cgrp::Snapshot,
        effects: &'a [Effect],
    ) -> cgrp::CommitFuture<'a> {
        Box::pin(async move {
            let candidate = self.candidate.take().ok_or(cgrp::Error::Reconcile)?;
            let spec = candidate
                .snapshot
                .fork
                .as_ref()
                .ok_or(cgrp::Error::Authority)?;
            let expected_effect = Effect::Membership {
                group: spec.group,
                lineage: spec.lineage,
                parents: spec.parents.clone(),
                members: spec.members.clone(),
                level: spec.level,
                policy_epoch: spec.policy_epoch,
                revision: spec.revision,
            };
            let matching = effects.contains(&expected_effect);
            if !matching
                || effects.iter().any(|effect| {
                    matches!(effect, Effect::Membership { group, .. } if group != &spec.group)
                })
                || snapshot.community() != candidate.snapshot.binding.community()
                || snapshot.group_state(&spec.group)?.revision() != spec.revision
            {
                return Err(cgrp::Error::Authority);
            }
            if let Some(expected_context) = candidate.required_context
                && snapshot.group_state(&spec.group)?.commitment()? != expected_context
            {
                return Err(cgrp::Error::Authority);
            }
            let previous = self
                .store
                .read("cgrp", b"snapshot.v1")
                .map_err(|_| cgrp::Error::Reconcile)?;
            let revision = match previous {
                Some(bytes) => postcard::from_bytes::<cgrp::Snapshot>(bytes)
                    .map_err(|_| cgrp::Error::Invalid)?
                    .revision(),
                None => 0,
            };
            if revision != expected {
                return Ok(cgrp::Commit::Conflict);
            }
            let bytes =
                Zeroizing::new(postcard::to_allocvec(snapshot).map_err(|_| cgrp::Error::Invalid)?);
            self.committed = Some(
                candidate
                    .persist_now(
                        self.store,
                        self.operation,
                        &[Change::Put {
                            owner: "cgrp",
                            key: b"snapshot.v1",
                            value: &bytes,
                        }],
                    )
                    .await
                    .map_err(|_| cgrp::Error::Reconcile)?,
            );
            Ok(cgrp::Commit::Applied)
        })
    }
}
impl Candidate {
    /// Groups and the matching MLS candidate become visible after one cwst CAS.
    pub async fn commit_groups<B: Backend>(
        self,
        keys: &mut impl Custody,
        groups: cgrp::Candidate,
        store: &mut Store<B>,
        operation: [u8; 32],
        governance: (&impl PolicySource, &impl cgrp::Authority),
        clock: &mut impl ckmg::Clock,
    ) -> Result<(Committed, cgrp::Snapshot, Vec<cgrp::CommittedEffect>)> {
        if !self.required_group {
            return Err(Error::State);
        }
        self.recheck(keys).await?;
        self.current_contacts(store)?;
        let previous = cgrp::Snapshot::load(self.snapshot.binding.community(), store)
            .map_err(storage_error)?;
        groups.check_base(&previous).map_err(|_| Error::Conflict)?;
        let now = now(clock)?;
        groups
            .revalidate(governance.0, governance.1, now)
            .map_err(authority_error)?;
        let spec = self.snapshot.fork.as_ref().ok_or(Error::State)?;
        if now >= spec.preparation_until {
            return Err(Error::Authority);
        }
        spec.current(&self.snapshot.binding, governance.0, now)?;
        let mut transaction = Transaction {
            candidate: Some(self),
            store,
            operation,
            committed: None,
        };
        let (snapshot, effects) = groups
            .persist(&mut transaction, now)
            .await
            .map_err(storage_error)?;
        Ok((
            transaction.committed.ok_or(Error::Storage)?,
            snapshot,
            effects,
        ))
    }
}

impl Candidate {
    fn current_contacts<B: Backend>(&self, store: &Store<B>) -> Result<()> {
        let contacts =
            ctcs::Contacts::load(self.snapshot.binding.clone(), store).map_err(authority_error)?;
        if contacts.version() != self.expected {
            return Err(Error::Conflict);
        }
        let spec = self.snapshot.fork.as_ref().ok_or(Error::State)?;
        if !self.required_group {
            let bytes = store
                .read("cgrp", b"snapshot.v1")
                .map_err(storage_error)?
                .ok_or(Error::Authority)?;
            let current: cgrp::Snapshot = postcard::from_bytes(bytes).map_err(encoding_error)?;
            if current.community() != self.snapshot.binding.community()
                || current.members(&spec.group).map_err(authority_error)? != &spec.members
            {
                return Err(Error::Authority);
            }
        }
        let peers = match self.events.first().expect("candidate always has an event") {
            Event::Received { message } => vec![message.sender.as_str()],
            Event::MembershipChanged => vec![],
            _ => spec.recipients(self.snapshot.binding.member()),
        };
        for peer in peers {
            if contacts.relation(peer).map_err(authority_error)?.state == ctcs::State::Blocked {
                return Err(Error::Authority);
            }
        }
        Ok(())
    }
    /// Recheck live devices, local blocks and signed policy immediately before
    /// committing a group message candidate and its outputs atomically.
    pub async fn commit_group<B: Backend>(
        self,
        keys: &mut impl Custody,
        store: &mut Store<B>,
        operation: [u8; 32],
        source: &impl PolicySource,
        clock: &mut impl ckmg::Clock,
    ) -> Result<Committed> {
        if self.required_group {
            return Err(Error::Authority);
        }
        self.recheck(keys).await?;
        self.current_contacts(store)?;
        let spec = self.snapshot.fork.as_ref().ok_or(Error::State)?;
        if !spec.members.contains(self.snapshot.binding.member()) {
            return Err(Error::Authority);
        }
        spec.current(&self.snapshot.binding, source, now(clock)?)?;
        self.persist_now(store, operation, &[]).await
    }
}
