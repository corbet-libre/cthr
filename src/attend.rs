//! Attend's two owner ports for a member room join: `ctnd::Threads` (MLS
//! evidence, from this crate) and `ctnd::Persistence` (the single owner
//! transaction). One `JoinSession` owns every capability of one attempt, so
//! the Groups decision (`Attend::begin`), the MLS join and the Attend
//! checkpoint become visible together or not at all; the Groups candidate is
//! consumed only by that final checkpoint. A lost attempt is discarded and
//! restarted, never resumed.
use super::*;
use cgrp::{Effect, PolicySource};
use ctnd::{OrderReply, OrderRequest, OrderedJoin, Phase, PortFuture, PreparedJoin};
use keys::Custody;
use std::{
    cell::{Cell, RefCell},
    ops::{Deref, DerefMut},
    rc::Rc,
};

/// The ordered member commit that installs the canonical context, delivered by
/// whoever receives room traffic after the newcomer's external commit holding
/// `after` was ordered.
pub trait ContextFeed {
    fn context_commit<'a>(&'a mut self, after: u64) -> ctnd::PortFuture<'a, Vec<u8>>;
}

/// A capability lent to one await at a time; never borrowed across an await.
struct Lease<T>(RefCell<Option<T>>);
struct Held<'a, T> {
    lease: &'a Lease<T>,
    value: Option<T>,
}
impl<T> Lease<T> {
    fn new(value: T) -> Self {
        Self(RefCell::new(Some(value)))
    }
    fn take(&self) -> ctnd::Result<Held<'_, T>> {
        let value = self.0.borrow_mut().take().ok_or(ctnd::Error::Invalid)?;
        Ok(Held {
            lease: self,
            value: Some(value),
        })
    }
}
impl<T> Held<'_, T> {
    /// Consume the capability for good (the Groups candidate at publication).
    fn keep(mut self) -> T {
        self.value.take().expect("held value present")
    }
}
impl<T> Drop for Held<'_, T> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            *self.lease.0.borrow_mut() = Some(value);
        }
    }
}
impl<T> Deref for Held<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value.as_ref().expect("held value present")
    }
}
impl<T> DerefMut for Held<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value.as_mut().expect("held value present")
    }
}

fn map(error: Error) -> ctnd::Error {
    match error {
        Error::Authority | Error::Scope => ctnd::Error::Authority,
        Error::Conflict => ctnd::Error::Reconcile,
        Error::Storage => ctnd::Error::Storage,
        _ => ctnd::Error::Unavailable,
    }
}

/// What the caller lends to one join attempt.
pub struct JoinParts<'a, K, B: Backend, S, A, C, F> {
    pub keys: &'a mut K,
    pub clock: &'a mut C,
    pub feed: &'a mut F,
    pub store: &'a mut Store<B>,
    /// This member's Threads for the room (no group yet).
    pub threads: &'a Threads,
    /// The prepared Groups join; consumed by the final checkpoint.
    pub groups: cgrp::Candidate,
    /// A current member's evidence for the group being joined.
    pub evidence: &'a ParentEvidence,
    pub source: &'a S,
    pub authority: &'a A,
    /// Assembly's ordering generation and join counter before this join.
    pub ordering: [u8; 16],
    pub counter: u64,
    /// Encrypted to the room after the join: profile keys and the like.
    pub handover: Vec<Vec<u8>>,
    /// The signed Groups `Join` request: the external commit authenticates it
    /// and members admit the newcomer only with it.
    pub companion: Vec<u8>,
    /// Distinguishes this attempt's shared checkpoint.
    pub operation: [u8; 32],
}

struct Inner<'a, K, B: Backend, S, A, C, F> {
    keys: Lease<&'a mut K>,
    clock: Lease<&'a mut C>,
    feed: Lease<&'a mut F>,
    store: Lease<&'a mut Store<B>>,
    groups: Lease<cgrp::Candidate>,
    threads: &'a Threads,
    evidence: &'a ParentEvidence,
    source: &'a S,
    authority: &'a A,
    ordering: [u8; 16],
    counter: u64,
    handover: Vec<Vec<u8>>,
    companion: Vec<u8>,
    operation: [u8; 32],
    /// Store version after this attempt's own last write; foreign writes since
    /// then refuse the final checkpoint.
    version: Cell<Option<u64>>,
    prepared: RefCell<Option<(RoomJoin, u64)>>,
    joined: RefCell<Option<(Candidate, Vec<Vec<u8>>)>>,
    outcome: RefCell<Option<(Committed, cgrp::Snapshot)>>,
}

pub struct JoinSession<'a, K, B: Backend, S, A, C, F>(Rc<Inner<'a, K, B, S, A, C, F>>);
pub struct SessionThreads<'a, K, B: Backend, S, A, C, F>(Rc<Inner<'a, K, B, S, A, C, F>>);
pub struct SessionStore<'a, K, B: Backend, S, A, C, F>(Rc<Inner<'a, K, B, S, A, C, F>>);

impl<'a, K, B, S, A, C, F> JoinSession<'a, K, B, S, A, C, F>
where
    K: Custody,
    B: Backend,
    S: PolicySource,
    A: cgrp::Authority,
    C: ckmg::Clock,
    F: ContextFeed,
{
    pub fn new(parts: JoinParts<'a, K, B, S, A, C, F>) -> Self {
        Self(Rc::new(Inner {
            keys: Lease::new(parts.keys),
            clock: Lease::new(parts.clock),
            feed: Lease::new(parts.feed),
            store: Lease::new(parts.store),
            groups: Lease::new(parts.groups),
            threads: parts.threads,
            evidence: parts.evidence,
            source: parts.source,
            authority: parts.authority,
            ordering: parts.ordering,
            counter: parts.counter,
            handover: parts.handover,
            companion: parts.companion,
            operation: parts.operation,
            version: Cell::new(None),
            prepared: RefCell::new(None),
            joined: RefCell::new(None),
            outcome: RefCell::new(None),
        }))
    }

    /// `Attend::begin` against this session's own Groups decision, so the
    /// decision that consented is the one the final checkpoint publishes.
    pub fn begin(
        &self,
        attend: &mut ctnd::Attend,
        member: &str,
        room: [u8; 16],
        source: &impl PolicySource,
        now: u64,
    ) -> ctnd::Result<()> {
        let groups = self.0.groups.take()?;
        let effects = groups.prepare_effects();
        attend.begin(
            effects.first().ok_or(ctnd::Error::Authority)?,
            member,
            room,
            source,
            now,
        )
    }

    pub fn threads(&self) -> SessionThreads<'a, K, B, S, A, C, F> {
        SessionThreads(self.0.clone())
    }

    pub fn persistence(&self) -> SessionStore<'a, K, B, S, A, C, F> {
        SessionStore(self.0.clone())
    }

    /// The published Threads state and Groups snapshot, once `Joined`.
    pub fn outcome(&self) -> Option<(Committed, cgrp::Snapshot)> {
        self.0.outcome.borrow_mut().take()
    }
}

impl<K, B, S, A, C, F> ctnd::Threads for SessionThreads<'_, K, B, S, A, C, F>
where
    K: Custody,
    B: Backend,
    S: PolicySource,
    A: cgrp::Authority,
    C: ckmg::Clock,
    F: ContextFeed,
{
    fn prepare<'a>(
        &'a mut self,
        group: &'a [u8; 32],
        membership_revision: u64,
    ) -> PortFuture<'a, PreparedJoin> {
        Box::pin(async move {
            let inner = &self.0;
            if inner.prepared.borrow().is_some() {
                return Err(ctnd::Error::Invalid);
            }
            let groups = inner.groups.take()?;
            let effects = groups.prepare_effects();
            let decision = effects.first().ok_or(ctnd::Error::Authority)?;
            let Effect::Membership {
                group: decided,
                revision,
                ..
            } = decision.event()
            else {
                return Err(ctnd::Error::Authority);
            };
            if decided != group || *revision != membership_revision {
                return Err(ctnd::Error::Authority);
            }
            let mut keys = inner.keys.take()?;
            let mut clock = inner.clock.take()?;
            let join = inner
                .threads
                .prepare_room_join(
                    &mut **keys,
                    decision,
                    inner.evidence,
                    &inner.companion,
                    inner.source,
                    &mut **clock,
                )
                .await
                .map_err(map)?;
            let prepared = PreparedJoin::new(
                inner.ordering,
                inner.counter,
                join.commit().to_vec(),
                join.epoch(),
            )?
            .with_companion(join.companion().to_vec())?;
            let epoch = join.epoch();
            *inner.prepared.borrow_mut() = Some((join, epoch));
            Ok(prepared)
        })
    }

    fn verify_order<'a>(
        &'a mut self,
        request: &'a OrderRequest,
        reply: &'a OrderReply,
    ) -> PortFuture<'a, OrderedJoin> {
        Box::pin(async move {
            let inner = &self.0;
            let (join, epoch) = inner
                .prepared
                .borrow_mut()
                .take()
                .ok_or(ctnd::Error::Invalid)?;
            if request.encrypted_commit != join.commit()
                || request.companion != join.companion()
                || reply.ordering != inner.ordering
                || request.ordering != inner.ordering
                || inner.counter.checked_add(1) != Some(reply.counter)
            {
                return Err(ctnd::Error::Reconcile);
            }
            let context = {
                let mut feed = inner.feed.take()?;
                feed.context_commit(reply.counter).await?
            };
            let groups = inner.groups.take()?;
            let effects = groups.prepare_effects();
            let decision = effects.first().ok_or(ctnd::Error::Authority)?;
            let mut keys = inner.keys.take()?;
            let mut clock = inner.clock.take()?;
            let (candidate, sealed) = join
                .finish(
                    &mut **keys,
                    decision,
                    &context,
                    &inner.handover,
                    &mut **clock,
                )
                .await
                .map_err(map)?;
            let ordered = OrderedJoin::new(inner.ordering, reply.counter, epoch, sealed.clone())?;
            *inner.joined.borrow_mut() = Some((candidate, sealed));
            Ok(ordered)
        })
    }
}

impl<K, B, S, A, C, F> ctnd::Persistence for SessionStore<'_, K, B, S, A, C, F>
where
    K: Custody,
    B: Backend,
    S: PolicySource,
    A: cgrp::Authority,
    C: ckmg::Clock,
    F: ContextFeed,
{
    fn commit<'a>(
        &'a mut self,
        expected: u64,
        checkpoint: &'a ctnd::Checkpoint,
        encrypted_outputs: &'a [Vec<u8>],
    ) -> PortFuture<'a, ()> {
        Box::pin(async move {
            let inner = &self.0;
            let slot = inner.threads.snapshot.slot;
            let bytes = postcard::to_allocvec(checkpoint).map_err(|_| ctnd::Error::Storage)?;
            let mut store = inner.store.take()?;
            let current = match store
                .read(ATTEND_OWNER, &slot)
                .map_err(|_| ctnd::Error::Storage)?
            {
                None => 0,
                Some(stored) => postcard::from_bytes::<ctnd::Checkpoint>(stored)
                    .map_err(|_| ctnd::Error::Storage)?
                    .local_revision(),
            };
            let base = inner.version.get().unwrap_or(inner.threads.expected);
            let version = store.version().map_err(|_| ctnd::Error::Storage)?;
            if current != expected || version != base {
                return Err(ctnd::Error::Reconcile);
            }
            let operation = *ckmg::hash(
                &serde_json::to_vec(&(
                    "cthr.attend.v1",
                    inner.operation,
                    checkpoint.local_revision(),
                ))
                .map_err(|_| ctnd::Error::Storage)?,
            )
            .value();
            if checkpoint.phase() != &Phase::Joined {
                if !encrypted_outputs.is_empty() {
                    return Err(ctnd::Error::Invalid);
                }
                store
                    .commit(
                        base,
                        operation,
                        &[Change::Put {
                            owner: ATTEND_OWNER,
                            key: &slot,
                            value: &bytes,
                        }],
                        &[],
                    )
                    .await
                    .map_err(|_| ctnd::Error::Storage)?;
                inner
                    .version
                    .set(Some(store.version().map_err(|_| ctnd::Error::Storage)?));
                return Ok(());
            }
            let (mut candidate, sealed) = inner
                .joined
                .borrow_mut()
                .take()
                .ok_or(ctnd::Error::Invalid)?;
            // Only this attempt's own checkpoint write happened since the
            // candidate was prepared (checked above), so its base moves with it.
            candidate.expected = base;
            if encrypted_outputs != sealed {
                return Err(ctnd::Error::Invalid);
            }
            let groups = inner.groups.take()?.keep();
            let mut keys = inner.keys.take()?;
            let mut clock = inner.clock.take()?;
            let published = candidate
                .commit_groups_with(
                    &mut **keys,
                    groups,
                    &mut **store,
                    operation,
                    (inner.source, inner.authority),
                    &mut **clock,
                    Some((ATTEND_OWNER, &slot, &bytes)),
                )
                .await
                .map_err(map)?;
            *inner.outcome.borrow_mut() = Some((published.0, published.1));
            Ok(())
        })
    }
}

const ATTEND_OWNER: &str = "ctnd";
