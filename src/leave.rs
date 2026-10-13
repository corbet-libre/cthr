//! Leaving a member room: the Groups `Leave`, the removal of this device's
//! Threads state for the group and the Attend withdrawal become visible in ONE
//! Store commit, or not at all. A removed device sends no MLS message of its
//! own (a member cannot commit its own removal); the other members learn of the
//! departure from the Groups record and drop the leaf at their next commit.
use super::*;
use cgrp::{Effect, PolicySource};
use ctnd::{Attend, Checkpoint, Phase, PortFuture};

const ATTEND_OWNER: &str = "ctnd";

impl Threads {
    /// The Attend participation stored for this group, if any, restored for
    /// withdrawal. A checkpoint of a lost attempt comes back as `Reconciling`.
    pub fn stored_attend<B: Backend>(&self, store: &Store<B>) -> Result<Option<Attend>> {
        let Some(bytes) = store
            .read(ATTEND_OWNER, &self.snapshot.slot)
            .map_err(storage_error)?
        else {
            return Ok(None);
        };
        let checkpoint: Checkpoint = postcard::from_bytes(bytes).map_err(encoding_error)?;
        Ok(Some(Attend::restore(checkpoint)))
    }
}

/// What the caller lends to one leave.
pub struct LeaveParts<'a, B: Backend, S, A, C> {
    pub store: &'a mut Store<B>,
    /// This member's Threads for the room's group.
    pub threads: &'a Threads,
    /// The prepared Groups `Leave`; consumed by the single commit.
    pub groups: cgrp::Candidate,
    pub source: &'a S,
    pub authority: &'a A,
    pub clock: &'a mut C,
    /// Distinguishes this leave's shared checkpoint.
    pub operation: [u8; 32],
}

struct Leave<'a, B: Backend, S, A> {
    store: &'a mut Store<B>,
    threads: &'a Threads,
    groups: Option<cgrp::Candidate>,
    source: &'a S,
    authority: &'a A,
    now: u64,
    operation: [u8; 32],
    outcome: Option<cgrp::Snapshot>,
}

struct Transaction<'a, B: Backend> {
    store: &'a mut Store<B>,
    slot: [u8; 32],
    group: cgrp::Id,
    member: String,
    operation: [u8; 32],
    attend: &'a [u8],
}

impl<B: Backend> cgrp::Persistence for Transaction<'_, B> {
    fn commit<'a>(
        &'a mut self,
        expected: u64,
        snapshot: &'a cgrp::Snapshot,
        effects: &'a [Effect],
    ) -> cgrp::CommitFuture<'a> {
        Box::pin(async move {
            // The Groups decision must be this member leaving this group, and
            // nothing about any other group.
            let left = effects.iter().any(|effect| {
                matches!(
                    effect,
                    Effect::Membership { group, members, .. }
                        if group == &self.group && !members.contains(&self.member)
                )
            });
            if !left
                || effects.iter().any(|effect| {
                    matches!(effect, Effect::Membership { group, .. } if group != &self.group)
                })
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
            let version = self.store.version().map_err(|_| cgrp::Error::Reconcile)?;
            self.store
                .commit(
                    version,
                    self.operation,
                    &[
                        Change::Put {
                            owner: "cgrp",
                            key: b"snapshot.v1",
                            value: &bytes,
                        },
                        Change::Delete {
                            owner: OWNER,
                            key: &self.slot,
                        },
                        Change::Put {
                            owner: ATTEND_OWNER,
                            key: &self.slot,
                            value: self.attend,
                        },
                    ],
                    &[],
                )
                .await
                .map_err(|_| cgrp::Error::Reconcile)?;
            Ok(cgrp::Commit::Applied)
        })
    }
}

impl<B: Backend, S: PolicySource, A: cgrp::Authority> ctnd::Persistence for Leave<'_, B, S, A> {
    fn commit<'a>(
        &'a mut self,
        expected: u64,
        checkpoint: &'a Checkpoint,
        encrypted_outputs: &'a [Vec<u8>],
    ) -> PortFuture<'a, ()> {
        Box::pin(async move {
            if checkpoint.phase() != &Phase::Withdrawn || !encrypted_outputs.is_empty() {
                return Err(ctnd::Error::Invalid);
            }
            let slot = self.threads.snapshot.slot;
            if checkpoint.group() != slot {
                return Err(ctnd::Error::Invalid);
            }
            let current = match self
                .store
                .read(ATTEND_OWNER, &slot)
                .map_err(|_| ctnd::Error::Storage)?
            {
                None => 0,
                Some(stored) => postcard::from_bytes::<Checkpoint>(stored)
                    .map_err(|_| ctnd::Error::Storage)?
                    .local_revision(),
            };
            let version = self.store.version().map_err(|_| ctnd::Error::Storage)?;
            if current != expected || version != self.threads.expected {
                return Err(ctnd::Error::Reconcile);
            }
            let bytes = postcard::to_allocvec(checkpoint).map_err(|_| ctnd::Error::Storage)?;
            let groups = self.groups.take().ok_or(ctnd::Error::Invalid)?;
            groups
                .revalidate(self.source, self.authority, self.now)
                .map_err(|_| ctnd::Error::Authority)?;
            let mut transaction = Transaction {
                store: &mut *self.store,
                slot,
                group: slot,
                member: self.threads.snapshot.binding.member().to_owned(),
                operation: self.operation,
                attend: &bytes,
            };
            let (snapshot, _) = groups
                .persist(&mut transaction, self.now)
                .await
                .map_err(|_| ctnd::Error::Reconcile)?;
            self.outcome = Some(snapshot);
            Ok(())
        })
    }
}

/// Withdraw `attend` and leave the group in one Store commit; returns the
/// published Groups snapshot. A failed leave changes nothing visible.
pub async fn leave_room<B, S, A, C>(
    attend: &mut Attend,
    parts: LeaveParts<'_, B, S, A, C>,
) -> ctnd::Result<cgrp::Snapshot>
where
    B: Backend,
    S: PolicySource,
    A: cgrp::Authority,
    C: ckmg::Clock,
{
    let now = parts.clock.now().map_err(|_| ctnd::Error::Unavailable)?;
    let mut leave = Leave {
        store: parts.store,
        threads: parts.threads,
        groups: Some(parts.groups),
        source: parts.source,
        authority: parts.authority,
        now,
        operation: parts.operation,
        outcome: None,
    };
    attend.withdraw(&mut leave).await?;
    leave.outcome.ok_or(ctnd::Error::Storage)
}
