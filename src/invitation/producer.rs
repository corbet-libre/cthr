use super::*;
use crate::{Threads, keys::Custody};
use cwst::{Store, backend::Backend};

impl InvitationStatement {
    /// Prepare public signing bytes only after checking each exact supplied
    /// export against this sender's original committed MLS and Groups owners.
    /// Keys must still authorize and sign the resulting complete bytes with a
    /// one-use device intent and its final current-owner hook. This is not a
    /// signing grant, nor permission to replace that hook with an earlier check.
    pub async fn from_committed<B: Backend>(
        expected: &InvitationExpected<'_>,
        publication: &cpfl::Publication,
        parents: &[&Threads],
        keys: &mut impl Custody,
        store: &Store<B>,
        source: &impl cgrp::PolicySource,
        clock: &mut impl ckmg::Clock,
    ) -> Result<Self> {
        if parents.len() != expected.parents.len() {
            return Err(Error::Authority);
        }
        let certificate = keys.certificate().clone();
        if certificate.binding != *expected.sender {
            return Err(Error::Authority);
        }
        // Bound and validate all original public inputs before owner awaits.
        let statement = Self::new(expected, &certificate, publication)?;
        let mut observed = clock.now().map_err(|_| Error::Clock)?;
        if observed >= expected.valid_until || observed < expected.request.effective_at {
            return Err(Error::Clock);
        }
        for (threads, evidence) in parents.iter().zip(expected.parents) {
            let verified_at = threads
                .verify_invitation_export(keys, store, evidence, source, clock)
                .await?;
            if verified_at < observed || verified_at >= expected.valid_until {
                return Err(Error::Clock);
            }
            observed = verified_at;
        }
        // Recheck ALL retained parent rows after the last owner await: checking
        // parent one only before parent two's await is not a final observation.
        for (threads, evidence) in parents.iter().zip(expected.parents) {
            threads.current_invitation_parent(store, evidence)?;
        }
        // These are shared borrows of one original Store view, not a lock on
        // independent handles. The actual signing composer must retain its
        // owner lease and freshly compare these exact parent/Contacts versions
        // again after any further await before releasing a device signature.
        let contacts =
            ctcs::Contacts::load(expected.sender.clone(), store).map_err(|_| Error::Authority)?;
        let relation = contacts
            .relation(expected.recipient.member())
            .map_err(|_| Error::Authority)?;
        if relation.state != ctcs::State::Established || relation.conflicted {
            return Err(Error::Authority);
        }
        let now = clock.now().map_err(|_| Error::Clock)?;
        if now < observed || now >= expected.valid_until || keys.certificate() != &certificate {
            return Err(Error::Clock);
        }
        let policy = source
            .current(expected.sender.community(), now)
            .map_err(|_| Error::Authority)?;
        policy.validate(now).map_err(|_| Error::Authority)?;
        if policy.epoch != expected.consent.policy_epoch {
            return Err(Error::Authority);
        }
        Ok(statement)
    }
}
