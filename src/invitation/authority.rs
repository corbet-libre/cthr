//! Fresh sealed invitation evidence for the original Groups parent port.
use super::*;

/// Adds only missing-parent authorization to an existing genuine Groups
/// authority. Consent and contact decisions remain with that owner.
/// Borrowing this adapter is not a lease across awaits: refresh the exact
/// invitation, Charter, Contacts and MLS evidence before each later use.
pub struct InvitationAuthority<'a, A> {
    original: &'a A,
    recipient: &'a Binding,
    parents: &'a [InvitedParent],
}
impl<'a, A: cgrp::Authority> InvitationAuthority<'a, A> {
    pub fn new(
        original: &'a A,
        recipient: &'a Binding,
        parents: &'a [InvitedParent],
    ) -> Result<Self> {
        if parents.is_empty()
            || parents.len() > 2
            || parents.iter().any(|parent| parent.recipient != *recipient)
            || parents.windows(2).any(|pair| {
                pair[0].state.id() >= pair[1].state.id()
                    || pair[0].operation != pair[1].operation
                    || pair[0].policy_epoch != pair[1].policy_epoch
                    || pair[0].command_digest != pair[1].command_digest
                    || pair[0].checked_at != pair[1].checked_at
            })
        {
            return Err(Error::Authority);
        }
        Ok(Self {
            original,
            recipient,
            parents,
        })
    }
}
impl<A: cgrp::Authority> cgrp::Authority for InvitationAuthority<'_, A> {
    fn consent(&self, consent: &cgrp::Consent, now: u64) -> cgrp::Result<()> {
        self.original.consent(consent, now)
    }
    fn contact(&self, community: &str, member: &str, contact: &str, now: u64) -> cgrp::Result<()> {
        self.original.contact(community, member, contact, now)
    }
    fn parent(
        &self,
        state: &cgrp::GroupState,
        request: &cgrp::Request,
        policy: &cgrp::Policy,
        now: u64,
    ) -> cgrp::Result<()> {
        let parent = self
            .parents
            .iter()
            .find(|parent| parent.state.id() == state.id())
            .ok_or(cgrp::Error::Authority)?;
        if parent.recipient != *self.recipient
            || state.community() != self.recipient.community()
            || parent.state != *state
            || parent.operation != request.operation
            || parent.policy_epoch != policy.epoch
            || parent.command_digest != request.command_digest()?
            || now != parent.checked_at
            || now >= parent.valid_until
        {
            return Err(cgrp::Error::Authority);
        }
        Ok(())
    }
}
