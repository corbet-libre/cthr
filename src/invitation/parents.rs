//! Maintained MLS import anchored by the exact current contact invitation.
use super::*;
use crate::{Error, crypto_error, decode_credential, encoding_error, group_context, parse};
use openmls::{group::PublicGroup, prelude::*};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use std::collections::BTreeSet;
use tls_codec::Deserialize as _;

/// One exact contact-endorsed parent with a genuine MLS context and roster.
/// This is not the latest public room, a Groups decision, a committed import,
/// or an assertion that every private peer Lineage is current.
pub struct InvitedParent {
    pub(super) state: cgrp::GroupState,
    pub(super) recipient: Binding,
    pub(super) operation: cgrp::Id,
    pub(super) policy_epoch: u64,
    pub(super) command_digest: cgrp::Id,
    pub(super) checked_at: u64,
    pub(super) valid_until: u64,
}
impl InvitedParent {
    pub fn state(&self) -> &cgrp::GroupState {
        &self.state
    }
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

impl InvitationProof {
    /// Verify the same current public invitation and import every exact parent
    /// with maintained OpenMLS in isolated storage. No accepted state changes.
    /// A caller crossing an await must repeat this against its newly observed
    /// original Charter, profile, committed Contacts and pending operation.
    pub fn verify_parents(
        &self,
        expected: &InvitationExpected<'_>,
        certificate: &KeyCertificate,
        publication: &cpfl::Publication,
        current: &InvitationCurrent<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        clock: &mut impl ckmg::Clock,
    ) -> Result<Vec<InvitedParent>> {
        if clock.now().map_err(|_| Error::Clock)? != current.now {
            return Err(Error::Clock);
        }
        let invitation = self.verify(expected, certificate, publication, current, contact)?;
        let mut parents = Vec::with_capacity(expected.parents.len());
        for evidence in expected.parents {
            // verify() already bound exact order/cardinality, canonical state,
            // all wire bounds and every byte of these three original values.
            let state = cgrp::GroupState::decode(&evidence.state).map_err(encoding_error)?;
            let info = match parse(&evidence.group_info)?.extract() {
                MlsMessageBodyIn::GroupInfo(info) => info,
                _ => return Err(Error::Encoding),
            };
            let tree = RatchetTreeIn::tls_deserialize_exact(&evidence.ratchet_tree)
                .map_err(encoding_error)?;
            let isolated = OpenMlsRustCrypto::default();
            let (imported, _) = PublicGroup::from_external(
                isolated.crypto(),
                isolated.storage(),
                tree,
                info,
                ProposalStore::new(),
            )
            .map_err(crypto_error)?;
            group_context::verify_context(imported.group_context(), &state)?;
            let mut members = BTreeSet::new();
            let mut exact_inviter = false;
            for member in imported.members() {
                let cert = decode_credential(&member.credential, &member.signature_key)?;
                if cert.binding.community() != expected.sender.community()
                    || !members.insert(cert.binding.member().to_owned())
                {
                    return Err(Error::Authority);
                }
                if cert.binding == *expected.sender {
                    if cert != *certificate {
                        return Err(Error::Authority);
                    }
                    exact_inviter = true;
                }
            }
            if !exact_inviter || &members != state.members() {
                return Err(Error::Authority);
            }
            parents.push(InvitedParent {
                state,
                recipient: expected.recipient.clone(),
                operation: expected.request.operation,
                policy_epoch: current.charter.policy_epoch(),
                command_digest: expected.request.command_digest().map_err(encoding_error)?,
                checked_at: current.now,
                valid_until: invitation.valid_until(),
            });
        }
        // No async boundary or arbitrary callback occurs after this cut.
        if clock.now().map_err(|_| Error::Clock)? != current.now {
            return Err(Error::Clock);
        }
        Ok(parents)
    }
}
