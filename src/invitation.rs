//! Original contact invitations bind current public device possession separately
//! from local private Lineage authority. Neither this wire nor its parsed fields
//! can choose an expected peer, recipient, operation or challenge.
use crate::{Error, Result, bounded_wire, purpose};
use ckmg::{Binding, KeyCertificate};
use serde::{Deserialize, Serialize};

mod authority;
mod owned_export;
mod parents;
mod producer;
mod verification;
pub use authority::InvitationAuthority;
pub use parents::InvitedParent;
pub use verification::{InvitationCurrent, VerifiedInvitation};

/// Exact independently retained original operation and recipient challenge.
/// The trusted application builds this from its pending invitation, not by
/// copying the submitted proof's fields. Construction grants no authority.
pub struct InvitationExpected<'a> {
    pub sender: &'a Binding,
    pub recipient: &'a Binding,
    pub request: &'a cgrp::Request,
    pub consent: &'a cgrp::Consent,
    /// Exact committed parent exports in the same canonical order as Request.parents.
    pub parents: &'a [crate::ParentEvidence],
    pub challenge: &'a [u8; 32],
    pub valid_until: u64,
}

/// Bounded canonical original owner bytes for one exact device-signing intent.
/// These bytes are public input, never a local signing authorization capability.
pub struct InvitationStatement {
    bytes: Vec<u8>,
}
impl InvitationStatement {
    /// Bind both original Consent and purpose certificate, plus the exact public
    /// profile. Ordinary Consent v2 and its unsigned authority field are unchanged.
    pub fn new(
        expected: &InvitationExpected<'_>,
        certificate: &KeyCertificate,
        publication: &cpfl::Publication,
    ) -> Result<Self> {
        let consent = expected.consent;
        let request = expected.request;
        if expected.sender.community() != expected.recipient.community()
            || expected.sender == expected.recipient
            || consent.member != expected.sender.member()
            || consent.community != expected.sender.community()
            || consent.operation != request.operation
            || consent.command_digest != request.command_digest().map_err(|_| Error::Encoding)?
            || consent.policy_epoch == 0
            || expected.valid_until == 0
            || expected.valid_until > consent.valid_until
            || certificate.binding != *expected.sender
            || certificate.purpose != purpose()
        {
            return Err(Error::Authority);
        }
        let recipient = expected.recipient.member();
        let included = match &request.command {
            cgrp::Command::Create { members, .. } | cgrp::Command::Fork { members, .. } => {
                request.actor == expected.sender.member() && members.contains(recipient)
            }
            cgrp::Command::Join { member, .. } => member == recipient && request.actor == recipient,
            cgrp::Command::Leave { .. } | cgrp::Command::Describe { .. } | cgrp::Command::Tick => {
                false
            }
        };
        if !included || consent.signature.len() != 64 {
            return Err(Error::Authority);
        }
        let parents = parent_digests(expected)?;
        // Check original owner bounds before hashing. This is not a decoder
        // that can turn untrusted serialized expectations into an authority.
        let consent_bytes = consent.signing_bytes().map_err(|_| Error::Encoding)?;
        bounded_wire(&consent_bytes)?;
        let certificate_bytes = postcard::to_allocvec(certificate).map_err(|_| Error::Encoding)?;
        bounded_wire(&certificate_bytes)?;
        let publication_bytes = publication.to_bytes().map_err(|_| Error::Encoding)?;
        bounded_wire(&publication_bytes)?;
        let bytes = postcard::to_allocvec(&(
            "cthr.invitation.v1\0",
            1u16,
            expected.sender,
            expected.recipient,
            request.operation,
            consent.command_digest,
            *ckmg::hash(&consent_bytes).value(),
            &consent.signature,
            *ckmg::hash(&certificate_bytes).value(),
            *ckmg::hash(&publication_bytes).value(),
            parents,
            expected.challenge,
            consent.policy_epoch,
            expected.valid_until,
        ))
        .map_err(|_| Error::Encoding)?;
        bounded_wire(&bytes)?;
        Ok(Self { bytes })
    }

    /// The original exact bytes to admit and sign through Keys' one-use device
    /// intent and final synchronous current-owner check; never a generic signer.
    pub fn signing_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn parent_digests(expected: &InvitationExpected<'_>) -> Result<Vec<[u8; 32]>> {
    if expected.parents.len() != expected.request.parents.len()
        || expected.parents.len() > 2
        || expected
            .request
            .parents
            .windows(2)
            .any(|pair| pair[0].id >= pair[1].id)
    {
        return Err(Error::Authority);
    }
    expected
        .parents
        .iter()
        .zip(&expected.request.parents)
        .map(|(evidence, parent)| {
            // Apply each original owner bound before canonical encoding/hashing.
            bounded_wire(&evidence.group_info)?;
            bounded_wire(&evidence.ratchet_tree)?;
            let state = cgrp::GroupState::decode(&evidence.state).map_err(|_| Error::Encoding)?;
            if state.community() != expected.sender.community()
                || state.id() != &parent.id
                || state.commitment().map_err(|_| Error::Encoding)? != parent.commitment
                || !state.members().contains(expected.sender.member())
            {
                return Err(Error::Authority);
            }
            let bytes = postcard::to_allocvec(&(
                "cthr.invitation.parent.v1\0",
                &evidence.state,
                &evidence.group_info,
                &evidence.ratchet_tree,
            ))
            .map_err(|_| Error::Encoding)?;
            Ok(*ckmg::hash(&bytes).value())
        })
        .collect()
}

/// Untrusted signature response. It contains no expected scope or authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationProof {
    statement: Vec<u8>,
    signature: Vec<u8>,
}
impl InvitationProof {
    pub fn signed(statement: &InvitationStatement, signature: &[u8; 64]) -> Self {
        Self {
            statement: statement.bytes.clone(),
            signature: signature.to_vec(),
        }
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.shape()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| Error::Encoding)?;
        bounded_wire(&bytes)?;
        Ok(bytes)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bounded_wire(bytes)?;
        let (proof, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| Error::Encoding)?;
        if !remainder.is_empty() {
            return Err(Error::Encoding);
        }
        proof.shape()?;
        Ok(proof)
    }
    fn shape(&self) -> Result<()> {
        bounded_wire(&self.statement)?;
        if self.signature.len() != 64 {
            return Err(Error::Encoding);
        }
        Ok(())
    }
}
