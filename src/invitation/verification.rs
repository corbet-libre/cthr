use super::*;

/// Borrow actual currently installed Charter and committed local Contacts.
/// The surrounding member owner must hold its genuine own-lineage authority
/// and rebuild this observation after every external await.
pub struct InvitationCurrent<'a> {
    pub charter: &'a cchr::VerifiedCharter,
    pub contacts: &'a ctcs::Contacts,
    pub issuance_action: &'a str,
    pub minimum_profile_revision: u64,
    pub now: u64,
}

/// Exact current public-device invitation authorization. No Clone/Serde, no
/// Lineage or private epoch verdict, no complete Groups/import/room authority.
pub struct VerifiedInvitation {
    certificate: KeyCertificate,
    statement: Vec<u8>,
    checked_at: u64,
    valid_until: u64,
}
impl VerifiedInvitation {
    pub fn certificate(&self) -> &KeyCertificate {
        &self.certificate
    }
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
    /// Re-run the actual public owner checks at a later cut. A retained result
    /// never substitutes for the currently installed Charter or Contacts state.
    pub fn recheck(
        &self,
        expected: &InvitationExpected<'_>,
        publication: &cpfl::Publication,
        proof: &InvitationProof,
        current: &InvitationCurrent<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<Self> {
        if current.now < self.checked_at || current.now >= self.valid_until {
            return Err(Error::Clock);
        }
        let mut verified =
            proof.verify(expected, &self.certificate, publication, current, contact)?;
        if verified.statement != self.statement {
            return Err(Error::Authority);
        }
        verified.valid_until = verified.valid_until.min(self.valid_until);
        Ok(verified)
    }
}
impl InvitationProof {
    /// Authenticate the complete original peer profile and BOTH exact device
    /// signatures. All expectations are independent retained owner values.
    pub fn verify(
        &self,
        expected: &InvitationExpected<'_>,
        certificate: &KeyCertificate,
        publication: &cpfl::Publication,
        current: &InvitationCurrent<'_>,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<VerifiedInvitation> {
        self.shape()?;
        if current.now >= expected.valid_until
            || expected.request.effective_at > current.now
            || current.charter.community() != expected.sender.community()
            || current.charter.policy_epoch() != expected.consent.policy_epoch
            || current.contacts.binding() != expected.recipient
            || current.minimum_profile_revision == 0
        {
            return Err(Error::Authority);
        }
        let relation = current
            .contacts
            .relation(expected.sender.member())
            .map_err(|_| Error::Authority)?;
        if relation.state != ctcs::State::Established || relation.conflicted {
            return Err(Error::Authority);
        }
        let statement = InvitationStatement::new(expected, certificate, publication)?;
        // Exact canonical comparison also rejects unknown versions, trailing
        // statement bytes and every changed expected field without decoding it.
        if statement.bytes != self.statement {
            return Err(Error::Authority);
        }
        let policy = current
            .charter
            .current_admission_policy(current.issuance_action, current.now)
            .map_err(|_| Error::Authority)?;
        let profile = cpfl::verify_publication(
            publication,
            &policy,
            current
                .charter
                .publication(cchr::Kind::Schema)
                .signed_bytes(),
            current.minimum_profile_revision,
            contact,
        )
        .map_err(|_| Error::Authority)?;
        let peer = profile.transcript();
        if peer.community != expected.sender.community()
            || peer.member != expected.sender.member()
            || certificate.device.value() != &peer.device
        {
            return Err(Error::Authority);
        }
        certificate
            .verify_device_certificate(expected.sender, &purpose(), &certificate.device)
            .map_err(|_| Error::Authority)?;
        let consent_signature: &[u8; 64] = expected
            .consent
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::Encoding)?;
        ckmg::verify_ed25519(
            &peer.device,
            &expected
                .consent
                .signing_bytes()
                .map_err(|_| Error::Encoding)?,
            consent_signature,
        )
        .map_err(|_| Error::Authority)?;
        let signature: &[u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::Encoding)?;
        ckmg::verify_ed25519(&peer.device, &self.statement, signature)
            .map_err(|_| Error::Authority)?;
        let valid_until = expected
            .valid_until
            .min(profile.authority_until())
            .min(current.charter.valid_until());
        if current.now >= valid_until {
            return Err(Error::Authority);
        }
        Ok(VerifiedInvitation {
            certificate: certificate.clone(),
            statement: self.statement.clone(),
            checked_at: current.now,
            valid_until,
        })
    }
}
