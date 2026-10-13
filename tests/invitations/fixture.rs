use super::*;

pub struct Fixture {
    pub sender: keys::Peer,
    pub recipient: keys::Peer,
    pub published: std::cell::RefCell<profile::Published>,
    pub publication: cpfl::Publication,
    pub store: cwst::Store<cwst::backend::Memory>,
    pub contacts: ctcs::Contacts,
    pub request: cgrp::Request,
    pub consent: cgrp::Consent,
    pub challenge: [u8; 32],
    pub parents: Vec<cthr::ParentEvidence>,
}
impl Fixture {
    pub async fn new() -> Self {
        let mut sender = keys::Peer::new("alice", 1).await;
        let mut recipient = keys::Peer::new("bob", 2).await;
        sender.time.0.set(NOW);
        recipient.time.0.set(NOW);
        let mut published = profile::Published::new();
        let publication = published.profile(&mut sender).await;
        let mut store = contacts::store().await;
        contacts::establish(&mut recipient, sender.binding.member(), &mut store).await;
        let contacts = ctcs::Contacts::load(recipient.binding.clone(), &store).unwrap();
        assert_eq!(
            contacts.relation(sender.binding.member()).unwrap().state,
            ctcs::State::Established
        );
        let request = cgrp::Request {
            operation: [60; 32],
            parents: vec![],
            effective_at: NOW,
            actor: sender.binding.member().into(),
            command: cgrp::Command::Create {
                id: [61; 32],
                members: ["alice".into(), "bob".into(), "carol".into()].into(),
                seed: false,
            },
            consents: vec![],
        };
        let mut consent = cgrp::Consent {
            community: "alpha".into(),
            member: sender.binding.member().into(),
            operation: request.operation,
            policy_epoch: 2,
            command_digest: request.command_digest().unwrap(),
            profile_visibility: true,
            valid_until: UNTIL,
            key_package: vec![],
            lineage_handle: vec![],
            signature: vec![],
            authority: vec![],
        };
        consent.signature = sender
            .sign(&consent.signing_bytes().unwrap(), UNTIL)
            .await
            .to_vec();
        Self {
            sender,
            recipient,
            published: std::cell::RefCell::new(published),
            publication,
            store,
            contacts,
            request,
            consent,
            challenge: [62; 32],
            parents: vec![],
        }
    }
    pub fn expected(&self) -> InvitationExpected<'_> {
        InvitationExpected {
            sender: &self.sender.binding,
            recipient: &self.recipient.binding,
            request: &self.request,
            consent: &self.consent,
            parents: &self.parents,
            challenge: &self.challenge,
            valid_until: UNTIL,
        }
    }
    pub fn current(&self, now: u64) -> Observation<'_> {
        Observation {
            published: self.published.borrow_mut(),
            contacts: &self.contacts,
            observed_at: now,
            now,
            issuance_action: ACTION,
            minimum_profile_revision: 1,
        }
    }
    pub async fn proof(&mut self) -> InvitationProof {
        let statement = InvitationStatement::new(
            &self.expected(),
            &self.sender.certificate,
            &self.publication,
        )
        .unwrap();
        let signature = self.sender.sign(statement.signing_bytes(), UNTIL).await;
        InvitationProof::signed(&statement, &signature)
    }
    pub fn verify(&self, proof: &InvitationProof, now: u64) -> cthr::Result<VerifiedInvitation> {
        proof.verify(
            &self.expected(),
            &self.sender.certificate,
            &self.publication,
            &self.current(now).view(),
            &clean,
        )
    }
}

// Retain the actual Charter observation while its borrowed owner view is used.
// No VerifiedCharter constructor or copied wire expectation is introduced.
pub struct Observation<'a> {
    published: std::cell::RefMut<'a, profile::Published>,
    contacts: &'a ctcs::Contacts,
    observed_at: u64,
    pub now: u64,
    pub issuance_action: &'static str,
    pub minimum_profile_revision: u64,
}
impl Observation<'_> {
    pub fn view(&mut self) -> InvitationCurrent<'_> {
        InvitationCurrent {
            charter: self.published.charter.current(self.observed_at).unwrap(),
            contacts: self.contacts,
            issuance_action: self.issuance_action,
            minimum_profile_revision: self.minimum_profile_revision,
            maximum_snapshot_age: 300,
            now: self.now,
        }
    }
}
