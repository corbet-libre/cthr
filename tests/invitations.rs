//! Genuine Keys signatures, Charter/Profile and committed Contacts composition.
//! The lineage and signed external CTCS answer fixture do not establish private
//! peer Lineage freshness, production G3, Waves release, or completed MLS import.
//! Community issuer decisions are genuinely signed fixture inputs, not a full
//! issuer admission journey. Parent import and Groups journal tests retain their
//! separate owner boundaries; they do not publish a combined MLS successor.
#[path = "invitations/contacts.rs"]
mod contacts;
#[path = "invitations/fixture.rs"]
mod fixture;
#[path = "invitations/keys.rs"]
mod keys;
#[path = "invitations/profile.rs"]
mod profile;
#[path = "support/mod.rs"]
mod support;
use cthr::invitation::{
    InvitationCurrent, InvitationExpected, InvitationProof, InvitationStatement, VerifiedInvitation,
};
use fixture::Fixture;
use futures::executor::block_on;

const ORIGIN: &str = "https://alpha.example.test";
const ACTION: &str = "admission";
const NOW: u64 = 1100;
const UNTIL: u64 = 1200;
fn clean(_: &str) -> cshm::ContactCheck {
    cshm::ContactCheck::Clear
}

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
macro_rules! shared {
    ($name:ident,$body:block)=> {
        #[cfg_attr(target_arch="wasm32",wasm_bindgen_test::wasm_bindgen_test)]
        #[cfg_attr(not(target_arch="wasm32"),test)]
        fn $name(){block_on(Box::pin(async $body));}
    };
}
#[path = "support/groups.rs"]
mod group_support;
#[path = "invitations/parents.rs"]
mod parents;
shared!(
    genuine_invitation_uses_same_authorized_device_and_current_publication,
    {
        let mut f = Fixture::new().await;
        let proof = f.proof().await;
        let wire = proof.to_bytes().unwrap();
        let proof = InvitationProof::from_bytes(&wire).unwrap();
        let verified = f.verify(&proof, NOW).unwrap();
        assert!(verified.certificate() == &f.sender.certificate);
        assert_eq!(verified.checked_at(), NOW);
        assert_eq!(verified.valid_until(), UNTIL);
        let later = verified
            .recheck(
                &f.expected(),
                &f.publication,
                &proof,
                &f.current(NOW + 1).view(),
                &clean,
            )
            .unwrap();
        assert_eq!(later.checked_at(), NOW + 1);
        assert_eq!(later.valid_until(), UNTIL);
        let mut earlier = f.current(NOW + 1);
        earlier.now = NOW - 1;
        assert!(
            verified
                .recheck(
                    &f.expected(),
                    &f.publication,
                    &proof,
                    &earlier.view(),
                    &clean
                )
                .is_err()
        );
        drop(earlier);
        assert!(f.verify(&proof, UNTIL).is_err());
    }
);
shared!(
    certificate_substitution_never_reuses_original_consent_or_device_proof,
    {
        let mut f = Fixture::new().await;
        let proof = f.proof().await;
        let mut unrelated = keys::Peer::new("alice", 3).await;
        let different = unrelated
            .keys
            .key(cthr::purpose())
            .await
            .unwrap()
            .certificate()
            .clone();
        for case in 0..5 {
            let mut certificate = f.sender.certificate.clone();
            match case {
                0 => certificate.purpose = ctcs::purpose(),
                1 => certificate.key = different.key,
                2 => certificate.device = different.device,
                3 => certificate.binding = f.recipient.binding.clone(),
                _ => certificate.epoch += 1,
            }
            assert!(
                proof
                    .verify(
                        &f.expected(),
                        &certificate,
                        &f.publication,
                        &f.current(NOW).view(),
                        &clean
                    )
                    .is_err()
            );
        }
        // Another genuine certificate for the same member cannot pass Guard with
        // an unlisted device, even when that new device signs the complete body.
        unrelated.time.0.set(NOW);
        let statement =
            InvitationStatement::new(&f.expected(), &different, &f.publication).unwrap();
        let signature = unrelated.sign(statement.signing_bytes(), UNTIL).await;
        let proof = InvitationProof::signed(&statement, &signature);
        assert!(
            proof
                .verify(
                    &f.expected(),
                    &different,
                    &f.publication,
                    &f.current(NOW).view(),
                    &clean
                )
                .is_err()
        );
    }
);
shared!(
    retained_operation_recipient_challenge_and_time_are_independent_expectations,
    {
        let mut f = Fixture::new().await;
        let proof = f.proof().await;
        for case in 0..8 {
            let mut request = f.request.clone();
            let mut consent = f.consent.clone();
            let mut recipient = f.recipient.binding.clone();
            let mut challenge = f.challenge;
            let mut until = UNTIL;
            match case {
                0 => request.operation[0] ^= 1,
                1 => request.actor = "bob".into(),
                2 => request.effective_at += 1,
                3 => challenge[0] ^= 1,
                4 => recipient = ckmg::Binding::new("alpha", "carol").unwrap(),
                5 => until -= 1,
                6 => consent.signature[0] ^= 1,
                _ => consent.policy_epoch += 1,
            }
            let expected = InvitationExpected {
                request: &request,
                consent: &consent,
                recipient: &recipient,
                challenge: &challenge,
                valid_until: until,
                ..f.expected()
            };
            assert!(
                proof
                    .verify(
                        &expected,
                        &f.sender.certificate,
                        &f.publication,
                        &f.current(NOW).view(),
                        &clean
                    )
                    .is_err()
            );
        }
    }
);
shared!(
    fresh_signed_revocations_and_policy_epoch_refuse_old_invitation,
    {
        for case in 0..3 {
            let mut f = Fixture::new().await;
            let proof = f.proof().await;
            let verified = f.verify(&proof, NOW).unwrap();
            match case {
                0 => f.published.get_mut().install(2, &["alice".into()], &[]),
                1 => f
                    .published
                    .get_mut()
                    .install(2, &[], &[*f.sender.certificate.device.value()]),
                _ => f.published.get_mut().install(3, &[], &[]),
            }
            assert!(f.verify(&proof, NOW).is_err());
            assert!(
                verified
                    .recheck(
                        &f.expected(),
                        &f.publication,
                        &proof,
                        &f.current(NOW).view(),
                        &clean
                    )
                    .is_err()
            );
        }
    }
);
shared!(
    contacts_must_be_reloaded_after_actual_committed_withdrawal,
    {
        let mut f = Fixture::new().await;
        let proof = f.proof().await;
        let verified = f.verify(&proof, NOW).unwrap();
        let prior = f.contacts.version();
        contacts::apply(
            &mut f.recipient,
            "alice",
            &mut f.store,
            ctcs::Action::Block,
            53,
        )
        .await;
        assert!(f.store.version().unwrap() > prior);
        // A saved Contacts view has no magical currentness. The surrounding owner
        // must load the actual checkpoint after its await, as this cut does.
        f.contacts = ctcs::Contacts::load(f.recipient.binding.clone(), &f.store).unwrap();
        assert_eq!(
            f.contacts.relation("alice").unwrap().state,
            ctcs::State::Blocked
        );
        assert!(f.verify(&proof, NOW).is_err());
        assert!(
            verified
                .recheck(
                    &f.expected(),
                    &f.publication,
                    &proof,
                    &f.current(NOW).view(),
                    &clean
                )
                .is_err()
        );
    }
);
shared!(profile_body_floor_and_device_signature_damage_refuse, {
    let mut f = Fixture::new().await;
    let proof = f.proof().await;
    for case in 0..4 {
        let mut publication =
            cpfl::Publication::from_bytes(&f.publication.to_bytes().unwrap()).unwrap();
        match case {
            0 => publication.signature[0] ^= 1,
            1 => publication.transcript[0] ^= 1,
            2 => publication.public_bundle[0] ^= 1,
            _ => publication.envelope[0] ^= 1,
        }
        assert!(
            proof
                .verify(
                    &f.expected(),
                    &f.sender.certificate,
                    &publication,
                    &f.current(NOW).view(),
                    &clean
                )
                .is_err()
        );
    }
    let mut current = f.current(NOW);
    current.minimum_profile_revision = 2;
    assert!(
        proof
            .verify(
                &f.expected(),
                &f.sender.certificate,
                &f.publication,
                &current.view(),
                &clean
            )
            .is_err()
    );
    drop(current);
    let mut current = f.current(NOW);
    current.issuance_action = "other";
    assert!(
        proof
            .verify(
                &f.expected(),
                &f.sender.certificate,
                &f.publication,
                &current.view(),
                &clean
            )
            .is_err()
    );
});
shared!(
    fresh_device_signature_does_not_repair_invalid_certificate_or_profile,
    {
        let mut f = Fixture::new().await;
        let mut certificate = f.sender.certificate.clone();
        certificate.epoch += 1;
        let statement =
            InvitationStatement::new(&f.expected(), &certificate, &f.publication).unwrap();
        let signature = f.sender.sign(statement.signing_bytes(), UNTIL).await;
        let proof = InvitationProof::signed(&statement, &signature);
        assert!(
            proof
                .verify(
                    &f.expected(),
                    &certificate,
                    &f.publication,
                    &f.current(NOW).view(),
                    &clean
                )
                .is_err()
        );

        let mut publication =
            cpfl::Publication::from_bytes(&f.publication.to_bytes().unwrap()).unwrap();
        publication.signature[0] ^= 1;
        let statement =
            InvitationStatement::new(&f.expected(), &f.sender.certificate, &publication).unwrap();
        let signature = f.sender.sign(statement.signing_bytes(), UNTIL).await;
        let proof = InvitationProof::signed(&statement, &signature);
        assert!(
            proof
                .verify(
                    &f.expected(),
                    &f.sender.certificate,
                    &publication,
                    &f.current(NOW).view(),
                    &clean
                )
                .is_err()
        );
    }
);
shared!(
    current_contact_scanner_is_required_even_with_genuine_publication,
    {
        let mut f = Fixture::new().await;
        let proof = f.proof().await;
        let verified = f.verify(&proof, NOW).unwrap();
        for result in [cshm::ContactCheck::Found, cshm::ContactCheck::Unavailable] {
            let scan = |_: &str| result;
            assert!(
                proof
                    .verify(
                        &f.expected(),
                        &f.sender.certificate,
                        &f.publication,
                        &f.current(NOW).view(),
                        &scan
                    )
                    .is_err()
            );
            assert!(
                verified
                    .recheck(
                        &f.expected(),
                        &f.publication,
                        &proof,
                        &f.current(NOW).view(),
                        &scan
                    )
                    .is_err()
            );
        }
    }
);
shared!(
    wire_has_exact_framing_and_signature_damage_never_creates_capability,
    {
        let mut f = Fixture::new().await;
        let proof = f.proof().await;
        let mut trailing = proof.to_bytes().unwrap();
        trailing.push(0);
        assert!(InvitationProof::from_bytes(&trailing).is_err());
        assert!(InvitationProof::from_bytes(&[]).is_err());
        assert!(InvitationProof::from_bytes(&vec![0; 1024 * 1024 + 1]).is_err());
        for field in ["statement", "signature"] {
            let mut value = serde_json::to_value(&proof).unwrap();
            let byte = value[field][0].as_u64().unwrap() as u8;
            value[field][0] = serde_json::json!(byte ^ 1);
            let damaged: InvitationProof = serde_json::from_value(value).unwrap();
            assert!(f.verify(&damaged, NOW).is_err());
        }
    }
);

shared!(
    renewed_current_charter_does_not_extend_retained_invitation_deadline,
    {
        let mut f = Fixture::new().await;
        let proof = f.proof().await;
        let published = f.published.get_mut();
        published.until = UNTIL - 10;
        published.install(2, &[], &[]);
        let verified = f.verify(&proof, NOW).unwrap();
        assert_eq!(verified.valid_until(), UNTIL - 10);
        let published = f.published.get_mut();
        published.until = 1400;
        published.install(2, &[], &[]);
        assert_eq!(f.verify(&proof, NOW).unwrap().valid_until(), UNTIL);
        let retained = verified
            .recheck(
                &f.expected(),
                &f.publication,
                &proof,
                &f.current(NOW).view(),
                &clean,
            )
            .unwrap();
        assert_eq!(retained.valid_until(), UNTIL - 10);
        assert!(
            retained
                .recheck(
                    &f.expected(),
                    &f.publication,
                    &proof,
                    &f.current(UNTIL - 10).view(),
                    &clean
                )
                .is_err()
        );
    }
);
