use super::*;
use cthr::invitation::InvitationAuthority;

// This adapter commits the original Groups journal through the real encrypted
// Store CAS. It does not claim combined Threads/Groups MLS publication.
struct Journal<'a> {
    store: &'a mut cwst::Store<cwst::backend::Memory>,
    operation: [u8; 32],
}
impl cgrp::Persistence for Journal<'_> {
    fn commit<'a>(
        &'a mut self,
        expected: u64,
        candidate: &'a cgrp::Snapshot,
        _: &'a [cgrp::Effect],
    ) -> cgrp::CommitFuture<'a> {
        Box::pin(async move {
            let current = cgrp::Snapshot::load("alpha", self.store)?;
            if current.revision() != expected {
                return Ok(cgrp::Commit::Conflict);
            }
            let version = self.store.version().map_err(|_| cgrp::Error::Reconcile)?;
            let bytes = postcard::to_allocvec(candidate).unwrap();
            self.store
                .commit(
                    version,
                    self.operation,
                    &[cwst::Change::Put {
                        owner: "cgrp",
                        key: b"snapshot.v1",
                        value: &bytes,
                    }],
                    &[],
                )
                .await
                .map_err(|_| cgrp::Error::Reconcile)?;
            Ok(cgrp::Commit::Applied)
        })
    }
}

pub(super) async fn exercise(f: &mut Fixture, setup: &mut Setup, count: usize) {
    let required: std::collections::BTreeSet<String> = match &f.request.command {
        cgrp::Command::Fork { members, .. } => members.clone(),
        cgrp::Command::Join { member, .. } => [member.clone()].into(),
        _ => panic!(),
    };
    f.request.consents.clear();
    for peer in std::iter::once(&mut f.sender)
        .chain(std::iter::once(&mut f.recipient))
        .chain(setup.peers.iter_mut())
    {
        if !required.contains(peer.binding.member()) && peer.binding.member() != "alice" {
            continue;
        }
        let mut consent = cgrp::Consent {
            community: "alpha".into(),
            member: peer.binding.member().into(),
            operation: f.request.operation,
            policy_epoch: 2,
            command_digest: f.request.command_digest().unwrap(),
            profile_visibility: true,
            valid_until: UNTIL,
            key_package: vec![],
            lineage_handle: vec![],
            signature: vec![],
            authority: vec![],
        };
        consent.signature = peer
            .sign(&consent.signing_bytes().unwrap(), UNTIL)
            .await
            .to_vec();
        if peer.binding.member() == "alice" {
            f.consent = consent.clone();
        }
        if required.contains(peer.binding.member()) {
            f.request.consents.push(consent);
        }
    }
    let proof = f.proof().await;
    let original = Groups {
        devices: std::iter::once(&f.sender)
            .chain(std::iter::once(&f.recipient))
            .chain(setup.peers.iter())
            .map(|peer| {
                (
                    peer.binding.member().into(),
                    *peer.certificate.device.value(),
                )
            })
            .collect(),
        contacts: &setup.contacts,
    };
    let base = cgrp::Snapshot::load("alpha", &f.store).unwrap();
    assert_eq!(base.revision(), 0);
    assert!(base.group_state(&[81; 32]).is_err());
    let candidate = {
        let mut clock = f.recipient.time.clone();
        let parents = proof
            .verify_parents(
                &f.expected(),
                &f.sender.certificate,
                &f.publication,
                &f.current(NOW).view(),
                &clean,
                &mut clock,
            )
            .unwrap();
        let states: Vec<_> = parents
            .iter()
            .map(|parent| parent.state().clone())
            .collect();
        // A genuine original authority cannot accept a raw imported state: its
        // new parent port refuses by default until the exact seal is attached.
        assert!(
            cgrp::prepare_with_parents(
                &base,
                &f.request,
                &states,
                &setup.source,
                &original,
                NOW,
                10
            )
            .is_err()
        );
        assert!(InvitationAuthority::new(&original, &f.sender.binding, &parents).is_err());
        let adapter = InvitationAuthority::new(&original, &f.recipient.binding, &parents).unwrap();
        let selected = cgrp::PolicySource::current(&setup.source, "alpha", NOW).unwrap();
        assert!(cgrp::Authority::parent(&adapter, &states[0], &f.request, &selected, NOW).is_ok());
        let mut changed = selected.clone();
        changed.epoch = 3;
        let next_source = group_support::SignedPolicy::new(&changed);
        let next = cgrp::PolicySource::current(&next_source, "alpha", NOW).unwrap();
        // A genuine newer signed Groups policy does not make an invitation
        // authenticated under Charter epoch2 into epoch3 parent authority.
        assert!(cgrp::Authority::parent(&adapter, &states[0], &f.request, &next, NOW).is_err());
        assert!(
            cgrp::prepare_with_parents(&base, &f.request, &states, &next_source, &adapter, NOW, 10)
                .is_err()
        );
        let candidate = cgrp::prepare_with_parents(
            &base,
            &f.request,
            &states,
            &setup.source,
            &adapter,
            NOW,
            10,
        )
        .unwrap();
        candidate.check_base(&base).unwrap();
        assert!(
            candidate
                .check_base(&cgrp::Snapshot::empty("beta".into()))
                .is_err()
        );
        let effects = candidate.prepare_effects();
        let target = if count == 12 { [85; 32] } else { [81; 32] };
        let effect = effects
            .iter()
            .find(|effect| effect.group_state().id() == &target)
            .unwrap();
        assert_eq!(effect.group_state().members().len(), count + 1);
        assert!(effect.group_state().members().contains("bob"));
        assert_eq!(
            effect.group_state().level(),
            if count == 12 {
                cgrp::Level::Ingroup
            } else {
                cgrp::Level::Public
            }
        );
        assert!(candidate.revalidate(&setup.source, &original, NOW).is_err());
        assert!(
            candidate
                .revalidate(&setup.source, &adapter, NOW + 1)
                .is_err()
        );
        let mut damaged = f.request.clone();
        damaged
            .consents
            .iter_mut()
            .find(|consent| consent.member == "bob")
            .unwrap()
            .signature[0] ^= 1;
        assert!(
            cgrp::prepare_with_parents(&base, &damaged, &states, &setup.source, &adapter, NOW, 10)
                .is_err()
        );
        let mut different = f.request.clone();
        different.operation[0] ^= 1;
        assert!(
            cgrp::prepare_with_parents(
                &base,
                &different,
                &states,
                &setup.source,
                &adapter,
                NOW,
                10
            )
            .is_err()
        );
        drop(effects);
        candidate
    };
    // Refresh genuine public owners and MLS import at the actual new clock cut.
    f.recipient.time.0.set(NOW + 1);
    {
        let mut clock = f.recipient.time.clone();
        let parents = proof
            .verify_parents(
                &f.expected(),
                &f.sender.certificate,
                &f.publication,
                &f.current(NOW + 1).view(),
                &clean,
                &mut clock,
            )
            .unwrap();
        let adapter = InvitationAuthority::new(&original, &f.recipient.binding, &parents).unwrap();
        candidate
            .revalidate(&setup.source, &adapter, NOW + 1)
            .unwrap();
        assert!(
            candidate
                .revalidate(&setup.source, &adapter, UNTIL)
                .is_err()
        );
    }
    let before = f.store.version().unwrap();
    let (_, committed_effects) = candidate
        .persist(
            &mut Journal {
                store: &mut f.store,
                operation: f.request.operation,
            },
            NOW + 1,
        )
        .await
        .unwrap();
    assert!(!committed_effects.is_empty());
    assert!(f.store.version().unwrap() > before);
    let current = cgrp::Snapshot::load("alpha", &f.store).unwrap();
    let target = if count == 12 { [85; 32] } else { [81; 32] };
    assert_eq!(current.members(&target).unwrap().len(), count + 1);
    let before = f.store.version().unwrap();
    {
        let mut clock = f.recipient.time.clone();
        let parents = proof
            .verify_parents(
                &f.expected(),
                &f.sender.certificate,
                &f.publication,
                &f.current(NOW + 1).view(),
                &clean,
                &mut clock,
            )
            .unwrap();
        let states: Vec<_> = parents
            .iter()
            .map(|parent| parent.state().clone())
            .collect();
        let adapter = InvitationAuthority::new(&original, &f.recipient.binding, &parents).unwrap();
        assert!(
            cgrp::prepare_with_parents(
                &current,
                &f.request,
                &states,
                &setup.source,
                &adapter,
                NOW + 1,
                10
            )
            .is_err()
        );
        assert!(cgrp::prepare(&current, &f.request, &setup.source, &adapter, NOW + 1, 10).is_err());
    }
    assert_eq!(f.store.version().unwrap(), before);
    let published = f.published.get_mut();
    published.now = NOW + 1;
    published.install(2, &["alice".into()], &[]);
    let mut clock = f.recipient.time.clone();
    assert!(
        proof
            .verify_parents(
                &f.expected(),
                &f.sender.certificate,
                &f.publication,
                &f.current(NOW + 1).view(),
                &clean,
                &mut clock
            )
            .is_err()
    );
    assert_eq!(f.store.version().unwrap(), before);
}
