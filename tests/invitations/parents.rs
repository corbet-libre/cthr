use super::*;
use std::collections::BTreeMap;
#[path = "parents/cuts.rs"]
mod cuts;
#[path = "parents/groups.rs"]
mod groups;

// All certificates below come from real Keys; current test lineage is the
// original lower-owner seam. Groups contact checks read committed CTCS state.
struct Directory {
    lineages: BTreeMap<String, ckmg::Lineage>,
    local_only: Option<ckmg::Binding>,
}
impl ctcs::DeviceAuthority for Directory {
    async fn current(&mut self, binding: &ckmg::Binding) -> Result<ckmg::Lineage, ctcs::Error> {
        if self
            .local_only
            .as_ref()
            .is_some_and(|local| local != binding)
        {
            return Err(ctcs::Error::Authority);
        }
        self.lineages
            .get(binding.member())
            .filter(|lineage| lineage.binding == *binding)
            .cloned()
            .ok_or(ctcs::Error::Authority)
    }
}
struct Groups<'a> {
    devices: BTreeMap<String, [u8; 32]>,
    contacts: &'a ctcs::Contacts,
    seed: Option<[u8; 64]>,
}
impl cgrp::Authority for Groups<'_> {
    fn consent(&self, consent: &cgrp::Consent, now: u64) -> cgrp::Result<()> {
        if consent.community != "alpha" || consent.policy_epoch != 2 || now >= consent.valid_until {
            return Err(cgrp::Error::Authority);
        }
        let key = self
            .devices
            .get(&consent.member)
            .ok_or(cgrp::Error::Authority)?;
        ckmg::verify_ed25519(
            key,
            &consent.signing_bytes()?,
            &consent
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| cgrp::Error::Authority)?,
        )
        .map_err(|_| cgrp::Error::Authority)
    }
    fn contact(&self, community: &str, member: &str, peer: &str, _: u64) -> cgrp::Result<()> {
        if community != self.contacts.binding().community()
            || member != self.contacts.binding().member()
        {
            return Err(cgrp::Error::Authority);
        }
        let relation = self
            .contacts
            .relation(peer)
            .map_err(|_| cgrp::Error::Authority)?;
        if relation.state != ctcs::State::Established || relation.conflicted {
            return Err(cgrp::Error::Authority);
        }
        Ok(())
    }
    fn seed(&self, community: &str, group: &cgrp::Id, now: u64) -> cgrp::Result<()> {
        if now >= UNTIL {
            return Err(cgrp::Error::Authority);
        }
        let signature = self.seed.as_ref().ok_or(cgrp::Error::Authority)?;
        ckmg::verify_ed25519(
            &ed25519_dalek::SigningKey::from_bytes(&[229; 32])
                .verifying_key()
                .to_bytes(),
            &seed_bytes(community, group),
            signature,
        )
        .map_err(|_| cgrp::Error::Authority)
    }
}
fn port<'a>(
    peer: &'a mut keys::Peer,
    directory: &'a mut Directory,
) -> cthr::keys::KeyPort<
    'a,
    support::Memory,
    support::Time,
    support::Random,
    keys::Current,
    Directory,
> {
    cthr::keys::KeyPort {
        keys: &mut peer.keys,
        handle: &peer.handle,
        devices: directory,
    }
}
fn seed_bytes(community: &str, group: &cgrp::Id) -> Vec<u8> {
    serde_json::to_vec(&("fixture.groups.seed", community, group, 2u64, UNTIL)).unwrap()
}
// The existing Groups external seed boundary uses an explicitly signed fixture
// grant for its one configured group. It is not a production operator issuer.
pub struct Setup {
    source: group_support::SignedPolicy,
    store: cwst::Store<cwst::backend::Memory>,
    threads: cthr::Threads,
    directory: Directory,
    peers: Vec<keys::Peer>,
    contacts: ctcs::Contacts,
}
pub async fn install(f: &mut Fixture, count: usize) -> Setup {
    assert!(matches!(count, 12 | 42));
    let mut peers = Vec::new();
    for index in 1..count {
        let peer =
            keys::Peer::new(&format!("peer-{index}"), u8::try_from(index + 3).unwrap()).await;
        peer.time.0.set(NOW);
        peers.push(peer);
    }
    let roster: std::collections::BTreeSet<_> = std::iter::once(&f.sender)
        .chain(peers.iter())
        .map(|peer| peer.binding.member().to_owned())
        .collect();
    let mut directory = Directory {
        lineages: std::iter::once(&f.sender)
            .chain(peers.iter())
            .map(|peer| (peer.binding.member().into(), peer.lineage.clone()))
            .collect(),
        local_only: None,
    };
    let mut store = contacts::store().await;
    contacts::establish(&mut f.sender, "bob", &mut store).await;
    if count == 12 {
        for peer in &peers {
            contacts::establish(&mut f.sender, peer.binding.member(), &mut store).await;
        }
    }
    let contacts = ctcs::Contacts::load(f.sender.binding.clone(), &store).unwrap();
    let seed = if count == 42 {
        use ed25519_dalek::Signer as _;
        Some(
            ed25519_dalek::SigningKey::from_bytes(&[229; 32])
                .sign(&seed_bytes("alpha", &[81; 32]))
                .to_bytes(),
        )
    } else {
        None
    };
    let authority = Groups {
        devices: std::iter::once(&f.sender)
            .chain(peers.iter())
            .map(|peer| {
                (
                    peer.binding.member().into(),
                    *peer.certificate.device.value(),
                )
            })
            .collect(),
        contacts: &contacts,
        seed,
    };
    let mut policy = group_support::policy();
    policy.epoch = 2;
    let source = group_support::SignedPolicy::new(&policy);
    let state = cgrp::Snapshot::empty("alpha".into());
    let mut request = cgrp::Request {
        operation: [80; 32],
        parents: vec![],
        effective_at: NOW,
        actor: "alice".into(),
        command: cgrp::Command::Create {
            id: [81; 32],
            members: roster.clone(),
            seed: count == 42,
        },
        consents: vec![],
    };
    for peer in std::iter::once(&mut f.sender).chain(peers.iter_mut()) {
        let mut consent = cgrp::Consent {
            community: "alpha".into(),
            member: peer.binding.member().into(),
            operation: request.operation,
            policy_epoch: 2,
            command_digest: request.command_digest().unwrap(),
            profile_visibility: count == 42,
            valid_until: UNTIL,
            key_package: vec![],
            signature: vec![],
            authority: vec![],
        };
        consent.signature = peer
            .sign(&consent.signing_bytes().unwrap(), UNTIL)
            .await
            .to_vec();
        request.consents.push(consent);
    }
    let groups = cgrp::prepare(&state, &request, &source, &authority, NOW, 10).unwrap();
    let mut packages = vec![];
    for (index, peer) in peers.iter_mut().enumerate() {
        let operation = u8::try_from(index + 82).unwrap();
        let mut peer_store = contacts::store().await;
        let threads = cthr::Threads::load(peer.binding.clone(), [81; 32], &peer_store).unwrap();
        let package = threads
            .key_package(&mut port(peer, &mut directory))
            .await
            .unwrap()
            .commit(
                &mut port(peer, &mut directory),
                &mut cthr::Unavailable,
                &mut peer_store,
                [operation; 32],
                &[],
            )
            .await
            .unwrap();
        let cthr::Event::KeyPackage { bytes } = &package.events()[0] else {
            panic!()
        };
        packages.push(bytes.clone());
    }
    let threads = cthr::Threads::load(f.sender.binding.clone(), [81; 32], &store).unwrap();
    let mut clock = f.sender.time.clone();
    let effects = groups.prepare_effects();
    let candidate = if count == 12 {
        threads
            .create_fork(
                &mut port(&mut f.sender, &mut directory),
                &effects[0],
                &packages,
                &mut clock,
            )
            .await
    } else {
        threads
            .create_room(
                &mut port(&mut f.sender, &mut directory),
                &effects[0],
                &packages,
                &mut clock,
            )
            .await
    }
    .unwrap();
    drop(effects);
    let (committed, state, _) = candidate
        .commit_groups(
            &mut port(&mut f.sender, &mut directory),
            groups,
            &mut store,
            [84; 32],
            (&source, &authority),
            &mut clock,
        )
        .await
        .unwrap();
    let evidence = committed
        .threads()
        .parent_evidence(
            &mut port(&mut f.sender, &mut directory),
            &store,
            &source,
            &mut clock,
        )
        .await
        .unwrap();
    assert!(!evidence.group_info.is_empty());
    assert!(!evidence.ratchet_tree.is_empty());
    let mut members = roster;
    assert!(members.insert("bob".into()));
    let command = cgrp::Command::Fork {
        id: [85; 32],
        parents: vec![[81; 32]],
        members,
        kind: cgrp::ForkKind::Add,
    };
    f.request = cgrp::Request {
        operation: [86; 32],
        parents: state.parent_references(&command).unwrap(),
        effective_at: NOW,
        actor: "alice".into(),
        command,
        consents: vec![],
    };
    f.consent.operation = f.request.operation;
    f.consent.command_digest = f.request.command_digest().unwrap();
    f.consent.signature = f
        .sender
        .sign(&f.consent.signing_bytes().unwrap(), UNTIL)
        .await
        .to_vec();
    f.parents = vec![evidence];
    cuts::producer(
        f,
        committed.threads(),
        &mut directory,
        &mut store,
        &source,
        &mut clock,
    )
    .await;
    let contacts = ctcs::Contacts::load(f.sender.binding.clone(), &store).unwrap();
    Setup {
        source,
        store,
        threads: committed.into_threads(),
        directory,
        peers,
        contacts,
    }
}

shared!(
    actual_committed_mls_parent_is_bound_and_imported_without_publication,
    {
        let mut f = Fixture::new().await;
        let mut setup = install(&mut f, 12).await;
        let proof = f.proof().await;
        let before = f.store.version().unwrap();
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
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].checked_at(), NOW);
        assert_eq!(parents[0].valid_until(), UNTIL);
        assert_eq!(parents[0].state().id(), &[81; 32]);
        assert_eq!(parents[0].state().members().len(), 12);
        assert_eq!(f.store.version().unwrap(), before);
        for field in 0..3 {
            let mut evidence: cthr::ParentEvidence =
                serde_json::from_value(serde_json::to_value(&f.parents[0]).unwrap()).unwrap();
            match field {
                0 => evidence.state[0] ^= 1,
                1 => evidence.group_info[0] ^= 1,
                _ => evidence.ratchet_tree[0] ^= 1,
            };
            let altered = [evidence];
            let expected = InvitationExpected {
                parents: &altered,
                ..f.expected()
            };
            assert!(
                proof
                    .verify_parents(
                        &expected,
                        &f.sender.certificate,
                        &f.publication,
                        &f.current(NOW).view(),
                        &clean,
                        &mut clock
                    )
                    .is_err()
            );
        }
        let expected = InvitationExpected {
            parents: &[],
            ..f.expected()
        };
        assert!(
            InvitationStatement::new(&expected, &f.sender.certificate, &f.publication).is_err()
        );
        // Even an actual device signature cannot turn malformed MLS bytes into
        // an imported parent. Bind the malformed bytes freshly to reach import.
        let original = std::mem::replace(&mut f.parents[0].group_info, vec![0]);
        let malformed = f.proof().await;
        assert!(f.verify(&malformed, NOW).is_ok());
        assert!(
            malformed
                .verify_parents(
                    &f.expected(),
                    &f.sender.certificate,
                    &f.publication,
                    &f.current(NOW).view(),
                    &clean,
                    &mut clock
                )
                .is_err()
        );
        f.parents[0].group_info = original;

        // Final clock must still be the same observed second after genuine
        // OpenMLS import; the second call advances only that actual clock cut.
        struct FinalCut {
            calls: u8,
        }
        impl ckmg::Clock for FinalCut {
            fn now(&mut self) -> Result<u64, ckmg::Error> {
                self.calls += 1;
                Ok(NOW + u64::from(self.calls > 1))
            }
        }
        assert!(
            proof
                .verify_parents(
                    &f.expected(),
                    &f.sender.certificate,
                    &f.publication,
                    &f.current(NOW).view(),
                    &clean,
                    &mut FinalCut { calls: 0 }
                )
                .is_err()
        );
        groups::exercise(&mut f, &mut setup, 12).await;
        cuts::deleted(&mut f, &mut setup).await;
    }
);

shared!(
    forty_two_member_parent_import_and_join_keep_actual_newcomer_actor,
    {
        let mut f = Fixture::new().await;
        let mut setup = install(&mut f, 42).await;
        f.request.command = cgrp::Command::Join {
            group: [81; 32],
            member: "bob".into(),
            vouches: Default::default(),
        };
        f.request.actor = "bob".into();
        f.consent.command_digest = f.request.command_digest().unwrap();
        f.consent.signature = f
            .sender
            .sign(&f.consent.signing_bytes().unwrap(), UNTIL)
            .await
            .to_vec();
        let proof = f.proof().await;
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
        assert_eq!(parents[0].state().members().len(), 42);
        assert_eq!(parents[0].valid_until(), UNTIL);
        groups::exercise(&mut f, &mut setup, 42).await;
        cuts::deleted(&mut f, &mut setup).await;
        f.request.actor = "alice".into();
        f.consent.command_digest = f.request.command_digest().unwrap();
        f.consent.signature = f
            .sender
            .sign(&f.consent.signing_bytes().unwrap(), UNTIL)
            .await
            .to_vec();
        assert!(
            InvitationStatement::new(&f.expected(), &f.sender.certificate, &f.publication).is_err()
        );
    }
);
