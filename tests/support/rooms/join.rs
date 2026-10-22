use super::*;
use cthr::{RoomAdmission, RoomJoin};

// Three-member living-room genesis, then a fourth member joins by the ordered
// external commit and the member commit that installs the canonical context.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn newcomer_joins_by_external_commit_then_context_commit() {
    block_on(Box::pin(async {
        let directory = Directory::default();
        let mut a = Fixture::new("m0", 1, directory.clone()).await;
        let mut b = Fixture::new("m1", 2, directory.clone()).await;
        let mut c = Fixture::new("m2", 3, directory.clone()).await;
        let mut d = Fixture::new("m3", 4, directory).await;
        let (_, mut astore) = a.store().await;
        let (_, mut bstore) = b.store().await;
        let (_, mut cstore) = c.store().await;
        let (_, mut dstore) = d.store().await;
        let base = group_support::history();
        group_support::install(&mut astore, &base).await;
        group_support::install(&mut bstore, &base).await;
        group_support::install(&mut cstore, &base).await;
        let source = group_support::SignedPolicy::new(&group_support::policy());
        let mut clock = Time::default();
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        let ct = Threads::load(c.binding.clone(), SLOT, &cstore).unwrap();
        let mut packages = vec![];
        let mut held = vec![];
        for (fixture, store, threads) in [(&mut b, &mut bstore, &bt), (&mut c, &mut cstore, &ct)] {
            let package = threads
                .key_package(&mut fixture.port())
                .await
                .unwrap()
                .commit(&mut fixture.port(), &mut Grant::new(), store, [1; 32], &[])
                .await
                .unwrap();
            let Event::KeyPackage { bytes } = &package.events()[0] else {
                panic!()
            };
            packages.push(bytes.clone());
            held.push(package);
        }
        let create = || {
            let request = group_support::request(
                &base,
                group_support::open(SLOT, 3),
                "m0",
                group_support::members(0, 3),
                true,
                1000,
            );
            cgrp::prepare(
                &base,
                &request,
                &source,
                &group_support::TestAuthority,
                1000,
                10,
            )
            .unwrap()
        };
        let groups = create();
        let candidate = at
            .create_room(
                &mut a.port(),
                &groups.prepare_effects()[0],
                &packages,
                &mut clock,
            )
            .await
            .unwrap();
        let (genesis, state, _) = candidate
            .commit_groups(
                &mut a.port(),
                groups,
                &mut astore,
                [2; 32],
                (&source, &group_support::TestAuthority),
                &mut clock,
            )
            .await
            .unwrap();
        let Event::Invitation { welcome, .. } = &genesis.events()[0] else {
            panic!()
        };
        let mut members = vec![];
        for (fixture, store, package) in [
            (&mut b, &mut bstore, &held[0]),
            (&mut c, &mut cstore, &held[1]),
        ] {
            let groups = create();
            let (joined, _, _) = package
                .threads()
                .join_room(
                    &mut fixture.port(),
                    &groups.prepare_effects()[0],
                    welcome,
                    &mut clock,
                )
                .await
                .unwrap()
                .commit_groups(
                    &mut fixture.port(),
                    groups,
                    store,
                    [2; 32],
                    (&source, &group_support::TestAuthority),
                    &mut clock,
                )
                .await
                .unwrap();
            members.push(joined);
        }
        let (bjoined, cjoined) = (members.remove(0), members.remove(0));
        // The newcomer's Groups owner holds the community's current record.
        put(
            &mut dstore,
            "cgrp",
            b"snapshot.v1",
            &postcard::to_allocvec(&state).unwrap(),
            201,
        )
        .await;

        let join = |snapshot: &cgrp::Snapshot| {
            let request = group_support::request(
                snapshot,
                cgrp::Command::Join {
                    group: SLOT,
                    member: "m3".into(),
                    vouches: Default::default(),
                },
                "m3",
                group_support::members(3, 4),
                true,
                1000,
            );
            cgrp::prepare(
                snapshot,
                &request,
                &source,
                &group_support::TestAuthority,
                1000,
                10,
            )
            .unwrap()
        };
        let evidence = genesis
            .threads()
            .parent_evidence(&mut a.port(), &astore, &source, &mut clock)
            .await
            .unwrap();
        let dt = Threads::load(d.binding.clone(), SLOT, &dstore).unwrap();

        let decision = join(&state);
        let started: RoomJoin = dt
            .prepare_room_join(
                &mut d.port(),
                &decision.prepare_effects()[0],
                &evidence,
                COMPANION,
                &source,
                &mut clock,
            )
            .await
            .unwrap();
        assert_eq!(started.epoch(), genesis.threads().epoch().unwrap() + 1);
        let external = started.commit().to_vec();

        // Leaf credential: exactly this community's scoped certificate, no
        // global or device-stable identifier, unlinkable across communities.
        let certificate = serde_json::to_vec(d.handle.certificate()).unwrap();
        assert!(
            external
                .windows(certificate.len())
                .any(|v| v == certificate)
        );
        let value: serde_json::Value = serde_json::from_slice(&certificate).unwrap();
        let mut fields: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        fields.sort();
        assert_eq!(
            fields,
            ["binding", "device", "epoch", "key", "purpose", "signature"]
        );
        assert_eq!(value["binding"]["community"], "alpha");
        assert_eq!(value["binding"]["member"], "m3");
        assert!(
            !external
                .windows(b"private-device-name".len())
                .any(|v| v == b"private-device-name")
        );
        let elsewhere = Fixture::in_community("beta", "m3", 4, Directory::default()).await;
        let other = elsewhere.handle.certificate();
        assert_ne!(other.device, d.handle.certificate().device);
        assert_ne!(other.key, d.handle.certificate().key);
        let other = serde_json::to_vec(other).unwrap();
        assert!(!external.windows(other.len()).any(|v| v == other));

        // Refusals: evidence and hand-over are checked, not trusted.
        macro_rules! again {
            ($evidence:expr) => {
                dt.prepare_room_join(
                    &mut d.port(),
                    &join(&state).prepare_effects()[0],
                    $evidence,
                    COMPANION,
                    &source,
                    &mut clock,
                )
            };
        }
        let mut bad = cthr::ParentEvidence {
            state: evidence.state.clone(),
            group_info: evidence.group_info.clone(),
            ratchet_tree: evidence.ratchet_tree.clone(),
        };
        *bad.state.last_mut().unwrap() ^= 1;
        assert!(again!(&bad).await.is_err());
        bad.state = evidence.state.clone();
        *bad.group_info.last_mut().unwrap() ^= 1;
        assert!(again!(&bad).await.is_err());
        bad.group_info = evidence.group_info.clone();
        bad.ratchet_tree.truncate(bad.ratchet_tree.len() - 1);
        assert!(again!(&bad).await.is_err());
        let spare = again!(&evidence).await.unwrap();
        for items in [vec![vec![]], vec![vec![1]; cthr::MAX_HANDOVER + 1]] {
            let spare = again!(&evidence).await.unwrap();
            let groups = join(&state);
            assert_eq!(
                spare
                    .finish(
                        &mut d.port(),
                        &groups.prepare_effects()[0],
                        &external,
                        &items,
                        &mut clock
                    )
                    .await
                    .err(),
                Some(Error::Limit)
            );
        }
        let groups = join(&state);
        assert!(
            spare
                .finish(
                    &mut d.port(),
                    &groups.prepare_effects()[0],
                    &external,
                    &[],
                    &mut clock
                )
                .await
                .is_err()
        );

        // Each existing member authenticates the external commit, then one of
        // them installs the canonical context in a member commit.
        let mut admissions: Vec<RoomAdmission> = vec![];
        for (fixture, store, threads) in [
            (&mut a, &astore, genesis.threads()),
            (&mut b, &bstore, bjoined.threads()),
            (&mut c, &cstore, cjoined.threads()),
        ] {
            let groups = join(&state);
            admissions.push(
                threads
                    .receive_room_join(
                        &mut fixture.port(),
                        store,
                        &groups.prepare_effects()[0],
                        &external,
                        COMPANION,
                        &mut clock,
                    )
                    .await
                    .unwrap(),
            );
        }
        // A corrupted external commit never produces an admission.
        let mut corrupted = external.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(
            genesis
                .threads()
                .receive_room_join(
                    &mut a.port(),
                    &astore,
                    &join(&state).prepare_effects()[0],
                    &corrupted,
                    COMPANION,
                    &mut clock,
                )
                .await
                .is_err()
        );

        // The commit authenticates its companion: another or no companion, and
        // so another consent, never produces an admission.
        for wrong in [&b"another-join-request"[..], &[][..]] {
            assert!(
                genesis
                    .threads()
                    .receive_room_join(
                        &mut a.port(),
                        &astore,
                        &join(&state).prepare_effects()[0],
                        &external,
                        wrong,
                        &mut clock,
                    )
                    .await
                    .is_err()
            );
        }

        let committer = admissions.remove(0);
        let groups = join(&state);
        let (committed, astate, _) = committer
            .commit_context(&mut a.port(), &groups.prepare_effects()[0], &mut clock)
            .await
            .unwrap()
            .commit_groups(
                &mut a.port(),
                groups,
                &mut astore,
                [30; 32],
                (&source, &group_support::TestAuthority),
                &mut clock,
            )
            .await
            .unwrap();
        let Event::MembershipCommit { bytes } = &committed.events()[0] else {
            panic!()
        };
        let context = bytes.clone();
        assert_eq!(
            astate.group_state(&SLOT).unwrap().members(),
            &group_support::members(0, 4)
        );
        let mut finished = vec![];
        for (fixture, store, admission) in [
            (&mut b, &mut bstore, admissions.remove(0)),
            (&mut c, &mut cstore, admissions.remove(0)),
        ] {
            let groups = join(&state);
            let (done, _, _) = admission
                .receive_context(
                    &mut fixture.port(),
                    &groups.prepare_effects()[0],
                    &context,
                    &mut clock,
                )
                .await
                .unwrap()
                .commit_groups(
                    &mut fixture.port(),
                    groups,
                    store,
                    [30; 32],
                    (&source, &group_support::TestAuthority),
                    &mut clock,
                )
                .await
                .unwrap();
            finished.push(done);
        }

        // The newcomer finishes with the same context commit and seals its
        // hand-over to the room in the resulting epoch.
        let groups = join(&state);
        let (djoined, _, _) = started
            .finish(
                &mut d.port(),
                &groups.prepare_effects()[0],
                &context,
                &[b"profile key".to_vec()],
                &mut clock,
            )
            .await
            .unwrap()
            .0
            .commit_groups(
                &mut d.port(),
                groups,
                &mut dstore,
                [30; 32],
                (&source, &group_support::TestAuthority),
                &mut clock,
            )
            .await
            .unwrap();
        assert_eq!(
            djoined.threads().epoch().unwrap(),
            committed.threads().epoch().unwrap()
        );
        // The room transport key is the epoch's exporter secret: every member of
        // the epoch derives the same one, and it changes with the epoch.
        let key = djoined.threads().transport_key().unwrap();
        assert_eq!(key, committed.threads().transport_key().unwrap());
        assert_eq!(key, finished[0].threads().transport_key().unwrap());
        assert_ne!(key, genesis.threads().transport_key().unwrap());
        let handover = djoined.outgoing()[0].bytes().to_vec();
        assert!(!handover.windows(11).any(|v| v == b"profile key"));
        let contacts = ctcs::Contacts::load(b.binding.clone(), &bstore).unwrap();
        let received = finished[0]
            .threads()
            .receive_group(&mut b.port(), &contacts, &source, &mut clock, &handover)
            .await
            .unwrap()
            .commit_group(&mut b.port(), &mut bstore, [31; 32], &source, &mut clock)
            .await
            .unwrap();
        assert_eq!(received.threads().history()[0].bytes, b"profile key");
    }));
}
