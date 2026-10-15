use super::*;
#[path = "rooms/attend.rs"]
mod attend;
#[path = "rooms/join.rs"]
mod join;
#[path = "rooms/update.rs"]
mod update;

// The existing fixture Authority verifies real signed Groups consents. The
// room descends from a real circle and ingroup history (Fork Open).
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn consented_room_genesis_commits_real_mls_and_groups_together() {
    block_on(Box::pin(async {
        let directory = Directory::default();
        let mut a = Fixture::new("m0", 1, directory.clone()).await;
        let mut b = Fixture::new("m1", 2, directory.clone()).await;
        let mut c = Fixture::new("m2", 3, directory).await;
        let (_, mut astore) = a.store().await;
        let (_, mut bstore) = b.store().await;
        let (_, mut cstore) = c.store().await;
        let base = group_support::history();
        group_support::install(&mut astore, &base).await;
        group_support::install(&mut bstore, &base).await;
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        let ct = Threads::load(c.binding.clone(), SLOT, &cstore).unwrap();
        let bp = bt
            .key_package(&mut b.port())
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [1; 32], &[])
            .await
            .unwrap();
        let cp = ct
            .key_package(&mut c.port())
            .await
            .unwrap()
            .commit(&mut c.port(), &mut Grant::new(), &mut cstore, [1; 32], &[])
            .await
            .unwrap();
        let packages: Vec<_> = [&bp, &cp]
            .into_iter()
            .map(|value| {
                let Event::KeyPackage { bytes } = &value.events()[0] else {
                    panic!()
                };
                bytes.clone()
            })
            .collect();
        let source = group_support::SignedPolicy::new(&group_support::policy());
        let empty = cgrp::Snapshot::empty("alpha".into());
        let public_request = group_support::request(
            &base,
            group_support::open(SLOT, 3),
            "m0",
            group_support::members(0, 3),
            true,
            1000,
        );
        let prepare = || {
            cgrp::prepare(
                &base,
                &public_request,
                &source,
                &group_support::TestAuthority,
                1000,
                10,
            )
            .unwrap()
        };
        let private_request = group_support::request(
            &empty,
            cgrp::Command::Create {
                id: SLOT,
                members: group_support::members(0, 3),
            },
            "m0",
            group_support::members(0, 3),
            false,
            1000,
        );
        let private = cgrp::prepare(
            &empty,
            &private_request,
            &source,
            &group_support::TestAuthority,
            1000,
            10,
        )
        .unwrap();
        let groups = prepare();
        let effects = groups.prepare_effects();
        let mut clock = Time::default();
        assert_eq!(
            at.create_room(
                &mut a.port(),
                &private.prepare_effects()[0],
                &packages,
                &mut clock
            )
            .await
            .err(),
            Some(Error::Unavailable)
        );
        assert_eq!(
            at.create_fork(&mut a.port(), &effects[0], &packages, &mut clock)
                .await
                .err(),
            Some(Error::Unavailable)
        );
        assert_eq!(
            at.create_room(&mut a.port(), &effects[0], &[], &mut clock)
                .await
                .err(),
            Some(Error::Authority)
        );
        update::genesis_mismatch(&at, &mut a, &mut astore, &packages, &source, &mut clock).await;
        let candidate = at
            .create_room(&mut a.port(), &effects[0], &packages, &mut clock)
            .await
            .unwrap();
        drop(effects);
        let (joined, state, _) = candidate
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
        let Event::Invitation { welcome, .. } = &joined.events()[0] else {
            panic!()
        };
        let later_request = group_support::request(
            &state,
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
        let later = cgrp::prepare(
            &state,
            &later_request,
            &source,
            &group_support::TestAuthority,
            1000,
            10,
        )
        .unwrap();
        assert_eq!(
            at.create_room(
                &mut a.port(),
                &later.prepare_effects()[0],
                &packages,
                &mut clock
            )
            .await
            .err(),
            Some(Error::Authority)
        );
        assert_eq!(
            cp.threads()
                .join_room(
                    &mut c.port(),
                    &later.prepare_effects()[0],
                    welcome,
                    &mut clock
                )
                .await
                .err(),
            Some(Error::Authority)
        );

        let mismatched_request = group_support::request(
            &base,
            group_support::open(SLOT, 3),
            "m0",
            group_support::members(0, 3),
            true,
            999,
        );
        let mismatched = cgrp::prepare(
            &base,
            &mismatched_request,
            &source,
            &group_support::TestAuthority,
            1000,
            10,
        )
        .unwrap();
        // Same certified roster and genuine Welcome, different authenticated
        // Groups timestamp. The MLS context must refuse that substitution.
        assert_eq!(
            bp.threads()
                .join_room(
                    &mut b.port(),
                    &mismatched.prepare_effects()[0],
                    welcome,
                    &mut clock
                )
                .await
                .err(),
            Some(Error::Authority)
        );
        assert_eq!(
            bp.threads()
                .join_fork(
                    &mut b.port(),
                    &prepare().prepare_effects()[0],
                    welcome,
                    &mut clock
                )
                .await
                .err(),
            Some(Error::Unavailable)
        );
        let bgroups = prepare();
        let effects = bgroups.prepare_effects();
        let candidate = bp
            .threads()
            .join_room(&mut b.port(), &effects[0], welcome, &mut clock)
            .await
            .unwrap();
        drop(effects);
        let (bjoined, bstate, _) = candidate
            .commit_groups(
                &mut b.port(),
                bgroups,
                &mut bstore,
                [2; 32],
                (&source, &group_support::TestAuthority),
                &mut clock,
            )
            .await
            .unwrap();
        assert_eq!(
            state.group_state(&SLOT).unwrap(),
            bstate.group_state(&SLOT).unwrap()
        );
        let parent = joined
            .threads()
            .parent_evidence(&mut a.port(), &astore, &source, &mut clock)
            .await
            .unwrap();
        let verified = bjoined
            .threads()
            .verify_parent_evidence(&mut b.port(), &bstore, &parent, &source, &mut clock)
            .await
            .unwrap();
        assert_eq!(verified.state(), &state.group_state(&SLOT).unwrap());
        assert_eq!(verified.state().level(), cgrp::Level::Public);
        // Merely receiving this real parent does not enroll the third member.
        assert!(
            cp.threads()
                .verify_parent_evidence(&mut c.port(), &cstore, &parent, &source, &mut clock)
                .await
                .is_err()
        );
        // Restore uses the same accepted private checkpoint, never a decoded
        // public roster as membership or current-state authority.
        let restored = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        restored
            .verify_parent_evidence(&mut b.port(), &bstore, &parent, &source, &mut clock)
            .await
            .unwrap();
        let contacts = ctcs::Contacts::load(a.binding.clone(), &astore).unwrap();
        let sent = joined
            .threads()
            .send_group(
                &mut a.port(),
                &contacts,
                &source,
                &mut clock,
                b"private room message",
            )
            .await
            .unwrap()
            .commit_group(&mut a.port(), &mut astore, [3; 32], &source, &mut clock)
            .await
            .unwrap();
        let wire = sent.outgoing()[0].bytes().to_vec();
        assert!(
            !wire
                .windows(b"private room message".len())
                .any(|v| v == b"private room message")
        );
        let contacts = ctcs::Contacts::load(b.binding.clone(), &bstore).unwrap();
        let received = restored
            .receive_group(&mut b.port(), &contacts, &source, &mut clock, &wire)
            .await
            .unwrap()
            .commit_group(&mut b.port(), &mut bstore, [3; 32], &source, &mut clock)
            .await
            .unwrap();
        assert_eq!(
            received.threads().history()[0].bytes,
            b"private room message"
        );
        let contacts = ctcs::Contacts::load(b.binding.clone(), &bstore).unwrap();
        assert!(
            received
                .threads()
                .receive_group(&mut b.port(), &contacts, &source, &mut clock, &wire)
                .await
                .is_err()
        );
        update::removal(
            &mut a,
            &mut b,
            (&mut astore, &mut bstore),
            &state,
            &source,
            &mut clock,
        )
        .await;
    }));
}
