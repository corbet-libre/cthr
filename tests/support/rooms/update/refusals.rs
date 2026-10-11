use super::*;

pub(super) async fn refusals(
    a: &mut Fixture,
    astore: &mut Store<Memory>,
    state: &cgrp::Snapshot,
    source: &group_support::SignedPolicy,
    clock: &mut Time,
) {
    let at = Threads::load(a.binding.clone(), SLOT, astore).unwrap();
    let old_epoch = at.epoch().unwrap();
    let prepare = |time| prepare(state, source, time);
    // The old metadata-only private-fork path cannot update a public room.
    assert_eq!(
        at.update_fork(&mut a.port(), &prepare(1001).prepare_effects()[0], clock)
            .await
            .err(),
        Some(Error::Unavailable)
    );
    let addition = group_support::request(
        state,
        cgrp::Command::Join {
            group: SLOT,
            member: "m3".into(),
            vouches: Default::default(),
        },
        "m3",
        group_support::members(3, 4),
        true,
        1001,
    );
    let addition = cgrp::prepare(
        state,
        &addition,
        source,
        &group_support::TestAuthority,
        1003,
        10,
    )
    .unwrap();
    assert_eq!(
        at.update_room(&mut a.port(), astore, &addition.prepare_effects()[0], clock)
            .await
            .err(),
        Some(Error::Authority)
    );

    // Removing a now-unavailable device remains possible. The old accepted MLS
    // tree authenticates its identity; every surviving device is still current.
    a.directory.0.borrow_mut().remove("m2").unwrap();
    let groups = prepare(1001);
    let candidate = at
        .update_room(&mut a.port(), astore, &groups.prepare_effects()[0], clock)
        .await
        .unwrap();
    assert_eq!(
        candidate
            .commit(&mut a.port(), &mut Grant::new(), astore, [20; 32], &[])
            .await
            .err(),
        Some(Error::Authority)
    );

    let groups = prepare(1001);
    let candidate = at
        .update_room(&mut a.port(), astore, &groups.prepare_effects()[0], clock)
        .await
        .unwrap();
    let survivor = a.directory.0.borrow_mut().remove("m1").unwrap();
    assert!(
        candidate
            .commit_groups(
                &mut a.port(),
                groups,
                astore,
                [21; 32],
                (source, &group_support::TestAuthority),
                clock
            )
            .await
            .is_err()
    );
    a.directory.0.borrow_mut().insert("m1".into(), survivor);
    assert_eq!(
        Threads::load(a.binding.clone(), SLOT, astore)
            .unwrap()
            .epoch()
            .unwrap(),
        old_epoch
    );

    let groups = prepare(1001);
    let candidate = at
        .update_room(&mut a.port(), astore, &groups.prepare_effects()[0], clock)
        .await
        .unwrap();
    let mut expired = Time::default();
    expired.0.set(1001 + cgrp::DAY);
    assert!(
        candidate
            .commit_groups(
                &mut a.port(),
                groups,
                astore,
                [22; 32],
                (source, &group_support::TestAuthority),
                &mut expired
            )
            .await
            .is_err()
    );

    let groups = prepare(1001);
    let candidate = at
        .update_room(&mut a.port(), astore, &groups.prepare_effects()[0], clock)
        .await
        .unwrap();
    let mut policy = group_support::policy();
    policy.epoch += 1;
    let changed = group_support::SignedPolicy::new(&policy);
    assert!(
        candidate
            .commit_groups(
                &mut a.port(),
                groups,
                astore,
                [23; 32],
                (&changed, &group_support::TestAuthority),
                clock
            )
            .await
            .is_err()
    );
    // Both decisions are genuine and have identical Effect::Membership fields,
    // but their canonical effective times differ. Their owners cannot be mixed
    // at the final shared commit even after successful MLS preparation.
    let original_groups = astore
        .read("cgrp", b"snapshot.v1")
        .unwrap()
        .unwrap()
        .to_vec();
    let original_version = astore.version().unwrap();
    let groups = prepare(1001);
    let candidate = at
        .update_room(&mut a.port(), astore, &groups.prepare_effects()[0], clock)
        .await
        .unwrap();
    assert!(
        candidate
            .commit_groups(
                &mut a.port(),
                prepare(1002),
                astore,
                [26; 32],
                (source, &group_support::TestAuthority),
                clock
            )
            .await
            .is_err()
    );
    assert_eq!(astore.version().unwrap(), original_version);
    assert_eq!(
        astore.read("cgrp", b"snapshot.v1").unwrap().unwrap(),
        original_groups
    );
    assert_eq!(
        Threads::load(a.binding.clone(), SLOT, astore)
            .unwrap()
            .epoch()
            .unwrap(),
        old_epoch
    );
}
