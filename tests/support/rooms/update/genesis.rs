use super::*;

pub(super) async fn refuses_mixed_context(
    threads: &Threads,
    a: &mut Fixture,
    store: &mut Store<Memory>,
    packages: &[Vec<u8>],
    source: &group_support::SignedPolicy,
    clock: &mut Time,
) {
    let empty = cgrp::Snapshot::empty("alpha".into());
    let prepare = |at| {
        let request = group_support::request(
            &empty,
            cgrp::Command::Create {
                id: SLOT,
                members: group_support::members(0, 3),
                seed: true,
            },
            "m0",
            group_support::members(0, 3),
            true,
            at,
        );
        cgrp::prepare(
            &empty,
            &request,
            source,
            &group_support::TestAuthority,
            1000,
            10,
        )
        .unwrap()
    };
    let groups = prepare(1000);
    let candidate = threads
        .create_room(&mut a.port(), &groups.prepare_effects()[0], packages, clock)
        .await
        .unwrap();
    let prior = store.version().unwrap();
    assert!(
        candidate
            .commit_groups(
                &mut a.port(),
                prepare(999),
                store,
                [30; 32],
                (source, &group_support::TestAuthority),
                clock
            )
            .await
            .is_err()
    );
    assert_eq!(store.version().unwrap(), prior);
    assert!(store.read("cgrp", b"snapshot.v1").unwrap().is_none());
    assert!(
        Threads::load(a.binding.clone(), SLOT, store)
            .unwrap()
            .epoch()
            .is_err()
    );
}
