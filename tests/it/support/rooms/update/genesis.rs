use super::*;

pub(super) async fn refuses_mixed_context(
    threads: &Threads,
    a: &mut Fixture,
    store: &mut Store<Memory>,
    packages: &[Vec<u8>],
    source: &group_support::SignedPolicy,
    clock: &mut Time,
) {
    let base = group_support::history();
    let installed = store
        .read("cgrp", b"snapshot.v1")
        .unwrap()
        .map(<[u8]>::to_vec);
    let prepare = |at| {
        let request = group_support::request(
            &base,
            group_support::open(SLOT, 3),
            "m0",
            group_support::members(0, 3),
            true,
            at,
        );
        cgrp::prepare(
            &base,
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
    assert_eq!(
        store
            .read("cgrp", b"snapshot.v1")
            .unwrap()
            .map(<[u8]>::to_vec),
        installed
    );
    assert!(
        Threads::load(a.binding.clone(), SLOT, store)
            .unwrap()
            .epoch()
            .is_err()
    );
}
