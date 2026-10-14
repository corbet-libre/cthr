use super::*;

pub(super) async fn refuses_mixed_context(
    threads: &Threads,
    a: &mut Fixture,
    store: &mut Store<Memory>,
    packages: &[Vec<u8>],
    source: &group_support::SignedPolicy,
    clock: &mut Time,
) {
    let base = group_support::open_base(source).await;
    let prepare = |at| {
        let request = group_support::open_room(&base, SLOT, at);
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
    let held = store.read("cgrp", b"snapshot.v1").unwrap().map(|bytes| bytes.to_vec());
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
        store.read("cgrp", b"snapshot.v1").unwrap().map(|bytes| bytes.to_vec()),
        held
    );
    assert!(
        Threads::load(a.binding.clone(), SLOT, store)
            .unwrap()
            .epoch()
            .is_err()
    );
}
