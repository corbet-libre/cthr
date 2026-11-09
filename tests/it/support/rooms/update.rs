use super::*;
#[path = "update/genesis.rs"]
mod genesis;
#[path = "update/refusals.rs"]
mod refusals;
pub(super) async fn genesis_mismatch(
    threads: &Threads,
    a: &mut Fixture,
    store: &mut Store<Memory>,
    packages: &[Vec<u8>],
    source: &group_support::SignedPolicy,
    clock: &mut Time,
) {
    genesis::refuses_mixed_context(threads, a, store, packages, source, clock).await;
}

// Continue the genuine three-member genesis fixture. No decoded roster is
// adopted: both survivors verify the signed Groups leave and actual MLS commit.
pub(super) async fn removal(
    a: &mut Fixture,
    b: &mut Fixture,
    c: &mut Fixture,
    stores: (&mut Store<Memory>, &mut Store<Memory>, &mut Store<Memory>),
    state: &cgrp::Snapshot,
    source: &group_support::SignedPolicy,
    clock: &mut Time,
) {
    let (astore, bstore, cstore) = stores;
    clock.0.set(1003);
    let prepare = |at| prepare(state, source, at);
    let at = Threads::load(a.binding.clone(), SLOT, astore).unwrap();
    let bt = Threads::load(b.binding.clone(), SLOT, bstore).unwrap();
    let old_epoch = at.epoch().unwrap();

    refusals::refusals(a, astore, state, source, clock).await;

    let groups = prepare(1001);
    let candidate = at
        .update_room(&mut a.port(), astore, &groups.prepare_effects()[0], clock)
        .await
        .unwrap();
    let (committed, updated, _) = candidate
        .commit_groups(
            &mut a.port(),
            groups,
            astore,
            [24; 32],
            (source, &group_support::TestAuthority),
            clock,
        )
        .await
        .unwrap();
    let Event::MembershipCommit { bytes } = &committed.events()[0] else {
        panic!()
    };
    let wire = bytes.clone();
    assert_eq!(committed.threads().epoch().unwrap(), old_epoch + 1);
    assert_eq!(
        updated.group_state(&SLOT).unwrap().members(),
        &group_support::members(0, 2)
    );
    assert_eq!(
        at.update_room(
            &mut a.port(),
            astore,
            &prepare(1001).prepare_effects()[0],
            clock
        )
        .await
        .err(),
        Some(Error::Conflict)
    );

    let mut corrupted = wire.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(
        bt.receive_room_update(
            &mut b.port(),
            bstore,
            &prepare(1001).prepare_effects()[0],
            &corrupted,
            clock
        )
        .await
        .is_err()
    );
    // Same real membership, different signed application effective time.
    // Authenticated MLS context must agree with the complete Groups record.
    assert_eq!(
        bt.receive_room_update(
            &mut b.port(),
            bstore,
            &prepare(1002).prepare_effects()[0],
            &wire,
            clock
        )
        .await
        .err(),
        Some(Error::Authority)
    );
    let groups = prepare(1001);
    let candidate = bt
        .receive_room_update(
            &mut b.port(),
            bstore,
            &groups.prepare_effects()[0],
            &wire,
            clock,
        )
        .await
        .unwrap();
    let (received, bstate, _) = candidate
        .commit_groups(
            &mut b.port(),
            groups,
            bstore,
            [24; 32],
            (source, &group_support::TestAuthority),
            clock,
        )
        .await
        .unwrap();
    assert_eq!(
        updated.group_state(&SLOT).unwrap(),
        bstate.group_state(&SLOT).unwrap()
    );
    assert_eq!(received.threads().epoch().unwrap(), old_epoch + 1);

    // The removed member (m2) holds the old epoch only. The commit names the
    // epoch it was made for, the survivors share the next epoch's transport
    // key, and nothing the removed member holds derives it: it cannot process
    // the commit that removed it and its state does not move.
    assert_eq!(cthr::wire_epoch(&wire).unwrap(), old_epoch);
    let removed = Threads::load(c.binding.clone(), SLOT, cstore).unwrap();
    assert_eq!(removed.epoch().unwrap(), old_epoch);
    let stale = removed.transport_keys().unwrap();
    let fresh = committed.threads().transport_keys().unwrap();
    assert!(received.threads().transport_keys().unwrap() == fresh);
    assert!(stale.aead != fresh.aead && stale.nonce != fresh.nonce);
    assert!(
        removed
            .receive_room_update(
                &mut c.port(),
                cstore,
                &prepare(1001).prepare_effects()[0],
                &wire,
                clock
            )
            .await
            .is_err()
    );
    let after = Threads::load(c.binding.clone(), SLOT, cstore).unwrap();
    assert_eq!(after.epoch().unwrap(), old_epoch);
    assert!(after.transport_keys().unwrap() == stale);
    assert_eq!(
        received
            .threads()
            .receive_room_update(
                &mut b.port(),
                bstore,
                &prepare(1001).prepare_effects()[0],
                &wire,
                clock
            )
            .await
            .err(),
        Some(Error::Authority)
    );

    let restored = Threads::load(a.binding.clone(), SLOT, astore).unwrap();
    let evidence = restored
        .parent_evidence(&mut a.port(), astore, source, clock)
        .await
        .unwrap();
    let restored_peer = Threads::load(b.binding.clone(), SLOT, bstore).unwrap();
    let verified = restored_peer
        .verify_parent_evidence(&mut b.port(), bstore, &evidence, source, clock)
        .await
        .unwrap();
    assert_eq!(verified.state().members(), &group_support::members(0, 2));
    let contacts = ctcs::Contacts::load(a.binding.clone(), astore).unwrap();
    let sent = restored
        .send_group(
            &mut a.port(),
            &contacts,
            source,
            clock,
            b"after real removal",
        )
        .await
        .unwrap()
        .commit_group(&mut a.port(), astore, [25; 32], source, clock)
        .await
        .unwrap();
    let message = sent.outgoing()[0].bytes().to_vec();
    let contacts = ctcs::Contacts::load(b.binding.clone(), bstore).unwrap();
    let received = restored_peer
        .receive_group(&mut b.port(), &contacts, source, clock, &message)
        .await
        .unwrap()
        .commit_group(&mut b.port(), bstore, [25; 32], source, clock)
        .await
        .unwrap();
    assert_eq!(
        received.threads().history().last().unwrap().bytes,
        b"after real removal"
    );
}

fn prepare(
    state: &cgrp::Snapshot,
    source: &group_support::SignedPolicy,
    at: u64,
) -> cgrp::Candidate {
    let request = group_support::request(
        state,
        cgrp::Command::Leave { group: SLOT },
        "m2",
        group_support::members(2, 3),
        true,
        at,
    );
    cgrp::prepare(
        state,
        &request,
        source,
        &group_support::TestAuthority,
        1003,
        10,
    )
    .unwrap()
}
