use super::*;
use std::{cell::RefCell, rc::Rc};

// The whole Attend flow over the real owners: consent decision, external commit,
// ordering, context commit, hand-over and one atomic Groups/Threads/Attend write.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn attend_joins_with_one_atomic_checkpoint() {
    flow(false);
}

// A forged context commit leaves only the Joining checkpoint: no Threads state,
// no Groups change, no Attend Joined record.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn attend_refusal_leaves_only_the_joining_checkpoint() {
    flow(true);
}

fn flow(corrupt: bool) {
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
        drop(members);
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

        // The Link double stands in for Assembly: it records the external commit
        // and returns the next join counter for the same ordering generation.
        let external = Rc::new(RefCell::new(None));
        struct Assembly(Rc<RefCell<Option<Vec<u8>>>>);
        impl ctnd::Link for Assembly {
            fn order<'a>(
                &'a mut self,
                request: &'a ctnd::OrderRequest,
            ) -> ctnd::PortFuture<'a, ctnd::OrderReply> {
                Box::pin(async move {
                    *self.0.borrow_mut() = Some(request.encrypted_commit.clone());
                    Ok(ctnd::OrderReply {
                        ordering: request.ordering,
                        counter: request.expected + 1,
                        proof: vec![],
                    })
                })
            }
        }
        // The member that admits: authenticates the ordered external commit and
        // commits the canonical context through the real Groups checkpoint.
        struct Admitter<'a> {
            fixture: &'a mut Fixture,
            store: &'a mut Store<Memory>,
            threads: &'a Threads,
            external: Rc<RefCell<Option<Vec<u8>>>>,
            state: cgrp::Snapshot,
            source: &'a group_support::SignedPolicy,
            join: &'a dyn Fn(&cgrp::Snapshot) -> cgrp::Candidate,
            corrupt: bool,
        }
        impl cthr::ContextFeed for Admitter<'_> {
            fn context_commit<'a>(&'a mut self, _: u64) -> ctnd::PortFuture<'a, Vec<u8>> {
                Box::pin(async move {
                    let mut clock = Time::default();
                    let wire = self.external.borrow().clone().unwrap();
                    let groups = (self.join)(&self.state);
                    let admission = self
                        .threads
                        .receive_room_join(
                            &mut self.fixture.port(),
                            self.store,
                            &groups.prepare_effects()[0],
                            &wire,
                            COMPANION,
                            &mut clock,
                        )
                        .await
                        .unwrap();
                    let (committed, _, _) = admission
                        .commit_context(
                            &mut self.fixture.port(),
                            &groups.prepare_effects()[0],
                            &mut clock,
                        )
                        .await
                        .unwrap()
                        .commit_groups(
                            &mut self.fixture.port(),
                            groups,
                            self.store,
                            [40; 32],
                            (self.source, &group_support::TestAuthority),
                            &mut clock,
                        )
                        .await
                        .unwrap();
                    let Event::MembershipCommit { bytes } = &committed.events()[0] else {
                        panic!()
                    };
                    let mut wire = bytes.clone();
                    if self.corrupt {
                        *wire.last_mut().unwrap() ^= 1;
                    }
                    Ok(wire)
                })
            }
        }

        if !corrupt {
            // Guards: a session refuses a decision for another group or
            // revision, a verification without a preparation, and an order whose
            // commit is not the one prepared.
            struct NoFeed;
            impl cthr::ContextFeed for NoFeed {
                fn context_commit<'a>(&'a mut self, _: u64) -> ctnd::PortFuture<'a, Vec<u8>> {
                    Box::pin(async { Err(ctnd::Error::Unavailable) })
                }
            }
            let mut gport = d.port();
            let mut gclock = clock.clone();
            let mut gfeed = NoFeed;
            let session = cthr::JoinSession::new(cthr::JoinParts {
                keys: &mut gport,
                clock: &mut gclock,
                feed: &mut gfeed,
                store: &mut dstore,
                threads: &dt,
                groups: join(&state),
                evidence: &evidence,
                source: &source,
                authority: &group_support::TestAuthority,
                ordering: [9; 16],
                counter: 7,
                handover: vec![],
                companion: COMPANION.to_vec(),
                operation: [51; 32],
            });
            let mut threads = session.threads();
            let request = ctnd::OrderRequest {
                room: [5; 16],
                ordering: [9; 16],
                expected: 7,
                encrypted_commit: vec![1],
                companion: COMPANION.to_vec(),
            };
            let reply = ctnd::OrderReply {
                ordering: [9; 16],
                counter: 8,
                proof: vec![],
            };
            assert_eq!(
                ctnd::Threads::verify_order(&mut threads, &request, &reply)
                    .await
                    .err(),
                Some(ctnd::Error::Invalid)
            );
            assert_eq!(
                ctnd::Threads::prepare(&mut threads, &[1; 32], 2)
                    .await
                    .err(),
                Some(ctnd::Error::Authority)
            );
            assert_eq!(
                ctnd::Threads::prepare(&mut threads, &SLOT, 99).await.err(),
                Some(ctnd::Error::Authority)
            );
            ctnd::Threads::prepare(&mut threads, &SLOT, 2)
                .await
                .unwrap();
            assert_eq!(
                ctnd::Threads::prepare(&mut threads, &SLOT, 2).await.err(),
                Some(ctnd::Error::Invalid)
            );
            assert_eq!(
                ctnd::Threads::verify_order(&mut threads, &request, &reply)
                    .await
                    .err(),
                Some(ctnd::Error::Reconcile)
            );
            drop(threads);
            drop(session);
        }

        let mut feed = Admitter {
            fixture: &mut a,
            store: &mut astore,
            threads: genesis.threads(),
            external: external.clone(),
            state: state.clone(),
            source: &source,
            join: &join,
            corrupt,
        };
        let mut attend = ctnd::Attend::new();
        let mut port = d.port();
        let session = cthr::JoinSession::new(cthr::JoinParts {
            keys: &mut port,
            clock: &mut clock,
            feed: &mut feed,
            store: &mut dstore,
            threads: &dt,
            groups: join(&state),
            evidence: &evidence,
            source: &source,
            authority: &group_support::TestAuthority,
            ordering: [9; 16],
            counter: 7,
            handover: vec![b"profile key".to_vec()],
            companion: COMPANION.to_vec(),
            operation: [50; 32],
        });
        let room = [5; 16];
        session
            .begin(&mut attend, "m3", room, &source, 1001)
            .unwrap();
        let mut threads = session.threads();
        let mut persistence = session.persistence();
        attend
            .prepare_join(&mut threads, &mut persistence, &source, 1001)
            .await
            .unwrap();
        assert_eq!(attend.phase(), &ctnd::Phase::Joining);
        let mut link = Assembly(external);
        let reply = attend.order(&mut link, &source, 1001).await.unwrap();
        assert_eq!(reply.counter, 8);
        let accepted = attend
            .accept(&reply, &mut threads, &mut persistence, &source, 1001)
            .await;
        if corrupt {
            assert!(accepted.is_err());
            drop(threads);
            drop(persistence);
            drop(session);
            let stored: ctnd::Checkpoint =
                postcard::from_bytes(dstore.read("ctnd", &SLOT).unwrap().unwrap()).unwrap();
            assert_eq!(stored.phase(), &ctnd::Phase::Joining);
            assert!(
                Threads::load(d.binding.clone(), SLOT, &dstore)
                    .unwrap()
                    .epoch()
                    .is_err()
            );
            let groups: cgrp::Snapshot =
                postcard::from_bytes(dstore.read("cgrp", b"snapshot.v1").unwrap().unwrap())
                    .unwrap();
            assert_eq!(
                groups.group_state(&SLOT).unwrap().members(),
                &group_support::members(0, 3)
            );
            return;
        }
        let handover = accepted.unwrap();
        assert_eq!(attend.phase(), &ctnd::Phase::Joined);
        assert_eq!(handover.len(), 1);
        assert!(!handover[0].windows(11).any(|v| v == b"profile key"));
        let (committed, snapshot) = session.outcome().unwrap();
        assert_eq!(
            snapshot.group_state(&SLOT).unwrap().members(),
            &group_support::members(0, 4)
        );
        assert!(committed.threads().epoch().is_ok());
        drop(threads);
        drop(persistence);
        drop(session);
        // Groups, Threads and the Attend checkpoint became visible together.
        let stored: ctnd::Checkpoint =
            postcard::from_bytes(dstore.read("ctnd", &SLOT).unwrap().unwrap()).unwrap();
        assert_eq!(stored.phase(), &ctnd::Phase::Joined);
        assert!(
            Threads::load(d.binding.clone(), SLOT, &dstore)
                .unwrap()
                .epoch()
                .is_ok()
        );
        let groups: cgrp::Snapshot =
            postcard::from_bytes(dstore.read("cgrp", b"snapshot.v1").unwrap().unwrap()).unwrap();
        assert_eq!(
            groups.group_state(&SLOT).unwrap().members(),
            &group_support::members(0, 4)
        );

        // Leaving: Groups, the Threads state and the Attend withdrawal change
        // together in one commit.
        let after = Threads::load(d.binding.clone(), SLOT, &dstore).unwrap();
        let mut attend = after.stored_attend(&dstore).unwrap().unwrap();
        assert_eq!(attend.phase(), &ctnd::Phase::Joined);
        let leave = cgrp::prepare(
            &groups,
            &group_support::request(
                &groups,
                cgrp::Command::Leave { group: SLOT },
                "m3",
                group_support::members(3, 4),
                true,
                1000,
            ),
            &source,
            &group_support::TestAuthority,
            1000,
            10,
        )
        .unwrap();
        let mut lclock = Time::default();
        // A room-scoped grant of the caller leaves with the room, in one commit.
        let held = dstore.version().unwrap();
        dstore
            .commit(
                held,
                [54; 32],
                &[cwst::Change::Put {
                    owner: "test.grant",
                    key: &SLOT,
                    value: b"grant",
                }],
                &[],
            )
            .await
            .unwrap();
        assert!(dstore.read("test.grant", &SLOT).unwrap().is_some());
        let after = Threads::load(d.binding.clone(), SLOT, &dstore).unwrap();
        let version = dstore.version().unwrap();
        let snapshot = cthr::leave_room(
            &mut attend,
            cthr::LeaveParts {
                store: &mut dstore,
                threads: &after,
                groups: leave,
                source: &source,
                authority: &group_support::TestAuthority,
                clock: &mut lclock,
                operation: [52; 32],
                dependents: &["test.grant"],
            },
        )
        .await
        .unwrap();
        assert_eq!(attend.phase(), &ctnd::Phase::Withdrawn);
        assert!(dstore.version().unwrap() > version);
        assert_eq!(dstore.read("test.grant", &SLOT).unwrap(), None);
        assert!(
            !snapshot
                .group_state(&SLOT)
                .unwrap()
                .members()
                .contains("m3")
        );
        let stored: ctnd::Checkpoint =
            postcard::from_bytes(dstore.read("ctnd", &SLOT).unwrap().unwrap()).unwrap();
        assert_eq!(stored.phase(), &ctnd::Phase::Withdrawn);
        assert!(dstore.read("cthr", &SLOT).unwrap().is_none());
        // Nothing of the room is left to resume or to read.
        let gone = Threads::load(d.binding.clone(), SLOT, &dstore).unwrap();
        assert!(gone.epoch().is_err());
    }));
}
