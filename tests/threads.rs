//! Real OpenMLS and scoped Keys vectors. Test issuers are not production G3/G2.
#[path = "support/groups.rs"]
mod group_support;
mod support;
use ckmg::{Binding, KeyHandle, Lineage};
use ctcs::DeviceAuthority;
use cthr::{DirectAuthority, Error, Event, Operation, Threads, keys::KeyPort};
use cwst::{Store, backend::Memory};
use ed25519_dalek::{Signer, SigningKey};
use futures::executor::block_on;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};
use support::{Guard, Machine, Time, create, machine, prf};
#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
const SLOT: [u8; 32] = [17; 32];
#[derive(Clone, Default)]
struct Directory(Rc<RefCell<BTreeMap<String, Lineage>>>);
impl DeviceAuthority for Directory {
    async fn current(&mut self, binding: &Binding) -> Result<Lineage, ctcs::Error> {
        self.0
            .borrow()
            .get(binding.member())
            .filter(|lineage| lineage.binding == *binding)
            .cloned()
            .ok_or(ctcs::Error::Authority)
    }
}
// An independent fixture signs exact participants and conversation. The adapter
// verifies it for every operation; it is not a production accounting substitute.
struct Grant {
    bytes: Vec<u8>,
    signature: [u8; 64],
}
impl Grant {
    fn new() -> Self {
        let bytes =
            serde_json::to_vec(&("test.direct.authorization", "alpha", "alice", "bob", SLOT))
                .unwrap();
        Self {
            signature: SigningKey::from_bytes(&[77; 32]).sign(&bytes).to_bytes(),
            bytes,
        }
    }
}
impl DirectAuthority for Grant {
    async fn authorize(
        &mut self,
        binding: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        _: Operation,
    ) -> cthr::Result<()> {
        let (a, b) = if binding.member() < peer {
            (binding.member(), peer)
        } else {
            (peer, binding.member())
        };
        let expected = serde_json::to_vec(&(
            "test.direct.authorization",
            binding.community(),
            a,
            b,
            conversation,
        ))
        .unwrap();
        if expected != self.bytes {
            return Err(Error::Authority);
        }
        ckmg::verify_ed25519(
            &SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes(),
            &expected,
            &self.signature,
        )
        .map_err(|_| Error::Authority)
    }
}
struct Fixture {
    keys: Machine,
    handle: KeyHandle,
    binding: Binding,
    directory: Directory,
    seed: u8,
}
impl Fixture {
    async fn new(member: &str, seed: u8, directory: Directory) -> Self {
        let guard = Guard::default();
        let binding = Binding::new("alpha", member).unwrap();
        let mut keys = machine(&support::Memory::default(), &Time::default(), &guard, seed);
        create(&mut keys, &guard, &prf(seed), &binding).await;
        let handle = keys.key(cthr::purpose()).await.unwrap();
        directory
            .0
            .borrow_mut()
            .insert(member.into(), guard.0.borrow()["alpha"].clone());
        Self {
            keys,
            handle,
            binding,
            directory,
            seed,
        }
    }
    fn port(&mut self) -> KeyPort<'_, support::Memory, Time, support::Random, Guard, Directory> {
        KeyPort {
            keys: &mut self.keys,
            handle: &self.handle,
            devices: &mut self.directory,
        }
    }
    async fn store(&self) -> (Memory, Store<Memory>) {
        let backend = Memory::new();
        let cipher = ckmg::passkey::store_cipher(&prf(self.seed), "alpha").unwrap();
        let store = Store::create(backend.clone(), &cipher, "alpha")
            .await
            .unwrap();
        (backend, store)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_roundtrip_is_durable_and_tamper_does_not_consume_ratchets() {
    block_on(async {
        let directory = Directory::default();
        let mut a = Fixture::new("alice", 1, directory.clone()).await;
        let mut b = Fixture::new("bob", 2, directory.clone()).await;
        let (abackend, mut astore) = a.store().await;
        let (bbackend, mut bstore) = b.store().await;
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        assert_eq!(at.epoch().err(), Some(Error::State));
        let candidate = bt.key_package(&mut b.port()).await.unwrap();
        assert!(bstore.load_pending().unwrap().is_empty());
        assert!(candidate.prepared_message().is_none());
        let package = candidate
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [1; 32], &[])
            .await
            .unwrap();
        let Event::KeyPackage { bytes } = &package.events()[0] else {
            panic!()
        };
        let mut grant = Grant::new();
        for invalid in [vec![], vec![0; 1024 * 1024 + 1], vec![1, 2, 3]] {
            assert!(
                at.create_direct(&mut a.port(), &mut grant, "bob", &invalid)
                    .await
                    .is_err()
            );
        }
        let mut altered = bytes.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(
            at.create_direct(&mut a.port(), &mut grant, "bob", &altered)
                .await
                .is_err()
        );
        assert_eq!(
            at.create_direct(&mut a.port(), &mut cthr::Unavailable, "bob", bytes)
                .await
                .err(),
            Some(Error::Unavailable)
        );
        assert!(
            at.create_direct(&mut a.port(), &mut grant, "wrong", bytes)
                .await
                .is_err()
        );
        let candidate = at
            .create_direct(&mut a.port(), &mut grant, "bob", bytes)
            .await
            .unwrap();
        assert!(astore.load_pending().unwrap().is_empty());
        let invitation = candidate
            .commit(&mut a.port(), &mut Grant::new(), &mut astore, [1; 32], &[])
            .await
            .unwrap();
        let Event::Invitation { welcome, .. } = &invitation.events()[0] else {
            panic!()
        };
        let joined = package
            .threads()
            .join_direct(&mut b.port(), &mut grant, "alice", welcome)
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [2; 32], &[])
            .await
            .unwrap();
        assert_eq!(joined.threads().epoch().unwrap(), 1);
        assert_eq!(
            joined.threads().key_package(&mut b.port()).await.err(),
            Some(Error::State)
        );
        assert_eq!(
            joined
                .threads()
                .join_direct(&mut b.port(), &mut grant, "alice", welcome)
                .await
                .err(),
            Some(Error::State)
        );
        assert_eq!(
            invitation
                .threads()
                .create_direct(&mut a.port(), &mut grant, "bob", bytes)
                .await
                .err(),
            Some(Error::State)
        );
        for invalid in [vec![], vec![1, 2, 3]] {
            assert!(
                joined
                    .threads()
                    .receive(&mut b.port(), &mut grant, &invalid)
                    .await
                    .is_err()
            );
        }
        assert!(
            joined
                .threads()
                .receive(&mut b.port(), &mut cthr::Unavailable, welcome)
                .await
                .is_err()
        );
        assert_eq!(invitation.threads().epoch().unwrap(), 1);
        let candidate = invitation
            .threads()
            .send(&mut a.port(), &mut grant, b"hello")
            .await
            .unwrap();
        assert!(invitation.threads().history().is_empty());
        let proposed = candidate.prepared_message().unwrap();
        assert!(proposed.binding() == &a.binding);
        assert_eq!(proposed.conversation(), &SLOT);
        assert_eq!(proposed.epoch(), 1);
        assert_eq!(proposed.sender(), "alice");
        assert_eq!(proposed.peer(), Some("bob"));
        assert_eq!(proposed.peer_certificate().unwrap().binding.member(), "bob");
        assert!(!proposed.receiving());
        assert_eq!(proposed.checkpoint_version(), astore.version().unwrap());
        assert_ne!(proposed.id(), &[0; 32]);
        let revoked = invitation
            .threads()
            .send(&mut a.port(), &mut grant, b"withheld")
            .await
            .unwrap();
        let current = directory.0.borrow_mut().remove("bob").unwrap();
        assert_eq!(
            revoked
                .commit(&mut a.port(), &mut grant, &mut astore, [42; 32], &[])
                .await
                .err(),
            Some(Error::Authority)
        );
        directory.0.borrow_mut().insert("bob".into(), current);
        let unavailable = invitation
            .threads()
            .send(&mut a.port(), &mut grant, b"withheld")
            .await
            .unwrap();
        assert_eq!(
            unavailable
                .commit(
                    &mut a.port(),
                    &mut cthr::Unavailable,
                    &mut astore,
                    [42; 32],
                    &[]
                )
                .await
                .err(),
            Some(Error::Unavailable)
        );
        assert!(invitation.threads().history().is_empty());
        let sent = candidate
            .commit(&mut a.port(), &mut Grant::new(), &mut astore, [2; 32], &[])
            .await
            .unwrap();
        let Event::Ciphertext { bytes: wire, .. } = &sent.events()[0] else {
            panic!()
        };
        let outgoing = sent.outgoing();
        assert_eq!(outgoing.len(), 1);
        assert!(outgoing[0].binding() == &a.binding);
        assert_eq!(outgoing[0].peer(), Some("bob"));
        assert_eq!(outgoing[0].recipients(), vec!["bob"]);
        assert_eq!(outgoing[0].conversation(), &SLOT);
        assert_eq!(outgoing[0].epoch(), 1);
        assert_eq!(outgoing[0].id(), ckmg::hash(wire).value());
        assert_eq!(outgoing[0].bytes(), wire);
        assert!(sent.accepted().is_empty());
        let mut tamper = wire.clone();
        *tamper.last_mut().unwrap() ^= 1;
        assert!(
            joined
                .threads()
                .receive(&mut b.port(), &mut grant, &tamper)
                .await
                .is_err()
        );
        let root = directory.0.borrow()["alice"].clone();
        directory.0.borrow_mut().get_mut("alice").unwrap().epoch += 1;
        assert_eq!(
            joined
                .threads()
                .receive(&mut b.port(), &mut grant, wire)
                .await
                .err(),
            Some(Error::Authority)
        );
        directory.0.borrow_mut().insert("alice".into(), root);
        let received = joined
            .threads()
            .receive(&mut b.port(), &mut grant, wire)
            .await
            .unwrap();
        assert!(joined.threads().history().is_empty());
        assert!(received.prepared_message().unwrap().receiving());
        let accepted = received
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [3; 32], &[])
            .await
            .unwrap();
        assert_eq!(accepted.threads().history()[0].bytes, b"hello");
        let receipts = accepted.accepted();
        assert!(receipts[0].binding() == &b.binding);
        assert_eq!(receipts[0].conversation(), &SLOT);
        assert_eq!(receipts[0].message().bytes, b"hello");
        assert!(accepted.outgoing().is_empty());
        assert!(
            accepted
                .threads()
                .receive(&mut b.port(), &mut grant, wire)
                .await
                .is_err()
        );
        let acipher = ckmg::passkey::store_cipher(&prf(1), "alpha").unwrap();
        let bcipher = ckmg::passkey::store_cipher(&prf(2), "alpha").unwrap();
        let mut astore = Store::open(abackend, &acipher, "alpha").await.unwrap();
        let mut bstore = Store::open(bbackend, &bcipher, "alpha").await.unwrap();
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        assert_eq!(bt.history()[0].bytes, b"hello");
        let reply = bt
            .send(&mut b.port(), &mut grant, b"reply")
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [4; 32], &[])
            .await
            .unwrap();
        let Event::Ciphertext { bytes, .. } = &reply.events()[0] else {
            panic!()
        };
        let received = at
            .receive(&mut a.port(), &mut grant, bytes)
            .await
            .unwrap()
            .commit(&mut a.port(), &mut Grant::new(), &mut astore, [3; 32], &[])
            .await
            .unwrap();
        assert_eq!(received.threads().history()[0].bytes, b"reply");
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn candidates_refuse_cross_scope_and_changed_checkpoint() {
    block_on(async {
        let mut a = Fixture::new("alice", 1, Directory::default()).await;
        let (backend, mut store) = a.store().await;
        assert!(Threads::load(a.binding.clone(), [0; 32], &store).is_err());
        assert!(Threads::load(Binding::new("beta", "alice").unwrap(), SLOT, &store).is_err());
        let at = Threads::load(a.binding.clone(), SLOT, &store).unwrap();
        let first = at.key_package(&mut a.port()).await.unwrap();
        let second = at.key_package(&mut a.port()).await.unwrap();
        let (_, mut foreign) = {
            let backend = Memory::new();
            let cipher = ckmg::passkey::store_cipher(&prf(1), "beta").unwrap();
            let store = Store::create(backend.clone(), &cipher, "beta")
                .await
                .unwrap();
            (backend, store)
        };
        let wrong = at.key_package(&mut a.port()).await.unwrap();
        assert_eq!(
            wrong
                .commit(&mut a.port(), &mut Grant::new(), &mut foreign, [1; 32], &[])
                .await
                .err(),
            Some(Error::Scope)
        );
        let wrong = at.key_package(&mut a.port()).await.unwrap();
        assert_eq!(
            wrong
                .commit(
                    &mut a.port(),
                    &mut Grant::new(),
                    &mut store,
                    [1; 32],
                    &[cwst::Change::Delete {
                        owner: "cthr",
                        key: b"x"
                    }]
                )
                .await
                .err(),
            Some(Error::Scope)
        );
        first
            .commit(&mut a.port(), &mut Grant::new(), &mut store, [1; 32], &[])
            .await
            .unwrap();
        assert_eq!(
            second
                .commit(&mut a.port(), &mut Grant::new(), &mut store, [2; 32], &[])
                .await
                .err(),
            Some(Error::Conflict)
        );
        let at = Threads::load(a.binding.clone(), SLOT, &store).unwrap();
        assert_eq!(
            at.send(&mut a.port(), &mut Grant::new(), b"").await.err(),
            Some(Error::Limit)
        );
        assert_eq!(
            at.send(&mut a.port(), &mut Grant::new(), b"x").await.err(),
            Some(Error::State)
        );
        let other = a
            .keys
            .key(ckmg::Purpose::new(ckmg::Scope::Device, "wrong", 1).unwrap())
            .await
            .unwrap();
        let mut wrong = KeyPort {
            keys: &mut a.keys,
            handle: &other,
            devices: &mut a.directory,
        };
        assert_eq!(at.key_package(&mut wrong).await.err(), Some(Error::Scope));
        let bytes = store.read("cthr", &SLOT).unwrap().unwrap();
        let mut checkpoint: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        checkpoint["version"] = 2.into();
        let bytes = serde_json::to_vec(&checkpoint).unwrap();
        store
            .commit(
                store.version().unwrap(),
                [3; 32],
                &[cwst::Change::Put {
                    owner: "cthr",
                    key: &SLOT,
                    value: &bytes,
                }],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            Threads::load(a.binding.clone(), SLOT, &store).err(),
            Some(Error::Scope)
        );
        let cipher = ckmg::passkey::store_cipher(&prf(1), "alpha").unwrap();
        let mut competing = Store::open(backend, &cipher, "alpha").await.unwrap();
        competing
            .commit(competing.version().unwrap(), [4; 32], &[], &[])
            .await
            .unwrap();
        assert!(
            store
                .commit(store.version().unwrap(), [5; 32], &[], &[])
                .await
                .is_err()
        );
        assert_eq!(
            Threads::load(a.binding.clone(), SLOT, &store).err(),
            Some(Error::Storage)
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_fork_membership_policy_and_checkpoint_are_one_transition() {
    block_on(async {
        let directory = Directory::default();
        let mut a = Fixture::new("m0", 1, directory.clone()).await;
        let mut b = Fixture::new("m1", 2, directory.clone()).await;
        let mut c = Fixture::new("m2", 3, directory).await;
        let (_, mut astore) = a.store().await;
        let (_, mut bstore) = b.store().await;
        let (_, mut cstore) = c.store().await;
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
            .map(|committed| match &committed.events()[0] {
                Event::KeyPackage { bytes } => bytes.clone(),
                _ => panic!(),
            })
            .collect();
        let mut policy = group_support::policy();
        policy.bands[3].history_messages = 2;
        let source = group_support::SignedPolicy::new(&policy);
        let empty = cgrp::Snapshot::empty("alpha".into());
        let request = group_support::request(
            &empty,
            cgrp::Command::Create {
                id: SLOT,
                members: group_support::members(0, 3),
                seed: false,
            },
            "m0",
            group_support::members(0, 3),
            false,
            1000,
        );
        let prepare = || {
            cgrp::prepare(
                &empty,
                &request,
                &source,
                &group_support::TestAuthority,
                1000,
                10,
            )
            .unwrap()
        };
        let groups = prepare();
        let effects = groups.prepare_effects();
        let mut clock = Time::default();
        let unauthorized = at
            .create_fork(&mut a.port(), &effects[0], &packages, &mut clock)
            .await
            .unwrap();
        assert_eq!(
            unauthorized
                .commit(&mut a.port(), &mut Grant::new(), &mut astore, [2; 32], &[])
                .await
                .err(),
            Some(Error::Authority)
        );
        let candidate = at
            .create_fork(&mut a.port(), &effects[0], &packages, &mut clock)
            .await
            .unwrap();
        drop(effects);
        let (joined, group_state, _) = candidate
            .commit_groups(
                &mut a.port(),
                groups,
                &mut astore,
                [2; 32],
                &source,
                &mut clock,
            )
            .await
            .unwrap();
        let Event::Invitation { welcome, .. } = &joined.events()[0] else {
            panic!()
        };
        assert_eq!(group_state.revision(), 1);
        let stored: cgrp::Snapshot =
            postcard::from_bytes(astore.read("cgrp", b"snapshot.v1").unwrap().unwrap()).unwrap();
        assert_eq!(stored.revision(), 1);
        assert_eq!(joined.threads().lineage().unwrap().0, SLOT);
        assert_eq!(
            joined.threads().notification(),
            Some(cgrp::Notification::EveryMessage)
        );
        let bgroups = prepare();
        let effects = bgroups.prepare_effects();
        let bc = bp
            .threads()
            .join_fork(&mut b.port(), &effects[0], welcome, &mut clock)
            .await
            .unwrap();
        drop(effects);
        let (bjoined, _, _) = bc
            .commit_groups(
                &mut b.port(),
                bgroups,
                &mut bstore,
                [2; 32],
                &source,
                &mut clock,
            )
            .await
            .unwrap();
        let cgroups = prepare();
        let effects = cgroups.prepare_effects();
        let cc = cp
            .threads()
            .join_fork(&mut c.port(), &effects[0], welcome, &mut clock)
            .await
            .unwrap();
        drop(effects);
        cc.commit_groups(
            &mut c.port(),
            cgroups,
            &mut cstore,
            [2; 32],
            &source,
            &mut clock,
        )
        .await
        .unwrap();
        let contacts = |member: &str, store: &Store<Memory>| {
            ctcs::Contacts::load(Binding::new("alpha", member).unwrap(), store).unwrap()
        };
        let mut at = joined.into_threads();
        let mut bt = bjoined.into_threads();
        for index in 0..policy.bands[0].burst {
            let sent = at
                .send_group(
                    &mut a.port(),
                    &contacts("m0", &astore),
                    &source,
                    &mut clock,
                    b"group message",
                )
                .await
                .unwrap()
                .commit_group(
                    &mut a.port(),
                    &mut astore,
                    [(index + 10) as u8; 32],
                    &source,
                    &mut clock,
                )
                .await
                .unwrap();
            let outgoing = sent.outgoing();
            assert_eq!(outgoing[0].peer(), None);
            assert_eq!(outgoing[0].recipients(), vec!["m1", "m2"]);
            let wire = outgoing[0].bytes().to_vec();
            let accepted = bt
                .receive_group(
                    &mut b.port(),
                    &contacts("m1", &bstore),
                    &source,
                    &mut clock,
                    &wire,
                )
                .await
                .unwrap()
                .commit_group(
                    &mut b.port(),
                    &mut bstore,
                    [(index + 10) as u8; 32],
                    &source,
                    &mut clock,
                )
                .await
                .unwrap();
            assert_eq!(accepted.threads().history().len(), usize::from(index) + 1);
            assert!(
                accepted
                    .threads()
                    .receive_group(
                        &mut b.port(),
                        &contacts("m1", &bstore),
                        &source,
                        &mut clock,
                        &wire
                    )
                    .await
                    .is_err()
            );
            at = sent.into_threads();
            bt = accepted.into_threads();
        }
        assert_eq!(
            at.send_group(
                &mut a.port(),
                &contacts("m0", &astore),
                &source,
                &mut clock,
                b"excess"
            )
            .await
            .err(),
            Some(Error::Pace)
        );
        let mut advanced = Time::default();
        advanced.0.set(1030);
        let sent = at
            .send_group(
                &mut a.port(),
                &contacts("m0", &astore),
                &source,
                &mut advanced,
                b"later",
            )
            .await
            .unwrap()
            .commit_group(&mut a.port(), &mut astore, [60; 32], &source, &mut advanced)
            .await
            .unwrap();
        let wire = sent.outgoing()[0].bytes().to_vec();
        assert_eq!(
            bt.receive_group(
                &mut b.port(),
                &contacts("m1", &bstore),
                &source,
                &mut clock,
                &wire
            )
            .await
            .err(),
            Some(Error::Pace)
        );
        // The declined receive did not consume its ratchet. It succeeds when the
        // receiver's actual local policy clock grants another cell.
        let accepted = bt
            .receive_group(
                &mut b.port(),
                &contacts("m1", &bstore),
                &source,
                &mut advanced,
                &wire,
            )
            .await
            .unwrap()
            .commit_group(&mut b.port(), &mut bstore, [60; 32], &source, &mut advanced)
            .await
            .unwrap();
        assert_eq!(accepted.threads().history().last().unwrap().bytes, b"later");
        let forks = group_support::request(
            &group_state,
            cgrp::Command::Fork {
                id: [18; 32],
                parents: vec![SLOT],
                members: group_support::members(0, 3),
                kind: cgrp::ForkKind::Split,
            },
            "m0",
            group_support::members(0, 3),
            false,
            1030,
        );
        let next = cgrp::prepare(
            &group_state,
            &forks,
            &source,
            &group_support::TestAuthority,
            1030,
            10,
        )
        .unwrap();
        assert!(
            accepted
                .threads()
                .history_for(&next.prepare_effects()[0], &mut advanced)
                .unwrap()
                .is_empty()
        );
        let expanded = group_support::request(
            &group_state,
            cgrp::Command::Fork {
                id: [19; 32],
                parents: vec![SLOT],
                members: group_support::members(0, 13),
                kind: cgrp::ForkKind::Add,
            },
            "m0",
            group_support::members(0, 13),
            false,
            1030,
        );
        let expanded = cgrp::prepare(
            &group_state,
            &expanded,
            &source,
            &group_support::TestAuthority,
            1030,
            10,
        )
        .unwrap();
        let disclosed = accepted
            .threads()
            .history_for(&expanded.prepare_effects()[0], &mut advanced)
            .unwrap();
        assert_eq!(disclosed.len(), 2);
        assert_eq!(disclosed.last().unwrap().bytes, b"later");
        let leave = group_support::request(
            &group_state,
            cgrp::Command::Leave { group: SLOT },
            "m1",
            group_support::members(1, 2),
            false,
            1030,
        );
        let leave = cgrp::prepare(
            &group_state,
            &leave,
            &source,
            &group_support::TestAuthority,
            1030,
            10,
        )
        .unwrap();
        let effects = leave.prepare_effects();
        let candidate = accepted
            .threads()
            .update_fork(&mut b.port(), &effects[0], &mut advanced)
            .await
            .unwrap();
        drop(effects);
        let (left, _, _) = candidate
            .commit_groups(
                &mut b.port(),
                leave,
                &mut bstore,
                [61; 32],
                &source,
                &mut advanced,
            )
            .await
            .unwrap();
        assert_eq!(left.threads().history().len(), 21);
        assert_eq!(
            left.threads()
                .send_group(
                    &mut b.port(),
                    &contacts("m1", &bstore),
                    &source,
                    &mut advanced,
                    b"left"
                )
                .await
                .err(),
            Some(Error::Authority)
        );
        // The previously committed old view now also fails the Vault version fence.
        assert_eq!(
            accepted
                .threads()
                .send_group(
                    &mut b.port(),
                    &contacts("m1", &bstore),
                    &source,
                    &mut advanced,
                    b"stale"
                )
                .await
                .err(),
            Some(Error::Conflict)
        );
        clock.0.set(999);
        assert_eq!(
            left.threads()
                .send_group(
                    &mut b.port(),
                    &contacts("m1", &bstore),
                    &source,
                    &mut clock,
                    b"old clock"
                )
                .await
                .err(),
            Some(Error::Clock)
        );
        clock.0.set(policy.valid_until);
        assert_eq!(
            left.threads()
                .send_group(
                    &mut b.port(),
                    &contacts("m1", &bstore),
                    &source,
                    &mut clock,
                    b"expired"
                )
                .await
                .err(),
            Some(Error::Authority)
        );
    });
}
