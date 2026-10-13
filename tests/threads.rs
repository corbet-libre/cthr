//! Real OpenMLS and scoped Keys vectors. Test issuers are not production G3/G2.
//! Large fixture futures are heap-pinned to fit the default browser Wasm stack.
#[path = "support/binary_payload_refusals.rs"]
mod binary_payload_refusals;
#[path = "support/groups.rs"]
mod group_support;
#[path = "support/rooms.rs"]
mod rooms;
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
const COMPANION: &[u8] = b"signed-join-request";
fn stage(name: &str) {
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::console_log!("{name}");
    #[cfg(not(target_arch = "wasm32"))]
    let _ = name;
}
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
        Self::pair("alice", "bob", SLOT)
    }
    fn pair(first: &str, second: &str, slot: [u8; 32]) -> Self {
        let (a, b) = if first < second {
            (first, second)
        } else {
            (second, first)
        };
        let bytes =
            serde_json::to_vec(&("test.direct.authorization", "alpha", a, b, slot)).unwrap();
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
// Receipt authority exists only inside this fixture. It signs a capability
// obtained from actual committed recipient history, not a fabricated receive.
struct Receipt {
    binding: Binding,
    recipient: String,
    conversation: [u8; 32],
    message: [u8; 32],
    epoch: u64,
    signature: [u8; 64],
}
impl Receipt {
    fn bytes(
        binding: &Binding,
        recipient: &str,
        conversation: &[u8; 32],
        message: &[u8; 32],
        epoch: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&(
            "fixture.durable.receipt",
            binding,
            recipient,
            conversation,
            message,
            epoch,
        ))
        .unwrap()
    }
    fn from_committed(accepted: &cthr::Accepted<'_>) -> Self {
        let binding =
            Binding::new(accepted.binding().community(), &accepted.message().sender).unwrap();
        let recipient = accepted.binding().member().to_owned();
        let conversation = *accepted.conversation();
        let message = accepted.message().id;
        let epoch = accepted.message().epoch;
        let signature = SigningKey::from_bytes(&[78; 32])
            .sign(&Self::bytes(
                &binding,
                &recipient,
                &conversation,
                &message,
                epoch,
            ))
            .to_bytes();
        Self {
            binding,
            recipient,
            conversation,
            message,
            epoch,
            signature,
        }
    }
}
impl cthr::Acceptance for Receipt {
    fn verify(
        &self,
        binding: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        message: &[u8; 32],
        epoch: u64,
    ) -> cthr::Result<()> {
        if binding != &self.binding
            || peer != self.recipient
            || conversation != &self.conversation
            || message != &self.message
            || epoch != self.epoch
        {
            return Err(Error::Authority);
        }
        ckmg::verify_ed25519(
            &SigningKey::from_bytes(&[78; 32]).verifying_key().to_bytes(),
            &Self::bytes(binding, peer, conversation, message, epoch),
            &self.signature,
        )
        .map_err(|_| Error::Authority)
    }
}
// Compose two actual owner ports incorrectly to exercise the binding guard.
// Verification and signing still run in Keys; no accepting authority is added.
struct Misbound<'a, A, B> {
    advertised: &'a mut A,
    signer: &'a mut B,
}
impl<A: cthr::keys::Custody, B: cthr::keys::Custody> cthr::keys::Custody for Misbound<'_, A, B> {
    fn certificate(&self) -> &ckmg::KeyCertificate {
        self.advertised.certificate()
    }
    async fn verify(&mut self, certificate: &ckmg::KeyCertificate) -> cthr::Result<()> {
        self.advertised.verify(certificate).await
    }
    async fn use_signer<T>(
        &mut self,
        use_signer: impl for<'key> FnOnce(ckmg::Ed25519Signer<'key>) -> cthr::Result<T>,
    ) -> cthr::Result<T> {
        self.signer.use_signer(use_signer).await
    }
}
struct MlsFixtureSigner<'a>(ckmg::Ed25519Signer<'a>);
struct UpstreamGroup {
    welcome: Vec<u8>,
    storage: Vec<(Vec<u8>, Vec<u8>)>,
}
impl openmls_traits::signatures::Signer for MlsFixtureSigner<'_> {
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, openmls_traits::signatures::SignerError> {
        self.0
            .sign(bytes)
            .map(|signature| signature.to_vec())
            .map_err(|_| openmls_traits::signatures::SignerError::SigningError)
    }
    fn signature_scheme(&self) -> openmls_traits::types::SignatureScheme {
        openmls_traits::types::SignatureScheme::ED25519
    }
}
struct Fixture {
    keys: Machine,
    guard: Guard,
    handle: KeyHandle,
    binding: Binding,
    directory: Directory,
    seed: u8,
}
impl Fixture {
    async fn new(member: &str, seed: u8, directory: Directory) -> Self {
        Self::in_community("alpha", member, seed, directory).await
    }
    async fn in_community(community: &str, member: &str, seed: u8, directory: Directory) -> Self {
        let guard = Guard::default();
        let binding = Binding::new(community, member).unwrap();
        let mut keys = machine(&support::Memory::default(), &Time::default(), &guard, seed);
        create(&mut keys, &guard, &prf(seed), &binding).await;
        let handle = keys.key(cthr::purpose()).await.unwrap();
        directory
            .0
            .borrow_mut()
            .insert(member.into(), guard.0.borrow()[community].clone());
        Self {
            keys,
            guard,
            handle,
            binding,
            directory,
            seed,
        }
    }
    async fn wire_package(&mut self, identity: Vec<u8>) -> Vec<u8> {
        use openmls::prelude::*;
        use tls_codec::Serialize;
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: self.handle.certificate().key.value().to_vec().into(),
        };
        self.keys
            .with_ed25519_signer(&self.handle, |signer| {
                KeyPackage::builder()
                    .build(
                        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                        &provider,
                        &MlsFixtureSigner(signer),
                        credential,
                    )
                    .unwrap()
                    .key_package()
                    .tls_serialize_detached()
                    .unwrap()
            })
            .await
            .unwrap()
    }
    async fn upstream_invitation(
        &mut self,
        slot: [u8; 32],
        identity: Vec<u8>,
        packages: &[Vec<u8>],
    ) -> Vec<u8> {
        self.upstream_group(slot, identity, packages).await.welcome
    }
    async fn upstream_group(
        &mut self,
        slot: [u8; 32],
        identity: Vec<u8>,
        packages: &[Vec<u8>],
    ) -> UpstreamGroup {
        use openmls::prelude::*;
        use openmls_traits::OpenMlsProvider;
        use tls_codec::{Deserialize, Serialize};
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        let packages: Vec<_> = packages
            .iter()
            .map(|wire| {
                KeyPackageIn::tls_deserialize_exact(wire)
                    .unwrap()
                    .validate(provider.crypto(), ProtocolVersion::Mls10)
                    .unwrap()
            })
            .collect();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: self.handle.certificate().key.value().to_vec().into(),
        };
        self.keys
            .with_ed25519_signer(&self.handle, |signer| {
                let signer = MlsFixtureSigner(signer);
                let config = MlsGroupCreateConfig::builder()
                    .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
                    .use_ratchet_tree_extension(true)
                    .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                    .build();
                let mut group = MlsGroup::new_with_group_id(
                    &provider,
                    &signer,
                    &config,
                    GroupId::from_slice(&slot),
                    credential,
                )
                .unwrap();
                let (_, welcome, _) = group.add_members(&provider, &signer, &packages).unwrap();
                group.merge_pending_commit(&provider).unwrap();
                UpstreamGroup {
                    welcome: welcome.tls_serialize_detached().unwrap(),
                    storage: provider
                        .storage()
                        .values
                        .read()
                        .unwrap()
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                }
            })
            .await
            .unwrap()
    }
    async fn paired(&mut self, seed: u8) -> Fixture {
        let mut keys = machine(
            &support::Memory::default(),
            &Time::default(),
            &self.guard,
            seed,
        );
        support::pair(&mut self.keys, &mut keys, &self.guard, &prf(seed)).await;
        let handle = keys.key(cthr::purpose()).await.unwrap();
        self.directory.0.borrow_mut().insert(
            self.binding.member().into(),
            self.guard.0.borrow()[self.binding.community()].clone(),
        );
        Fixture {
            keys,
            handle,
            guard: self.guard.clone(),
            binding: self.binding.clone(),
            directory: self.directory.clone(),
            seed,
        }
    }
    async fn upstream_join_proposal(&mut self, slot: [u8; 32], epoch: u64) -> Vec<u8> {
        use openmls::prelude::*;
        use openmls_traits::OpenMlsProvider;
        use tls_codec::Serialize;
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(
                serde_json::to_vec(self.handle.certificate()).unwrap(),
            )
            .into(),
            signature_key: self.handle.certificate().key.value().to_vec().into(),
        };
        self.keys
            .with_ed25519_signer(&self.handle, |signer| {
                let signer = MlsFixtureSigner(signer);
                let package = KeyPackage::builder()
                    .build(
                        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                        &provider,
                        &signer,
                        credential,
                    )
                    .unwrap();
                openmls::messages::external_proposals::JoinProposal::new::<
                    <openmls_rust_crypto::OpenMlsRustCrypto as OpenMlsProvider>::StorageProvider,
                >(
                    package.key_package().clone(),
                    GroupId::from_slice(&slot),
                    epoch.into(),
                    &signer,
                )
                .unwrap()
                .tls_serialize_detached()
                .unwrap()
            })
            .await
            .unwrap()
    }
    // Adversarial peer input comes from actual upstream OpenMLS using the
    // fixture's committed provider state and borrowed Keys signer. Production
    // APIs deliberately never expose this provider state or permit these sends.
    async fn upstream_message(
        &mut self,
        store: &Store<Memory>,
        plaintext: Option<&[u8]>,
    ) -> Vec<u8> {
        use openmls::prelude::*;
        use openmls_traits::OpenMlsProvider;
        use tls_codec::Serialize;
        let snapshot: serde_json::Value =
            serde_json::from_slice(store.read("cthr", &SLOT).unwrap().unwrap()).unwrap();
        let entries: Vec<(Vec<u8>, Vec<u8>)> =
            serde_json::from_value(snapshot["storage"].clone()).unwrap();
        let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
        provider.storage().values.write().unwrap().extend(entries);
        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(&SLOT))
            .unwrap()
            .unwrap();
        self.keys
            .with_ed25519_signer(&self.handle, |signer| {
                let signer = MlsFixtureSigner(signer);
                let message = if let Some(bytes) = plaintext {
                    group.create_message(&provider, &signer, bytes).unwrap()
                } else {
                    group
                        .propose_remove_member(&provider, &signer, group.own_leaf_index())
                        .unwrap()
                        .0
                };
                message.tls_serialize_detached().unwrap()
            })
            .await
            .unwrap()
    }
    fn port(&mut self) -> KeyPort<'_, support::Memory, Time, support::Random, Guard, Directory> {
        KeyPort {
            keys: &mut self.keys,
            handle: &self.handle,
            devices: &mut self.directory,
        }
    }
    async fn block(&mut self, peer: &str, store: &mut Store<Memory>, operation: u8) {
        let handle = self.keys.key(ctcs::purpose()).await.unwrap();
        let contacts = ctcs::Contacts::load(self.binding.clone(), store).unwrap();
        let event = contacts.request(peer, ctcs::Action::Block).unwrap();
        let cert = handle.certificate().clone();
        let signature = self
            .keys
            .sign(&handle, &event.signing_bytes(&cert).unwrap())
            .await
            .unwrap();
        contacts
            .prepare(
                event.signed(cert, signature),
                &mut self.directory,
                &mut ctcs::UnavailableOutcomes,
            )
            .await
            .unwrap()
            .commit(
                (&mut self.directory, &mut ctcs::UnavailableOutcomes),
                store,
                [operation; 32],
                &[],
                &[],
            )
            .await
            .unwrap();
    }
    async fn store(&self) -> (Memory, Store<Memory>) {
        let backend = Memory::new();
        let community = self.binding.community();
        let cipher = ckmg::passkey::store_cipher(&prf(self.seed), community).unwrap();
        let store = Store::create(backend.clone(), &cipher, community)
            .await
            .unwrap();
        (backend, store)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_roundtrip_is_durable_and_tamper_does_not_consume_ratchets() {
    block_on(Box::pin(async {
        let directory = Directory::default();
        let mut a = Fixture::new("alice", 1, directory.clone()).await;
        let mut b = Fixture::new("bob", 2, directory.clone()).await;
        let (abackend, mut astore) = a.store().await;
        let (bbackend, mut bstore) = b.store().await;
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        assert_eq!(at.epoch().err(), Some(Error::State));
        assert_eq!(
            at.key_package(&mut Misbound {
                advertised: &mut a.port(),
                signer: &mut b.port()
            })
            .await
            .err(),
            Some(Error::Authority)
        );
        assert_eq!(
            at.key_package(&mut b.port()).await.err(),
            Some(Error::Scope)
        );
        let wrong_handle = a.keys.key(ctcs::purpose()).await.unwrap();
        assert_eq!(
            at.key_package(&mut KeyPort {
                keys: &mut a.keys,
                handle: &wrong_handle,
                devices: &mut a.directory,
            })
            .await
            .err(),
            Some(Error::Scope)
        );
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
        assert_eq!(
            at.create_direct(&mut a.port(), &mut grant, "alice", bytes)
                .await
                .err(),
            Some(Error::Scope)
        );
        for (identity, expected) in [
            (vec![7; 16_385], Error::Limit),
            (b"invalid".to_vec(), Error::Encoding),
        ] {
            let package = b.wire_package(identity).await;
            assert_eq!(
                at.create_direct(&mut a.port(), &mut grant, "bob", &package)
                    .await
                    .err(),
                Some(expected)
            );
        }
        let mut wrong_purpose = b.handle.certificate().clone();
        wrong_purpose.purpose = ctcs::purpose();
        let mut wrong_key = b.handle.certificate().clone();
        wrong_key.key = a.handle.certificate().clone().key;
        let mut wrong_peer = b.handle.certificate().clone();
        wrong_peer.binding = Binding::new("alpha", "other").unwrap();
        let mut wrong_community = b.handle.certificate().clone();
        wrong_community.binding = Binding::new("beta", "bob").unwrap();
        for (certificate, expected) in [
            (wrong_purpose, Error::Authority),
            (wrong_key, Error::Authority),
            (wrong_peer, Error::Scope),
            (wrong_community, Error::Scope),
        ] {
            let package = b
                .wire_package(serde_json::to_vec(&certificate).unwrap())
                .await;
            assert_eq!(
                at.create_direct(&mut a.port(), &mut grant, "bob", &package)
                    .await
                    .err(),
                Some(expected)
            );
        }
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
        let wrong_group = a
            .upstream_invitation(
                [18; 32],
                serde_json::to_vec(a.handle.certificate()).unwrap(),
                std::slice::from_ref(bytes),
            )
            .await;
        assert_eq!(
            package
                .threads()
                .join_direct(&mut b.port(), &mut grant, "alice", &wrong_group)
                .await
                .err(),
            Some(Error::Scope)
        );
        let joined = package
            .threads()
            .join_direct(&mut b.port(), &mut grant, "alice", welcome)
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [2; 32], &[])
            .await
            .unwrap();
        let old_lineage = b.directory.0.borrow()["bob"].clone();
        let mut replacement = Fixture::new("bob", 8, b.directory.clone()).await;
        let mut checkpoint: serde_json::Value =
            serde_json::from_slice(bstore.read("cthr", &SLOT).unwrap().unwrap()).unwrap();
        checkpoint["certificate"] = serde_json::to_value(replacement.handle.certificate()).unwrap();
        let mut replaced = copied_store(&b, &bstore).await;
        put(
            &mut replaced,
            "cthr",
            &SLOT,
            &serde_json::to_vec(&checkpoint).unwrap(),
            201,
        )
        .await;
        assert_eq!(
            Threads::load(b.binding.clone(), SLOT, &replaced)
                .unwrap()
                .send(&mut replacement.port(), &mut grant, b"old device tree")
                .await
                .err(),
            Some(Error::Authority)
        );
        b.directory.0.borrow_mut().insert("bob".into(), old_lineage);
        let mut outsider = Fixture::new("joining", 9, directory.clone()).await;
        let proposal = outsider
            .upstream_join_proposal(SLOT, joined.threads().epoch().unwrap())
            .await;
        assert_eq!(
            joined
                .threads()
                .receive(&mut b.port(), &mut grant, &proposal)
                .await
                .err(),
            Some(Error::Authority)
        );
        // Two genuinely paired, currently registered devices of the same member
        // still cannot stand for two distinct direct-conversation participants.
        // Import their real upstream provider as a damaged owner checkpoint.
        let mut second_b = b.paired(11).await;
        let package = second_b
            .wire_package(serde_json::to_vec(second_b.handle.certificate()).unwrap())
            .await;
        let same_member = b
            .upstream_group(
                SLOT,
                serde_json::to_vec(b.handle.certificate()).unwrap(),
                &[package],
            )
            .await;
        let mut checkpoint: serde_json::Value =
            serde_json::from_slice(astore.read("cthr", &SLOT).unwrap().unwrap()).unwrap();
        checkpoint["storage"] = serde_json::to_value(same_member.storage).unwrap();
        let mut damaged = copied_store(&a, &astore).await;
        put(
            &mut damaged,
            "cthr",
            &SLOT,
            &serde_json::to_vec(&checkpoint).unwrap(),
            201,
        )
        .await;
        assert_eq!(
            Threads::load(a.binding.clone(), SLOT, &damaged)
                .unwrap()
                .send(&mut a.port(), &mut grant, b"one member twice")
                .await
                .err(),
            Some(Error::Authority)
        );
        assert_eq!(joined.threads().epoch().unwrap(), 1);
        for (plaintext, expected) in [
            (Some(vec![]), Error::Limit),
            (Some(vec![7; 1024 * 1024 / 2 + 1]), Error::Limit),
            (None, Error::Unavailable),
        ] {
            let wire = a.upstream_message(&astore, plaintext.as_deref()).await;
            assert_eq!(
                joined
                    .threads()
                    .receive(&mut b.port(), &mut grant, &wire)
                    .await
                    .err(),
                Some(expected)
            );
        }

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
        assert_eq!(
            invitation
                .threads()
                .send(&mut a.port(), &mut grant, &vec![0; 1024 * 1024 / 2 + 1])
                .await
                .err(),
            Some(Error::Limit)
        );
        let large = invitation
            .threads()
            .send(&mut a.port(), &mut grant, &vec![255; 300_000])
            .await
            .unwrap();
        assert_eq!(
            large
                .commit(&mut a.port(), &mut grant, &mut astore, [81; 32], &[])
                .await
                .err(),
            Some(Error::Limit)
        );
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
        let mut receipt = Receipt::from_committed(&receipts[0]);
        let id = receipt.message;
        Box::pin(malformed_fork_receipt_refuses(&mut a, &astore, &receipt)).await;
        assert_eq!(
            sent.threads().acknowledge(&[0; 32], &receipt).err(),
            Some(Error::State)
        );
        receipt.signature[0] ^= 1;
        assert_eq!(
            sent.threads().acknowledge(&id, &receipt).err(),
            Some(Error::Authority)
        );
        receipt.signature[0] ^= 1;
        let acknowledged = sent.threads().acknowledge(&id, &receipt).unwrap();
        assert!(sent.threads().history().is_empty());
        assert!(acknowledged.prepared_message().is_none());
        let acked = acknowledged
            .commit(&mut a.port(), &mut grant, &mut astore, [10; 32], &[])
            .await
            .unwrap();
        assert_eq!(acked.threads().history()[0].bytes, b"hello");
        assert!(acked.accepted().is_empty());
        assert!(acked.outgoing().is_empty());
        assert_eq!(
            acked.threads().acknowledge(&id, &receipt).err(),
            Some(Error::State)
        );
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
        assert_eq!(received.threads().history()[1].bytes, b"reply");
    }));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn candidates_refuse_cross_scope_and_changed_checkpoint() {
    block_on(Box::pin(async {
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
            .commit(
                &mut a.port(),
                &mut Grant::new(),
                &mut store,
                [1; 32],
                &[cwst::Change::Delete {
                    owner: "fixture",
                    key: b"absent",
                }],
            )
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
    }));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn real_fork_membership_policy_and_checkpoint_are_one_transition() {
    stage("fork fixture entered");
    block_on(Box::pin(async {
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
        let public_request = group_support::request(
            &empty,
            cgrp::Command::Create {
                id: SLOT,
                members: group_support::members(0, 3),
                seed: true,
            },
            "m0",
            group_support::members(0, 3),
            true,
            1000,
        );
        let public = cgrp::prepare(
            &empty,
            &public_request,
            &source,
            &group_support::TestAuthority,
            1000,
            10,
        )
        .unwrap();
        assert_eq!(
            at.create_fork(
                &mut a.port(),
                &public.prepare_effects()[0],
                &packages,
                &mut clock
            )
            .await
            .err(),
            Some(Error::Unavailable)
        );
        let mut wrong_cert = b.handle.certificate().clone();
        wrong_cert.binding = Binding::new("beta", "m1").unwrap();
        let foreign_package = b
            .wire_package(serde_json::to_vec(&wrong_cert).unwrap())
            .await;
        assert_eq!(
            at.create_fork(
                &mut a.port(),
                &effects[0],
                &[foreign_package, packages[1].clone()],
                &mut clock
            )
            .await
            .err(),
            Some(Error::Authority)
        );
        wrong_cert.binding = Binding::new("alpha", "outsider").unwrap();
        let unknown_package = b
            .wire_package(serde_json::to_vec(&wrong_cert).unwrap())
            .await;
        assert_eq!(
            at.create_fork(
                &mut a.port(),
                &effects[0],
                &[unknown_package, packages[1].clone()],
                &mut clock
            )
            .await
            .err(),
            Some(Error::Authority)
        );

        let wrong_slot = Threads::load(a.binding.clone(), [18; 32], &astore).unwrap();
        assert_eq!(
            wrong_slot
                .create_fork(&mut a.port(), &effects[0], &packages, &mut clock)
                .await
                .err(),
            Some(Error::Scope)
        );
        let mut foreign = Fixture::in_community("beta", "m0", 5, Directory::default()).await;
        let (_, foreign_store) = foreign.store().await;
        let foreign_threads = Threads::load(foreign.binding.clone(), SLOT, &foreign_store).unwrap();
        assert_eq!(
            foreign_threads
                .create_fork(&mut foreign.port(), &effects[0], &packages, &mut clock)
                .await
                .err(),
            Some(Error::Scope)
        );
        let mut outsider = Fixture::new("outsider", 4, a.directory.clone()).await;
        // Maintained OpenMLS permits credential/application authorization to be
        // supplied by the application. These are genuine MLS invitations with
        // hostile application identities, not mocked cryptographic messages.
        stage("fork hostile invitations");
        for creator in [&mut foreign, &mut outsider] {
            let identity = serde_json::to_vec(creator.handle.certificate()).unwrap();
            let welcome = creator.upstream_invitation(SLOT, identity, &packages).await;
            assert_eq!(
                bp.threads()
                    .join_fork(&mut b.port(), &effects[0], &welcome, &mut clock)
                    .await
                    .err(),
                Some(Error::Authority)
            );
        }
        for binding in [Binding::new("beta", "m2").unwrap(), b.binding.clone()] {
            let mut certificate = c.handle.certificate().clone();
            certificate.binding = binding;
            let hostile = c
                .wire_package(serde_json::to_vec(&certificate).unwrap())
                .await;
            let identity = serde_json::to_vec(a.handle.certificate()).unwrap();
            let welcome = a
                .upstream_invitation(SLOT, identity, &[packages[0].clone(), hostile])
                .await;
            assert_eq!(
                bp.threads()
                    .join_fork(&mut b.port(), &effects[0], &welcome, &mut clock)
                    .await
                    .err(),
                Some(Error::Authority)
            );
        }
        stage("fork hostile invitations refused");
        let (_, outside_store) = outsider.store().await;
        let outside = Threads::load(outsider.binding.clone(), SLOT, &outside_store).unwrap();
        assert_eq!(
            outside
                .create_fork(&mut outsider.port(), &effects[0], &packages, &mut clock)
                .await
                .err(),
            Some(Error::Scope)
        );
        let mut expired = Time::default();
        expired.0.set(effects[0].valid_until());
        assert_eq!(
            at.create_fork(&mut a.port(), &effects[0], &packages, &mut expired)
                .await
                .err(),
            Some(Error::Authority)
        );
        assert_eq!(
            at.create_fork(&mut a.port(), &effects[0], &[], &mut clock)
                .await
                .err(),
            Some(Error::Authority)
        );
        assert_eq!(
            at.create_fork(
                &mut a.port(),
                &effects[0],
                &[packages[0].clone(), packages[0].clone()],
                &mut clock
            )
            .await
            .err(),
            Some(Error::Authority)
        );
        assert!(
            at.create_fork(
                &mut a.port(),
                &effects[0],
                &[vec![1, 2, 3], packages[1].clone()],
                &mut clock
            )
            .await
            .is_err()
        );
        let held = at
            .create_fork(&mut a.port(), &effects[0], &packages, &mut clock)
            .await
            .unwrap();
        assert_eq!(
            held.commit_group(&mut a.port(), &mut astore, [80; 32], &source, &mut clock)
                .await
                .err(),
            Some(Error::Authority)
        );
        let held = at
            .create_fork(&mut a.port(), &effects[0], &packages, &mut clock)
            .await
            .unwrap();
        assert_eq!(
            held.commit_groups(
                &mut a.port(),
                prepare(),
                &mut astore,
                [80; 32],
                (&source, &group_support::TestAuthority),
                &mut expired
            )
            .await
            .err(),
            Some(Error::Authority)
        );
        let other_request = group_support::request(
            &empty,
            cgrp::Command::Create {
                id: [18; 32],
                members: group_support::members(0, 3),
                seed: false,
            },
            "m0",
            group_support::members(0, 3),
            false,
            1000,
        );
        let other_group = cgrp::prepare(
            &empty,
            &other_request,
            &source,
            &group_support::TestAuthority,
            1000,
            10,
        )
        .unwrap();
        let held = at
            .create_fork(&mut a.port(), &effects[0], &packages, &mut clock)
            .await
            .unwrap();
        assert_eq!(
            held.commit_groups(
                &mut a.port(),
                other_group,
                &mut astore,
                [80; 32],
                (&source, &group_support::TestAuthority),
                &mut clock
            )
            .await
            .err(),
            Some(Error::Storage)
        );
        let key_candidate = at.key_package(&mut a.port()).await.unwrap();
        assert_eq!(
            key_candidate
                .commit_groups(
                    &mut a.port(),
                    prepare(),
                    &mut astore,
                    [80; 32],
                    (&source, &group_support::TestAuthority),
                    &mut clock
                )
                .await
                .err(),
            Some(Error::State)
        );
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
        let (_, mut divergent) = a.store().await;
        let direct = at
            .create_direct(
                &mut a.port(),
                &mut Grant::pair("m0", "m1", SLOT),
                "m1",
                &packages[0],
            )
            .await
            .unwrap()
            .commit(
                &mut a.port(),
                &mut Grant::pair("m0", "m1", SLOT),
                &mut divergent,
                [1; 32],
                &[],
            )
            .await
            .unwrap();
        let Event::Invitation {
            welcome: undersized,
            commit: not_welcome,
        } = &direct.events()[0]
        else {
            panic!()
        };
        assert_eq!(
            bp.threads()
                .join_fork(&mut b.port(), &effects[0], undersized, &mut clock)
                .await
                .err(),
            Some(Error::Authority)
        );
        assert_eq!(
            bp.threads()
                .join_fork(&mut b.port(), &effects[0], not_welcome, &mut clock)
                .await
                .err(),
            Some(Error::Encoding)
        );
        assert_eq!(
            bp.threads()
                .join_direct(
                    &mut b.port(),
                    &mut Grant::pair("m0", "m1", SLOT),
                    "m0",
                    not_welcome
                )
                .await
                .err(),
            Some(Error::Encoding)
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
                (&source, &group_support::TestAuthority),
                &mut clock,
            )
            .await
            .unwrap();
        let Event::Invitation { welcome, .. } = &joined.events()[0] else {
            panic!()
        };
        let other_time = group_support::request(
            &empty,
            cgrp::Command::Create {
                id: SLOT,
                members: group_support::members(0, 3),
                seed: false,
            },
            "m0",
            group_support::members(0, 3),
            false,
            999,
        );
        let other_time = cgrp::prepare(
            &empty,
            &other_time,
            &source,
            &group_support::TestAuthority,
            1000,
            10,
        )
        .unwrap();
        // Real Welcome, same MLS roster and valid signed consent; only the
        // authenticated canonical application state differs. Joining must fail.
        assert_eq!(
            bp.threads()
                .join_fork(
                    &mut b.port(),
                    &other_time.prepare_effects()[0],
                    welcome,
                    &mut clock
                )
                .await
                .err(),
            Some(Error::Authority)
        );
        assert_eq!(
            wrong_slot
                .join_fork(
                    &mut a.port(),
                    &prepare().prepare_effects()[0],
                    welcome,
                    &mut clock
                )
                .await
                .err(),
            Some(Error::Scope)
        );
        assert_eq!(
            bp.threads()
                .join_direct(
                    &mut b.port(),
                    &mut Grant::pair("m0", "m1", SLOT),
                    "m0",
                    welcome
                )
                .await
                .err(),
            Some(Error::Scope)
        );
        assert_eq!(group_state.revision(), 1);
        let initial = prepare();
        let effect = initial.prepare_effects();
        assert_eq!(
            joined
                .threads()
                .create_fork(&mut a.port(), &effect[0], &packages, &mut clock)
                .await
                .err(),
            Some(Error::State)
        );
        assert_eq!(
            joined
                .threads()
                .join_fork(&mut a.port(), &effect[0], welcome, &mut clock)
                .await
                .err(),
            Some(Error::State)
        );
        assert_eq!(
            joined
                .threads()
                .update_fork(&mut a.port(), &effect[0], &mut clock)
                .await
                .err(),
            Some(Error::Authority)
        );
        let mut regressed = Time::default();
        regressed.0.set(999);
        assert_eq!(
            joined
                .threads()
                .update_fork(&mut a.port(), &effect[0], &mut regressed)
                .await
                .err(),
            Some(Error::Clock)
        );
        let contacts = ctcs::Contacts::load(a.binding.clone(), &astore).unwrap();
        for invalid in [vec![], vec![0; 1024 * 1024 / 2 + 1]] {
            assert_eq!(
                joined
                    .threads()
                    .send_group(&mut a.port(), &contacts, &source, &mut clock, &invalid)
                    .await
                    .err(),
                Some(Error::Limit)
            );
        }
        let mut corrupted = group_support::SignedPolicy::new(&policy);
        corrupted.corrupt();
        assert_eq!(
            joined
                .threads()
                .send_group(
                    &mut a.port(),
                    &contacts,
                    &corrupted,
                    &mut clock,
                    b"forged policy"
                )
                .await
                .err(),
            Some(Error::Authority)
        );
        let mut changed = policy.clone();
        changed.epoch += 1;
        assert_eq!(
            joined
                .threads()
                .send_group(
                    &mut a.port(),
                    &contacts,
                    &group_support::SignedPolicy::new(&changed),
                    &mut clock,
                    b"new epoch"
                )
                .await
                .err(),
            Some(Error::Authority)
        );
        let mut changed = policy.clone();
        changed.bands[0].burst += 1;
        assert_eq!(
            joined
                .threads()
                .send_group(
                    &mut a.port(),
                    &contacts,
                    &group_support::SignedPolicy::new(&changed),
                    &mut clock,
                    b"changed band"
                )
                .await
                .err(),
            Some(Error::Authority)
        );
        let stored: cgrp::Snapshot =
            postcard::from_bytes(astore.read("cgrp", b"snapshot.v1").unwrap().unwrap()).unwrap();
        assert_eq!(stored.revision(), 1);
        let parent = joined
            .threads()
            .parent_evidence(&mut a.port(), &astore, &source, &mut clock)
            .await
            .unwrap();
        assert_eq!(
            cgrp::GroupState::decode(&parent.state).unwrap(),
            group_state.group_state(&SLOT).unwrap()
        );
        assert!(!parent.group_info.is_empty());
        assert!(!parent.ratchet_tree.is_empty());
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
                (&source, &group_support::TestAuthority),
                &mut clock,
            )
            .await
            .unwrap();
        let before_newcomer = cstore.version().unwrap();
        assert!(
            cp.threads()
                .verify_parent_evidence(&mut c.port(), &cstore, &parent, &source, &mut clock,)
                .await
                .is_err()
        );
        assert_eq!(cstore.version().unwrap(), before_newcomer);
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
            (&source, &group_support::TestAuthority),
            &mut clock,
        )
        .await
        .unwrap();
        let contacts = |member: &str, store: &Store<Memory>| {
            ctcs::Contacts::load(Binding::new("alpha", member).unwrap(), store).unwrap()
        };
        let before_parent_check = bstore.version().unwrap();
        let verified_parent = bjoined
            .threads()
            .verify_parent_evidence(&mut b.port(), &bstore, &parent, &source, &mut clock)
            .await
            .unwrap();
        assert_eq!(
            verified_parent.state(),
            &group_state.group_state(&SLOT).unwrap()
        );
        assert_eq!(verified_parent.checked_at(), 1000);
        assert_eq!(bstore.version().unwrap(), before_parent_check);
        let malformed_parent = cthr::ParentEvidence {
            state: parent.state.clone(),
            group_info: vec![0],
            ratchet_tree: parent.ratchet_tree.clone(),
        };
        assert!(
            bjoined
                .threads()
                .verify_parent_evidence(
                    &mut b.port(),
                    &bstore,
                    &malformed_parent,
                    &source,
                    &mut clock,
                )
                .await
                .is_err()
        );
        assert_eq!(bstore.version().unwrap(), before_parent_check);
        let mut tampered_parent = cthr::ParentEvidence {
            state: parent.state.clone(),
            group_info: parent.group_info.clone(),
            ratchet_tree: parent.ratchet_tree.clone(),
        };
        *tampered_parent.group_info.last_mut().unwrap() ^= 1;
        assert!(
            bjoined
                .threads()
                .verify_parent_evidence(
                    &mut b.port(),
                    &bstore,
                    &tampered_parent,
                    &source,
                    &mut clock,
                )
                .await
                .is_err()
        );
        assert_eq!(bstore.version().unwrap(), before_parent_check);
        stage("fork baseline established");
        let mut at = joined.into_threads();
        let mut bt = bjoined.into_threads();
        let proposal = outsider
            .upstream_join_proposal(SLOT, bt.epoch().unwrap())
            .await;
        assert_eq!(
            bt.receive_group(
                &mut b.port(),
                &contacts("m1", &bstore),
                &source,
                &mut clock,
                &proposal
            )
            .await
            .err(),
            Some(Error::Authority)
        );
        for (plaintext, expected) in [
            (Some(vec![]), Error::Limit),
            (Some(vec![7; 1024 * 1024 / 2 + 1]), Error::Limit),
            (None, Error::Unavailable),
        ] {
            let wire = a.upstream_message(&astore, plaintext.as_deref()).await;
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
                Some(expected)
            );
        }
        stage("fork message roundtrips");
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
        assert_eq!(
            accepted
                .threads()
                .history_for(&prepare().prepare_effects()[0], &mut advanced)
                .err(),
            Some(Error::Authority)
        );
        let mut expired_history = Time::default();
        expired_history
            .0
            .set(expanded.prepare_effects()[0].valid_until());
        assert_eq!(
            accepted
                .threads()
                .history_for(&expanded.prepare_effects()[0], &mut expired_history)
                .err(),
            Some(Error::Authority)
        );

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
                (&source, &group_support::TestAuthority),
                &mut advanced,
            )
            .await
            .unwrap();
        assert_eq!(left.threads().history().len(), 21);
        assert!(
            left.threads()
                .parent_evidence(&mut b.port(), &bstore, &source, &mut advanced)
                .await
                .is_err()
        );
        assert_eq!(
            left.threads()
                .receive_group(
                    &mut b.port(),
                    &contacts("m1", &bstore),
                    &source,
                    &mut advanced,
                    &wire
                )
                .await
                .err(),
            Some(Error::Authority)
        );

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
        // Signed block updates stop both preparing a message and publishing a
        // previously prepared message through the shared Store version fence.
        let mut later = Time::default();
        later.0.set(1060);
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let held = at
            .send_group(
                &mut a.port(),
                &contacts("m0", &astore),
                &source,
                &mut later,
                b"held before block",
            )
            .await
            .unwrap();
        a.block("m2", &mut astore, 90).await;
        assert_eq!(
            held.commit_group(&mut a.port(), &mut astore, [91; 32], &source, &mut later)
                .await
                .err(),
            Some(Error::Conflict)
        );
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        assert_eq!(
            at.send_group(
                &mut a.port(),
                &contacts("m0", &astore),
                &source,
                &mut later,
                b"blocked"
            )
            .await
            .err(),
            Some(Error::Authority)
        );
        c.block("m0", &mut cstore, 90).await;
        let ct = Threads::load(c.binding.clone(), SLOT, &cstore).unwrap();
        assert_eq!(
            ct.receive_group(
                &mut c.port(),
                &contacts("m2", &cstore),
                &source,
                &mut later,
                &wire
            )
            .await
            .err(),
            Some(Error::Authority)
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
    }));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn fork_owner_checkpoint_boundaries() {
    stage("checkpoint fixture entered");
    block_on(Box::pin(async {
        let directory = Directory::default();
        let mut a = Fixture::new("m0", 1, directory.clone()).await;
        let mut b = Fixture::new("m1", 2, directory.clone()).await;
        let mut c = Fixture::new("m2", 3, directory).await;
        let (_, mut astore) = a.store().await;
        let (_, mut bstore) = b.store().await;
        let (_, mut cstore) = c.store().await;
        let mut packages = vec![];
        for (fixture, store) in [(&mut b, &mut bstore), (&mut c, &mut cstore)] {
            let threads = Threads::load(fixture.binding.clone(), SLOT, store).unwrap();
            let committed = threads
                .key_package(&mut fixture.port())
                .await
                .unwrap()
                .commit(&mut fixture.port(), &mut Grant::new(), store, [1; 32], &[])
                .await
                .unwrap();
            let Event::KeyPackage { bytes } = &committed.events()[0] else {
                panic!()
            };
            packages.push(bytes.clone());
        }
        let empty = cgrp::Snapshot::empty("alpha".into());
        let source = group_support::SignedPolicy::new(&group_support::policy());
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
        let candidate = Threads::load(a.binding.clone(), SLOT, &astore)
            .unwrap()
            .create_fork(&mut a.port(), &effects[0], &packages, &mut clock)
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
        let groups = prepare();
        let effects = groups.prepare_effects();
        let candidate = Threads::load(b.binding.clone(), SLOT, &bstore)
            .unwrap()
            .join_fork(&mut b.port(), &effects[0], welcome, &mut clock)
            .await
            .unwrap();
        drop(effects);
        candidate
            .commit_groups(
                &mut b.port(),
                groups,
                &mut bstore,
                [2; 32],
                (&source, &group_support::TestAuthority),
                &mut clock,
            )
            .await
            .unwrap();
        stage("checkpoint baseline established");
        Box::pin(fork_checkpoint_refusals(
            &mut a, &mut b, &astore, &bstore, &state, &source,
        ))
        .await;
        stage("checkpoint refusals complete");
    }));
}

// Import actual committed owner records into a separate encrypted Store. This
// exercises restore and cross-owner publication inputs without exposing or
// mutating a private candidate or replacing an owner state machine.
async fn copied_store(fixture: &Fixture, source: &Store<Memory>) -> Store<Memory> {
    let (_, mut target) = fixture.store().await;
    let changes: Vec<_> = [
        ("cthr", SLOT.as_slice()),
        ("cgrp", b"snapshot.v1"),
        ("ctcs", b"journal.v1"),
    ]
    .into_iter()
    .filter_map(|(owner, key)| {
        source
            .read(owner, key)
            .unwrap()
            .map(|value| cwst::Change::Put { owner, key, value })
    })
    .collect();
    target.commit(0, [200; 32], &changes, &[]).await.unwrap();
    target
}

async fn put(store: &mut Store<Memory>, owner: &str, key: &[u8], value: &[u8], op: u8) {
    store
        .commit(
            store.version().unwrap(),
            [op; 32],
            &[cwst::Change::Put { owner, key, value }],
            &[],
        )
        .await
        .unwrap();
}

// Real persistence for Groups-only fixture transitions (opening and expiration
// do not yet have a Threads engine). Enforce predecessor revision, then use the
// actual encrypted Store CAS; never fabricate a prepared or committed effect.
struct GroupsStore<'a>(&'a mut Store<Memory>);
impl cgrp::Persistence for GroupsStore<'_> {
    fn commit<'a>(
        &'a mut self,
        expected: u64,
        snapshot: &'a cgrp::Snapshot,
        _: &'a [cgrp::Effect],
    ) -> cgrp::CommitFuture<'a> {
        Box::pin(async move {
            if !self.0.is_scope(snapshot.community()) {
                return Err(cgrp::Error::Authority);
            }
            let bytes = self
                .0
                .read("cgrp", b"snapshot.v1")
                .map_err(|_| cgrp::Error::Reconcile)?;
            let revision = match bytes {
                Some(bytes) => postcard::from_bytes::<cgrp::Snapshot>(bytes)
                    .map_err(|_| cgrp::Error::Invalid)?
                    .revision(),
                None => 0,
            };
            if revision != expected {
                return Ok(cgrp::Commit::Conflict);
            }
            let bytes = postcard::to_allocvec(snapshot).map_err(|_| cgrp::Error::Invalid)?;
            let operation = *ckmg::hash(&bytes).value();
            self.0
                .commit(
                    self.0.version().map_err(|_| cgrp::Error::Reconcile)?,
                    operation,
                    &[cwst::Change::Put {
                        owner: "cgrp",
                        key: b"snapshot.v1",
                        value: &bytes,
                    }],
                    &[],
                )
                .await
                .map_err(|_| cgrp::Error::Reconcile)?;
            Ok(cgrp::Commit::Applied)
        })
    }
}

async fn malformed_fork_receipt_refuses(
    a: &mut Fixture,
    source: &Store<Memory>,
    receipt: &Receipt,
) {
    let policy = group_support::SignedPolicy::new(&group_support::policy());
    let mut target = copied_store(a, source).await;
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
    let (created, _) = cgrp::prepare(
        &empty,
        &request,
        &policy,
        &group_support::TestAuthority,
        1000,
        10,
    )
    .unwrap()
    .persist(&mut GroupsStore(&mut target), 1000)
    .await
    .unwrap();
    let request = group_support::request(
        &created,
        cgrp::Command::Leave { group: SLOT },
        "m0",
        group_support::members(0, 1),
        false,
        1000,
    );
    let leave = cgrp::prepare(
        &created,
        &request,
        &policy,
        &group_support::TestAuthority,
        1000,
        10,
    )
    .unwrap();
    let effects = leave.prepare_effects();
    let effect = &effects[0];
    let cgrp::Effect::Membership {
        group,
        lineage,
        parents,
        members,
        level,
        policy_epoch,
        revision,
    } = effect.event()
    else {
        panic!()
    };
    let mut snapshot: serde_json::Value =
        serde_json::from_slice(source.read("cthr", &SLOT).unwrap().unwrap()).unwrap();
    // Malformed persisted data combines a real pending direct receipt with a
    // different genuine Groups membership. The public ACK preparation method
    // must not make that hybrid snapshot publishable as a group candidate.
    snapshot["fork"] = serde_json::json!({
        "group": group, "lineage": lineage, "parents": parents, "members": members,
        "roster": [a.binding.member(), receipt.recipient.as_str()], "level": level,
        "band": effect.policy_band(), "policy_epoch": policy_epoch,
        "policy_until": effect.policy_valid_until(), "preparation_until": effect.valid_until(),
        "revision": revision, "last_time": 1000, "pace": {},
    });
    drop(effects);
    leave
        .persist(&mut GroupsStore(&mut target), 1000)
        .await
        .unwrap();
    put(
        &mut target,
        "cthr",
        &SLOT,
        &serde_json::to_vec(&snapshot).unwrap(),
        201,
    )
    .await;
    let threads = Threads::load(a.binding.clone(), SLOT, &target).unwrap();
    let held = threads.acknowledge(&receipt.message, receipt).unwrap();
    let before = target.version().unwrap();
    assert_eq!(
        held.commit_group(
            &mut a.port(),
            &mut target,
            [202; 32],
            &policy,
            &mut Time::default()
        )
        .await
        .err(),
        Some(Error::Authority)
    );
    assert_eq!(target.version().unwrap(), before);
    assert!(target.load_pending().unwrap().is_empty());
}

async fn owner_effect_refusals(
    a: &mut Fixture,
    astore: &Store<Memory>,
    state: &cgrp::Snapshot,
    source: &group_support::SignedPolicy,
) {
    let mut group_store = copied_store(a, astore).await;
    let add = group_support::request(
        state,
        cgrp::Command::Fork {
            id: [18; 32],
            parents: vec![SLOT],
            members: group_support::members(0, 13),
            kind: cgrp::ForkKind::Add,
        },
        "m0",
        group_support::members(0, 13),
        false,
        1000,
    );
    let (expanded, _) = cgrp::prepare(state, &add, source, &group_support::TestAuthority, 1000, 10)
        .unwrap()
        .persist(&mut GroupsStore(&mut group_store), 1000)
        .await
        .unwrap();
    let open = group_support::request(
        &expanded,
        cgrp::Command::Fork {
            id: [19; 32],
            parents: vec![[18; 32]],
            members: group_support::members(0, 13),
            kind: cgrp::ForkKind::Open,
        },
        "m0",
        group_support::members(0, 13),
        true,
        1000,
    );
    let (opened, _) = cgrp::prepare(
        &expanded,
        &open,
        source,
        &group_support::TestAuthority,
        1000,
        10,
    )
    .unwrap()
    .persist(&mut GroupsStore(&mut group_store), 1000)
    .await
    .unwrap();
    let deadline = 1000 + group_support::policy().open_seconds;
    let request = group_support::request(
        &opened,
        cgrp::Command::Tick,
        "m0",
        Default::default(),
        false,
        deadline,
    );
    let expired = cgrp::prepare(
        &opened,
        &request,
        source,
        &group_support::TestAuthority,
        deadline,
        10,
    )
    .unwrap();
    let effects = expired.prepare_effects();
    let nonmembership = effects
        .iter()
        .find(|effect| matches!(effect.event(), cgrp::Effect::ConsentLapsed { .. }))
        .unwrap();
    let threads = Threads::load(a.binding.clone(), SLOT, astore).unwrap();
    let mut clock = Time::default();
    clock.0.set(deadline);
    assert_eq!(
        threads.history_for(nonmembership, &mut clock).err(),
        Some(Error::Authority)
    );
    let (_, store) = a.store().await;
    let empty = Threads::load(a.binding.clone(), SLOT, &store).unwrap();
    assert_eq!(
        empty
            .create_fork(&mut a.port(), nonmembership, &[], &mut clock)
            .await
            .err(),
        Some(Error::Authority)
    );

    let foreign = Fixture::in_community("beta", "m0", 10, Directory::default()).await;
    let (_, mut store) = foreign.store().await;
    let mut checkpoint: serde_json::Value =
        serde_json::from_slice(astore.read("cthr", &SLOT).unwrap().unwrap()).unwrap();
    checkpoint["binding"] = serde_json::to_value(&foreign.binding).unwrap();
    put(
        &mut store,
        "cthr",
        &SLOT,
        &serde_json::to_vec(&checkpoint).unwrap(),
        200,
    )
    .await;
    let foreign_threads = Threads::load(foreign.binding.clone(), SLOT, &store).unwrap();
    let membership = effects
        .iter()
        .find(|effect| matches!(effect.event(), cgrp::Effect::Membership { .. }))
        .unwrap();
    assert_eq!(
        foreign_threads.history_for(membership, &mut clock).err(),
        Some(Error::Authority)
    );
}

async fn fork_checkpoint_refusals(
    a: &mut Fixture,
    b: &mut Fixture,
    astore: &Store<Memory>,
    bstore: &Store<Memory>,
    state: &cgrp::Snapshot,
    source: &group_support::SignedPolicy,
) {
    let mut clock = Time::default();
    let leave_request = group_support::request(
        state,
        cgrp::Command::Leave { group: SLOT },
        "m1",
        group_support::members(1, 2),
        false,
        1000,
    );
    let leave = || {
        cgrp::prepare(
            state,
            &leave_request,
            source,
            &group_support::TestAuthority,
            1000,
            10,
        )
        .unwrap()
    };
    let groups = leave();
    let effects = groups.prepare_effects();
    let original: serde_json::Value =
        serde_json::from_slice(astore.read("cthr", &SLOT).unwrap().unwrap()).unwrap();
    Box::pin(owner_effect_refusals(a, astore, state, source)).await;
    let without_local = ["m0", "m2", "m3"].into_iter().map(str::to_owned).collect();
    let without_local_request = group_support::request(
        state,
        cgrp::Command::Fork {
            id: [18; 32],
            parents: vec![SLOT],
            members: without_local,
            kind: cgrp::ForkKind::Add,
        },
        "m0",
        ["m0", "m2", "m3"].into_iter().map(str::to_owned).collect(),
        false,
        1000,
    );
    let without_local = cgrp::prepare(
        state,
        &without_local_request,
        source,
        &group_support::TestAuthority,
        1000,
        10,
    )
    .unwrap();
    assert_eq!(
        Threads::load(b.binding.clone(), SLOT, bstore)
            .unwrap()
            .history_for(&without_local.prepare_effects()[0], &mut clock)
            .err(),
        Some(Error::Authority)
    );

    // Same event contents do not authorize swapping in another community's
    // genuine prepared owner transaction.
    let foreign_source =
        group_support::SignedPolicy::for_community("beta", &group_support::policy());
    let foreign_empty = cgrp::Snapshot::empty("beta".into());
    let create = group_support::request(
        &foreign_empty,
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
    let foreign = Fixture::in_community("beta", "m0", 10, Directory::default()).await;
    let (_, mut foreign_store) = foreign.store().await;
    let (foreign_state, _) = cgrp::prepare(
        &foreign_empty,
        &create,
        &foreign_source,
        &group_support::TestAuthority,
        1000,
        10,
    )
    .unwrap()
    .persist(&mut GroupsStore(&mut foreign_store), 1000)
    .await
    .unwrap();
    let foreign_leave = group_support::request(
        &foreign_state,
        cgrp::Command::Leave { group: SLOT },
        "m1",
        group_support::members(1, 2),
        false,
        1000,
    );
    let foreign_groups = cgrp::prepare(
        &foreign_state,
        &foreign_leave,
        &foreign_source,
        &group_support::TestAuthority,
        1000,
        10,
    )
    .unwrap();
    let mut target = copied_store(a, astore).await;
    let threads = Threads::load(a.binding.clone(), SLOT, &target).unwrap();
    let held = threads
        .update_fork(&mut a.port(), &effects[0], &mut clock)
        .await
        .unwrap();
    assert_eq!(
        held.commit_groups(
            &mut a.port(),
            foreign_groups,
            &mut target,
            [201; 32],
            (source, &group_support::TestAuthority),
            &mut clock
        )
        .await
        .err(),
        Some(Error::Conflict)
    );

    for (field, value) in [
        ("lineage", serde_json::to_value([18u8; 32]).unwrap()),
        ("parents", serde_json::to_value(vec![[18u8; 32]]).unwrap()),
        ("members", serde_json::json!(["m0", "m1"])),
    ] {
        let mut changed = original.clone();
        changed["fork"][field] = value;
        let mut target = copied_store(a, astore).await;
        put(
            &mut target,
            "cthr",
            &SLOT,
            &serde_json::to_vec(&changed).unwrap(),
            201,
        )
        .await;
        let threads = Threads::load(a.binding.clone(), SLOT, &target).unwrap();
        assert_eq!(
            threads
                .update_fork(&mut a.port(), &effects[0], &mut clock)
                .await
                .err(),
            Some(Error::Authority),
            "corrupt fork {field}"
        );
    }

    let mut target = copied_store(a, astore).await;
    let mut changed = original.clone();
    changed["fork"]["group"] = serde_json::to_value([18u8; 32]).unwrap();
    put(
        &mut target,
        "cthr",
        &SLOT,
        &serde_json::to_vec(&changed).unwrap(),
        201,
    )
    .await;
    let threads = Threads::load(a.binding.clone(), SLOT, &target).unwrap();
    let contacts = ctcs::Contacts::load(a.binding.clone(), &target).unwrap();
    assert_eq!(
        threads
            .send_group(&mut a.port(), &contacts, source, &mut clock, b"wrong group")
            .await
            .err(),
        Some(Error::Scope)
    );

    // The outer checkpoint can name a currently valid replacement device while
    // its real MLS tree still contains the original device. Neither is enough
    // to authorize continuation on the other device's ratchet.
    let old_lineage = a.directory.0.borrow()["m0"].clone();
    let mut replacement = Fixture::new("m0", 8, a.directory.clone()).await;
    let mut changed = original.clone();
    changed["certificate"] = serde_json::to_value(replacement.handle.certificate()).unwrap();
    let mut target = copied_store(a, astore).await;
    put(
        &mut target,
        "cthr",
        &SLOT,
        &serde_json::to_vec(&changed).unwrap(),
        201,
    )
    .await;
    let threads = Threads::load(a.binding.clone(), SLOT, &target).unwrap();
    let contacts = ctcs::Contacts::load(a.binding.clone(), &target).unwrap();
    assert_eq!(
        threads
            .send_group(
                &mut replacement.port(),
                &contacts,
                source,
                &mut clock,
                b"replacement device"
            )
            .await
            .err(),
        Some(Error::Authority)
    );
    a.directory.0.borrow_mut().insert("m0".into(), old_lineage);

    let contacts_wrong_owner = ctcs::Contacts::load(b.binding.clone(), bstore).unwrap();
    assert_eq!(
        Threads::load(a.binding.clone(), SLOT, astore)
            .unwrap()
            .send_group(
                &mut a.port(),
                &contacts_wrong_owner,
                source,
                &mut clock,
                b"wrong owner"
            )
            .await
            .err(),
        Some(Error::Conflict)
    );

    // Groups bytes are untrusted restored data. The actual Groups candidate is
    // valid, but its checkpoint predecessor must also decode and match.
    for (index, bytes) in [
        b"invalid".to_vec(),
        postcard::to_allocvec(&cgrp::Snapshot::empty("alpha".into())).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        let mut target = copied_store(a, astore).await;
        put(&mut target, "cgrp", b"snapshot.v1", &bytes, 201).await;
        let threads = Threads::load(a.binding.clone(), SLOT, &target).unwrap();
        let held = threads
            .update_fork(&mut a.port(), &effects[0], &mut clock)
            .await
            .unwrap();
        let before = target.version().unwrap();
        assert_eq!(
            held.commit_groups(
                &mut a.port(),
                leave(),
                &mut target,
                [202; 32],
                (source, &group_support::TestAuthority),
                &mut clock
            )
            .await
            .err(),
            Some(if index == 0 {
                Error::Storage
            } else {
                Error::Conflict
            })
        );
        assert_eq!(target.version().unwrap(), before);
        assert!(target.load_pending().unwrap().is_empty());
    }

    // A separate real Store writer wins after preparation. The combined Groups
    // and MLS transaction must expose neither history nor an output on CAS loss.
    let backend = Memory::new();
    let cipher = ckmg::passkey::store_cipher(&prf(a.seed), "alpha").unwrap();
    let mut target = Store::create(backend.clone(), &cipher, "alpha")
        .await
        .unwrap();
    let groups_bytes = astore.read("cgrp", b"snapshot.v1").unwrap().unwrap();
    target
        .commit(
            0,
            [200; 32],
            &[
                cwst::Change::Put {
                    owner: "cthr",
                    key: &SLOT,
                    value: astore.read("cthr", &SLOT).unwrap().unwrap(),
                },
                cwst::Change::Put {
                    owner: "cgrp",
                    key: b"snapshot.v1",
                    value: groups_bytes,
                },
            ],
            &[],
        )
        .await
        .unwrap();
    let threads = Threads::load(a.binding.clone(), SLOT, &target).unwrap();
    let held = threads
        .update_fork(&mut a.port(), &effects[0], &mut clock)
        .await
        .unwrap();
    let mut competing = Store::open(backend.clone(), &cipher, "alpha")
        .await
        .unwrap();
    put(&mut competing, "fixture", b"writer", b"won", 201).await;
    assert_eq!(
        held.commit_groups(
            &mut a.port(),
            leave(),
            &mut target,
            [202; 32],
            (source, &group_support::TestAuthority),
            &mut clock
        )
        .await
        .err(),
        Some(Error::Storage)
    );
    let reopened = Store::open(backend, &cipher, "alpha").await.unwrap();
    assert_eq!(
        reopened.read("cgrp", b"snapshot.v1").unwrap().unwrap(),
        groups_bytes
    );
    assert!(reopened.load_pending().unwrap().is_empty());

    // Signed departure changes the active member set while retaining the real
    // MLS roster. A cryptographically valid application from the departed member
    // cannot pass the owner membership check.
    let mut target = copied_store(a, astore).await;
    let threads = Threads::load(a.binding.clone(), SLOT, &target).unwrap();
    let (changed, departed_state, _) = threads
        .update_fork(&mut a.port(), &effects[0], &mut clock)
        .await
        .unwrap()
        .commit_groups(
            &mut a.port(),
            leave(),
            &mut target,
            [201; 32],
            (source, &group_support::TestAuthority),
            &mut clock,
        )
        .await
        .unwrap();
    let wire = b.upstream_message(bstore, Some(b"after departure")).await;
    let contacts = ctcs::Contacts::load(a.binding.clone(), &target).unwrap();
    assert_eq!(
        changed
            .threads()
            .receive_group(&mut a.port(), &contacts, source, &mut clock, &wire)
            .await
            .err(),
        Some(Error::Authority)
    );
    let sent = changed
        .threads()
        .send_group(
            &mut a.port(),
            &contacts,
            source,
            &mut clock,
            b"remaining peers",
        )
        .await
        .unwrap()
        .commit_group(&mut a.port(), &mut target, [202; 32], source, &mut clock)
        .await
        .unwrap();
    assert_eq!(sent.outgoing()[0].recipients(), vec!["m2"]);

    // An independently valid, but inconsistent owner checkpoint cannot authorize
    // the pending message. Community and membership are both rechecked.
    for bytes in [
        postcard::to_allocvec(&cgrp::Snapshot::empty("beta".into())).unwrap(),
        postcard::to_allocvec(&departed_state).unwrap(),
    ] {
        let mut target = copied_store(a, astore).await;
        put(&mut target, "cgrp", b"snapshot.v1", &bytes, 201).await;
        let threads = Threads::load(a.binding.clone(), SLOT, &target).unwrap();
        let contacts = ctcs::Contacts::load(a.binding.clone(), &target).unwrap();
        let held = threads
            .send_group(
                &mut a.port(),
                &contacts,
                source,
                &mut clock,
                b"mismatched owner state",
            )
            .await
            .unwrap();
        let before = target.version().unwrap();
        assert_eq!(
            held.commit_group(&mut a.port(), &mut target, [202; 32], source, &mut clock)
                .await
                .err(),
            Some(Error::Authority)
        );
        assert_eq!(target.version().unwrap(), before);
        assert!(target.load_pending().unwrap().is_empty());
    }

    // Same-version stores from different views cannot bypass the publication
    // check merely because the numeric version happens to agree.
    let mut unblocked = copied_store(a, astore).await;
    put(&mut unblocked, "fixture", b"writer", b"other", 201).await;
    let mut blocked = copied_store(a, astore).await;
    a.block("m2", &mut blocked, 201).await;
    assert_eq!(unblocked.version().unwrap(), blocked.version().unwrap());
    let threads = Threads::load(a.binding.clone(), SLOT, &unblocked).unwrap();
    let contacts = ctcs::Contacts::load(a.binding.clone(), &unblocked).unwrap();
    let held = threads
        .send_group(
            &mut a.port(),
            &contacts,
            source,
            &mut clock,
            b"blocked view",
        )
        .await
        .unwrap();
    assert_eq!(
        held.commit_group(&mut a.port(), &mut blocked, [202; 32], source, &mut clock)
            .await
            .err(),
        Some(Error::Authority)
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_owned_checkpoints_and_locked_keys_fail_without_output() {
    block_on(Box::pin(async {
        let mut a = Fixture::new("alice", 1, Directory::default()).await;
        let (_, mut store) = a.store().await;
        let empty = Threads::load(a.binding.clone(), SLOT, &store).unwrap();
        let package = empty
            .key_package(&mut a.port())
            .await
            .unwrap()
            .commit(&mut a.port(), &mut Grant::new(), &mut store, [1; 32], &[])
            .await
            .unwrap();
        let valid: serde_json::Value =
            serde_json::from_slice(store.read("cthr", &SLOT).unwrap().unwrap()).unwrap();
        let mut variants = vec![(b"invalid".to_vec(), Error::Encoding)];
        let mut binding = valid.clone();
        binding["binding"] = serde_json::to_value(Binding::new("alpha", "bob").unwrap()).unwrap();
        variants.push((serde_json::to_vec(&binding).unwrap(), Error::Scope));
        let mut slot = valid.clone();
        slot["slot"] = serde_json::to_value([18u8; 32]).unwrap();
        variants.push((serde_json::to_vec(&slot).unwrap(), Error::Scope));
        let mut duplicate = valid.clone();
        let item = duplicate["storage"][0].clone();
        duplicate["storage"].as_array_mut().unwrap().push(item);
        variants.push((serde_json::to_vec(&duplicate).unwrap(), Error::Encoding));
        let mut absent = valid.clone();
        absent["group"] = serde_json::json!([1, 2, 3]);
        variants.push((serde_json::to_vec(&absent).unwrap(), Error::State));
        for (index, (bytes, error)) in variants.iter().enumerate() {
            store
                .commit(
                    store.version().unwrap(),
                    [(index + 2) as u8; 32],
                    &[cwst::Change::Put {
                        owner: "cthr",
                        key: &SLOT,
                        value: bytes,
                    }],
                    &[],
                )
                .await
                .unwrap();
            assert_eq!(
                Threads::load(a.binding.clone(), SLOT, &store).err(),
                Some(*error)
            );
        }
        let bytes = serde_json::to_vec(&valid).unwrap();
        store
            .commit(
                store.version().unwrap(),
                [20; 32],
                &[cwst::Change::Put {
                    owner: "cthr",
                    key: &SLOT,
                    value: &bytes,
                }],
                &[],
            )
            .await
            .unwrap();
        let threads = Threads::load(a.binding.clone(), SLOT, &store).unwrap();
        let original_lineage = a.directory.0.borrow()["alice"].clone();
        let mut replacement = Fixture::new("alice", 8, a.directory.clone()).await;
        assert_eq!(
            threads.key_package(&mut replacement.port()).await.err(),
            Some(Error::Authority)
        );
        a.directory
            .0
            .borrow_mut()
            .insert("alice".into(), original_lineage);
        a.keys.lock();
        assert_eq!(
            threads.key_package(&mut a.port()).await.err(),
            Some(Error::Authority)
        );
        assert_eq!(package.into_threads().history().len(), 0);
    }));
}
