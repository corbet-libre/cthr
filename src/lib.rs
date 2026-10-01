//! OpenMLS candidate/checkpoint engine. No output exists before durable commit.
mod fork;
pub mod keys;
use ckmg::{Binding, KeyCertificate, Purpose, Scope};
use cwst::{Change, Output, Store, backend::Backend};
use keys::{Custody, ScopedSigner};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use zeroize::{Zeroize, Zeroizing};

const OWNER: &str = "cthr";
const MAX_WIRE: usize = 1024 * 1024;
const MAX_CHECKPOINT: usize = 8 * MAX_WIRE;
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum Error {
    Encoding,
    Limit,
    Scope,
    Authority,
    Unavailable,
    State,
    Crypto,
    Storage,
    Conflict,
    Clock,
    Pace,
}

pub fn purpose() -> Purpose {
    Purpose::new(Scope::Device, "cthr.mls", 1).expect("static purpose")
}

/// Authorization belongs to Waves/Contacts and the door's verified device context.
/// Implementations must require current owner evidence for this exact operation.
/// Missing proofs or first-contact release evidence return Unavailable.
#[allow(async_fn_in_trait)]
pub trait DirectAuthority {
    async fn authorize(
        &mut self,
        binding: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        operation: Operation,
    ) -> Result<()>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Establish,
    Send,
    Receive,
}
pub struct Unavailable;
impl DirectAuthority for Unavailable {
    async fn authorize(&mut self, _: &Binding, _: &str, _: &[u8; 32], _: Operation) -> Result<()> {
        Err(Error::Unavailable)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u8,
    binding: Binding,
    slot: [u8; 32],
    certificate: Option<KeyCertificate>,
    peer: Option<String>,
    group: Option<Vec<u8>>,
    storage: Vec<(Vec<u8>, Vec<u8>)>,
    accepted: Vec<Message>,
    pending: Vec<Message>,
    #[serde(default)]
    fork: Option<fork::Fork>,
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        for (_, value) in &mut self.storage {
            value.zeroize();
        }
        for message in self.accepted.iter_mut().chain(self.pending.iter_mut()) {
            message.bytes.zeroize();
        }
    }
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub id: [u8; 32],
    pub sender: String,
    pub epoch: u64,
    pub bytes: Vec<u8>,
    #[serde(default)]
    pub accepted_at: u64,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    KeyPackage {
        bytes: Vec<u8>,
    },
    Invitation {
        commit: Vec<u8>,
        welcome: Vec<u8>,
    },
    Ciphertext {
        id: [u8; 32],
        epoch: u64,
        bytes: Vec<u8>,
    },
    Received {
        message: Message,
    },
    Joined,
    MembershipChanged,
    Accepted {
        message: Message,
    },
}

pub struct Threads {
    snapshot: Snapshot,
    expected: u64,
    base: Option<Zeroizing<Vec<u8>>>,
}
pub struct Candidate {
    snapshot: Snapshot,
    expected: u64,
    base: Option<Zeroizing<Vec<u8>>>,
    events: Vec<Event>,
    required_group: bool,
}
/// A sealed description for a sibling checkpoint participant. It carries no
/// plaintext or ciphertext and grants no permission to transmit or acknowledge.
pub struct PreparedMessage<'a> {
    candidate: &'a Candidate,
    message: &'a Message,
    receiving: bool,
}
impl PreparedMessage<'_> {
    pub fn binding(&self) -> &Binding {
        &self.candidate.snapshot.binding
    }
    pub fn conversation(&self) -> &[u8; 32] {
        &self.candidate.snapshot.slot
    }
    pub fn id(&self) -> &[u8; 32] {
        &self.message.id
    }
    pub fn epoch(&self) -> u64 {
        self.message.epoch
    }
    pub fn sender(&self) -> &str {
        &self.message.sender
    }
    pub fn peer(&self) -> Option<&str> {
        self.candidate.snapshot.peer.as_deref()
    }
    pub fn receiving(&self) -> bool {
        self.receiving
    }
    pub fn checkpoint_version(&self) -> u64 {
        self.candidate.expected
    }
    /// The public credential from this candidate's actual authenticated MLS tree.
    pub fn peer_certificate(&self) -> Option<KeyCertificate> {
        let peer = self.peer()?;
        let view = Threads {
            snapshot: self.candidate.snapshot.clone(),
            expected: self.candidate.expected,
            base: self.candidate.base.clone(),
        };
        let working = view
            .working()
            .expect("private candidate has validated provider state");
        let group = view
            .group(&working)
            .expect("message candidate has a validated MLS group");
        Some(
            group
                .members()
                .map(|member| {
                    decode_credential(&member.credential, &member.signature_key)
                        .expect("candidate roster was authenticated")
                })
                .find(|cert| cert.binding.member() == peer)
                .expect("direct candidate has exactly its verified peer"),
        )
    }
}
impl Candidate {
    pub fn prepared_message(&self) -> Option<PreparedMessage<'_>> {
        match self.events.first()? {
            Event::Ciphertext { id, .. } => {
                self.snapshot
                    .pending
                    .iter()
                    .find(|m| &m.id == id)
                    .map(|message| PreparedMessage {
                        candidate: self,
                        message,
                        receiving: false,
                    })
            }
            Event::Received { message } => Some(PreparedMessage {
                candidate: self,
                message,
                receiving: true,
            }),
            _ => None,
        }
    }
}
/// Durable output capabilities cannot be constructed from decoded DTOs.
pub struct Outgoing<'a> {
    committed: &'a Committed,
    id: &'a [u8; 32],
    epoch: u64,
    bytes: &'a [u8],
}
impl Outgoing<'_> {
    pub fn binding(&self) -> &Binding {
        &self.committed.threads.snapshot.binding
    }
    pub fn peer(&self) -> Option<&str> {
        self.committed.threads.snapshot.peer.as_deref()
    }
    pub fn recipients(&self) -> Vec<&str> {
        let snapshot = &self.committed.threads.snapshot;
        match &snapshot.fork {
            Some(fork) => fork.recipients(snapshot.binding.member()),
            None => snapshot.peer.as_deref().into_iter().collect(),
        }
    }
    pub fn conversation(&self) -> &[u8; 32] {
        &self.committed.threads.snapshot.slot
    }
    pub fn id(&self) -> &[u8; 32] {
        self.id
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
}
pub struct Accepted<'a> {
    committed: &'a Committed,
    message: &'a Message,
}
impl Accepted<'_> {
    pub fn binding(&self) -> &Binding {
        &self.committed.threads.snapshot.binding
    }
    pub fn conversation(&self) -> &[u8; 32] {
        &self.committed.threads.snapshot.slot
    }
    pub fn message(&self) -> &Message {
        self.message
    }
}
/// Delivery implements this only for a verified, durably accepted recipient ACK.
/// ACK acceptance never supplies a Waves Answer or another domain outcome.
pub trait Acceptance {
    fn verify(
        &self,
        binding: &Binding,
        peer: &str,
        conversation: &[u8; 32],
        message: &[u8; 32],
        epoch: u64,
    ) -> Result<()>;
}
pub struct Committed {
    threads: Threads,
    events: Vec<Event>,
}
impl Committed {
    pub fn threads(&self) -> &Threads {
        &self.threads
    }
    pub fn events(&self) -> &[Event] {
        &self.events
    }
    pub fn into_threads(self) -> Threads {
        self.threads
    }
    pub fn outgoing(&self) -> Vec<Outgoing<'_>> {
        self.events
            .iter()
            .filter_map(|event| match event {
                Event::Ciphertext { id, epoch, bytes } => Some(Outgoing {
                    committed: self,
                    id,
                    epoch: *epoch,
                    bytes,
                }),
                _ => None,
            })
            .collect()
    }
    pub fn accepted(&self) -> Vec<Accepted<'_>> {
        self.events
            .iter()
            .filter_map(|event| match event {
                Event::Received { message } => Some(Accepted {
                    committed: self,
                    message,
                }),
                _ => None,
            })
            .collect()
    }
}
struct Working(OpenMlsRustCrypto);
impl Drop for Working {
    fn drop(&mut self) {
        if let Ok(mut storage) = self.0.storage().values.write() {
            for value in storage.values_mut() {
                value.zeroize();
            }
            storage.clear();
        }
    }
}
impl Threads {
    pub fn load<B: Backend>(binding: Binding, slot: [u8; 32], store: &Store<B>) -> Result<Self> {
        if slot == [0; 32] || !store.is_scope(binding.community()) {
            return Err(Error::Scope);
        }
        let expected = store.version().map_err(|_| Error::Storage)?;
        let base = store
            .read(OWNER, &slot)
            .map_err(|_| Error::Storage)?
            .map(|bytes| Zeroizing::new(bytes.to_vec()));
        let snapshot = if let Some(bytes) = &base {
            if bytes.len() > MAX_CHECKPOINT {
                return Err(Error::Limit);
            }
            let snapshot: Snapshot = serde_json::from_slice(bytes).map_err(|_| Error::Encoding)?;
            if snapshot.version != 1 || snapshot.binding != binding || snapshot.slot != slot {
                return Err(Error::Scope);
            }
            snapshot
        } else {
            Snapshot {
                version: 1,
                binding,
                slot,
                certificate: None,
                peer: None,
                group: None,
                storage: vec![],
                accepted: vec![],
                pending: vec![],
                fork: None,
            }
        };
        let value = Self {
            snapshot,
            expected,
            base,
        };
        let working = value.working()?;
        if value.snapshot.group.is_some() {
            value.group(&working)?;
        }
        Ok(value)
    }
    pub fn history(&self) -> &[Message] {
        &self.snapshot.accepted
    }
    pub fn epoch(&self) -> Result<u64> {
        let working = self.working()?;
        Ok(self.group(&working)?.epoch().as_u64())
    }
    fn working(&self) -> Result<Working> {
        let working = Working(OpenMlsRustCrypto::default());
        {
            let mut storage = working
                .0
                .storage()
                .values
                .write()
                .map_err(|_| Error::Storage)?;
            for (key, value) in &self.snapshot.storage {
                if storage.insert(key.clone(), value.clone()).is_some() {
                    return Err(Error::Encoding);
                }
            }
        }
        Ok(working)
    }
    fn group(&self, working: &Working) -> Result<MlsGroup> {
        let id = self.snapshot.group.as_ref().ok_or(Error::State)?;
        MlsGroup::load(working.0.storage(), &GroupId::from_slice(id))
            .map_err(|_| Error::Crypto)?
            .ok_or(Error::State)
    }
    async fn local(&self, keys: &mut impl Custody) -> Result<KeyCertificate> {
        let cert = keys.certificate().clone();
        if cert.binding != self.snapshot.binding || cert.purpose != purpose() {
            return Err(Error::Scope);
        }
        if let Some(stored) = &self.snapshot.certificate
            && stored != &cert
        {
            return Err(Error::Authority);
        }
        keys.verify(&cert).await?;
        Ok(cert)
    }
    fn candidate(
        &self,
        working: &Working,
        group: Option<&MlsGroup>,
        cert: KeyCertificate,
        peer: Option<String>,
        events: Vec<Event>,
    ) -> Result<Candidate> {
        let mut snapshot = self.snapshot.clone();
        snapshot.certificate = Some(cert);
        snapshot.peer = peer;
        snapshot.group = group.map(|g| g.group_id().as_slice().to_vec());
        snapshot.storage = working
            .0
            .storage()
            .values
            .read()
            .map_err(|_| Error::Storage)?
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Ok(Candidate {
            snapshot,
            expected: self.expected,
            base: self.base.clone(),
            events,
            required_group: false,
        })
    }
    pub async fn key_package(&self, keys: &mut impl Custody) -> Result<Candidate> {
        if self.snapshot.group.is_some() {
            return Err(Error::State);
        }
        let cert = self.local(keys).await?;
        let credential = credential(&cert)?;
        let working = self.working()?;
        let package = keys
            .use_signer(|signer| {
                check_signer(&signer, &cert)?;
                KeyPackage::builder()
                    .build(SUITE, &working.0, &ScopedSigner(signer), credential)
                    .map_err(|_| Error::Crypto)?
                    .key_package()
                    .tls_serialize_detached()
                    .map_err(|_| Error::Encoding)
            })
            .await?;
        self.candidate(
            &working,
            None,
            cert,
            None,
            vec![Event::KeyPackage { bytes: package }],
        )
    }
    pub async fn create_direct(
        &self,
        keys: &mut impl Custody,
        authority: &mut impl DirectAuthority,
        peer: &str,
        package: &[u8],
    ) -> Result<Candidate> {
        if self.snapshot.group.is_some() {
            return Err(Error::State);
        }
        let cert = self.local(keys).await?;
        check_peer(&cert.binding, peer)?;
        authority
            .authorize(
                &cert.binding,
                peer,
                &self.snapshot.slot,
                Operation::Establish,
            )
            .await?;
        bounded_wire(package)?;
        let working = self.working()?;
        let package = KeyPackageIn::tls_deserialize_exact(package)
            .map_err(|_| Error::Encoding)?
            .validate(working.0.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| Error::Crypto)?;
        let peer_cert = decode_credential(
            package.leaf_node().credential(),
            package.leaf_node().signature_key().as_slice(),
        )?;
        exact_peer(&cert.binding, peer, &peer_cert)?;
        keys.verify(&peer_cert).await?;
        let credential = credential(&cert)?;
        let (group, commit, welcome) = keys
            .use_signer(|signer| {
                check_signer(&signer, &cert)?;
                let signer = ScopedSigner(signer);
                let mut group = MlsGroup::new_with_group_id(
                    &working.0,
                    &signer,
                    &config(),
                    GroupId::from_slice(&self.snapshot.slot),
                    credential,
                )
                .map_err(|_| Error::Crypto)?;
                let (commit, welcome, _) = group
                    .add_members(&working.0, &signer, &[package])
                    .map_err(|_| Error::Crypto)?;
                let commit = commit
                    .tls_serialize_detached()
                    .map_err(|_| Error::Encoding)?;
                let welcome = welcome
                    .tls_serialize_detached()
                    .map_err(|_| Error::Encoding)?;
                group
                    .merge_pending_commit(&working.0)
                    .map_err(|_| Error::Crypto)?;
                Ok((group, commit, welcome))
            })
            .await?;
        self.candidate(
            &working,
            Some(&group),
            cert,
            Some(peer.into()),
            vec![Event::Invitation { commit, welcome }],
        )
    }
    pub async fn join_direct(
        &self,
        keys: &mut impl Custody,
        authority: &mut impl DirectAuthority,
        peer: &str,
        wire: &[u8],
    ) -> Result<Candidate> {
        if self.snapshot.group.is_some() {
            return Err(Error::State);
        }
        let cert = self.local(keys).await?;
        check_peer(&cert.binding, peer)?;
        authority
            .authorize(
                &cert.binding,
                peer,
                &self.snapshot.slot,
                Operation::Establish,
            )
            .await?;
        let welcome = match parse(wire)?.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(Error::Encoding),
        };
        let working = self.working()?;
        let staged =
            StagedWelcome::new_from_welcome(&working.0, config().join_config(), welcome, None)
                .map_err(|_| Error::Crypto)?;
        let sender = staged.welcome_sender().map_err(|_| Error::Crypto)?;
        let sender_cert =
            decode_credential(sender.credential(), sender.signature_key().as_slice())?;
        exact_peer(&cert.binding, peer, &sender_cert)?;
        keys.verify(&sender_cert).await?;
        let group = staged.into_group(&working.0).map_err(|_| Error::Crypto)?;
        self.verify_roster(keys, &group, &cert, peer).await?;
        self.candidate(
            &working,
            Some(&group),
            cert,
            Some(peer.into()),
            vec![Event::Joined],
        )
    }
    async fn verify_roster(
        &self,
        keys: &mut impl Custody,
        group: &MlsGroup,
        local: &KeyCertificate,
        peer: &str,
    ) -> Result<()> {
        if group.group_id().as_slice() != self.snapshot.slot || group.members().count() != 2 {
            return Err(Error::Scope);
        }
        let mut members = BTreeSet::new();
        for member in group.members() {
            let cert = decode_credential(&member.credential, &member.signature_key)?;
            if cert.binding == local.binding {
                if cert != *local {
                    return Err(Error::Authority);
                }
            } else {
                exact_peer(&local.binding, peer, &cert)?;
            }
            keys.verify(&cert).await?;
            members.insert(cert.binding.member().to_owned());
        }
        if members.len() != 2 {
            return Err(Error::Authority);
        }
        Ok(())
    }
    pub async fn send(
        &self,
        keys: &mut impl Custody,
        authority: &mut impl DirectAuthority,
        bytes: &[u8],
    ) -> Result<Candidate> {
        if bytes.is_empty() || bytes.len() > MAX_WIRE / 2 {
            return Err(Error::Limit);
        }
        let cert = self.local(keys).await?;
        let peer = self.snapshot.peer.as_deref().ok_or(Error::State)?;
        authority
            .authorize(&cert.binding, peer, &self.snapshot.slot, Operation::Send)
            .await?;
        let working = self.working()?;
        let mut group = self.group(&working)?;
        self.verify_roster(keys, &group, &cert, peer).await?;
        let epoch = group.epoch().as_u64();
        let wire = keys
            .use_signer(|signer| {
                check_signer(&signer, &cert)?;
                group
                    .create_message(&working.0, &ScopedSigner(signer), bytes)
                    .map_err(|_| Error::Crypto)?
                    .tls_serialize_detached()
                    .map_err(|_| Error::Encoding)
            })
            .await?;
        let id = *ckmg::hash(&wire).value();
        let message = Message {
            id,
            sender: cert.binding.member().into(),
            epoch,
            bytes: bytes.to_vec(),
            accepted_at: 0,
        };
        let mut candidate = self.candidate(
            &working,
            Some(&group),
            cert,
            Some(peer.into()),
            vec![Event::Ciphertext {
                id,
                epoch,
                bytes: wire,
            }],
        )?;
        candidate.snapshot.pending.push(message);
        Ok(candidate)
    }
    pub fn acknowledge(&self, id: &[u8; 32], acceptance: &impl Acceptance) -> Result<Candidate> {
        let peer = self.snapshot.peer.as_deref().ok_or(Error::State)?;
        let index = self
            .snapshot
            .pending
            .iter()
            .position(|message| &message.id == id)
            .ok_or(Error::State)?;
        let message = &self.snapshot.pending[index];
        acceptance.verify(
            &self.snapshot.binding,
            peer,
            &self.snapshot.slot,
            id,
            message.epoch,
        )?;
        let mut snapshot = self.snapshot.clone();
        let message = snapshot.pending.remove(index);
        snapshot.accepted.push(message.clone());
        Ok(Candidate {
            snapshot,
            expected: self.expected,
            base: self.base.clone(),
            events: vec![Event::Accepted { message }],
            required_group: false,
        })
    }
    pub async fn receive(
        &self,
        keys: &mut impl Custody,
        authority: &mut impl DirectAuthority,
        wire: &[u8],
    ) -> Result<Candidate> {
        let cert = self.local(keys).await?;
        let peer = self.snapshot.peer.as_deref().ok_or(Error::State)?;
        authority
            .authorize(&cert.binding, peer, &self.snapshot.slot, Operation::Receive)
            .await?;
        let message = parse(wire)?
            .try_into_protocol_message()
            .map_err(|_| Error::Encoding)?;
        let working = self.working()?;
        let mut group = self.group(&working)?;
        self.verify_roster(keys, &group, &cert, peer).await?;
        let processed = group
            .process_message(&working.0, message)
            .map_err(|_| Error::Crypto)?;
        let sender = match processed.sender() {
            Sender::Member(index) => group.member_at(*index).ok_or(Error::Authority)?,
            _ => return Err(Error::Authority),
        };
        let sender_cert = decode_credential(processed.credential(), &sender.signature_key)?;
        exact_peer(&cert.binding, peer, &sender_cert)?;
        keys.verify(&sender_cert).await?;
        // Direct membership is immutable. Group/room changes require owner decisions.
        let bytes = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
            _ => return Err(Error::Unavailable),
        };
        if bytes.is_empty() || bytes.len() > MAX_WIRE / 2 {
            return Err(Error::Limit);
        }
        let message = Message {
            id: *ckmg::hash(wire).value(),
            sender: peer.into(),
            epoch: group.epoch().as_u64(),
            bytes,
            accepted_at: 0,
        };
        let mut candidate = self.candidate(
            &working,
            Some(&group),
            cert,
            Some(peer.into()),
            vec![Event::Received {
                message: message.clone(),
            }],
        )?;
        candidate.snapshot.accepted.push(message);
        Ok(candidate)
    }
}
impl Candidate {
    pub async fn commit<B: Backend>(
        self,
        keys: &mut impl Custody,
        authority: &mut impl DirectAuthority,
        store: &mut Store<B>,
        operation: [u8; 32],
        companions: &[Change<'_>],
    ) -> Result<Committed> {
        if self.snapshot.fork.is_some() {
            return Err(Error::Authority);
        }
        self.recheck(keys).await?;
        if let Some(peer) = &self.snapshot.peer {
            let action = match self.events.first().expect("candidate always has an event") {
                Event::Invitation { .. } | Event::Joined => Operation::Establish,
                Event::Ciphertext { .. } => Operation::Send,
                _ => Operation::Receive,
            };
            authority
                .authorize(&self.snapshot.binding, peer, &self.snapshot.slot, action)
                .await?;
        }
        self.persist(store, operation, companions).await
    }
    async fn recheck(&self, keys: &mut impl Custody) -> Result<()> {
        let view = Threads {
            snapshot: self.snapshot.clone(),
            expected: self.expected,
            base: self.base.clone(),
        };
        let cert = view.local(keys).await?;
        // Also ask Keys to recheck the local unlocked handle; certificate
        // validity alone does not prove that the local signer remains usable.
        keys.use_signer(|signer| check_signer(&signer, &cert))
            .await?;
        if self.snapshot.group.is_some() {
            let working = view.working()?;
            let group = view.group(&working)?;
            if let Some(spec) = &self.snapshot.fork {
                view.fork_roster(keys, &group, &cert, spec).await?;
            } else {
                view.verify_roster(
                    keys,
                    &group,
                    &cert,
                    self.snapshot.peer.as_deref().ok_or(Error::State)?,
                )
                .await?;
            }
        }
        Ok(())
    }
    async fn persist<B: Backend>(
        self,
        store: &mut Store<B>,
        operation: [u8; 32],
        companions: &[Change<'_>],
    ) -> Result<Committed> {
        if !store.is_scope(self.snapshot.binding.community()) {
            return Err(Error::Scope);
        }
        if store
            .read(OWNER, &self.snapshot.slot)
            .map_err(|_| Error::Storage)?
            != self.base.as_ref().map(|bytes| bytes.as_slice())
        {
            return Err(Error::Conflict);
        }
        let bytes =
            Zeroizing::new(serde_json::to_vec(&self.snapshot).map_err(|_| Error::Encoding)?);
        if bytes.len() > MAX_CHECKPOINT {
            return Err(Error::Limit);
        }
        let mut changes = vec![];
        for c in companions {
            let owner = match c {
                Change::Put { owner, .. } | Change::Delete { owner, .. } => owner,
            };
            if *owner == OWNER {
                return Err(Error::Scope);
            }
            changes.push(match c {
                Change::Put { owner, key, value } => Change::Put { owner, key, value },
                Change::Delete { owner, key } => Change::Delete { owner, key },
            });
        }
        changes.push(Change::Put {
            owner: OWNER,
            key: &self.snapshot.slot,
            value: &bytes,
        });
        let mut outputs = vec![];
        for (index, event) in self.events.iter().enumerate() {
            let bytes = serde_json::to_vec(event).map_err(|_| Error::Encoding)?;
            let id = *ckmg::hash(
                &serde_json::to_vec(&("cthr.output.v1", operation, index, &bytes))
                    .map_err(|_| Error::Encoding)?,
            )
            .value();
            outputs.push(Output { id, bytes });
        }
        let expected = store
            .commit(self.expected, operation, &changes, &outputs)
            .await
            .map_err(|_| Error::Storage)?;
        Ok(Committed {
            threads: Threads {
                snapshot: self.snapshot,
                expected,
                base: Some(bytes),
            },
            events: self.events,
        })
    }
}
fn config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .build()
}
fn credential(cert: &KeyCertificate) -> Result<CredentialWithKey> {
    Ok(CredentialWithKey {
        credential: BasicCredential::new(serde_json::to_vec(cert).map_err(|_| Error::Encoding)?)
            .into(),
        signature_key: cert.key.value().to_vec().into(),
    })
}
fn decode_credential(credential: &Credential, key: &[u8]) -> Result<KeyCertificate> {
    let basic = BasicCredential::try_from(credential.clone()).map_err(|_| Error::Encoding)?;
    if basic.identity().len() > 16384 {
        return Err(Error::Limit);
    }
    let cert: KeyCertificate =
        serde_json::from_slice(basic.identity()).map_err(|_| Error::Encoding)?;
    if cert.key.value().as_slice() != key || cert.purpose != purpose() {
        return Err(Error::Authority);
    }
    Ok(cert)
}
fn check_signer(signer: &ckmg::Ed25519Signer<'_>, cert: &KeyCertificate) -> Result<()> {
    if signer.public_key() != cert.key.value() {
        return Err(Error::Authority);
    }
    Ok(())
}
fn check_peer(binding: &Binding, peer: &str) -> Result<()> {
    Binding::new(binding.community(), peer).map_err(|_| Error::Scope)?;
    if peer == binding.member() {
        return Err(Error::Scope);
    }
    Ok(())
}
fn exact_peer(binding: &Binding, peer: &str, certificate: &KeyCertificate) -> Result<()> {
    if certificate.binding.community() != binding.community()
        || certificate.binding.member() != peer
    {
        return Err(Error::Scope);
    }
    Ok(())
}
fn bounded_wire(wire: &[u8]) -> Result<()> {
    if wire.is_empty() || wire.len() > MAX_WIRE {
        return Err(Error::Limit);
    }
    Ok(())
}
fn parse(wire: &[u8]) -> Result<MlsMessageIn> {
    bounded_wire(wire)?;
    MlsMessageIn::tls_deserialize_exact(wire).map_err(|_| Error::Encoding)
}
