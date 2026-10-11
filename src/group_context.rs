//! Original Groups metadata in maintained MLS authenticated context.
use super::*;
use openmls::extensions::UnknownExtension;
use openmls::group::PublicGroup;

// Private use in the MLS Extension Types registry (0xF000..=0xFFFF).
// No public registry allocation is claimed. Payload v1 = u16 version || hash.
pub(super) const GROUP_STATE_EXTENSION: u16 = 0xF701;

pub(super) fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::Unknown(GROUP_STATE_EXTENSION)]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

fn payload(state: &cgrp::GroupState) -> Result<Vec<u8>> {
    let mut bytes = 1u16.to_be_bytes().to_vec();
    bytes.extend_from_slice(&state.commitment().map_err(authority_error)?);
    Ok(bytes)
}

pub(super) fn extensions(state: &cgrp::GroupState) -> Result<Extensions<GroupContext>> {
    Extensions::try_from(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(GROUP_STATE_EXTENSION)],
            &[],
            &[CredentialType::Basic],
        )),
        Extension::Unknown(GROUP_STATE_EXTENSION, UnknownExtension(payload(state)?)),
    ])
    .map_err(encoding_error)
}

pub(super) fn config(state: &cgrp::GroupState) -> Result<MlsGroupCreateConfig> {
    Ok(MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .capabilities(capabilities())
        .with_group_context_extensions(extensions(state)?)
        .build())
}

pub(super) fn verify(group: &MlsGroup, state: &cgrp::GroupState) -> Result<()> {
    let expected = payload(state)?;
    if group.group_id().as_slice() != state.id()
        || group
            .extensions()
            .unknown(GROUP_STATE_EXTENSION)
            .is_none_or(|extension| extension.0 != expected)
        || group
            .extensions()
            .required_capabilities()
            .is_none_or(|required| {
                !required
                    .extension_types()
                    .contains(&ExtensionType::Unknown(GROUP_STATE_EXTENSION))
            })
    {
        return Err(Error::Authority);
    }
    // OpenMLS rejects duplicate extension types while parsing Extensions. Exact
    // payload equality rejects missing, truncated and unsupported versions.
    Ok(())
}

/// Public MLS evidence and its canonical application state. This serializable
/// transport value is NOT an invitation, freshness assertion or capability.
#[derive(Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParentEvidence {
    pub state: Vec<u8>,
    pub group_info: Vec<u8>,
    pub ratchet_tree: Vec<u8>,
}

/// Exact parent authenticated against this member's committed MLS checkpoint.
/// No deserializer or public constructor; it cannot authorize a newcomer import.
pub struct VerifiedParent {
    state: cgrp::GroupState,
    checked_at: u64,
}

impl VerifiedParent {
    pub fn state(&self) -> &cgrp::GroupState {
        &self.state
    }
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
}

impl Threads {
    /// Existing-member verification uses the exact accepted MLS context as its
    /// independent anchor. Maintained PublicGroup import writes only to a fresh
    /// private provider, which is discarded; accepted device storage is untouched.
    /// A newcomer without that checkpoint is refused, never bootstrapped from
    /// the import body's own claimed hash or signing key.
    pub async fn verify_parent_evidence<B: Backend>(
        &self,
        keys: &mut impl Custody,
        store: &Store<B>,
        evidence: &ParentEvidence,
        source: &impl cgrp::PolicySource,
        clock: &mut impl ckmg::Clock,
    ) -> Result<VerifiedParent> {
        bounded_wire(&evidence.group_info)?;
        bounded_wire(&evidence.ratchet_tree)?;
        let state = cgrp::GroupState::decode(&evidence.state).map_err(encoding_error)?;
        let local = self.local(keys).await?;
        let expected = cgrp::Snapshot::load(local.binding.community(), store)
            .map_err(storage_error)?
            .group_state(&self.snapshot.slot)
            .map_err(authority_error)?;
        if state != expected {
            return Err(Error::Authority);
        }
        let spec = self.snapshot.fork.as_ref().ok_or(Error::State)?;
        if !spec.matches_state(&state) {
            return Err(Error::Authority);
        }
        let working = self.working()?;
        let accepted = self.group(&working)?;
        verify(&accepted, &state)?;
        let group_info = match parse(&evidence.group_info)?.extract() {
            MlsMessageBodyIn::GroupInfo(info) => info,
            _ => return Err(Error::Encoding),
        };
        let tree =
            RatchetTreeIn::tls_deserialize_exact(&evidence.ratchet_tree).map_err(encoding_error)?;
        let isolated = OpenMlsRustCrypto::default();
        let (imported, _) = PublicGroup::from_external(
            isolated.crypto(),
            isolated.storage(),
            tree,
            group_info,
            ProposalStore::new(),
        )
        .map_err(crypto_error)?;
        if imported
            .group_context()
            .tls_serialize_detached()
            .map_err(encoding_error)?
            != accepted
                .public_group()
                .group_context()
                .tls_serialize_detached()
                .map_err(encoding_error)?
        {
            return Err(Error::Authority);
        }
        let mut members = BTreeSet::new();
        for member in imported.members() {
            let certificate = decode_credential(&member.credential, &member.signature_key)?;
            if certificate.binding.community() != local.binding.community()
                || !members.insert(certificate.binding.member().to_owned())
                || (certificate.binding == local.binding && certificate != local)
            {
                return Err(Error::Authority);
            }
            keys.verify(&certificate).await?;
        }
        if &members != state.members() {
            return Err(Error::Authority);
        }
        let checked_at = clock.now().map_err(|_| Error::Clock)?;
        spec.current(&local.binding, source, checked_at)?;
        let contacts = ctcs::Contacts::load(local.binding, store).map_err(authority_error)?;
        self.contacts(&contacts)?;
        Ok(VerifiedParent { state, checked_at })
    }

    /// Export only a committed parent whose actual MLS roster and context match
    /// the current canonical Groups record. A metadata-only departure cannot be
    /// exported as a new authenticated parent. Import still needs an independent
    /// current invitation or exact locally committed parent anchor.
    pub async fn parent_evidence<B: Backend>(
        &self,
        keys: &mut impl Custody,
        store: &Store<B>,
        source: &impl cgrp::PolicySource,
        clock: &mut impl ckmg::Clock,
    ) -> Result<ParentEvidence> {
        let local = self.local(keys).await?;
        let groups =
            cgrp::Snapshot::load(local.binding.community(), store).map_err(storage_error)?;
        let state = groups
            .group_state(&self.snapshot.slot)
            .map_err(authority_error)?;
        let spec = self.snapshot.fork.as_ref().ok_or(Error::State)?;
        let working = self.working()?;
        let group = self.group(&working)?;
        verify(&group, &state)?;
        if !spec.matches_state(&state) {
            return Err(Error::Authority);
        }
        self.fork_roster(keys, &group, &local, spec).await?;
        let group_info = keys
            .use_signer(|signer| {
                check_signer(&signer, &local)?;
                group
                    .export_group_info(working.0.crypto(), &ScopedSigner(signer), true)
                    .map_err(crypto_error)?
                    .tls_serialize_detached()
                    .map_err(encoding_error)
            })
            .await?;
        spec.current(
            &local.binding,
            source,
            clock.now().map_err(|_| Error::Clock)?,
        )?;
        let contacts =
            ctcs::Contacts::load(local.binding.clone(), store).map_err(authority_error)?;
        self.contacts(&contacts)?;
        let evidence = ParentEvidence {
            state: state.canonical_bytes().map_err(encoding_error)?,
            group_info,
            ratchet_tree: group
                .export_ratchet_tree()
                .tls_serialize_detached()
                .map_err(encoding_error)?,
        };
        bounded_wire(&evidence.group_info)?;
        bounded_wire(&evidence.ratchet_tree)?;
        Ok(evidence)
    }
}
