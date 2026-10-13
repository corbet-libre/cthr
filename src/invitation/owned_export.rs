//! Authenticate an invitation export against accepted local history. Other
//! roster certificates are history here, not fresh private peer authority.
use crate::*;
use openmls::group::PublicGroup;
use std::collections::BTreeMap;

impl Threads {
    pub(super) async fn verify_invitation_export<B: Backend>(
        &self,
        keys: &mut impl Custody,
        store: &Store<B>,
        evidence: &ParentEvidence,
        source: &impl cgrp::PolicySource,
        clock: &mut impl ckmg::Clock,
    ) -> Result<u64> {
        bounded_wire(&evidence.group_info)?;
        bounded_wire(&evidence.ratchet_tree)?;
        self.invitation_checkpoint(store)?;
        let started = clock.now().map_err(|_| Error::Clock)?;
        // Only the genuine LOCAL original Keys authority is requested. There
        // is no peer Vault lookup and no fabricated remote Lineage.
        let local = self.local(keys).await?;
        let state = cgrp::GroupState::decode(&evidence.state).map_err(encoding_error)?;
        let expected = cgrp::Snapshot::load(local.binding.community(), store)
            .map_err(storage_error)?
            .group_state(&self.snapshot.slot)
            .map_err(authority_error)?;
        let spec = self.snapshot.fork.as_ref().ok_or(Error::State)?;
        if state != expected || !spec.matches_state(&state) {
            return Err(Error::Authority);
        }
        let working = self.working()?;
        let accepted = self.group(&working)?;
        group_context::verify(&accepted, &state)?;
        let info = match parse(&evidence.group_info)?.extract() {
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
            info,
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
        let original = accepted_roster(accepted.members(), local.binding.community())?;
        let received = accepted_roster(imported.members(), local.binding.community())?;
        if received != original
            || original.get(local.binding.member()) != Some(&local)
            || original.keys().cloned().collect::<BTreeSet<_>>() != *state.members()
        {
            return Err(Error::Authority);
        }
        // Retain original own-handle checking through its final synchronous
        // callback. It exports no signature or new accepted state here.
        keys.use_signer(|signer| check_signer(&signer, &local))
            .await?;
        self.invitation_checkpoint(store)?;
        let contacts =
            ctcs::Contacts::load(local.binding.clone(), store).map_err(authority_error)?;
        self.contacts(&contacts)?;
        let now = clock.now().map_err(|_| Error::Clock)?;
        if now < started {
            return Err(Error::Clock);
        }
        spec.current(&local.binding, source, now)?;
        Ok(now)
    }

    /// Repeat only exact original row comparisons; no MLS work or owner await.
    pub(super) fn current_invitation_parent<B: Backend>(
        &self,
        store: &Store<B>,
        evidence: &ParentEvidence,
    ) -> Result<()> {
        self.invitation_checkpoint(store)?;
        let state = cgrp::GroupState::decode(&evidence.state).map_err(encoding_error)?;
        let current = cgrp::Snapshot::load(self.snapshot.binding.community(), store)
            .map_err(storage_error)?
            .group_state(&self.snapshot.slot)
            .map_err(authority_error)?;
        if current != state {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    fn invitation_checkpoint<B: Backend>(&self, store: &Store<B>) -> Result<()> {
        store.version().map_err(storage_error)?;
        if !store.is_scope(self.snapshot.binding.community())
            || store
                .read(OWNER, &self.snapshot.slot)
                .map_err(storage_error)?
                != self.base.as_ref().map(|bytes| bytes.as_slice())
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

fn accepted_roster(
    members: impl Iterator<Item = Member>,
    community: &str,
) -> Result<BTreeMap<String, KeyCertificate>> {
    let mut roster = BTreeMap::new();
    for member in members {
        let certificate = decode_credential(&member.credential, &member.signature_key)?;
        if certificate.binding.community() != community
            || roster
                .insert(certificate.binding.member().into(), certificate)
                .is_some()
        {
            return Err(Error::Authority);
        }
    }
    Ok(roster)
}
