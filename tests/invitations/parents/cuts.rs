use super::*;

pub(super) async fn producer(
    f: &mut Fixture,
    threads: &cthr::Threads,
    directory: &mut Directory,
    store: &mut cwst::Store<cwst::backend::Memory>,
    source: &group_support::SignedPolicy,
    clock: &mut support::Time,
) {
    // After authenticating and committing the actual parent, this adapter
    // deliberately refuses every nonlocal private lineage lookup. The public
    // invitation owner must use accepted history, not infer peer Vault state.
    directory.local_only = Some(f.sender.binding.clone());
    let sender = f.sender.binding.clone();
    let statement = InvitationStatement::from_committed(
        &InvitationExpected {
            sender: &sender,
            recipient: &f.recipient.binding,
            request: &f.request,
            consent: &f.consent,
            parents: &f.parents,
            challenge: &f.challenge,
            valid_until: UNTIL,
        },
        &f.publication,
        &[threads],
        &mut port(&mut f.sender, directory),
        store,
        source,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(
        statement.signing_bytes(),
        InvitationStatement::new(&f.expected(), &f.sender.certificate, &f.publication)
            .unwrap()
            .signing_bytes()
    );
    for field in 0..3 {
        let evidence = &mut f.parents[0];
        let bytes = match field {
            0 => &mut evidence.state,
            1 => &mut evidence.group_info,
            _ => &mut evidence.ratchet_tree,
        };
        let original = bytes[0];
        bytes[0] ^= 1;
        let result = InvitationStatement::from_committed(
            &InvitationExpected {
                sender: &sender,
                recipient: &f.recipient.binding,
                request: &f.request,
                consent: &f.consent,
                parents: &f.parents,
                challenge: &f.challenge,
                valid_until: UNTIL,
            },
            &f.publication,
            &[threads],
            &mut port(&mut f.sender, directory),
            store,
            source,
            clock,
        )
        .await;
        assert!(result.is_err());
        let evidence = &mut f.parents[0];
        let bytes = match field {
            0 => &mut evidence.state,
            1 => &mut evidence.group_info,
            _ => &mut evidence.ratchet_tree,
        };
        bytes[0] = original;
    }
}

pub(super) async fn deleted(f: &mut Fixture, setup: &mut Setup) {
    let sender = f.sender.binding.clone();
    let prior = setup.store.version().unwrap();
    setup
        .store
        .commit(
            prior,
            [95; 32],
            &[cwst::Change::Delete {
                owner: "cthr",
                key: &[81; 32],
            }],
            &[],
        )
        .await
        .unwrap();
    let mut clock = f.sender.time.clone();
    let result = InvitationStatement::from_committed(
        &InvitationExpected {
            sender: &sender,
            recipient: &f.recipient.binding,
            request: &f.request,
            consent: &f.consent,
            parents: &f.parents,
            challenge: &f.challenge,
            valid_until: UNTIL,
        },
        &f.publication,
        &[&setup.threads],
        &mut port(&mut f.sender, &mut setup.directory),
        &setup.store,
        &setup.source,
        &mut clock,
    )
    .await;
    assert!(matches!(result, Err(cthr::Error::Conflict)));
}
