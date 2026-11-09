use super::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn binary_payload_refusals_preserve_ratchet_across_reopen() {
    block_on(async {
        let directory = Directory::default();
        let mut a = Fixture::new("alice", 1, directory.clone()).await;
        let mut b = Fixture::new("bob", 2, directory.clone()).await;
        let (abackend, mut astore) = a.store().await;
        let (bbackend, mut bstore) = b.store().await;
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        let pkg = bt
            .key_package(&mut b.port())
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [1; 32], &[])
            .await
            .unwrap();
        let Event::KeyPackage { bytes: pkg_bytes } = &pkg.events()[0] else {
            panic!()
        };
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        let mut grant = Grant::new();
        let invitation = at
            .create_direct(&mut a.port(), &mut grant, "bob", pkg_bytes)
            .await
            .unwrap()
            .commit(&mut a.port(), &mut Grant::new(), &mut astore, [1; 32], &[])
            .await
            .unwrap();
        let Event::Invitation { welcome, .. } = &invitation.events()[0] else {
            panic!()
        };
        let joined = pkg
            .threads()
            .join_direct(&mut b.port(), &mut grant, "alice", welcome)
            .await
            .unwrap()
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [2; 32], &[])
            .await
            .unwrap();
        assert!(joined.threads().history().is_empty());
        let payload: Vec<u8> = vec![
            0, 255, 0, 128, 1, 254, 0, 195, 169, 240, 159, 140, 141, 0, 72, 0, 253, 7,
        ];
        let sent = invitation
            .threads()
            .send(&mut a.port(), &mut grant, &payload)
            .await
            .unwrap()
            .commit(&mut a.port(), &mut Grant::new(), &mut astore, [2; 32], &[])
            .await
            .unwrap();
        let Event::Ciphertext { bytes: wire, .. } = &sent.events()[0] else {
            panic!()
        };
        let expected_id = *ckmg::hash(wire).value();
        let before = bstore.version().unwrap();
        let truncated = wire[..wire.len() - 1].to_vec();
        assert!(
            joined
                .threads()
                .receive(&mut b.port(), &mut Grant::new(), &truncated)
                .await
                .is_err()
        );
        assert_eq!(bstore.version().unwrap(), before);
        assert!(
            Threads::load(b.binding.clone(), SLOT, &bstore)
                .unwrap()
                .history()
                .is_empty()
        );
        let mut trailing = wire.clone();
        trailing.push(0x00);
        assert!(
            joined
                .threads()
                .receive(&mut b.port(), &mut Grant::new(), &trailing)
                .await
                .is_err()
        );
        assert_eq!(bstore.version().unwrap(), before);
        assert!(
            Threads::load(b.binding.clone(), SLOT, &bstore)
                .unwrap()
                .history()
                .is_empty()
        );
        let bcipher = ckmg::passkey::store_cipher(&prf(2), "alpha").unwrap();
        let bstore = Store::open(bbackend.clone(), &bcipher, "alpha")
            .await
            .unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        assert!(bt.history().is_empty());
        assert_eq!(bstore.version().unwrap(), before);
        {
            let candidate = bt
                .receive(&mut b.port(), &mut Grant::new(), wire)
                .await
                .unwrap();
            assert!(candidate.prepared_message().unwrap().receiving());
            drop(candidate);
        }
        let bcipher = ckmg::passkey::store_cipher(&prf(2), "alpha").unwrap();
        let mut bstore = Store::open(bbackend.clone(), &bcipher, "alpha")
            .await
            .unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        assert!(bt.history().is_empty());
        assert_eq!(bstore.version().unwrap(), before);
        let candidate = bt
            .receive(&mut b.port(), &mut Grant::new(), wire)
            .await
            .unwrap();
        assert_eq!(candidate.prepared_message().unwrap().id(), &expected_id);
        let committed = candidate
            .commit(&mut b.port(), &mut Grant::new(), &mut bstore, [3; 32], &[])
            .await
            .unwrap();
        assert_eq!(committed.threads().history().len(), 1);
        assert_eq!(committed.threads().history()[0].bytes, payload);
        assert_eq!(committed.threads().history()[0].id, expected_id);
        assert_eq!(committed.threads().history()[0].sender, "alice");
        let receipts = committed.accepted();
        assert_eq!(receipts.len(), 1);
        let receipt = Receipt::from_committed(&receipts[0]);
        let id = receipt.message;
        let acknowledged = sent
            .threads()
            .acknowledge(&id, &receipt)
            .unwrap()
            .commit(&mut a.port(), &mut grant, &mut astore, [10; 32], &[])
            .await
            .unwrap();
        assert_eq!(acknowledged.threads().history()[0].bytes, payload);
        let bcipher = ckmg::passkey::store_cipher(&prf(2), "alpha").unwrap();
        let bstore = Store::open(bbackend.clone(), &bcipher, "alpha")
            .await
            .unwrap();
        let bt = Threads::load(b.binding.clone(), SLOT, &bstore).unwrap();
        assert_eq!(bt.history().len(), 1);
        assert_eq!(bt.history()[0].bytes, payload);
        assert_eq!(bt.history()[0].id, expected_id);
        let settled = bstore.version().unwrap();
        assert!(
            bt.receive(&mut b.port(), &mut Grant::new(), wire)
                .await
                .is_err()
        );
        assert_eq!(bstore.version().unwrap(), settled);
        assert_eq!(
            Threads::load(b.binding.clone(), SLOT, &bstore)
                .unwrap()
                .history()
                .len(),
            1
        );
        assert_eq!(
            Threads::load(b.binding.clone(), SLOT, &bstore)
                .unwrap()
                .history()[0]
                .bytes,
            payload
        );
        let acipher = ckmg::passkey::store_cipher(&prf(1), "alpha").unwrap();
        let astore = Store::open(abackend, &acipher, "alpha").await.unwrap();
        let at = Threads::load(a.binding.clone(), SLOT, &astore).unwrap();
        assert_eq!(at.history().len(), 1);
        assert_eq!(at.history()[0].id, expected_id);
        assert_eq!(at.history()[0].bytes, payload);
    });
}
