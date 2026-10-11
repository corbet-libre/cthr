use super::*;
use ed25519_dalek::{Signer as _, SigningKey};

pub struct Devices(pub ckmg::Lineage);
impl ctcs::DeviceAuthority for Devices {
    async fn current(&mut self, binding: &ckmg::Binding) -> Result<ckmg::Lineage, ctcs::Error> {
        if self.0.binding != *binding {
            return Err(ctcs::Error::Authority);
        }
        self.0.verify().map_err(|_| ctcs::Error::Authority)?;
        Ok(self.0.clone())
    }
}
// Original CTCS external outcome boundary: a narrowly signed fixture answer,
// NOT production Waves release or an accounting acceptance substitute.
pub struct Answer;
fn answer_bytes(binding: &ckmg::Binding, peer: &str) -> Vec<u8> {
    serde_json::to_vec(&("fixture.answer", binding, peer, [50u8; 32])).unwrap()
}
impl ctcs::OutcomeAuthority for Answer {
    async fn answered(
        &mut self,
        binding: &ckmg::Binding,
        peer: &str,
        conversation: &[u8; 32],
        evidence: &[u8],
    ) -> Result<(), ctcs::Error> {
        if conversation != &[50; 32] {
            return Err(ctcs::Error::Authority);
        }
        ckmg::verify_ed25519(
            &SigningKey::from_bytes(&[71; 32]).verifying_key().to_bytes(),
            &answer_bytes(binding, peer),
            &evidence.try_into().map_err(|_| ctcs::Error::Authority)?,
        )
        .map_err(|_| ctcs::Error::Authority)
    }
}
pub async fn store() -> cwst::Store<cwst::backend::Memory> {
    let cipher = ckmg::passkey::store_cipher(&support::prf(42), "alpha").unwrap();
    cwst::Store::create(cwst::backend::Memory::new(), &cipher, "alpha")
        .await
        .unwrap()
}
pub async fn apply(
    recipient: &mut keys::Peer,
    peer: &str,
    store: &mut cwst::Store<cwst::backend::Memory>,
    action: ctcs::Action,
    operation: u8,
) {
    let contacts = ctcs::Contacts::load(recipient.binding.clone(), store).unwrap();
    let event = contacts.request(peer, action).unwrap();
    let handle = recipient.keys.key(ctcs::purpose()).await.unwrap();
    let certificate = handle.certificate().clone();
    let signature = recipient
        .keys
        .sign(&handle, &event.signing_bytes(&certificate).unwrap())
        .await
        .unwrap();
    let mut devices = Devices(recipient.lineage.clone());
    let candidate = contacts
        .prepare(
            event.signed(certificate, signature),
            &mut devices,
            &mut Answer,
        )
        .await
        .unwrap();
    candidate
        .commit(
            (&mut devices, &mut Answer),
            store,
            [operation; 32],
            &[],
            &[],
        )
        .await
        .unwrap();
}
pub async fn establish(
    recipient: &mut keys::Peer,
    peer: &str,
    store: &mut cwst::Store<cwst::backend::Memory>,
) {
    let operation = 51 + u8::try_from(store.version().unwrap()).unwrap();
    apply(
        recipient,
        peer,
        store,
        ctcs::Action::Begin {
            conversation: [50; 32],
        },
        operation,
    )
    .await;
    let evidence = SigningKey::from_bytes(&[71; 32])
        .sign(&answer_bytes(&recipient.binding, peer))
        .to_bytes()
        .to_vec();
    apply(
        recipient,
        peer,
        store,
        ctcs::Action::Answered {
            conversation: [50; 32],
            evidence,
        },
        operation + 1,
    )
    .await;
}
