use super::*;
use crate::support;
use ckmg::{Action, Authority, Authorization, Error, IntentVerifier};

// The original signed test lineage owns these fixtures. It is not production
// passkey G3. Device signatures still require Keys' exact one-use intent and
// final retained-lineage check; no fixture private key leaves Keys.
pub struct Current {
    guard: support::Guard,
    intent: IntentVerifier,
}
impl Current {
    fn current(&self, request: &Authorization<'_>) -> Result<(), Error> {
        let anchors = self.guard.0.borrow();
        let lineage = anchors
            .get(request.binding.community())
            .ok_or(Error::Unauthorized)?;
        if lineage.binding != *request.binding
            || Some(lineage.root) != request.root
            || lineage.epoch != request.epoch
            || !lineage.devices.contains(&request.device)
        {
            return Err(Error::Revoked);
        }
        Ok(())
    }
}
impl Authority for Current {
    async fn check(&mut self, request: Authorization<'_>) -> Result<(), Error> {
        match request.action {
            Action::LendProfileCustody => self.current(&request),
            Action::SignDeviceEd25519 => {
                self.current(&request)?;
                self.intent.consume(&request, ORIGIN)
            }
            _ => self.guard.check(request).await,
        }
    }
    fn check_device_signing_current(&mut self, request: Authorization<'_>) -> Result<u64, Error> {
        self.current(&request)?;
        Ok(request.now)
    }
}

pub type Machine = ckmg::Keys<support::Memory, support::Time, support::Random, Current>;
pub struct Peer {
    pub binding: ckmg::Binding,
    pub keys: Machine,
    pub certificate: ckmg::KeyCertificate,
    pub handle: ckmg::KeyHandle,
    pub lineage: ckmg::Lineage,
    pub time: support::Time,
    admission: ckmg::IntentAdmission,
}
impl Peer {
    pub async fn new(member: &str, seed: u8) -> Self {
        let binding = ckmg::Binding::new("alpha", member).unwrap();
        let memory = support::Memory::default();
        let time = support::Time::default();
        let guard = support::Guard::default();
        let mut original = support::machine(&memory, &time, &guard, seed);
        support::create(&mut original, &guard, &support::prf(seed), &binding).await;
        let lineage = original.lineage().await.unwrap();
        drop(original);
        let (admission, intent) = ckmg::intent_channel();
        let mut keys = ckmg::Keys::new(
            memory,
            time.clone(),
            support::Random::new(seed + 10),
            Current { guard, intent },
        );
        keys.unlock(&support::prf(seed), "alpha").await.unwrap();
        let handle = keys.key(cthr::purpose()).await.unwrap();
        let certificate = handle.certificate().clone();
        Self {
            binding,
            keys,
            certificate,
            handle,
            lineage,
            time,
            admission,
        }
    }
    pub async fn sign(&mut self, bytes: &[u8], until: u64) -> [u8; 64] {
        // Device signatures are typed: the format is the one whose tag leads the bytes.
        let format = ckmg::DeviceFormat::of(bytes).expect("a device format");
        let intent = self
            .admission
            .admit(
                ckmg::AdmittedCommand {
                    binding: self.binding.clone(),
                    origin: ORIGIN.into(),
                    action: Action::SignDeviceEd25519,
                    device: self.certificate.device,
                    root: Some(self.lineage.root),
                    epoch: self.lineage.epoch,
                    target: None,
                    statement: None,
                    transcript: Some(bytes.to_vec()),
                    format: Some(format),
                    expires: until,
                },
                self.time.0.get(),
            )
            .unwrap();
        let signature = self
            .keys
            .sign_device_ed25519_current(format, bytes, until)
            .await
            .unwrap();
        drop(intent);
        signature
    }
}
