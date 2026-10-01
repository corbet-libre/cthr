//! Adapt scoped Keys capabilities to OpenMLS without exporting any private key.
use crate::{Error, Result, purpose};
use ckmg::{Authority, Clock, Entropy, KeyCertificate, KeyHandle, Keys, SecureStore};
use ctcs::DeviceAuthority;
use openmls_traits::{
    signatures::{Signer, SignerError},
    types::SignatureScheme,
};

#[allow(async_fn_in_trait)]
pub trait Custody {
    fn certificate(&self) -> &KeyCertificate;
    async fn verify(&mut self, certificate: &KeyCertificate) -> Result<()>;
    async fn use_signer<T>(
        &mut self,
        use_signer: impl for<'key> FnOnce(ckmg::Ed25519Signer<'key>) -> Result<T>,
    ) -> Result<T>;
}

pub struct KeyPort<'a, S, C, R, A, D> {
    pub keys: &'a mut Keys<S, C, R, A>,
    pub handle: &'a KeyHandle,
    pub devices: &'a mut D,
}
impl<S: SecureStore, C: Clock, R: Entropy, A: Authority, D: DeviceAuthority> Custody
    for KeyPort<'_, S, C, R, A, D>
{
    fn certificate(&self) -> &KeyCertificate {
        self.handle.certificate()
    }
    async fn verify(&mut self, certificate: &KeyCertificate) -> Result<()> {
        let current = self
            .devices
            .current(&certificate.binding)
            .await
            .map_err(|_| Error::Authority)?;
        certificate
            .verify(&current, &purpose())
            .map_err(|_| Error::Authority)
    }
    async fn use_signer<T>(
        &mut self,
        f: impl for<'key> FnOnce(ckmg::Ed25519Signer<'key>) -> Result<T>,
    ) -> Result<T> {
        self.keys
            .with_ed25519_signer(self.handle, f)
            .await
            .map_err(|_| Error::Authority)?
    }
}

pub(crate) struct ScopedSigner<'key>(pub(crate) ckmg::Ed25519Signer<'key>);
impl Signer for ScopedSigner<'_> {
    fn sign(&self, payload: &[u8]) -> std::result::Result<Vec<u8>, SignerError> {
        self.0
            .sign(payload)
            .map(|s| s.to_vec())
            .map_err(|_| SignerError::SigningError)
    }
    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
