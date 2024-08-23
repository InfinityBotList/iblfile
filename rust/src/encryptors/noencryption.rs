use crate::autoencrypted::AutoEncryptor;

pub struct NoEncryptionSource;

impl AutoEncryptor for NoEncryptionSource {
    fn id(&self) -> String {
        "noencryption$$$$".to_string()
    }

    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, crate::Error> {
        Ok(data.to_vec())
    }

    fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, crate::Error> {
        Ok(data.to_vec())
    }
}
