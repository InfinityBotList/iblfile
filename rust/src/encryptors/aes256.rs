use crate::autoencrypted::AutoEncryptor;
use crate::Error;
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use rand::Rng;
use rand::RngCore;

#[derive(Debug, Clone, Copy)]
pub enum HashMethod {
    Sha256,
}

pub struct AES256Source {
    encryption_key: String,
    hashed_key: Option<Vec<u8>>,
    salt: Option<[u8; 8]>,
    cipher: Option<Aes256Gcm>,
}

impl AES256Source {
    pub fn new(encryption_key: String) -> Self {
        AES256Source {
            encryption_key,
            hashed_key: None,
            salt: None,
            cipher: None,
        }
    }

    /// Reset the encryption state
    pub fn reset(&mut self) {
        self.hashed_key = None;
        self.salt = None;
        self.cipher = None;
    }

    fn init(&mut self) -> Result<(), Error> {
        if self.hashed_key.is_none() {
            // Create 8 byte salt
            if self.salt.is_none() {
                let mut salt = [0u8; 8];
                rand::thread_rng().fill_bytes(&mut salt);
                self.salt = Some(salt);
            }

            // 8 byte salt
            let salt = self.salt.unwrap();
            let argon2 = Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                match argon2::ParamsBuilder::new()
                    .t_cost(1)
                    .m_cost(64 * 1024)
                    .p_cost(4)
                    .output_len(32)
                    .build()
                {
                    Ok(params) => params,
                    Err(e) => return Err(format!("Failed to build argon2 params: {}", e).into()),
                },
            );

            let mut hashed_key = vec![0u8; 32];
            argon2
                .hash_password_into(self.encryption_key.as_bytes(), &salt, &mut hashed_key)
                .map_err(|e| format!("Failed to hash password: {}", e))?;

            self.hashed_key = Some(hashed_key);
        }

        if self.cipher.is_none() {
            let hashed_key = self.hashed_key.as_ref().unwrap();
            let cipher = Aes256Gcm::new_from_slice(hashed_key)?;
            self.cipher = Some(cipher);
        }

        Ok(())
    }
}

impl AutoEncryptor for AES256Source {
    fn id(&self) -> String {
        "aes256$$$$$$$$$$".to_string()
    }

    fn encrypt(&mut self, b: &[u8]) -> Result<Vec<u8>, Error> {
        self.init()?;

        let random_slice = rand::thread_rng().gen::<[u8; 12]>();
        let nonce = Nonce::from_slice(&random_slice);
        let cipher = self.cipher.as_ref().unwrap();

        let mut encrypted = cipher
            .encrypt(nonce, b)
            .map_err(|e| format!("Failed to encrypt: {:?}", e))?;

        // Format must be <salt><nonce><ciphertext>
        let mut result = Vec::with_capacity(8 + 12 + encrypted.len());
        result.extend_from_slice(&self.salt.unwrap());
        result.extend_from_slice(nonce.as_slice());
        result.append(&mut encrypted);

        Ok(result)
    }

    fn decrypt(&mut self, b: &[u8]) -> Result<Vec<u8>, Error> {
        if b.len() < 20 {
            return Err("Invalid data".into());
        }

        self.salt = Some(<[u8; 8]>::try_from(&b[..8]).unwrap());
        let (nonce, ciphertext) = b[8..].split_at(12);

        self.init()?;

        let cipher = self.cipher.as_ref().unwrap();
        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Failed to decrypt: {:?}", e).into())
    }
}
