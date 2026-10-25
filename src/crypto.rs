use anyhow::Result;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

pub const NONCE_SIZE: usize = 24;
pub const KEY_SIZE: usize = 32;

/// Долгосрочная криптографическая личность устройства.
/// Закрытый ключ нельзя отправлять по сети.
pub struct DeviceIdentity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl DeviceIdentity {
    /// Генерирует новую пару Ed25519.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// Временная пара X25519 для одной передачи.
pub struct EphemeralKeypair {
    private_key: StaticSecret,
    pub public_key: X25519PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);

        Self {
            private_key,
            public_key,
        }
    }

    /// Создаёт общий секрет с публичным ключом другой стороны.
    pub fn shared_secret(&self, other_public_key: &X25519PublicKey) -> [u8; 32] {
        self.private_key.diffie_hellman(other_public_key).to_bytes()
    }
}

/// Ключ шифрования одной сессии передачи.
#[derive(Clone)]
pub struct SessionKey([u8; KEY_SIZE]);

impl SessionKey {
    /// Производит ключ сессии из общего X25519-секрета.
    /// `context` нужен для разделения разных назначений ключей.
    pub fn derive(shared_secret: [u8; 32], context: &[u8]) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
        let mut key = [0u8; KEY_SIZE];

        hkdf.expand(context, &mut key)
            .map_err(|_| anyhow::anyhow!("не удалось вывести ключ сессии"))?;

        Ok(Self(key))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        let key = Key::from_slice(&self.0);
        XChaCha20Poly1305::new(key)
    }

    /// Шифрует один блок файла.
    ///
    /// Номер блока передаётся как associated data:
    /// его нельзя незаметно заменить или переставить.
    pub fn encrypt_block(&self, block_number: u64, plaintext: &[u8]) -> Result<EncryptedBlock> {
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        let associated_data = block_number.to_be_bytes();
        let ciphertext = self
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| anyhow::anyhow!("Failed to encrypt the block"))?;
        Ok(EncryptedBlock {
            block_number,
            nonce,
            ciphertext,
        })
    }

    /// Расшифровывает блок и проверяет его целостность.
    pub fn decrypt_block(&self, block: &EncryptedBlock) -> Result<Vec<u8>> {
        let associated_data = block.block_number.to_be_bytes();

        self.cipher()
            .decrypt(
                XNonce::from_slice(&block.nonce),
                chacha20poly1305::aead::Payload {
                    msg: &block.ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "Unable to decrypt the block: the data is corrupted or the key is incorrect"
                )
            })
    }
}

/// Зашифрованный блок файла.
#[derive(Debug, Clone)]
pub struct EncryptedBlock {
    pub block_number: u64,
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_encrypts_and_decrypts_block() {
        let sender = EphemeralKeypair::generate();
        let receiver = EphemeralKeypair::generate();

        let sender_secret = sender.shared_secret(&receiver.public_key);
        let receiver_secret = receiver.shared_secret(&sender.public_key);

        assert_eq!(sender_secret, receiver_secret);

        let sender_key = SessionKey::derive(sender_secret, b"kingfish/file-transfer/v1").unwrap();
        let receiver_key =
            SessionKey::derive(receiver_secret, b"kingfish/file-transfer/v1").unwrap();

        let original = b"hello from KingFish";
        let encrypted = sender_key.encrypt_block(0, original).unwrap();
        let decrypted = receiver_key.decrypt_block(&encrypted).unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn modified_block_is_rejected() {
        let sender = EphemeralKeypair::generate();
        let receiver = EphemeralKeypair::generate();

        let secret = sender.shared_secret(&receiver.public_key);
        let key = SessionKey::derive(secret, b"kingfish/file-transfer/v1").unwrap();

        let mut encrypted = key.encrypt_block(0, b"data").unwrap();
        encrypted.ciphertext[0] ^= 1;

        assert!(key.decrypt_block(&encrypted).is_err());
    }
}
