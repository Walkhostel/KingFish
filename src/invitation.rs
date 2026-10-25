use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{DeviceIdentity, EphemeralKeypair};

const INVITATION_PREFIX: &str = "kingfish://v1/";
const INVITATION_LIFETIME_SECONDS: u64 = 300;

/// Данные приглашения до добавления подписи.
#[derive(Debug, Serialize)]
struct SignableInvitation {
    version: u8,
    invitation_id: [u8; 16],
    sender_address: String,
    sender_identity_key: [u8; 32],
    sender_ephemeral_key: [u8; 32],
    expires_at: u64,
}

/// Полное приглашение, которое можно передать другому пользователю.
#[derive(Debug, Serialize, Deserialize)]
pub struct Invitation {
    pub version: u8,
    pub invitation_id: [u8; 16],
    pub sender_address: String,
    pub sender_identity_key: [u8; 32],
    pub sender_ephemeral_key: [u8; 32],
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

impl Invitation {
    /// Создаёт новое подписанное приглашение.
    pub fn create(
        identity: &DeviceIdentity,
        ephemeral_keypair: &EphemeralKeypair,
        sender_address: String,
    ) -> Result<Self> {
        let mut invitation_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut invitation_id);

        let expires_at = current_timestamp()?
            .checked_add(INVITATION_LIFETIME_SECONDS)
            .ok_or_else(|| anyhow!("время действия приглашения переполнилось"))?;

        let signable = SignableInvitation {
            version: 1,
            invitation_id,
            sender_address,
            sender_identity_key: identity.public_key_bytes(),
            sender_ephemeral_key: ephemeral_keypair.public_key.to_bytes(),
            expires_at,
        };

        let payload =
            serde_json::to_vec(&signable).context("не удалось сериализовать приглашение")?;

        let signature = identity.signing_key.sign(&payload);

        Ok(Self {
            version: signable.version,
            invitation_id: signable.invitation_id,
            sender_address: signable.sender_address,
            sender_identity_key: signable.sender_identity_key,
            sender_ephemeral_key: signable.sender_ephemeral_key,
            expires_at: signable.expires_at,
            signature: signature.to_bytes().to_vec(),
        })
    }

    /// Кодирует приглашение для передачи через терминал, чат или QR-код.
    pub fn encode(&self) -> Result<String> {
        let data = serde_json::to_vec(self).context("не удалось сериализовать приглашение")?;

        Ok(format!(
            "{}{}",
            INVITATION_PREFIX,
            URL_SAFE_NO_PAD.encode(data)
        ))
    }

    /// Разбирает приглашение и проверяет его подпись и срок действия.
    pub fn decode(encoded: &str) -> Result<Self> {
        let payload = encoded
            .strip_prefix(INVITATION_PREFIX)
            .ok_or_else(|| anyhow!("неверный префикс приглашения"))?;

        let data = URL_SAFE_NO_PAD
            .decode(payload)
            .context("неверное base64-кодирование приглашения")?;

        let invitation: Self =
            serde_json::from_slice(&data).context("неверный формат приглашения")?;

        if invitation.version != 1 {
            return Err(anyhow!(
                "неподдерживаемая версия приглашения: {}",
                invitation.version
            ));
        }

        let signable = invitation.signable_data()?;
        let signable_bytes =
            serde_json::to_vec(&signable).context("не удалось восстановить подписанные данные")?;

        let verifying_key = VerifyingKey::from_bytes(&invitation.sender_identity_key)
            .context("некорректный публичный ключ отправителя")?;

        let signature_bytes: [u8; 64] = invitation
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("некорректная длина подписи"))?;

        let signature = Signature::from_bytes(&signature_bytes);

        verifying_key
            .verify(&signable_bytes, &signature)
            .map_err(|_| anyhow!("подпись приглашения недействительна"))?;

        let now = current_timestamp()?;

        if invitation.expires_at <= now {
            return Err(anyhow!("срок действия приглашения истёк"));
        }

        Ok(invitation)
    }

    fn signable_data(&self) -> Result<SignableInvitation> {
        Ok(SignableInvitation {
            version: self.version,
            invitation_id: self.invitation_id,
            sender_address: self.sender_address.clone(),
            sender_identity_key: self.sender_identity_key,
            sender_ephemeral_key: self.sender_ephemeral_key,
            expires_at: self.expires_at,
        })
    }

    pub fn is_expired(&self) -> Result<bool> {
        Ok(self.expires_at <= current_timestamp()?)
    }
}

fn current_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("системные часы установлены раньше UNIX-времени")
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitation_round_trip() {
        let identity = DeviceIdentity::generate();
        let ephemeral = EphemeralKeypair::generate();

        let invitation =
            Invitation::create(&identity, &ephemeral, "192.168.1.10:4242".to_string()).unwrap();

        let encoded = invitation.encode().unwrap();
        let decoded = Invitation::decode(&encoded).unwrap();

        assert_eq!(decoded.invitation_id, invitation.invitation_id);
        assert_eq!(decoded.sender_address, "192.168.1.10:4242");
        assert!(!decoded.is_expired().unwrap());
    }

    #[test]
    fn modified_invitation_is_rejected() {
        let identity = DeviceIdentity::generate();
        let ephemeral = EphemeralKeypair::generate();

        let invitation =
            Invitation::create(&identity, &ephemeral, "127.0.0.1:4242".to_string()).unwrap();

        let mut encoded = invitation.encode().unwrap();
        encoded.push('x');

        assert!(Invitation::decode(&encoded).is_err());
    }
}
