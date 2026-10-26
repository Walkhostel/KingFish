//! Протокол обмена: кадры, сообщения, шифрованный канал.
//!
//! Схема установки соединения:
//!
//! 1. Получатель создаёт приглашение со своим одноразовым ключом (invitation.rs).
//! 2. Отправитель подключается и шлёт открытое [Hello] со своим одноразовым ключом.
//! 3. Обе стороны считают общий секрет X25519 и выводят ключ сессии.
//! 4. Всё дальше идёт через [SecureChannel]: XChaCha20-Poly1305,
//!    каждый блок привязан к своему номеру как associated data.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::crypto::{EncryptedBlock, NONCE_SIZE, SessionKey};

/// Максимальный размер одного кадра — защита от атаки на память:
/// длина приходит до данных, и без лимита злоумышленник заставил бы
/// выделить гигабайты одним числом.
pub const MAX_FRAME_SIZE: u32 = 8 * 1024 * 1024;

/// Тег управляющего сообщения внутри зашифрованного блока.
const TAG_CONTROL: u8 = 0x01;
/// Тег куска файла внутри зашифрованного блока.
const TAG_DATA: u8 = 0x02;

/// Открытое приветствие отправителя файла.
///
/// Это единственное незашифрованное сообщение в протоколе:
/// на момент его отправки общий ключ ещё не создан.
/// Секретных данных здесь нет — только публичные ключи.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    /// Id приглашения, на которое отвечает отправитель.
    /// Получатель принимает только свой id.
    pub invitation_id: [u8; 16],
    /// Долгосрочный ключ личности отправителя — по нему получатель
    /// видит, кто шлёт файл (отпечаток).
    pub sender_identity_key: [u8; 32],
    /// Одноразовый X25519-ключ отправителя на эту передачу.
    pub sender_ephemeral_key: [u8; 32],
    /// Подпись Ed25519 от (invitation_id || sender_ephemeral_key).
    /// Доказывает, что владелец identity-ключа и создал этот ephemeral-ключ:
    /// подменить чужой ключ на свой не выйдет.
    pub signature: Vec<u8>,
}

/// Управляющие сообщения. Ходят только внутри шифрованного канала.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Отправитель предлагает файл.
    FileOffer { name: String, size: u64 },
    /// Получатель согласен принять.
    Accept,
    /// Получатель отказался.
    Reject { reason: String },
    /// Отправитель закончил: вот blake3-хеш исходного файла.
    Done { blake3_hash: [u8; 32] },
}

/// То, что приходит из зашифрованного канала.
#[derive(Debug)]
pub enum ChannelMessage {
    Control(ControlMessage),
    Data(Vec<u8>),
}

/// Контекст вывода ключа сессии.
///
/// Привязывает ключ к конкретному приглашению и обоим ephemeral-ключам:
/// один и тот же DH-секрет не даст тот же ключ в другой передаче,
/// а подмена ephemeral-ключа посредником ломает вывод ключа у обеих сторон.
pub fn session_context(
    invitation_id: &[u8; 16],
    invitation_ephemeral_key: &[u8; 32],
    sender_ephemeral_key: &[u8; 32],
) -> Vec<u8> {
    let mut context = Vec::with_capacity(24 + 16 + 32 + 32);
    context.extend_from_slice(b"kingfish/file-transfer/v1");
    context.extend_from_slice(invitation_id);
    context.extend_from_slice(invitation_ephemeral_key);
    context.extend_from_slice(sender_ephemeral_key);
    context
}

/// Записывает кадр: [4 байта длины, big-endian][данные].
pub async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let length = u32::try_from(payload.len()).context("кадр слишком большой")?;
    anyhow::ensure!(length <= MAX_FRAME_SIZE, "кадр больше допустимого");

    stream
        .write_all(&length.to_be_bytes())
        .await
        .context("не удалось отправить длину кадра")?;
    stream
        .write_all(payload)
        .await
        .context("не удалось отправить кадр")?;
    stream.flush().await.context("не удалось протолкнуть кадр")?;

    Ok(())
}

/// Читает один кадр.
pub async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut length_bytes = [0u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .await
        .context("не удалось прочитать длину кадра")?;

    let length = u32::from_be_bytes(length_bytes);
    anyhow::ensure!(
        length <= MAX_FRAME_SIZE,
        "пришёл кадр больше допустимого — соединение закрыто"
    );

    let mut payload = vec![0u8; length as usize];
    stream
        .read_exact(&mut payload)
        .await
        .context("не удалось прочитать кадр")?;

    Ok(payload)
}

/// Бинарный формат зашифрованного блока:
/// [8 байт номера][24 байта nonce][шифротекст с тегом Poly1305].
pub fn encode_block(block: &EncryptedBlock) -> Vec<u8> {
    let mut data = Vec::with_capacity(8 + NONCE_SIZE + block.ciphertext.len());
    data.extend_from_slice(&block.block_number.to_be_bytes());
    data.extend_from_slice(&block.nonce);
    data.extend_from_slice(&block.ciphertext);
    data
}

/// Обратное преобразование для [encode_block].
pub fn decode_block(data: &[u8]) -> Result<EncryptedBlock> {
    anyhow::ensure!(data.len() >= 8 + NONCE_SIZE, "блок слишком короткий");

    let block_number = u64::from_be_bytes(data[..8].try_into().unwrap());
    let nonce: [u8; NONCE_SIZE] = data[8..8 + NONCE_SIZE].try_into().unwrap();
    let ciphertext = data[8 + NONCE_SIZE..].to_vec();

    Ok(EncryptedBlock {
        block_number,
        nonce,
        ciphertext,
    })
}

/// Шифрованный канал поверх TCP.
///
/// Счётчики блоков не дают переиграть, выкинуть или переставить блоки:
/// номер блока — часть подписанных данных.
pub struct SecureChannel {
    stream: TcpStream,
    key: SessionKey,
    send_counter: u64,
    receive_counter: u64,
}

impl SecureChannel {
    pub fn new(stream: TcpStream, key: SessionKey) -> Self {
        Self {
            stream,
            key,
            send_counter: 0,
            receive_counter: 0,
        }
    }

    pub async fn send_control(&mut self, message: &ControlMessage) -> Result<()> {
        let payload = serde_json::to_vec(message)
            .context("не удалось сериализовать управляющее сообщение")?;
        self.send_tagged(TAG_CONTROL, &payload).await
    }

    pub async fn send_data(&mut self, chunk: &[u8]) -> Result<()> {
        self.send_tagged(TAG_DATA, chunk).await
    }

    async fn send_tagged(&mut self, tag: u8, payload: &[u8]) -> Result<()> {
        let mut plaintext = Vec::with_capacity(1 + payload.len());
        plaintext.push(tag);
        plaintext.extend_from_slice(payload);

        let block = self.key.encrypt_block(self.send_counter, &plaintext)?;
        self.send_counter += 1;

        write_frame(&mut self.stream, &encode_block(&block)).await
    }

    pub async fn receive(&mut self) -> Result<ChannelMessage> {
        let frame = read_frame(&mut self.stream).await?;
        let block = decode_block(&frame)?;

        anyhow::ensure!(
            block.block_number == self.receive_counter,
            "нарушен порядок блоков: канал повреждён или подделан"
        );
        self.receive_counter += 1;

        let plaintext = self.key.decrypt_block(&block)?;
        let (tag, payload) = plaintext
            .split_first()
            .ok_or_else(|| anyhow!("пустой блок"))?;

        match *tag {
            TAG_CONTROL => {
                let message = serde_json::from_slice(payload)
                    .context("повреждённое управляющее сообщение")?;
                Ok(ChannelMessage::Control(message))
            }
            TAG_DATA => Ok(ChannelMessage::Data(payload.to_vec())),
            other => Err(anyhow!("неизвестный тип сообщения: {other:#x}")),
        }
    }
}
