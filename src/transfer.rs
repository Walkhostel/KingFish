//! Сценарии передачи файла: сторона получателя и сторона отправителя.

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::crypto::EphemeralKeypair;
use crate::endpoint::Endpoint;
use crate::identity::{fingerprint, load_or_create_identity};
use crate::invitation::Invitation;
use crate::protocol::{
    ChannelMessage, ControlMessage, Hello, SecureChannel, read_frame, session_context, write_frame,
};
use crate::transport::{accept_connection, bind_ipv6, connect};

/// Размер куска, которым файл идёт по сети.
const CHUNK_SIZE: usize = 64 * 1024;

/// Сторона получателя: поднимает слушатель, создаёт одноразовое
/// приглашение и ждёт отправителя.
pub async fn run_receiver(
    port: u16,
    output_dir: &Path,
    address_override: Option<Ipv6Addr>,
) -> Result<()> {
    let identity = load_or_create_identity()?;

    let endpoint = match address_override {
        Some(address) => Endpoint::new(address, port),
        None => Endpoint::discover(port)?,
    };

    let ephemeral = EphemeralKeypair::generate();
    let invitation = Invitation::create(&identity, &ephemeral, endpoint.socket_address())?;
    let code = invitation.encode()?;

    let listener = bind_ipv6(port).await?;

    println!("слушаю {endpoint}");
    println!("твой отпечаток: {}", fingerprint(&identity.public_key_bytes()));
    println!();
    println!("код приглашения — отправь тому, кто шлёт файл (живёт 5 минут):");
    println!("{code}");
    println!();
    println!("жду подключения... (Ctrl+C — выход)");

    loop {
        let (stream, peer) = match accept_connection(&listener).await {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!("ошибка приёма подключения: {error:#}");
                continue;
            }
        };

        println!("\nподключение от {peer}");

        match handle_connection(stream, &ephemeral, &invitation, output_dir).await {
            Ok(true) => {
                println!("передача завершена");
                return Ok(());
            }
            Ok(false) => println!("отправитель отклонён, жду дальше..."),
            Err(error) => eprintln!("соединение разорвано: {error:#}"),
        }
    }
}

/// Обрабатывает одно входящее подключение.
/// Возвращает Ok(true), если файл успешно принят.
async fn handle_connection(
    mut stream: TcpStream,
    ephemeral: &EphemeralKeypair,
    invitation: &Invitation,
    output_dir: &Path,
) -> Result<bool> {
    // 1. Открытое приветствие
    let frame = read_frame(&mut stream).await?;
    let hello: Hello = serde_json::from_slice(&frame).context("неверный формат приветствия")?;

    anyhow::ensure!(
        hello.invitation_id == invitation.invitation_id,
        "пришёл ответ на чужое приглашение"
    );

    verify_hello(&hello)?;

    // 2. Общий секрет и ключ сессии
    let sender_ephemeral_key = X25519PublicKey::from(hello.sender_ephemeral_key);
    let shared_secret = ephemeral.shared_secret(&sender_ephemeral_key);
    let context = session_context(
        &invitation.invitation_id,
        &invitation.sender_ephemeral_key,
        &hello.sender_ephemeral_key,
    );
    let session_key = crate::crypto::SessionKey::derive(shared_secret, &context)?;
    let mut channel = SecureChannel::new(stream, session_key);

    // 3. Первое зашифрованное сообщение — предложение файла
    let (name, size) = match channel.receive().await? {
        ChannelMessage::Control(ControlMessage::FileOffer { name, size }) => (name, size),
        _ => bail!("отправитель должен начать с предложения файла"),
    };

    println!();
    println!("отправитель: {}", fingerprint(&hello.sender_identity_key));
    println!("файл: {name} ({size} байт)");

    if !ask_yes_no("принять? [y/N] ").await? {
        channel
            .send_control(&ControlMessage::Reject {
                reason: "получатель отклонил передачу".to_string(),
            })
            .await?;
        return Ok(false);
    }

    channel.send_control(&ControlMessage::Accept).await?;

    // 4. Приём блоков
    receive_blocks(&mut channel, &name, size, output_dir).await?;
    Ok(true)
}

/// Проверяет, что ephemeral-ключ из приветствия действительно
/// создан владельцем identity-ключа отправителя.
fn verify_hello(hello: &Hello) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(&hello.sender_identity_key)
        .context("некорректный identity-ключ отправителя")?;

    let signature_bytes: [u8; 64] = hello
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("некорректная длина подписи приветствия"))?;
    let signature = Signature::from_bytes(&signature_bytes);

    let mut signed_data = Vec::with_capacity(16 + 32);
    signed_data.extend_from_slice(&hello.invitation_id);
    signed_data.extend_from_slice(&hello.sender_ephemeral_key);

    verifying_key
        .verify(&signed_data, &signature)
        .map_err(|_| anyhow!("подпись приветствия недействительна"))?;

    Ok(())
}

/// Принимает блоки, пишет во временный файл .part,
/// проверяет хеш и только потом переименовывает в нормальное имя.
async fn receive_blocks(
    channel: &mut SecureChannel,
    name: &str,
    expected_size: u64,
    output_dir: &Path,
) -> Result<()> {
    // Имя от отправителя — недоверенное: отрезаем любые пути,
    // чтобы нельзя было записать файл куда-то ещё (../../etc/...).
    let safe_name = Path::new(name)
        .file_name()
        .ok_or_else(|| anyhow!("некорректное имя файла"))?
        .to_string_lossy()
        .to_string();

    tokio::fs::create_dir_all(output_dir)
        .await
        .with_context(|| format!("не удалось создать {}", output_dir.display()))?;

    let temporary_path = output_dir.join(format!("{safe_name}.part"));
    let mut file = File::create(&temporary_path)
        .await
        .with_context(|| format!("не удалось создать {}", temporary_path.display()))?;

    // Любая ошибка передачи — удаляем недокачанный .part.
    if let Err(error) = stream_blocks(channel, &mut file, expected_size).await {
        drop(file);
        let _ = tokio::fs::remove_file(&temporary_path).await;
        return Err(error);
    }

    file.flush().await?;
    drop(file);

    let final_path = unique_path(output_dir, &safe_name);
    tokio::fs::rename(&temporary_path, &final_path)
        .await
        .with_context(|| format!("не удалось переименовать в {}", final_path.display()))?;

    println!("файл сохранён: {}", final_path.display());
    Ok(())
}

/// Читает блоки до Done, пишет в файл, сверяет размер и blake3-хеш.
async fn stream_blocks(
    channel: &mut SecureChannel,
    file: &mut File,
    expected_size: u64,
) -> Result<()> {
    let mut hasher = blake3::Hasher::new();
    let mut received: u64 = 0;

    let expected_hash = loop {
        match channel.receive().await? {
            ChannelMessage::Data(chunk) => {
                received += chunk.len() as u64;

                if received > expected_size {
                    bail!("отправитель прислал больше данных, чем обещал");
                }

                hasher.update(&chunk);
                file.write_all(&chunk).await?;
                eprint!("\rпринято {received}/{expected_size} байт");
            }
            ChannelMessage::Control(ControlMessage::Done { blake3_hash }) => break blake3_hash,
            ChannelMessage::Control(other) => {
                bail!("неожиданное сообщение посреди передачи: {other:?}");
            }
        }
    };
    eprintln!();

    anyhow::ensure!(
        received == expected_size,
        "размер не сошёлся: обещали {expected_size}, пришло {received}"
    );
    anyhow::ensure!(
        hasher.finalize().as_bytes() == &expected_hash,
        "хеш не сошёлся — файл повреждён при передаче"
    );

    Ok(())
}

/// Если файл с таким именем уже есть — добавляет суффикс .1, .2 и т.д.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }

    for index in 1u32.. {
        let candidate = dir.join(format!("{name}.{index}"));
        if !candidate.exists() {
            return candidate;
        }
    }

    unreachable!()
}

/// Сторона отправителя: берёт код приглашения, подключается
/// к получателю и шлёт файл после его согласия.
pub async fn run_sender(file_path: &Path, code: &str) -> Result<()> {
    let invitation = Invitation::decode(code)?;
    let identity = load_or_create_identity()?;
    let ephemeral = EphemeralKeypair::generate();

    let metadata = std::fs::metadata(file_path)
        .with_context(|| format!("не удалось открыть {}", file_path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "это не обычный файл: {}",
        file_path.display()
    );

    let file_size = metadata.len();
    let file_name = file_path
        .file_name()
        .ok_or_else(|| anyhow!("некорректный путь к файлу"))?
        .to_string_lossy()
        .to_string();

    println!("подключаюсь к {}...", invitation.sender_address);
    let mut stream = connect(&invitation.sender_address).await?;
    println!(
        "соединение установлено; отпечаток получателя: {}",
        fingerprint(&invitation.sender_identity_key)
    );
    println!("сверь его с получателем — это защита от посредника");

    // 1. Приветствие: одноразовый ключ + подпись от identity
    let mut signed_data = Vec::with_capacity(16 + 32);
    signed_data.extend_from_slice(&invitation.invitation_id);
    signed_data.extend_from_slice(ephemeral.public_key.as_bytes());
    let signature = identity.signing_key.sign(&signed_data);

    let hello = Hello {
        invitation_id: invitation.invitation_id,
        sender_identity_key: identity.public_key_bytes(),
        sender_ephemeral_key: ephemeral.public_key.to_bytes(),
        signature: signature.to_bytes().to_vec(),
    };
    write_frame(&mut stream, &serde_json::to_vec(&hello)?).await?;

    // 2. Ключ сессии — тот же, что выведет получатель
    let receiver_ephemeral_key = X25519PublicKey::from(invitation.sender_ephemeral_key);
    let shared_secret = ephemeral.shared_secret(&receiver_ephemeral_key);
    let context = session_context(
        &invitation.invitation_id,
        &invitation.sender_ephemeral_key,
        ephemeral.public_key.as_bytes(),
    );
    let session_key = crate::crypto::SessionKey::derive(shared_secret, &context)?;
    let mut channel = SecureChannel::new(stream, session_key);

    // 3. Предложение файла
    channel
        .send_control(&ControlMessage::FileOffer {
            name: file_name.clone(),
            size: file_size,
        })
        .await?;
    println!("жду решения получателя...");

    match channel.receive().await? {
        ChannelMessage::Control(ControlMessage::Accept) => println!("принято! отправляю..."),
        ChannelMessage::Control(ControlMessage::Reject { reason }) => {
            bail!("получатель отклонил передачу: {reason}")
        }
        _ => bail!("неожиданный ответ получателя"),
    }

    // 4. Потоковая отправка с подсчётом хеша на лету
    let mut file = File::open(file_path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut sent: u64 = 0;

    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }

        let chunk = &buffer[..read];
        hasher.update(chunk);
        channel.send_data(chunk).await?;

        sent += read as u64;
        eprint!("\rотправлено {sent}/{file_size} байт");
    }
    eprintln!();

    let hash = hasher.finalize();
    channel
        .send_control(&ControlMessage::Done {
            blake3_hash: *hash.as_bytes(),
        })
        .await?;

    println!("файл «{file_name}» доставлен");
    Ok(())
}

/// Спрашивает пользователя. Блокирующий stdin выносим в отдельный
/// поток, чтобы не останавливать tokio-runtime.
async fn ask_yes_no(question: &str) -> Result<bool> {
    use std::io::Write as _;

    print!("{question}");
    std::io::stdout().flush()?;

    let answer = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map(|_| line)
    })
    .await
    .context("не удалось прочитать ответ")??;

    Ok(matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "д" | "да"
    ))
}
