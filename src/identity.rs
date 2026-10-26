//! Хранение долгосрочной личности устройства.
//!
//! Ключ создаётся при первом запуске и лежит в конфиг-папке
//! с правами 0600 — по той же схеме, что ~/.ssh/id_ed25519.

use anyhow::{Context, Result, anyhow};
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

use crate::crypto::DeviceIdentity;

/// Путь к файлу с долгосрочным ключом устройства.
fn identity_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("dev", "kingfish", "kingfish")
        .ok_or_else(|| anyhow!("не удалось определить конфигурационную папку"))?;

    Ok(dirs.config_dir().join("identity.key"))
}

/// Загружает личность с диска; при первом запуске создаёт новую.
pub fn load_or_create_identity() -> Result<DeviceIdentity> {
    let path = identity_path()?;

    if path.exists() {
        let bytes = fs::read(&path)
            .with_context(|| format!("не удалось прочитать {}", path.display()))?;

        let key_bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("повреждённый файл ключа {}", path.display()))?;

        DeviceIdentity::from_bytes(key_bytes)
    } else {
        let identity = DeviceIdentity::generate();

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("не удалось создать {}", parent.display()))?;
        }

        fs::write(&path, identity.private_key_bytes())
            .with_context(|| format!("не удалось записать {}", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .context("не удалось выставить права на файл ключа")?;
        }

        Ok(identity)
    }
}

/// Короткий отпечаток публичного ключа — для показа пользователю.
/// Сверяй его со второй стороной по голосу или в мессенджере:
/// это защита от активного посредника при первом контакте, как в SSH.
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    let hash = blake3::hash(public_key);
    let hex = hash.to_hex();
    hex[..16].to_string()
}
