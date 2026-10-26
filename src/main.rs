use anyhow::Result;
use clap::{Parser, Subcommand};
use std::net::Ipv6Addr;
use std::path::PathBuf;

use kingfish::endpoint::Endpoint;
use kingfish::identity::{fingerprint, load_or_create_identity};
use kingfish::transfer::{run_receiver, run_sender};

#[derive(Parser)]
#[command(
    name = "kingfish",
    version,
    about = "P2P-передача файлов со сквозным шифрованием (IPv6, без серверов)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Принять файл: поднимает слушатель и печатает одноразовый код приглашения
    Receive {
        /// Порт для входящих подключений
        #[arg(short, long, default_value_t = 4242)]
        port: u16,
        /// Папка для сохранения файлов
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        /// Подставить адрес вручную (например ::1 для локального теста)
        #[arg(short, long)]
        address: Option<Ipv6Addr>,
    },
    /// Отправить файл по коду приглашения
    Send {
        /// Путь к отправляемому файлу
        file: PathBuf,
        /// Код приглашения kingfish://v1/...
        code: String,
    },
    /// Показать свои IPv6-адреса и отпечаток ключа
    Address {
        #[arg(short, long, default_value_t = 4242)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Receive {
            port,
            output,
            address,
        } => run_receiver(port, &output, address).await,
        Command::Send { file, code } => run_sender(&file, &code).await,
        Command::Address { port } => {
            let identity = load_or_create_identity()?;
            let endpoints = Endpoint::discover_all(port)?;

            println!(
                "отпечаток твоего ключа: {}",
                fingerprint(&identity.public_key_bytes())
            );

            if endpoints.is_empty() {
                println!("глобальных IPv6-адресов не найдено — обмен невозможен");
            } else {
                println!("адреса, на которые тебя можно пригласить:");
                for endpoint in endpoints {
                    println!("  {endpoint}");
                }
            }

            Ok(())
        }
    }
}
