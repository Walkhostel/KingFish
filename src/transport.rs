use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

/// Запускает IPv6-only listener.
///
/// `"[::]:4242"` означает:
/// - слушать IPv6;
/// - принимать подключения на всех IPv6-интерфейсах;
/// - порт 4242.
pub async fn bind_ipv6(port: u16) -> Result<TcpListener> {
    let address = format!("[::]:{port}");

    let listener = TcpListener::bind(&address)
        .await
        .with_context(|| format!("не удалось открыть IPv6-порт {port}"))?;

    Ok(listener)
}

/// Принимает одно входящее соединение.
pub async fn accept_connection(listener: &TcpListener) -> Result<(TcpStream, SocketAddr)> {
    listener
        .accept()
        .await
        .context("ошибка принятия входящего соединения")
}

/// Подключается к другому устройству по IPv6.
pub async fn connect(address: &str) -> Result<TcpStream> {
    TcpStream::connect(address)
        .await
        .with_context(|| format!("не удалось подключиться к {address}"))
}
