use anyhow::{Result, anyhow};
use if_addrs::{IfAddr, get_if_addrs};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv6Addr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    pub address: Ipv6Addr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(address: Ipv6Addr, port: u16) -> Self {
        Self { address, port }
    }

    /// Формат, пригодный для подключения к IPv6-адресу.
    ///
    /// IPv6 в адресе обязательно заключается в квадратные скобки:
    /// [2001:db8::1]:4242
    pub fn socket_address(&self) -> String {
        format!("[{}]:{}", self.address, self.port)
    }

    /// Возвращает глобальный IPv6-адрес устройства.
    pub fn discover(port: u16) -> Result<Self> {
        let interfaces = get_if_addrs()
            .map_err(|error| anyhow!("не удалось получить сетевые интерфейсы: {error}"))?;

        let mut candidates = Vec::new();

        for interface in interfaces {
            let IfAddr::V6(address) = interface.addr else {
                continue;
            };

            let ip = address.ip;

            if is_usable_global_ipv6(ip) {
                candidates.push(ip);
            }
        }

        let address = candidates.into_iter().next().ok_or_else(|| {
            anyhow!(
                "не найден глобальный IPv6-адрес; \
                     проверь IPv6 у провайдера и настройки сети"
            )
        })?;

        Ok(Self::new(address, port))
    }

    /// Возвращает все найденные глобальные IPv6-адреса.
    pub fn discover_all(port: u16) -> Result<Vec<Self>> {
        let interfaces = get_if_addrs()
            .map_err(|error| anyhow!("не удалось получить сетевые интерфейсы: {error}"))?;

        let endpoints = interfaces
            .into_iter()
            .filter_map(|interface| match interface.addr {
                IfAddr::V6(address) if is_usable_global_ipv6(address.ip) => {
                    Some(Self::new(address.ip, port))
                }
                _ => None,
            })
            .collect();

        Ok(endpoints)
    }
}

/// Оставляем только глобальные IPv6-адреса.
///
/// Исключаем:
/// - ::1 — loopback;
/// - fe80::/10 — link-local;
/// - fc00::/7 — unique-local;
/// - :: — unspecified.
fn is_usable_global_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    let first_segment = segments[0];

    let is_link_local = (first_segment & 0xffc0) == 0xfe80;
    let is_unique_local = (first_segment & 0xfe00) == 0xfc00;

    !ip.is_unspecified() && !ip.is_loopback() && !is_link_local && !is_unique_local
}

impl fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[{}]:{}", self.address, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_global_ipv6() {
        let address: Ipv6Addr = "2001:db8::1".parse().unwrap();

        assert!(is_usable_global_ipv6(address));
    }

    #[test]
    fn rejects_loopback() {
        assert!(!is_usable_global_ipv6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn rejects_link_local() {
        let address: Ipv6Addr = "fe80::1".parse().unwrap();

        assert!(!is_usable_global_ipv6(address));
    }

    #[test]
    fn formats_socket_address_correctly() {
        let endpoint = Endpoint::new("2001:db8::1".parse().unwrap(), 4242);

        assert_eq!(endpoint.socket_address(), "[2001:db8::1]:4242");
    }
}
