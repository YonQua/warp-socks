// 解析 wg0.conf，字段名和 lib/domain/wireguard.sh: write_wg_config() 一一对应。
// 该文件里没有 DNS/MTU/PersistentKeepalive 字段——这些在 warp-plus 的
// `--wgconf` 模式下本来就不生效（app/app.go: runWireguard() 硬编码），
// 新实现直接硬编码等价的值（MTU=1330, keepalive=5s），不读、不写这些字段。

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use anyhow::{anyhow, bail, Context, Result};

pub struct WgConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub endpoint: SocketAddr,
    pub reserved: [u8; 3],
    pub address_v4: Ipv4Addr,
    pub address_v6: Ipv6Addr,
}

fn decode_key(b64: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .with_context(|| format!("base64 解码失败: {b64}"))?;
    raw.try_into()
        .map_err(|v: Vec<u8>| anyhow!("key 长度应为32字节，实际 {}", v.len()))
}

pub fn parse_wg_conf(path: &str) -> Result<WgConfig> {
    let text = fs::read_to_string(path).with_context(|| format!("读取 {path} 失败"))?;

    let mut private_key = None;
    let mut peer_public_key = None;
    let mut endpoint = None;
    let mut reserved = [0u8; 3];
    let mut address_v4 = None;
    let mut address_v6 = None;

    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "PrivateKey" => private_key = Some(decode_key(value)?),
            "PublicKey" => peer_public_key = Some(decode_key(value)?),
            "Endpoint" => {
                let addr = value
                    .to_socket_addrs()
                    .with_context(|| format!("Endpoint 解析失败: {value}"))?
                    .next()
                    .ok_or_else(|| anyhow!("Endpoint 无法解析为地址: {value}"))?;
                endpoint = Some(addr);
            }
            "Reserved" => {
                let parts: Vec<&str> = value.split(',').collect();
                if parts.len() != 3 {
                    bail!("Reserved 字段格式错误: {value}");
                }
                for (i, p) in parts.iter().enumerate() {
                    reserved[i] = p
                        .trim()
                        .parse()
                        .with_context(|| format!("Reserved 解析失败: {value}"))?;
                }
            }
            "Address" => {
                let ip_part = value.split('/').next().unwrap_or(value).trim();
                match ip_part.parse::<std::net::IpAddr>() {
                    Ok(std::net::IpAddr::V4(v4)) => address_v4 = Some(v4),
                    Ok(std::net::IpAddr::V6(v6)) => address_v6 = Some(v6),
                    Err(e) => bail!("Address 解析失败: {value}: {e}"),
                }
            }
            _ => {}
        }
    }

    Ok(WgConfig {
        private_key: private_key.ok_or_else(|| anyhow!("wg0.conf 缺少 PrivateKey"))?,
        peer_public_key: peer_public_key
            .ok_or_else(|| anyhow!("wg0.conf 缺少 [Peer] PublicKey"))?,
        endpoint: endpoint.ok_or_else(|| anyhow!("wg0.conf 缺少 Endpoint"))?,
        reserved,
        address_v4: address_v4.ok_or_else(|| anyhow!("wg0.conf 缺少 IPv4 Address"))?,
        address_v6: address_v6.ok_or_else(|| anyhow!("wg0.conf 缺少 IPv6 Address"))?,
    })
}
