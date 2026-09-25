//! Cloudflare MASQUE H2 CONNECT-IP outlet over a Psiphon TCP upstream.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use smoltcp::wire::{IpAddress, IpCidr};

use super::h2;
use crate::netstack::{Net, NetConfig};
use crate::outbound::ip;
use crate::outbound::{Connected, Host, Outbound};
use crate::registration::RegCredentials;

pub struct MasqueH2 {
    net: Net,
}

impl MasqueH2 {
    /// Establish the H2 CONNECT-IP tunnel through the supplied Psiphon upstream.
    ///
    /// # Errors
    /// Returns an error if registration addresses, the H2 tunnel, or the IP stack fail.
    pub async fn new(creds: &RegCredentials, upstream: Arc<dyn Outbound>) -> Result<Self> {
        let config = build_net_config(creds)?;
        let device = h2::connect(creds, upstream).await?;
        let net = Net::new(device, config).context("启动 MASQUE H2 双栈网络栈失败")?;
        Ok(Self { net })
    }
}

fn build_net_config(creds: &RegCredentials) -> Result<NetConfig> {
    let registration = &creds.registration;
    let mut addrs = Vec::with_capacity(2);

    if !registration.assigned_ipv4.trim().is_empty() {
        let ip: Ipv4Addr = registration
            .assigned_ipv4
            .parse()
            .context("MASQUE 注册 IPv4 地址无效")?;
        let address = IpAddress::from(IpAddr::V4(ip));
        addrs.push(IpCidr::new(address, 32));
    }
    if !registration.assigned_ipv6.trim().is_empty() {
        let ip: Ipv6Addr = registration
            .assigned_ipv6
            .parse()
            .context("MASQUE 注册 IPv6 地址无效")?;
        let address = IpAddress::from(IpAddr::V6(ip));
        addrs.push(IpCidr::new(address, 128));
    }
    if addrs.is_empty() {
        bail!("MASQUE 注册信息缺少分配的 IPv4/IPv6 地址");
    }

    Ok(ip::net_config(addrs))
}

#[async_trait]
impl Outbound for MasqueH2 {
    fn name(&self) -> &'static str {
        "MASQUE-H2"
    }

    async fn connect_tcp(&self, host: Host, port: u16) -> std::io::Result<Connected> {
        ip::connect_tcp(&self.net, host, port).await
    }
}
