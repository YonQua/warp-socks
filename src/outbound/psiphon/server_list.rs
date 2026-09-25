use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::read::ZlibDecoder;
use rsa::{pkcs1v15::Pkcs1v15Sign, pkcs8::DecodePublicKey, RsaPublicKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::outbound::{https, Outbound};

const SERVER_LIST_HOST: &str = "s3.amazonaws.com";
const SERVER_LIST_PATH: &str = "/psiphon/web/mjr4-p23r-puwl/server_list_compressed";
const SIGNING_PUBLIC_KEY: &str = include_str!("signing_key.txt");
const MAX_PACKAGE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerEntry {
    pub ip_address: String,
    pub ssh_port: u16,
    pub ssh_username: String,
    pub ssh_password: String,
    pub ssh_host_key: String,
    pub capabilities: Vec<String>,
    pub region: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatedPackage {
    data: String,
    signing_public_key_digest: String,
    signature: String,
}

pub async fn fetch(outbound: &dyn Outbound, country: &str) -> Result<Vec<ServerEntry>> {
    let compressed = https::get(
        outbound,
        SERVER_LIST_HOST,
        SERVER_LIST_PATH,
        MAX_PACKAGE_BYTES,
        Duration::from_secs(30),
    )
    .await
    .context("failed to download Psiphon server list")?;

    let country = country.to_owned();
    tokio::task::spawn_blocking(move || decode(&compressed, &country))
        .await
        .context("Psiphon server list decoding task failed")?
}

fn decode(compressed: &[u8], country: &str) -> Result<Vec<ServerEntry>> {
    let mut decoded = Vec::new();
    ZlibDecoder::new(compressed)
        .take((MAX_PACKAGE_BYTES + 1) as u64)
        .read_to_end(&mut decoded)
        .context("failed to decompress Psiphon server list")?;
    if decoded.len() > MAX_PACKAGE_BYTES {
        bail!("Psiphon server list exceeds decompressed size limit");
    }

    let package: AuthenticatedPackage =
        serde_json::from_slice(&decoded).context("invalid Psiphon server list package")?;
    let signing_key = SIGNING_PUBLIC_KEY.trim();
    let digest = STANDARD
        .decode(&package.signing_public_key_digest)
        .context("invalid Psiphon signing key digest")?;
    if digest.as_slice() != Sha256::digest(signing_key.as_bytes()).as_slice() {
        bail!("Psiphon signing key digest mismatch");
    }
    let key_der = STANDARD
        .decode(signing_key)
        .context("invalid Psiphon signing public key")?;
    let key =
        RsaPublicKey::from_public_key_der(&key_der).context("invalid Psiphon RSA public key")?;
    let signature = STANDARD
        .decode(&package.signature)
        .context("invalid Psiphon server list signature")?;
    key.verify(
        Pkcs1v15Sign::new::<Sha256>(),
        &Sha256::digest(package.data.as_bytes()),
        &signature,
    )
    .context("Psiphon server list signature verification failed")?;

    // The signed data is a newline-separated list of hex-encoded legacy entries.
    let mut entries = Vec::new();
    for line in package.data.lines().filter(|line| !line.is_empty()) {
        let Ok(bytes) = hex::decode(line) else {
            continue;
        };
        let mut fields = bytes.splitn(5, |byte| *byte == b' ');
        let Some(json) = fields.nth(4) else { continue };
        let Ok(entry) = serde_json::from_slice::<ServerEntry>(json) else {
            continue;
        };
        if entry.region.eq_ignore_ascii_case(country) && entry.ip_address.parse::<IpAddr>().is_ok()
        {
            entries.push(entry);
        }
    }
    Ok(entries)
}
