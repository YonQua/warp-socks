// 隧道内 DNS 解析：对应 Go 版 wireguard/tun/netstack/tun.go 里
// LookupContextHost/exchange 的角色——本项目的 SOCKS5 CONNECT 用
// `curl --socks5-hostname`（lib/core/probe.sh:23），域名解析必须在
// 隧道内完成，不能用宿主机自己的 DNS。
//
// 报文编解码手写而非引入通用 DNS crate：查询侧只需要单问题、无压缩的
// 最简报文；响应侧只需要跳过 name（含压缩指针）取出 A/AAAA 记录，
// Go 版自己也是手写 dnsmessage 而非依赖第三方库，同等复杂度没必要
// 为此引入一整个 DNS 库依赖。
//
// Phase 2 起查询通过项目内 Net 的虚拟 UDP socket 发送——和 SOCKS5
// CONNECT 的 TCP 流走同一个虚拟网卡，不再需要手搓 IP/UDP 头（那是 Phase 1
// 独立验证 boringtun 收发时的临时做法，现在虚拟网卡本身就是应用层 socket）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::netstack::Net;
use anyhow::{bail, Context, Result};
use rand::Rng;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RecordType {
    A,
    Aaaa,
}

impl RecordType {
    fn qtype(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Aaaa => 28,
        }
    }
}

// 进程级 DNS 缓存：浏览器加载单个网页常常对同一 host 开多条并发连接（比如
// HTTP/1.1 每 origin 6 条是经典行为），每条 SOCKS5/SOCKS4/HTTP CONNECT 都
// 各自调用一次 resolve()，缓存前会各走一次隧道内往返，重复消耗本就吃紧的
// 隧道带宽。按响应里的真实 TTL 缓存（夹在 5s~300s 之间：下限避免 TTL=0
// 时缓存形同虚设，上限避免小概率的 DNS 生效延迟导致长时间用旧地址）。
const CACHE_MIN_TTL: Duration = Duration::from_secs(5);
const CACHE_MAX_TTL: Duration = Duration::from_secs(300);

struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

static CACHE: LazyLock<Mutex<HashMap<(String, RecordType), CacheEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn cache_get(key: &(String, RecordType)) -> Option<Vec<IpAddr>> {
    let cache = CACHE.lock().unwrap();
    let entry = cache.get(key)?;
    (entry.expires_at > Instant::now()).then(|| entry.addrs.clone())
}

// 命中数上限之后才顺带清理过期项，避免每次写入都遍历整个表；域名种类
// 有限的场景下（个人/小规模代理）这个上限基本不会被触及。
fn cache_put(key: (String, RecordType), addrs: Vec<IpAddr>, ttl_secs: u32) {
    let ttl = Duration::from_secs(ttl_secs as u64).clamp(CACHE_MIN_TTL, CACHE_MAX_TTL);
    let mut cache = CACHE.lock().unwrap();
    if cache.len() > 500 {
        let now = Instant::now();
        cache.retain(|_, e| e.expires_at > now);
    }
    cache.insert(
        key,
        CacheEntry {
            addrs,
            expires_at: Instant::now() + ttl,
        },
    );
}

fn encode_dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&[0u8; 6]); // AN/NS/AR COUNT

    for label in name.trim_end_matches('.').split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0); // root

    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    msg
}

// 跳过一个 DNS name 字段（label 序列或压缩指针），返回紧随其后的位置。
// 压缩指针只占 2 字节且不需要跟随指向的位置——跳过时不关心具体域名内容。
fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        if pos >= buf.len() {
            bail!("DNS 报文越界: name 解析越界");
        }
        let len = buf[pos];
        if len == 0 {
            return Ok(pos + 1);
        } else if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                bail!("DNS 报文越界: 压缩指针越界");
            }
            return Ok(pos + 2);
        } else {
            pos += 1 + len as usize;
        }
    }
}

// 返回解析出的地址，以及这些地址里最小的 TTL（秒，供 resolve() 决定缓存
// 多久；没有任何 A/AAAA 记录时无意义，调用方会先检查 addrs 是否为空）。
fn parse_dns_response(buf: &[u8], expected_id: u16) -> Result<(Vec<IpAddr>, u32)> {
    if buf.len() < 12 {
        bail!("DNS 响应过短: {} 字节", buf.len());
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        bail!("DNS 响应 ID 不匹配: 期望 {expected_id}, 实际 {id}");
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos += 4; // QTYPE + QCLASS
    }

    let mut addrs = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            bail!("DNS 响应越界: answer 头部不完整");
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > buf.len() {
            bail!("DNS 响应越界: rdata 不完整");
        }
        match (rtype, rdlength) {
            (1, 4) => {
                addrs.push(IpAddr::V4(Ipv4Addr::new(
                    buf[pos],
                    buf[pos + 1],
                    buf[pos + 2],
                    buf[pos + 3],
                )));
                min_ttl = min_ttl.min(ttl);
            }
            (28, 16) => {
                let octets: [u8; 16] = buf[pos..pos + 16].try_into().unwrap();
                addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
                min_ttl = min_ttl.min(ttl);
            }
            _ => {}
        }
        pos += rdlength;
    }

    Ok((addrs, min_ttl))
}

// 通过隧道虚拟网卡的 UDP socket 向 dns_server 解析一个域名。
pub async fn resolve(
    net: &Net,
    dns_server: SocketAddr,
    name: &str,
    record_type: RecordType,
    timeout: Duration,
) -> Result<Vec<IpAddr>> {
    let cache_key = (name.to_ascii_lowercase(), record_type);
    if let Some(addrs) = cache_get(&cache_key) {
        return Ok(addrs);
    }

    let query_id: u16 = rand::thread_rng().gen();
    let query = encode_dns_query(query_id, name, record_type.qtype());

    let sock = net
        .udp_bind("0.0.0.0:0".parse().unwrap())
        .await
        .context("绑定隧道内 UDP socket 失败")?;
    sock.send_to(&query, dns_server)
        .await
        .context("发送 DNS 查询失败")?;

    // 隧道并发吞吐较高时单个 UDP 包偶发丢失是正常现象，之前只发一次查询就
    // 死等整个 timeout，一丢包就是几秒钟的超时失败。按固定间隔重发同一个
    // query_id（幂等）明显提升单次丢包场景下的成功率，不改变对调用方暴露
    // 的总超时时长。
    const RETRY_INTERVAL: Duration = Duration::from_millis(1200);

    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("DNS 解析 {name} 超时（{timeout:?}）");
        }
        let wait = remaining.min(RETRY_INTERVAL);
        match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) if from == dns_server => {
                if let Ok((addrs, ttl)) = parse_dns_response(&buf[..n], query_id) {
                    if !addrs.is_empty() {
                        cache_put(cache_key, addrs.clone(), ttl);
                        return Ok(addrs);
                    }
                }
            }
            Ok(Ok(_)) => continue, // 非期望来源，丢弃继续等
            Ok(Err(e)) => return Err(e).context("隧道内 UDP 接收失败"),
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    bail!("DNS 解析 {name} 超时（{timeout:?}）");
                }
                sock.send_to(&query, dns_server)
                    .await
                    .context("重发 DNS 查询失败")?;
            }
        }
    }
}
