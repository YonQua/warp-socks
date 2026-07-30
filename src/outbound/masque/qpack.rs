// 最小 QPACK + H3 frame 实现，仅服务于 MASQUE CONNECT（普通 HTTP/3 CONNECT，
// 非 RFC 9440 extended CONNECT）。不依赖 h3/qpack crate——那些 crate 的
// CONNECT 路径要么不完整要么帧导向不匹配，这里按 RFC 9114/9204 手写刚好够用的字节。
//
// 编码对照 RFC 9204 附录 B.1（已逐字节核验）：
//   - 请求头用纯静态表引用，Required Insert Count = 0，Base = 0 → 前缀固定 0x00 0x00
//   - :method=CONNECT  → Indexed Static #15        → 0xCF
//   - :authority=host  → Literal Name Ref #0       → 0x50 <len> <host>
//   - authorization    → Literal Name Ref #84 (N=1)→ 0x7F 0x45 <len> <token>
// 响应只需确认 :status=200（Indexed Static #25）。
//
// authorization 用 never-indexed literal（N=1）：RFC 9204 §7.1.3 明确建议
// Authorization/Cookie 不进动态表，边缘同样接受。
//
// 不额外带 host 字段：:authority 用 DoH 解析后的 IP，若再带一条值不同的
// host=域名 字面量，会因 :authority 与 Host 值不一致触发边缘按 RFC 9114
// §4.3.1 / RFC 9113 §8.3.1 的一致性校验，以 H3_MESSAGE_ERROR reset 流。

/// HPACK 前缀整数编码（RFC 7541 §5.1，QPACK 沿用）。
/// `prefix_bits` 个高位已被 `prefix_max` 占用，剩余值用 7-bit 续字节。
fn encode_integer(out: &mut Vec<u8>, value: u64, prefix_bits: u8, prefix_max: u8) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(prefix_max | value as u8);
    } else {
        out.push(prefix_max | max as u8);
        let mut rest = value - max;
        while rest >= 128 {
            out.push(((rest & 0x7f) as u8) | 0x80);
            rest >>= 7;
        }
        out.push(rest as u8);
    }
}

/// 8-bit 前缀字符串字面量（H=0，不 Huffman）：H(1)=0 + Length(7+) + 字节。
fn encode_string(out: &mut Vec<u8>, s: &[u8]) {
    encode_integer(out, s.len() as u64, 7, 0x00);
    out.extend_from_slice(s);
}

/// H3 frame（RFC 9114 §7.1）：Type(varint) + Length(varint) + Payload。
/// varint 用 QUIC 可变长度整数（RFC 9000 §16），这里用 1/2 字节编码即可。
fn write_frame(out: &mut Vec<u8>, frame_type: u64, payload: &[u8]) {
    write_varint(out, frame_type);
    write_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// QUIC 可变长度整数编码（RFC 9000 §16）。长度值 0..64 用 1 字节，否则 2 字节。
fn write_varint(out: &mut Vec<u8>, value: u64) {
    if value < (1 << 6) {
        out.push(value as u8);
    } else if value < (1 << 14) {
        out.push(0x40 | ((value >> 8) as u8));
        out.push((value & 0xff) as u8);
    } else if value < (1 << 30) {
        out.push(0x80 | ((value >> 24) as u8));
        out.push(((value >> 16) & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push((value & 0xff) as u8);
    } else {
        out.push(0xc0 | ((value >> 56) as u8));
        for shift in (0..56).rev() {
            out.push(((value >> shift) & 0xff) as u8);
        }
    }
}

/// 读 QUIC 可变长度整数（RFC 9000 §16）。返回 (值, 消耗字节数)。
#[allow(dead_code)]
fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for &b in &buf[1..len] {
        value = (value << 8) | b as u64;
    }
    Some((value, len))
}

/// 编码 MASQUE CONNECT 请求头的 QPACK field section。
///
/// 输出：`00 00`（RIC=0, Base=0 前缀）+ 三条字段行。
/// `authority` 是 `host:port`（已解析出的 IP:port，或字面量 IP）。
///
/// 不附加 host 字段：曾尝试额外带一条 `host=域名:port` 字面量给边缘做策略/
/// 日志，但 `:authority` 是解析后的 IP，与 host 值不一致时边缘按 RFC 9114
/// §4.3.1 / RFC 9113 §8.3.1 的一致性校验以 `H3_MESSAGE_ERROR`（270）reset
/// 了流，因此这里只发 `:authority`。
pub fn encode_connect_request(authority: &str, bearer_token: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    // QPACK encoded field section 前缀：Required Insert Count(8-bit)=0, Base S(1)+Delta(7)=0
    out.push(0x00);
    out.push(0x00);

    // :method = CONNECT —— Indexed Field Line, Static #15 (1 T 001111)
    out.push(0b11001111);

    // :authority = host:port —— Literal with Name Ref, Static #0, N=0, T=1 → 0x50
    out.push(0b01010000);
    encode_string(&mut out, authority.as_bytes());

    // authorization = Bearer <token> —— Literal with Name Ref, Static #84, N=1, T=1
    //   第一字节：0 1 1 1 1111 = 0x7F（4-bit prefix 填满 15，因为 84 ≥ 15）
    //   续字节：84 - 15 = 69 → 0x45
    out.push(0x7F);
    out.push(0x45);
    encode_string(&mut out, bearer_token.as_bytes());

    out
}

/// 把 QPACK field section 封装成 H3 HEADERS frame（type=0x01）。
pub fn headers_frame(qpack_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(qpack_payload.len() + 4);
    write_frame(&mut out, 0x01, qpack_payload);
    out
}

/// 把隧道字节封装成 H3 DATA frame（type=0x00）。CONNECT 成功后，隧道两端的
/// 应用数据都要经过这层分帧（RFC 9114 §4.4，对应 HTTP/2 CONNECT 里 DATA
/// frame 承载隧道字节的语义）——warp-go 靠 quic-go 的 http3.RequestStream
/// 自动做这层分帧，我们手写实现所以要显式包一层。
pub fn data_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 9);
    write_frame(&mut out, 0x00, payload);
    out
}

/// 控制流前导：stream type(0x00=control) + 空 SETTINGS frame（type=0x04, len=0）。
/// 空 SETTINGS 表示用 QPACK 默认表容量 0、不阻塞流，足够发起 CONNECT。
pub fn control_stream_prelude() -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    out.push(0x00); // control stream type
    write_frame(&mut out, 0x04, &[]); // SETTINGS frame, empty
    out
}

/// H3 CONNECT 响应里我们关心的字段：状态码 + 可选的 Cloudflare 边缘落地 colo
/// （如 "LAX"），后者只用于日志展示，取不到不算错误。
pub struct ResponseHeaders {
    pub status: u16,
    pub colo: Option<String>,
}

/// 解析响应 HEADERS frame 的完整 QPACK field section。
///
/// 逐行解析：Indexed Field Line 取静态表状态码；Literal with Name Reference
/// （值来自动态/静态表引用的头，我们不关心，只跳过）；Literal with Literal Name
/// （字段名也是字面量，`cf-warp-colo` 这类自定义头必然走这条，值和名字常见 Huffman
/// 压缩，见 huffman.rs）。
///
/// # Errors
/// 解析失败、数据不足、或字段序列中未出现 :status 时返回错误。
pub fn decode_headers(payload: &[u8]) -> Result<ResponseHeaders, &'static str> {
    // QPACK 前缀至少 2 字节：Required Insert Count(8) + Base(1+7)。这里只需跳过。
    let mut pos = skip_integer(payload, 0, 8)?;
    pos = skip_integer(payload, pos, 7)?; // Base

    let mut status = None;
    let mut colo = None;

    while pos < payload.len() {
        let b = payload[pos];
        if b & 0x80 != 0 {
            // Indexed Field Line: 1 T Index(6)
            let static_table = b & 0x40 != 0;
            let (idx, n) = decode_integer(payload, pos, 6)?;
            pos = n;
            if static_table {
                if idx == 25 {
                    status = Some(200);
                } else if let Some(code) = static_status(idx) {
                    status = Some(code);
                }
            }
        } else if b & 0xc0 == 0x40 {
            // Literal with Name Ref: 01 N T NameIndex(4) + value。这类字段的名字
            // 来自表，我们关心的自定义头都不在表里，值也不用管，跳过即可。
            let (_, n) = decode_integer(payload, pos, 4)?;
            pos = skip_literal_value(payload, n)?;
        } else if b & 0xe0 == 0x20 {
            // Literal with Literal Name（RFC 9204 §4.5.6）：001 N H NameLen(3) +
            // name + H Len(7) + value，name/value 各自独立标记是否 Huffman 压缩。
            let name_huffman = b & 0x08 != 0;
            let (name_len, n) = decode_integer(payload, pos, 3)?;
            let name_end = n.checked_add(name_len as usize).ok_or("字段名长度溢出")?;
            if name_end > payload.len() {
                return Err("字段名内容越界");
            }
            let name = decode_string(&payload[n..name_end], name_huffman)?;
            let (value, new_pos) = read_literal_value(payload, name_end)?;
            pos = new_pos;
            if name == b"cf-warp-colo" {
                colo = String::from_utf8(value).ok();
            }
        } else {
            return Err("响应包含未预期的 post-base 字段");
        }
    }
    let status = status.ok_or("响应头中未找到 :status")?;
    Ok(ResponseHeaders { status, colo })
}

/// 读一个 H+Length(7 位前缀) + 字节串，按 H 标记决定是否过 Huffman 解码。
fn read_literal_value(payload: &[u8], pos: usize) -> Result<(Vec<u8>, usize), &'static str> {
    if pos >= payload.len() {
        return Err("值长度解析越界");
    }
    let huffman = payload[pos] & 0x80 != 0;
    let (len, start) = decode_integer(payload, pos, 7)?;
    let end = start.checked_add(len as usize).ok_or("值长度溢出")?;
    if end > payload.len() {
        return Err("值内容越界");
    }
    Ok((decode_string(&payload[start..end], huffman)?, end))
}

/// 只跳过一个值字段，不关心内容（Literal with Name Ref 分支用）。
fn skip_literal_value(payload: &[u8], pos: usize) -> Result<usize, &'static str> {
    let (len, start) = decode_integer(payload, pos, 7)?;
    let end = start.checked_add(len as usize).ok_or("值长度溢出")?;
    if end > payload.len() {
        return Err("值内容越界");
    }
    Ok(end)
}

fn decode_string(raw: &[u8], huffman: bool) -> Result<Vec<u8>, &'static str> {
    if huffman {
        super::huffman::decode(raw).map_err(|_| "Huffman 解码失败")
    } else {
        Ok(raw.to_vec())
    }
}

/// QPACK 静态表 :status 索引到状态码的映射（仅常见的几个）。
fn static_status(idx: u64) -> Option<u16> {
    match idx {
        24 => Some(103),
        25 => Some(200),
        26 => Some(304),
        27 => Some(404),
        28 => Some(503),
        63 => Some(100),
        64 => Some(204),
        65 => Some(206),
        66 => Some(302),
        67 => Some(400),
        68 => Some(403),
        69 => Some(421),
        70 => Some(425),
        71 => Some(500),
        _ => None,
    }
}

/// 解码前缀整数，返回 (值, 新位置)。
fn decode_integer(buf: &[u8], pos: usize, prefix_bits: u8) -> Result<(u64, usize), &'static str> {
    let max = (1u64 << prefix_bits) - 1;
    let mask = max as u8;
    if pos >= buf.len() {
        return Err("整数解析越界");
    }
    let mut value = (buf[pos] & mask) as u64;
    let mut p = pos + 1;
    if value < max {
        return Ok((value, p));
    }
    let mut shift = 0u32;
    loop {
        if p >= buf.len() {
            return Err("整数续字节越界");
        }
        let b = buf[p];
        p += 1;
        value += ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 56 {
            return Err("整数过长");
        }
    }
    Ok((value, p))
}

/// 跳过一个前缀整数（不关心值），返回新位置。
fn skip_integer(buf: &[u8], pos: usize, prefix_bits: u8) -> Result<usize, &'static str> {
    decode_integer(buf, pos, prefix_bits).map(|(_, p)| p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_method_connect_is_indexed_static_15() {
        let req = encode_connect_request("example.com:443", "tkn");
        // 前缀 00 00，然后 :method CONNECT = 0xCF
        assert_eq!(&req[..3], &[0x00, 0x00, 0xCF]);
    }

    #[test]
    fn encode_authority_matches_rfc_b1_pattern() {
        // 对照 RFC 9204 B.1：:path=/index.html 编码为 51 0b <bytes>。
        // 我们 :authority 同为 Literal Name Ref(T=1)，NameIndex=0 → 50 0b <bytes>。
        let req = encode_connect_request("example.com:443", "x");
        // 找到 :authority 行：0x50 之后是长度 0x0b? example.com:443 是 15 字节
        let auth_value = b"example.com:443";
        let mut expect = vec![0x00, 0x00, 0xCF];
        expect.push(0x50);
        expect.push(auth_value.len() as u8);
        expect.extend_from_slice(auth_value);
        assert_eq!(&req[..expect.len()], &expect[..]);
    }

    #[test]
    fn encode_authorization_uses_static_84_never_indexed() {
        let req = encode_connect_request("h:1", "abc");
        // authorization 段：0x7F 0x45 然后 H=0 + len + "abc"
        let auth_idx = req
            .windows(2)
            .position(|w| w == [0x7F, 0x45])
            .expect("应有 authorization 编码");
        assert_eq!(req[auth_idx + 2], 3); // len=3
        assert_eq!(&req[auth_idx + 3..auth_idx + 6], b"abc");
    }

    #[test]
    fn headers_frame_wraps_with_type_1() {
        let payload = [0x00, 0x00, 0xCF];
        let f = headers_frame(&payload);
        assert_eq!(f[0], 0x01); // HEADERS type
        assert_eq!(f[1], 3); // length varint
        assert_eq!(&f[2..], &payload);
    }

    #[test]
    fn data_frame_wraps_with_type_0() {
        let payload = [1u8, 2, 3];
        let f = data_frame(&payload);
        assert_eq!(f[0], 0x00); // DATA type
        assert_eq!(f[1], 3); // length varint
        assert_eq!(&f[2..], &payload);
    }

    #[test]
    fn control_stream_prelude_is_settings() {
        let p = control_stream_prelude();
        assert_eq!(p[0], 0x00); // control stream type
        assert_eq!(p[1], 0x04); // SETTINGS frame type
        assert_eq!(p[2], 0x00); // length 0
    }

    #[test]
    fn decode_status_200_indexed() {
        // 响应：前缀 00 00 + Indexed Static #25 = 0xD9
        let resp = [0x00, 0x00, 0xD9];
        assert_eq!(decode_headers(&resp).unwrap().status, 200);
    }

    #[test]
    fn decode_status_404_indexed() {
        let resp = [0x00, 0x00, 0xDB]; // #27 = 404
        assert_eq!(decode_headers(&resp).unwrap().status, 404);
    }

    #[test]
    fn decode_headers_extracts_colo_from_real_response() {
        // 真实 MASQUE CONNECT 响应抓包（见 outbound/masque/mod.rs 的手工解析记录）：
        // :status=200 + cf-warp-metal + cf-warp-colo=LAX（Huffman）+ cf-team。
        let resp = hex(
            "0000d92f0324ab781d95ad49523a3f8508a57db6bf2f0224ab781d95ac43d07f\
             83cf0fe72d24ab24a3a796640db6196429630000d32db446a42942d0000000000f",
        );
        let headers = decode_headers(&resp).unwrap();
        assert_eq!(headers.status, 200);
        assert_eq!(headers.colo.as_deref(), Some("LAX"));
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn varint_roundtrip() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 25);
        assert_eq!(read_varint(&buf), Some((25, 1)));

        let mut buf = Vec::new();
        write_varint(&mut buf, 15293);
        assert_eq!(read_varint(&buf), Some((15293, 2)));
    }
}
