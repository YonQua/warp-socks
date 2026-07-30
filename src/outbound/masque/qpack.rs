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

/// 从响应 HEADERS frame 的 QPACK 负载里提取 :status 码。
///
/// 响应通常是 Indexed Static #25（:status=200）→ 字节 0xD9，但为稳健起见
/// 通用解析：跳过 QPACK 前缀，逐行解析直到找到 :status。
///
/// # Errors
/// 解析失败或数据不足时返回错误。
pub fn decode_status(payload: &[u8]) -> Result<u16, &'static str> {
    // QPACK 前缀至少 2 字节：Required Insert Count(8) + Base(1+7)。这里只需跳过。
    // Required Insert Count 用 8-bit prefix；若 ≥255 还会有续字节，跳过到读完。
    let mut pos = skip_integer(payload, 0, 8)?;
    pos = skip_integer(payload, pos, 7)?; // Base

    while pos < payload.len() {
        let b = payload[pos];
        if b & 0x80 != 0 {
            // Indexed Field Line: 1 T Index(6)
            let static_table = b & 0x40 != 0;
            let (idx, n) = decode_integer(payload, pos, 6)?;
            pos = n;
            if static_table && idx == 25 {
                return Ok(200);
            }
            // 其它 status 索引（如 26=304, 27=404, 28=503, 63=100, 64=204...）
            if static_table {
                if let Some(code) = static_status(idx) {
                    return Ok(code);
                }
            }
        } else if b & 0xc0 == 0x40 {
            // Literal with Name Ref: 01 N T NameIndex(4) + value
            let (_, n) = decode_integer(payload, pos, 4)?;
            pos = n;
            let (name_is_status, after_name) = (false, pos); // 名字引用无法直接判定 :status
            let _ = name_is_status;
            pos = skip_string(payload, after_name)?;
        } else if b & 0xe0 == 0x20 {
            // Literal with Literal Name: 001 N NameLen(4-ish) ... 复杂，跳过整行
            // 名字长度在 4-bit prefix（实际编码见 §4.5.6，这里宽松跳过 value 即可）
            // 为健壮性：遇到无法确定的行直接报错，调用方应只收到纯 indexed 响应。
            return Err("响应包含 literal-name 字段，无法最小解析 status");
        } else {
            // post-base indexed/literal，MASQUE 响应不会用到
            return Err("响应包含 post-base 字段，未预期");
        }
    }
    Err("响应头中未找到 :status")
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

/// 跳过一个 8-bit 前缀字符串字面量（H + Length(7) + bytes），返回新位置。
fn skip_string(buf: &[u8], pos: usize) -> Result<usize, &'static str> {
    if pos >= buf.len() {
        return Err("字符串解析越界");
    }
    let (len, p) = decode_integer(buf, pos, 7)?;
    let end = p.checked_add(len as usize).ok_or("字符串长度溢出")?;
    if end > buf.len() {
        return Err("字符串内容越界");
    }
    Ok(end)
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
        assert_eq!(decode_status(&resp).unwrap(), 200);
    }

    #[test]
    fn decode_status_404_indexed() {
        let resp = [0x00, 0x00, 0xDB]; // #27 = 404
        assert_eq!(decode_status(&resp).unwrap(), 404);
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
