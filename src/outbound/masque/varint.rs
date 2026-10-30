//! H3 帧与 H2 capsule 共用 QUIC 整数编码；协议细节由锁定版本的 Quinn 实现。

use quinn_proto::{coding::Codec, VarInt};

pub(super) fn write(out: &mut Vec<u8>, value: u64) {
    // 调用方只传固定帧类型或有界缓冲区长度，均小于 QUIC 的 62-bit 上限。
    VarInt::from_u64(value)
        .expect("frame type and bounded payload length fit QUIC varint")
        .encode(out);
}

pub(super) fn read(mut bytes: &[u8]) -> Option<(u64, usize)> {
    let before = bytes.len();
    let value = VarInt::decode(&mut bytes).ok()?;
    Some((value.into_inner(), before - bytes.len()))
}
