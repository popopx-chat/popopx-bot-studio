"""POPOPX 隐私增强邀请链接的跨语言加密封装格式（v1）。

Wire format::

    link  = "https://popopx.chat." + base64url(nonce || ciphertext || tag)

* key   = HKDF-SHA256(ikm=MASTER_KEY, salt=HKDF_SALT, info=HKDF_INFO, len=32)
* nonce = 12 字节随机数，每条链接独立生成
* AEAD  = ChaCha20-Poly1305，空 AAD，16 字节 tag 由 ``cryptography`` 追加在密文后
* token = 无填充 Base64URL（字母表 ``A-Z a-z 0-9 - _``）

密钥随客户端一起编译：这是隐藏 ``smpN.popopx.im`` 节点域名与集群拓扑的隐私层，
而不是对拿到 App 二进制的人的保密承诺。``opaque_invite_vectors.json``（与本模块
同目录）是其他语言实现必须逐字节匹配的契约，自检组 ``invite_codec`` 会双向校验。
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

FORMAT_VERSION = 1
LINK_PREFIX = "https://popopx.chat."
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32
AAD = b""

# 固定主密钥：换掉它会让所有已发出的隐私链接失效，客户端也必须同步换。
MASTER_KEY = bytes.fromhex("6223e28971f041bbc5f8f71d2257dd3f910c3ca4f16d1ceab02906201ae63d30")
HKDF_SALT = b"popopx.chat opaque invite v1"
HKDF_INFO = b"popopx-opaque-invite-key"

MAX_ADDRESS_BYTES = 4096
# 12B nonce + 4096B 明文 + 16B tag 的 base64url 上界（含取整余量）。
MAX_TOKEN_CHARS = ((NONCE_BYTES + MAX_ADDRESS_BYTES + TAG_BYTES + 2) // 3) * 4

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class OpaqueInviteError(ValueError):
    """邀请链接无法封装或解封：格式、长度或 AEAD 校验失败。"""


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = KEY_BYTES) -> bytes:
    """HKDF-SHA256（RFC 5869）；自检用 RFC 向量与本函数对照。"""
    if not isinstance(length, int) or not 1 <= length <= 255 * hashes.SHA256().digest_size:
        raise ValueError(f"HKDF 输出长度必须在 1..{255 * hashes.SHA256().digest_size} 之间")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def derive_invite_key() -> bytes:
    """从固定主密钥派生唯一的邀请链接 AEAD 密钥。"""
    return hkdf_sha256(MASTER_KEY, HKDF_SALT, HKDF_INFO, KEY_BYTES)


INVITE_KEY = derive_invite_key()


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(token: str) -> bytes:
    if not token or not _TOKEN_RE.match(token):
        raise OpaqueInviteError("邀请链接编码必须是 1 位以上的 Base64URL 字符（不允许填充或空白）")
    if len(token) % 4 == 1:
        raise OpaqueInviteError("邀请链接编码长度非法（Base64URL 长度模 4 不能为 1）")
    padded = token + "=" * (-len(token) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise OpaqueInviteError(f"邀请链接编码无法解码：{type(exc).__name__}") from exc


def _clean_address(address: str) -> str:
    if not isinstance(address, str):
        raise OpaqueInviteError(f"联系地址必须是字符串，收到 {type(address).__name__}")
    text = address.strip()
    if not text:
        raise OpaqueInviteError("联系地址不能为空")
    if any(ch in text for ch in "\x00\r\n"):
        raise OpaqueInviteError("联系地址不能包含 NUL 或换行")
    if len(text.encode("utf-8")) > MAX_ADDRESS_BYTES:
        raise OpaqueInviteError(f"联系地址超过 {MAX_ADDRESS_BYTES} 字节上限")
    return text


def encode_invite_link(address: str, *, nonce: Optional[bytes] = None) -> str:
    """把原始 ``smp://`` 联系地址封装为 ``https://popopx.chat.<Base64URL>``。

    ``nonce`` 只用于跨语言测试向量的确定性复现；生产调用一律省略，由
    :func:`secrets.token_bytes` 生成 12 字节随机 nonce。
    """
    text = _clean_address(address)
    if nonce is None:
        nonce = secrets.token_bytes(NONCE_BYTES)
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_BYTES:
        raise OpaqueInviteError(f"nonce 必须是 {NONCE_BYTES} 字节")
    sealed = ChaCha20Poly1305(INVITE_KEY).encrypt(bytes(nonce), text.encode("utf-8"), AAD)
    return LINK_PREFIX + b64url_encode(bytes(nonce) + sealed)


def decode_invite_link(link: str) -> str:
    """解封 ``https://popopx.chat.<Base64URL>``，返回原始联系地址。

    密文被截断、篡改或密钥不匹配时抛 :class:`OpaqueInviteError`，绝不返回半截明文。
    """
    if not isinstance(link, str):
        raise OpaqueInviteError(f"邀请链接必须是字符串，收到 {type(link).__name__}")
    text = link.strip()
    if not text.startswith(LINK_PREFIX):
        raise OpaqueInviteError(f"邀请链接必须以 {LINK_PREFIX!r} 开头")
    token = text[len(LINK_PREFIX):]
    if len(token) > MAX_TOKEN_CHARS:
        raise OpaqueInviteError(f"邀请链接编码超过 {MAX_TOKEN_CHARS} 字符上限")
    raw = b64url_decode(token)
    if len(raw) < NONCE_BYTES + TAG_BYTES + 1:
        raise OpaqueInviteError("邀请链接密文长度不足（至少 12B nonce + 1B 明文 + 16B tag）")
    nonce, sealed = raw[:NONCE_BYTES], raw[NONCE_BYTES:]
    try:
        plain = ChaCha20Poly1305(INVITE_KEY).decrypt(nonce, sealed, AAD)
    except InvalidTag as exc:
        raise OpaqueInviteError("邀请链接密文校验失败：疑似被截断或篡改") from exc
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OpaqueInviteError("邀请链接明文不是合法 UTF-8") from exc


def looks_like_opaque_invite(text: str) -> bool:
    """轻量前缀判断，不尝试解密；供 UI 与路由分流使用。"""
    return isinstance(text, str) and text.strip().startswith(LINK_PREFIX)


__all__ = [
    "FORMAT_VERSION",
    "LINK_PREFIX",
    "NONCE_BYTES",
    "TAG_BYTES",
    "KEY_BYTES",
    "AAD",
    "MASTER_KEY",
    "HKDF_SALT",
    "HKDF_INFO",
    "INVITE_KEY",
    "MAX_ADDRESS_BYTES",
    "MAX_TOKEN_CHARS",
    "OpaqueInviteError",
    "hkdf_sha256",
    "derive_invite_key",
    "b64url_encode",
    "b64url_decode",
    "encode_invite_link",
    "decode_invite_link",
    "looks_like_opaque_invite",
]