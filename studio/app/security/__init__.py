"""共享安全工具：POPOPX 隐私增强邀请链接封装。"""

from .opaque_invite_codec import (
    FORMAT_VERSION,
    INVITE_KEY,
    LINK_PREFIX,
    OpaqueInviteError,
    decode_invite_link,
    encode_invite_link,
    looks_like_opaque_invite,
)

__all__ = [
    "FORMAT_VERSION",
    "INVITE_KEY",
    "LINK_PREFIX",
    "OpaqueInviteError",
    "decode_invite_link",
    "encode_invite_link",
    "looks_like_opaque_invite",
]