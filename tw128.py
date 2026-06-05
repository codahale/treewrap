"""TW128 reference implementation.

TW128 is the 128-bit TreeWrap instantiation using Keccak-p[1600,12], a
256-bit capacity, 256-bit keys, 256-bit nonces, and 256-bit tags.
"""

from __future__ import annotations

import hmac

from duplex import MAX_BYTE_ALIGNED_SIGMA_BYTES, Duplex

KEY_BYTES = 32
NONCE_BYTES = 32
TAG_BYTES = 32
CHUNK_BYTES = 8183
MAX_MESSAGE_BYTES = (1 << 64) * CHUNK_BYTES
RHO_BYTES = MAX_BYTE_ALIGNED_SIGMA_BYTES
SUFFIX_BITS = 4

ROOT_PREFIX = b"TW128R"
LEAF_PREFIX = b"TW128L"

INIT_LAST = 0x0C
AD_MORE = 0x09
AD_LAST = 0x0D
MSG_MORE = 0x0A
MSG_LAST = 0x0E
AGG_MORE = 0x0B
AGG_LAST = 0x0F


class InvalidTag(Exception):
    """Raised when TW128 authentication fails."""


def encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes
) -> bytes:
    """Return ciphertext || 32-byte root tag."""
    ciphertext, tag = encrypt_detached(key, nonce, plaintext, associated_data)
    return ciphertext + tag


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext_and_tag: bytes,
    associated_data: bytes,
) -> bytes:
    """Verify ciphertext || tag and return plaintext, or raise InvalidTag."""
    ciphertext_and_tag = _as_bytes("ciphertext_and_tag", ciphertext_and_tag)
    if len(ciphertext_and_tag) < TAG_BYTES:
        raise InvalidTag("ciphertext is shorter than the TW128 tag")
    ciphertext = ciphertext_and_tag[:-TAG_BYTES]
    tag = ciphertext_and_tag[-TAG_BYTES:]
    return decrypt_detached(key, nonce, ciphertext, associated_data, tag)


def encrypt_detached(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: bytes,
) -> tuple[bytes, bytes]:
    """Return (ciphertext, root_tag)."""
    key, nonce, associated_data, plaintext = _validate_common(
        key, nonce, associated_data, plaintext
    )
    if len(plaintext) > MAX_MESSAGE_BYTES:
        raise ValueError(f"plaintext must be at most {MAX_MESSAGE_BYTES} bytes")

    root_plaintext = plaintext[:CHUNK_BYTES]
    leaf_plaintext = plaintext[CHUNK_BYTES:]

    root, keystream = _new_root(
        key, nonce, associated_data, _first_block_len(root_plaintext)
    )

    if not leaf_plaintext:
        # Single chunk (no leaves): elide the aggregation phase. The closing
        # root MSG_LAST call emits the root tag directly, mirroring a leaf.
        root_ciphertext, root_tag = _encrypt_overwrite(
            root, root_plaintext, keystream, TAG_BYTES
        )
        return root_ciphertext, root_tag

    root_ciphertext, _ = _encrypt_overwrite(root, root_plaintext, keystream, 0)

    ciphertext_parts = [root_ciphertext]
    leaf_tags = []
    for chunk_id, chunk in enumerate(_chunks(leaf_plaintext, CHUNK_BYTES), start=1):
        leaf, leaf_keystream = _new_leaf(key, nonce, chunk_id, _first_block_len(chunk))
        leaf_ciphertext, leaf_tag = _encrypt_overwrite(
            leaf, chunk, leaf_keystream, TAG_BYTES
        )
        ciphertext_parts.append(leaf_ciphertext)
        leaf_tags.append(leaf_tag)

    root_tag = _absorb_leaf_tags(root, leaf_tags)
    return b"".join(ciphertext_parts), root_tag


def decrypt_detached(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes,
    tag: bytes,
) -> bytes:
    """Verify detached tag and return plaintext, or raise InvalidTag."""
    key, nonce, associated_data, ciphertext = _validate_common(
        key, nonce, associated_data, ciphertext
    )
    if len(ciphertext) > MAX_MESSAGE_BYTES:
        raise ValueError(f"ciphertext must be at most {MAX_MESSAGE_BYTES} bytes")
    tag = _as_bytes("tag", tag)
    if len(tag) != TAG_BYTES:
        raise InvalidTag(f"tag must be {TAG_BYTES} bytes")

    root_ciphertext = ciphertext[:CHUNK_BYTES]
    leaf_ciphertext = ciphertext[CHUNK_BYTES:]

    root, keystream = _new_root(
        key, nonce, associated_data, _first_block_len(root_ciphertext)
    )

    if not leaf_ciphertext:
        # Single chunk (no leaves): elide the aggregation phase. The closing
        # root MSG_LAST call emits the root tag directly, mirroring a leaf.
        root_plaintext, expected_tag = _decrypt_overwrite(
            root, root_ciphertext, keystream, TAG_BYTES
        )
        if not hmac.compare_digest(expected_tag, tag):
            raise InvalidTag("TW128 authentication failed")
        return root_plaintext

    root_plaintext, _ = _decrypt_overwrite(root, root_ciphertext, keystream, 0)

    plaintext_parts = [root_plaintext]
    leaf_tags = []
    for chunk_id, chunk in enumerate(_chunks(leaf_ciphertext, CHUNK_BYTES), start=1):
        leaf, leaf_keystream = _new_leaf(key, nonce, chunk_id, _first_block_len(chunk))
        leaf_plaintext, leaf_tag = _decrypt_overwrite(
            leaf, chunk, leaf_keystream, TAG_BYTES
        )
        plaintext_parts.append(leaf_plaintext)
        leaf_tags.append(leaf_tag)

    expected_tag = _absorb_leaf_tags(root, leaf_tags)
    if not hmac.compare_digest(expected_tag, tag):
        raise InvalidTag("TW128 authentication failed")
    return b"".join(plaintext_parts)


def _new_root(
    key: bytes, nonce: bytes, associated_data: bytes, first_out_len: int
) -> tuple[Duplex, bytes]:
    duplex = Duplex()
    init = ROOT_PREFIX + key + nonce
    if associated_data:
        # Associated-data phase: the init call emits no keystream, and the
        # closing AD_LAST block produces the first chunk-0 keystream block.
        duplex.duplexing_bits(init, INIT_LAST, SUFFIX_BITS, 0)
        keystream = _absorb_ad(duplex, associated_data, first_out_len)
    else:
        # Empty associated data: elide the AD phase entirely. The init call
        # itself emits the first chunk-0 keystream block, mirroring leaf init.
        keystream = duplex.duplexing_bits(init, INIT_LAST, SUFFIX_BITS, first_out_len)
    return duplex, keystream


def _new_leaf(
    key: bytes, nonce: bytes, chunk_id: int, first_out_len: int
) -> tuple[Duplex, bytes]:
    duplex = Duplex()
    init = LEAF_PREFIX + key + nonce + _le_u64(chunk_id)
    keystream = duplex.duplexing_bits(init, INIT_LAST, SUFFIX_BITS, first_out_len)
    return duplex, keystream


def _absorb_ad(duplex: Duplex, associated_data: bytes, first_out_len: int) -> bytes:
    blocks = _split_at_least_one(associated_data, RHO_BYTES)
    for block in blocks[:-1]:
        duplex.duplexing_bits(block, AD_MORE, SUFFIX_BITS, 0)
    return duplex.duplexing_bits(blocks[-1], AD_LAST, SUFFIX_BITS, first_out_len)


def _encrypt_overwrite(
    duplex: Duplex,
    plaintext: bytes,
    keystream: bytes,
    final_out_len: int,
) -> tuple[bytes, bytes]:
    blocks = _split_at_least_one(plaintext, RHO_BYTES)
    ciphertext = bytearray()
    current_keystream = keystream
    for index, block in enumerate(blocks):
        if len(current_keystream) != len(block):
            raise ValueError("keystream length does not match plaintext block length")
        encrypted = _xor_bytes(block, current_keystream)
        ciphertext.extend(encrypted)
        last = index == len(blocks) - 1
        next_len = final_out_len if last else len(blocks[index + 1])
        suffix = MSG_LAST if last else MSG_MORE
        current_keystream = duplex.duplexing_bits(
            encrypted, suffix, SUFFIX_BITS, next_len
        )
    return bytes(ciphertext), current_keystream


def _decrypt_overwrite(
    duplex: Duplex,
    ciphertext: bytes,
    keystream: bytes,
    final_out_len: int,
) -> tuple[bytes, bytes]:
    blocks = _split_at_least_one(ciphertext, RHO_BYTES)
    plaintext = bytearray()
    current_keystream = keystream
    for index, block in enumerate(blocks):
        if len(current_keystream) != len(block):
            raise ValueError("keystream length does not match ciphertext block length")
        decrypted = _xor_bytes(block, current_keystream)
        plaintext.extend(decrypted)
        last = index == len(blocks) - 1
        next_len = final_out_len if last else len(blocks[index + 1])
        suffix = MSG_LAST if last else MSG_MORE
        current_keystream = duplex.duplexing_bits(block, suffix, SUFFIX_BITS, next_len)
    return bytes(plaintext), current_keystream


def _absorb_leaf_tags(duplex: Duplex, leaf_tags: list[bytes]) -> bytes:
    transcript = b"".join(leaf_tags) + _le_u64(len(leaf_tags))
    blocks = _split_at_least_one(transcript, RHO_BYTES)
    for block in blocks[:-1]:
        duplex.duplexing_bits(block, AGG_MORE, SUFFIX_BITS, 0)
    return duplex.duplexing_bits(blocks[-1], AGG_LAST, SUFFIX_BITS, TAG_BYTES)


def _validate_common(
    key: bytes,
    nonce: bytes,
    associated_data: bytes,
    data: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    key = _as_bytes("key", key)
    nonce = _as_bytes("nonce", nonce)
    associated_data = _as_bytes("associated_data", associated_data)
    data = _as_bytes("data", data)
    if len(key) != KEY_BYTES:
        raise ValueError(f"key must be {KEY_BYTES} bytes")
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce must be {NONCE_BYTES} bytes")
    return key, nonce, associated_data, data


def _split_at_least_one(data: bytes, size: int) -> list[bytes]:
    if not data:
        return [b""]
    return [data[index : index + size] for index in range(0, len(data), size)]


def _chunks(data: bytes, size: int) -> list[bytes]:
    return [data[index : index + size] for index in range(0, len(data), size)]


def _first_block_len(data: bytes) -> int:
    return 0 if not data else min(len(data), RHO_BYTES)


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _le_u64(value: int) -> bytes:
    if value < 0 or value >= 1 << 64:
        raise ValueError("value does not fit in le_u64")
    return value.to_bytes(8, "little")


def _as_bytes(name: str, value: bytes) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    return bytes(value)
