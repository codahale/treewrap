"""
TW128 — reference implementation of the TW128 instantiation of TreeWrap.

Parameters (Section 7):
    p        = Keccak-p[1600, 12]
    b        = 1600          (200 bytes)
    c        = 256           (32 bytes)
    r        = 1344          (168 bytes)
    k        = 256           (32 bytes)
    nonce    ∈ {0,1}^128     (16 bytes)
    B        = 64512 bits    (8064 bytes = 48 × 168)
    t_leaf   = 256           (32 bytes)
    τ        = 256           (32 bytes)
    η        = encode_string (SP 800-185)
    ν        = right_encode  (SP 800-185)
    α        = 0

Padding is pad10* from [Men23]: append a 1 bit, then zeros to fill to a
multiple of r.  This is NOT FIPS 202's pad10*1 (no trailing 1 bit).
In byte terms (Keccak LSB-first): append 0x01, then 0x00 bytes.
"""

from __future__ import annotations
from hmac import compare_digest

from keccak import keccak_p1600
from sp800185 import encode_string, right_encode

# -- constants -----------------------------------------------------------------

_B      = 200    # state width in bytes
_R      = 168    # rate in bytes
_C      = 32     # capacity in bytes
_K      = 32     # key length in bytes
_NONCE  = 16     # nonce length in bytes
_CHUNK  = 8064   # chunk size in bytes
_TLEAF  = 32     # leaf tag in bytes
_TAG    = 32     # final tag in bytes

_ZERO_B = bytes(_B)

# -- pad10* --------------------------------------------------------------------

def _pad(data: bytes) -> list[bytes]:
    """pad10*: append 0x01 then 0x00 bytes to the next multiple of _R."""
    buf = bytearray(data)
    buf.append(0x01)
    buf.extend(bytes(-len(buf) % _R))
    return [bytes(buf[i : i + _R]) for i in range(0, len(buf), _R)]

# -- keyed duplex (Section 2.3.1, α = 0) --------------------------------------

class _KD:
    __slots__ = ("_s",)

    def __init__(self) -> None:
        self._s = bytearray(_B)

    def init(self, key: bytes, iv: bytes) -> None:
        """S ← K ∥ IV"""
        self._s[:] = key + iv

    def squeeze(self) -> bytes:
        """Apply p(S) and return the rate part."""
        keccak_p1600(self._s)
        return bytes(self._s[:_R])

    def absorb(self, z: bytes, flag: bool, block: bytes) -> None:
        """S ← S ⊕ [flag]·(Z∥0^c) ⊕ B after a squeeze of Z."""
        s = self._s
        if flag:
            # rate part: S[:r] ⊕ Z ⊕ B[:r] = B[:r]  (overwrite)
            s[:_R] = block[:_R]
            # capacity part: S[r:] ⊕ B[r:]
            for i in range(_R, _B):
                s[i] ^= block[i]
        else:
            for i in range(_B):
                s[i] ^= block[i]

    def duplex(self, flag: bool, block: bytes) -> bytes:
        """S ← p(S);  Z ← S[:r];  S ← S ⊕ [flag]·(Z∥0^c) ⊕ B;  return Z"""
        z = self.squeeze()
        self.absorb(z, flag, block)
        return z

# -- IV construction (Section 7) ----------------------------------------------

def _iv(nonce: bytes, j: int) -> bytes:
    """IV^TW128_j(U) = 0^{1344−128−|ν(j)|} ∥ U ∥ ν(j)"""
    nu = right_encode(j)
    return bytes(_R - _NONCE - len(nu)) + nonce + nu

# -- LeafWrap (Section 3.2) ---------------------------------------------------

def _leafwrap(key: bytes, iv: bytes, x: bytes, dec: bool) -> tuple[bytes, bytes]:
    """LeafWrap[p](K, V, X, m) → (Y, T)"""
    kd = _KD()
    kd.init(key, iv)

    y_buf = bytearray()
    if not dec:
        for blk in _pad(x):
            frame = blk + b"\x01" + bytes(_C - 1)  # X̃_j ∥ 1 ∥ 0^{c−1}
            z = kd.duplex(False, frame)
            y_buf.extend(a ^ b for a, b in zip(z, blk))
    else:
        # Decryption must reproduce the encryption transcript on the final
        # padded block, including any ciphertext suffix that was not transmitted.
        full_blocks, rem = divmod(len(x), _R)
        total_blocks = (len(x) + 1 + _R - 1) // _R
        off = 0

        for j in range(total_blocks):
            if j < full_blocks:
                c_full = x[off : off + _R]
                off += _R
                z = kd.duplex(True, c_full + b"\x01" + bytes(_C - 1))
                y_buf.extend(a ^ b for a, b in zip(z, c_full))
                continue

            vis_len = rem if j == full_blocks else 0
            c_vis = x[off : off + vis_len]
            off += vis_len

            z = kd.squeeze()
            p_vis = bytes(a ^ b for a, b in zip(z[:vis_len], c_vis))
            p_full = p_vis + b"\x01" + bytes(_R - vis_len - 1)
            c_full = bytes(a ^ b for a, b in zip(z, p_full))
            kd.absorb(z, True, c_full + b"\x01" + bytes(_C - 1))
            y_buf.extend(p_vis)

    # squeeze one block (t_leaf ≤ r)
    tag_raw = kd.duplex(False, _ZERO_B)

    return bytes(y_buf[: len(x)]), tag_raw[:_TLEAF]

# -- TrunkSponge (Section 3.3) ------------------------------------------------

def _trunk_sponge(key: bytes, iv: bytes, w: bytes) -> bytes:
    """TrunkSponge[p](K, IV, W; output length τ) → T"""
    blocks = _pad(w)
    kd = _KD()
    kd.init(key, iv)

    for blk in blocks:
        kd.duplex(False, blk + bytes(_C))            # W̃_j ∥ 0^c

    # squeeze one block (τ ≤ r)
    raw = kd.duplex(False, _ZERO_B)
    return raw[:_TAG]

# -- enc_out (Section 2.4) ----------------------------------------------------

def _enc_out(ad: bytes, leaf_tags: list[bytes], n: int) -> bytes:
    """η(A) ∥ T_0 ∥ ··· ∥ T_{n−1} ∥ ν(n)"""
    return encode_string(ad) + b"".join(leaf_tags) + right_encode(n)

# -- TreeWrap core (Section 3.4) ----------------------------------------------

def _treewrap(
    key: bytes, nonce: bytes, ad: bytes, x: bytes, dec: bool,
) -> tuple[bytes, bytes]:
    """TreeWrap(K, U, A, X, m) → (Y, T)"""
    chunks = [x[i : i + _CHUNK] for i in range(0, len(x), _CHUNK)] if x else []
    n = len(chunks)

    y_parts: list[bytes] = []
    leaf_tags: list[bytes] = []
    for i, chunk in enumerate(chunks):
        yi, ti = _leafwrap(key, _iv(nonce, i + 1), chunk, dec)
        y_parts.append(yi)
        leaf_tags.append(ti)

    y = b"".join(y_parts)
    tag = _trunk_sponge(key, _iv(nonce, 0), _enc_out(ad, leaf_tags, n))
    return y, tag

# -- AEAD interface (Section 3.5) ---------------------------------------------

def encrypt(key: bytes, nonce: bytes, ad: bytes, plaintext: bytes) -> bytes:
    """TW128.ENC(K, U, A, P) → C  (|C| = |P| + 32)"""
    if len(key) != _K:
        raise ValueError(f"key must be {_K} bytes")
    if len(nonce) != _NONCE:
        raise ValueError(f"nonce must be {_NONCE} bytes")
    y, tag = _treewrap(key, nonce, ad, plaintext, False)
    return y + tag


def decrypt(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes) -> bytes | None:
    """TW128.DEC(K, U, A, C) → P or None"""
    if len(key) != _K:
        raise ValueError(f"key must be {_K} bytes")
    if len(nonce) != _NONCE:
        raise ValueError(f"nonce must be {_NONCE} bytes")
    if len(ciphertext) < _TAG:
        return None
    y, tag = ciphertext[:-_TAG], ciphertext[-_TAG:]
    p, tag2 = _treewrap(key, nonce, ad, y, True)
    if not compare_digest(tag, tag2):
        return None
    return p


# -- smoke test ----------------------------------------------------------------

if __name__ == "__main__":
    import os

    k = os.urandom(32)
    n = os.urandom(16)

    # empty plaintext
    ct = encrypt(k, n, b"", b"")
    assert len(ct) == 32
    assert decrypt(k, n, b"", ct) == b""

    # short plaintext
    n = os.urandom(16)
    pt = b"hello treewrap"
    ct = encrypt(k, n, b"ad", pt)
    assert len(ct) == len(pt) + 32
    assert decrypt(k, n, b"ad", ct) == pt

    # wrong AD → reject
    assert decrypt(k, n, b"bad", ct) is None

    # tampered ciphertext → reject
    bad = bytearray(ct)
    bad[0] ^= 1
    assert decrypt(k, n, b"ad", bytes(bad)) is None

    # multi-chunk (just over one chunk boundary)
    pt2 = os.urandom(8064 + 1)
    n2 = os.urandom(16)
    ct2 = encrypt(k, n2, b"", pt2)
    assert decrypt(k, n2, b"", ct2) == pt2

    # exactly one chunk
    pt3 = os.urandom(8064)
    n3 = os.urandom(16)
    ct3 = encrypt(k, n3, b"aad", pt3)
    assert decrypt(k, n3, b"aad", ct3) == pt3

    # large: 3 full chunks + partial
    pt4 = os.urandom(8064 * 3 + 999)
    n4 = os.urandom(16)
    ct4 = encrypt(k, n4, b"x", pt4)
    assert decrypt(k, n4, b"x", ct4) == pt4

    # targeted short/rate/chunk boundaries
    for m in (0, 1, 2, 15, 16, 17, _R - 1, _R, _R + 1, _CHUNK - 1, _CHUNK, _CHUNK + 1):
        n5 = os.urandom(16)
        pt5 = os.urandom(m)
        ct5 = encrypt(k, n5, b"ad", pt5)
        assert decrypt(k, n5, b"ad", ct5) == pt5

    print("all tests passed")
