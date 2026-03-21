"""
TW128 — reference implementation of the TW128 instantiation of TreeWrap.

This is the `TrunkWrap + later LeafWrap` design from the current paper draft:
    p        = Keccak-p[1600, 12]
    b        = 1600          (200 bytes)
    c        = 256           (32 bytes)
    r        = 1344          (168 bytes)
    k        = 256           (32 bytes)
    nonce    ∈ {0,1}^128     (16 bytes)
    B        = 65024 bits    (8128 bytes)
    t_leaf   = 256           (32 bytes)
    τ        = 256           (32 bytes)
    ν        = right_encode  (used only for IV derivation)
    δ_ad     = 0x00
    δ_tc     = 0x01
    α        = 0

The trunk handles:
    - optional associated-data absorption,
    - encryption/decryption of chunk 0,
    - optional absorption of later hidden leaf tags,
    - final squeezing of the authentication tag.

Later chunks are processed by the existing LeafWrap transcript under disjoint
IVs `iv(U, i)` for `i >= 1`.

Padding is pad10* from [Men23]: append a 1 bit, then zeros to fill to a
multiple of r. This is NOT FIPS 202's pad10*1 (no trailing 1 bit).
In byte terms (Keccak LSB-first): append 0x01, then 0x00 bytes.
"""

from __future__ import annotations

from hmac import compare_digest

from keccak import keccak_p1600
from sp800185 import right_encode


# -- constants -----------------------------------------------------------------

_B = 200
_R = 168
_C = 32
_K = 32
_NONCE = 16
_CHUNK = 8128
_TLEAF = 32
_TAG = 32

_ZERO_B = bytes(_B)
_DS_AD = b"\x00"
_DS_TC = b"\x01"


# -- pad10* --------------------------------------------------------------------

def _pad(data: bytes) -> list[bytes]:
    """pad10*: append 0x01 then 0x00 bytes to the next multiple of _R."""
    buf = bytearray(data)
    buf.append(0x01)
    buf.extend(bytes(-len(buf) % _R))
    return [bytes(buf[i : i + _R]) for i in range(0, len(buf), _R)]


def _pad_phase(data: bytes, trailer: bytes) -> list[bytes]:
    """Phase-local pad10*: append trailer, then apply pad10*."""
    return _pad(data + trailer)


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
            s[:_R] = block[:_R]
            for i in range(_R, _B):
                s[i] ^= block[i]
        else:
            for i in range(_B):
                s[i] ^= block[i]

    def duplex(self, flag: bool, block: bytes) -> bytes:
        """S ← p(S); Z ← S[:r]; S ← S ⊕ [flag]·(Z∥0^c) ⊕ B; return Z"""
        z = self.squeeze()
        self.absorb(z, flag, block)
        return z


# -- IV construction -----------------------------------------------------------

def _iv(nonce: bytes, j: int) -> bytes:
    """IV^TW128_j(U) = 0^{1344−128−|ν(j)|} ∥ U ∥ ν(j)."""
    nu = right_encode(j)
    return bytes(_R - _NONCE - len(nu)) + nonce + nu


# -- shared body transcript ----------------------------------------------------

def _duplex_body(kd: _KD, x: bytes, dec: bool) -> bytes:
    """Shared body transcript used by TrunkWrap.body and later LeafWrap."""
    y_buf = bytearray()

    if not dec:
        for blk in _pad(x):
            frame = blk + b"\x01" + bytes(_C - 1)
            z = kd.duplex(False, frame)
            y_buf.extend(a ^ b for a, b in zip(z, blk))
        return bytes(y_buf[: len(x)])

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

    return bytes(y_buf)


# -- trunk transcript ----------------------------------------------------------

def _trunk_init(key: bytes, iv: bytes, ad: bytes) -> _KD:
    kd = _KD()
    kd.init(key, iv)
    if ad:
        for blk in _pad_phase(ad, _DS_AD):
            kd.duplex(False, blk + bytes(_C))
    return kd


def _trunk_body(kd: _KD, x: bytes, dec: bool) -> bytes:
    return _duplex_body(kd, x, dec)


def _trunk_finalize(kd: _KD, leaf_tags: list[bytes]) -> bytes:
    if leaf_tags:
        tail = b"".join(leaf_tags)
        for blk in _pad_phase(tail, _DS_TC):
            kd.duplex(False, blk + bytes(_C))
    raw = kd.duplex(False, _ZERO_B)
    return raw[:_TAG]


# -- later leaves --------------------------------------------------------------

def _leafwrap(key: bytes, iv: bytes, x: bytes, dec: bool) -> tuple[bytes, bytes]:
    kd = _KD()
    kd.init(key, iv)
    y = _duplex_body(kd, x, dec)
    tag_raw = kd.duplex(False, _ZERO_B)
    return y, tag_raw[:_TLEAF]


# -- TreeWrap core -------------------------------------------------------------

def _split_chunks(x: bytes) -> list[bytes]:
    return [x[i : i + _CHUNK] for i in range(0, len(x), _CHUNK)] if x else []


def _treewrap(
    key: bytes, nonce: bytes, ad: bytes, x: bytes, dec: bool,
) -> tuple[bytes, bytes]:
    """TreeWrap(K, U, A, X, m) → (Y, T)"""
    chunks = _split_chunks(x)
    kd = _trunk_init(key, _iv(nonce, 0), ad)

    if not chunks:
        return b"", _trunk_finalize(kd, [])

    y_parts: list[bytes] = []
    y0 = _trunk_body(kd, chunks[0], dec)
    y_parts.append(y0)

    leaf_tags: list[bytes] = []
    for i, chunk in enumerate(chunks[1:], start=1):
        yi, ti = _leafwrap(key, _iv(nonce, i), chunk, dec)
        y_parts.append(yi)
        leaf_tags.append(ti)

    tag = _trunk_finalize(kd, leaf_tags)
    return b"".join(y_parts), tag


# -- AEAD interface ------------------------------------------------------------

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

    k = os.urandom(_K)

    # empty message, empty AD
    n0 = os.urandom(_NONCE)
    ct0 = encrypt(k, n0, b"", b"")
    assert len(ct0) == _TAG
    assert decrypt(k, n0, b"", ct0) == b""

    # empty message, nonempty AD
    n1 = os.urandom(_NONCE)
    ct1 = encrypt(k, n1, b"ad", b"")
    assert decrypt(k, n1, b"ad", ct1) == b""
    assert decrypt(k, n1, b"bad", ct1) is None

    # short one-chunk message
    n2 = os.urandom(_NONCE)
    pt2 = b"hello treewrap"
    ct2 = encrypt(k, n2, b"", pt2)
    assert len(ct2) == len(pt2) + _TAG
    assert decrypt(k, n2, b"", ct2) == pt2

    # one chunk with AD
    n3 = os.urandom(_NONCE)
    pt3 = os.urandom(_CHUNK)
    ct3 = encrypt(k, n3, b"aad", pt3)
    assert decrypt(k, n3, b"aad", ct3) == pt3

    # wrong AD → reject
    assert decrypt(k, n3, b"bad", ct3) is None

    # tampered ciphertext → reject
    bad = bytearray(ct3)
    bad[0] ^= 1
    assert decrypt(k, n3, b"aad", bytes(bad)) is None

    # multi-chunk (just over one chunk boundary)
    pt4 = os.urandom(_CHUNK + 1)
    n4 = os.urandom(_NONCE)
    ct4 = encrypt(k, n4, b"", pt4)
    assert decrypt(k, n4, b"", ct4) == pt4

    # large: 3 full chunks + partial
    pt5 = os.urandom(_CHUNK * 3 + 999)
    n5 = os.urandom(_NONCE)
    ct5 = encrypt(k, n5, b"x", pt5)
    assert decrypt(k, n5, b"x", ct5) == pt5

    # targeted short/rate/chunk boundaries
    for m in (0, 1, 2, 15, 16, 17, _R - 1, _R, _R + 1, _CHUNK - 1, _CHUNK, _CHUNK + 1):
        n6 = os.urandom(_NONCE)
        pt = os.urandom(m)
        ad = os.urandom((m * 7) % 41)
        ct = encrypt(k, n6, ad, pt)
        assert decrypt(k, n6, ad, ct) == pt

    print("all tests passed")
