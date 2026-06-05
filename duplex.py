"""BDPV11 duplex object for the TW128 parameter set.

The public API is byte-oriented, with optional low-order suffix bits for
SHA-3-style domain separation before pad10*1 is applied.
"""

from __future__ import annotations

from keccak import keccak_p1600_12


WIDTH_BYTES = 200
CAPACITY_BYTES = 32
RATE_BYTES = WIDTH_BYTES - CAPACITY_BYTES
RATE_BITS = RATE_BYTES * 8
MAX_SIGMA_BITS = RATE_BITS - 2
MAX_BYTE_ALIGNED_SIGMA_BYTES = MAX_SIGMA_BITS // 8


class Duplex:
    """Strict BDPV11 duplex over Keccak-p[1600,12] with c=256, r=1344."""

    def __init__(self) -> None:
        self._state = bytearray(WIDTH_BYTES)

    def duplexing(self, sigma: bytes, out_len: int) -> bytes:
        """Absorb byte-aligned sigma, permute, and return out_len bytes."""
        return self.duplexing_bits(sigma, 0, 0, out_len)

    def duplexing_bits(
        self,
        sigma: bytes,
        suffix: int,
        suffix_bits: int,
        out_len: int,
    ) -> bytes:
        """Absorb sigma || low suffix_bits of suffix as one duplex call.

        Bits inside suffix are interpreted LSB-first, matching Keccak/SHA-3
        delimited suffix conventions. The resulting bitstring must fit in one
        rate block after pad10*1 is appended.
        """
        sigma = _as_bytes("sigma", sigma)
        if not isinstance(out_len, int):
            raise TypeError("out_len must be an integer byte count")
        if out_len < 0 or out_len > RATE_BYTES:
            raise ValueError(f"out_len must be in 0..{RATE_BYTES}")
        if not isinstance(suffix, int):
            raise TypeError("suffix must be an integer")
        if not isinstance(suffix_bits, int):
            raise TypeError("suffix_bits must be an integer")
        if suffix_bits < 0 or suffix_bits > 7:
            raise ValueError("suffix_bits must be in 0..7")
        if suffix < 0 or suffix >= (1 << suffix_bits):
            raise ValueError("suffix does not fit in suffix_bits")

        sigma_bits = len(sigma) * 8 + suffix_bits
        if sigma_bits > MAX_SIGMA_BITS:
            raise ValueError(
                f"sigma is too long for one duplex call: {sigma_bits} bits > "
                f"{MAX_SIGMA_BITS} bits"
            )

        block = bytearray(RATE_BYTES)
        block[: len(sigma)] = sigma
        bit_offset = len(sigma) * 8

        for bit in range(suffix_bits):
            if suffix & (1 << bit):
                block[(bit_offset + bit) // 8] |= 1 << ((bit_offset + bit) % 8)

        pad_bit = bit_offset + suffix_bits
        block[pad_bit // 8] |= 1 << (pad_bit % 8)
        block[RATE_BYTES - 1] |= 0x80

        for i, value in enumerate(block):
            self._state[i] ^= value
        keccak_p1600_12(self._state)
        return bytes(self._state[:out_len])


def _as_bytes(name: str, value: bytes) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    return bytes(value)
