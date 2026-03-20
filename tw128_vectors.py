"""Deterministic TW128 test-vector generator and verifier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tw128 import decrypt, encrypt


def _pattern(length: int, start: int) -> bytes:
    return bytes((start + i) & 0xFF for i in range(length))


def _hex(data: bytes) -> str:
    return data.hex()


def _vector_specs() -> list[dict[str, object]]:
    return [
        {
            "name": "empty",
            "description": "Empty AD and empty plaintext.",
            "key": _pattern(32, 0x00),
            "nonce": _pattern(16, 0x10),
            "ad": b"",
            "plaintext": b"",
        },
        {
            "name": "short_ad_short_pt",
            "description": "Short AD and short plaintext.",
            "key": _pattern(32, 0x20),
            "nonce": _pattern(16, 0x30),
            "ad": _pattern(7, 0x40),
            "plaintext": _pattern(15, 0x50),
        },
        {
            "name": "rate_minus_1",
            "description": "Plaintext length r-1 = 167 bytes.",
            "key": _pattern(32, 0x60),
            "nonce": _pattern(16, 0x70),
            "ad": _pattern(33, 0x80),
            "plaintext": _pattern(167, 0x90),
        },
        {
            "name": "rate_exact",
            "description": "Plaintext length r = 168 bytes.",
            "key": _pattern(32, 0xA0),
            "nonce": _pattern(16, 0xB0),
            "ad": _pattern(34, 0xC0),
            "plaintext": _pattern(168, 0xD0),
        },
        {
            "name": "rate_plus_1",
            "description": "Plaintext length r+1 = 169 bytes.",
            "key": _pattern(32, 0xE0),
            "nonce": _pattern(16, 0xF0),
            "ad": _pattern(35, 0x11),
            "plaintext": _pattern(169, 0x22),
        },
        {
            "name": "two_rate_blocks",
            "description": "Plaintext length 2r = 336 bytes.",
            "key": _pattern(32, 0x33),
            "nonce": _pattern(16, 0x55),
            "ad": _pattern(48, 0x77),
            "plaintext": _pattern(336, 0x99),
        },
        {
            "name": "chunk_minus_1",
            "description": "Plaintext length B-1 = 8063 bytes.",
            "key": _pattern(32, 0x12),
            "nonce": _pattern(16, 0x23),
            "ad": _pattern(23, 0x34),
            "plaintext": _pattern(8063, 0x45),
        },
        {
            "name": "chunk_exact",
            "description": "Plaintext length B = 8064 bytes.",
            "key": _pattern(32, 0x56),
            "nonce": _pattern(16, 0x67),
            "ad": _pattern(24, 0x78),
            "plaintext": _pattern(8064, 0x89),
        },
        {
            "name": "chunk_plus_1",
            "description": "Plaintext length B+1 = 8065 bytes.",
            "key": _pattern(32, 0x9A),
            "nonce": _pattern(16, 0xAB),
            "ad": _pattern(25, 0xBC),
            "plaintext": _pattern(8065, 0xCD),
        },
        {
            "name": "two_chunks_exact",
            "description": "Plaintext length 2B = 16128 bytes.",
            "key": _pattern(32, 0x21),
            "nonce": _pattern(16, 0x43),
            "ad": _pattern(26, 0x65),
            "plaintext": _pattern(16128, 0x87),
        },
        {
            "name": "two_chunks_plus_1",
            "description": "Plaintext length 2B+1 = 16129 bytes.",
            "key": _pattern(32, 0xA1),
            "nonce": _pattern(16, 0xC3),
            "ad": _pattern(27, 0xE5),
            "plaintext": _pattern(16129, 0x07),
        },
    ]


def build_vectors() -> dict[str, object]:
    vectors: list[dict[str, object]] = []
    for spec in _vector_specs():
        key = spec["key"]
        nonce = spec["nonce"]
        ad = spec["ad"]
        plaintext = spec["plaintext"]
        assert isinstance(key, bytes)
        assert isinstance(nonce, bytes)
        assert isinstance(ad, bytes)
        assert isinstance(plaintext, bytes)
        ciphertext = encrypt(key, nonce, ad, plaintext)
        recovered = decrypt(key, nonce, ad, ciphertext)
        assert recovered == plaintext
        vectors.append(
            {
                "name": spec["name"],
                "description": spec["description"],
                "key_hex": _hex(key),
                "nonce_hex": _hex(nonce),
                "ad_hex": _hex(ad),
                "plaintext_hex": _hex(plaintext),
                "ciphertext_hex": _hex(ciphertext),
            }
        )

    return {
        "scheme": "TW128",
        "source": "tw128.py",
        "vectors": vectors,
    }


def verify(path: Path) -> None:
    doc = json.loads(path.read_text())
    for vector in doc["vectors"]:
        key = bytes.fromhex(vector["key_hex"])
        nonce = bytes.fromhex(vector["nonce_hex"])
        ad = bytes.fromhex(vector["ad_hex"])
        plaintext = bytes.fromhex(vector["plaintext_hex"])
        ciphertext = bytes.fromhex(vector["ciphertext_hex"])
        got = encrypt(key, nonce, ad, plaintext)
        if got != ciphertext:
            raise SystemExit(f"ciphertext mismatch for {vector['name']}")
        recovered = decrypt(key, nonce, ad, ciphertext)
        if recovered != plaintext:
            raise SystemExit(f"decrypt mismatch for {vector['name']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        type=Path,
        help="Write the generated vectors to the given JSON file.",
    )
    parser.add_argument(
        "--verify",
        type=Path,
        help="Verify an existing JSON vector file against the reference implementation.",
    )
    args = parser.parse_args()

    if args.verify is not None:
        verify(args.verify)
        print("ok")
        return

    doc = json.dumps(build_vectors(), indent=2)
    if args.write is not None:
        args.write.write_text(doc)
        print("ok")
        return

    print(doc)


if __name__ == "__main__":
    main()
