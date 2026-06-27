from fractions import Fraction
from pathlib import Path
import hashlib
import json
import os
import unittest

import tw128
from duplex import CAPACITY_BYTES, RATE_BYTES, WIDTH_BYTES, Duplex
from tw128 import (
    CHUNK_BYTES,
    RHO_BYTES,
    TAG_BYTES,
    InvalidTag,
    decrypt,
    encrypt,
)

KEY = bytes(range(32))
NONCE = bytes(range(32, 64))
AD = b"treewrap associated data"
BITS_PER_BYTE = 8
INDEX_BITS = 64
PAD10STAR1_BITS = 2

TV_PATH = Path(__file__).with_name("tw128_tv.json")
UPDATE_TV = os.environ.get("UPDATE_TW128") == "1"

APPENDIX_PATH = (
    Path(__file__).with_name("paper") / "sections" / "appendix-test-vectors.tex"
)
APPENDIX_BEGIN = "% >>> generated test vectors (regenerate with UPDATE_TW128=1) >>>"
APPENDIX_END = "% <<< generated test vectors <<<"

# Inputs at most this many bytes are printed in full hex in the paper; larger
# inputs are given by their length and a SHA-256 digest, with the full bytes
# available in tw128_tv.json.
PAPER_FULL_HEX_MAX = 32

# The curated vectors shown in the paper appendix, in display order. Every
# name must be produced by _tv_cases().
PAPER_VECTORS = [
    (
        "pt-empty-ad-empty",
        "Empty associated data and empty message: the associated data and "
        "aggregation phases are both elided, and the root tag is emitted by "
        "the single closing message call with no leaves.",
    ),
    (
        "ad-rho+1-pt-empty",
        "Multi-block associated data with an empty message: the associated data "
        "spans two rate blocks and no message bytes are processed.",
    ),
    (
        "pt-32b-ad-empty",
        "Empty associated data and a single-block message: the root message "
        "phase only, no leaves.",
    ),
    (
        "pt-rho+1-ad-empty",
        "Empty associated data and a two-block message: the root keystream is "
        "chained across two rate blocks.",
    ),
    (
        "pt-chunk-ad-empty",
        "A message of exactly one chunk: the root is full, there is still no "
        "leaf, and the aggregation phase is elided so the closing root message "
        "call emits the tag.",
    ),
    (
        "pt-chunk+1-ad-empty",
        "A message of one chunk and one further byte: one root chunk and one "
        "leaf, exercising leaf tag aggregation.",
    ),
    (
        "pt-2chunk+1-ad-empty",
        "A multi-leaf message of two chunks and one further byte: the full tree "
        "path with two leaves.",
    ),
    (
        "ad-2rho+3-pt-16b",
        "Multi-block associated data with a short message: the associated data "
        "blocks dominate the cost.",
    ),
    (
        "keys-ff",
        "An all-ones key and nonce with a multi-chunk message.",
    ),
]


def sample(size):
    return bytes((17 * index + 31) % 256 for index in range(size))


class DuplexTests(unittest.TestCase):
    def test_full_tw128_payload_fits_with_suffix_and_padding(self):
        duplex = Duplex()
        out = duplex.duplexing_bits(b"\x00" * RHO_BYTES, 0x0F, 4, TAG_BYTES)
        self.assertEqual(len(out), TAG_BYTES)

    def test_payload_larger_than_tw128_rho_is_rejected(self):
        duplex = Duplex()
        with self.assertRaises(ValueError):
            duplex.duplexing_bits(b"\x00" * (RHO_BYTES + 1), 0x0F, 4, 0)


class TW128NumericsTests(unittest.TestCase):
    def test_rate_capacity_and_payload_limit_match_proof(self):
        width_bits = WIDTH_BYTES * BITS_PER_BYTE
        capacity_bits = CAPACITY_BYTES * BITS_PER_BYTE
        rate_bits = RATE_BYTES * BITS_PER_BYTE

        self.assertEqual(width_bits, 1600)
        self.assertEqual(capacity_bits, 256)
        self.assertEqual(rate_bits, 1344)

        proof_rho_bits = (
            (rate_bits - tw128.SUFFIX_BITS - PAD10STAR1_BITS) // BITS_PER_BYTE
        ) * BITS_PER_BYTE
        self.assertEqual(proof_rho_bits, 1336)
        self.assertEqual(RHO_BYTES * BITS_PER_BYTE, proof_rho_bits)
        self.assertLessEqual(
            proof_rho_bits + tw128.SUFFIX_BITS + PAD10STAR1_BITS,
            rate_bits,
        )

    def test_initialization_and_leaf_index_range_match_proof(self):
        key_bits = tw128.KEY_BYTES * BITS_PER_BYTE
        nonce_bits = tw128.NONCE_BYTES * BITS_PER_BYTE
        root_prefix_bits = len(tw128.ROOT_PREFIX) * BITS_PER_BYTE
        leaf_prefix_bits = len(tw128.LEAF_PREFIX) * BITS_PER_BYTE
        rho_bits = RHO_BYTES * BITS_PER_BYTE

        self.assertEqual(root_prefix_bits + key_bits + nonce_bits, 560)
        self.assertLessEqual(root_prefix_bits + key_bits + nonce_bits, rho_bits)
        self.assertEqual(leaf_prefix_bits + key_bits + nonce_bits + INDEX_BITS, 624)
        self.assertLessEqual(
            leaf_prefix_bits + key_bits + nonce_bits + INDEX_BITS,
            rho_bits,
        )

        chunk_bits = CHUNK_BYTES * BITS_PER_BYTE
        self.assertEqual(chunk_bits, 65464)
        max_message_bits = (1 << INDEX_BITS) * chunk_bits
        self.assertEqual(tw128.MAX_MESSAGE_BYTES * BITS_PER_BYTE, max_message_bits)
        n_l_max = (max_message_bits + chunk_bits - 1) // chunk_bits - 1
        self.assertEqual(n_l_max, (1 << INDEX_BITS) - 1)
        self.assertEqual(tw128._le_u64((1 << INDEX_BITS) - 1), b"\xff" * 8)
        with self.assertRaises(ValueError):
            tw128._le_u64(1 << INDEX_BITS)

    def test_beta_substitution_constants_match_proof(self):
        rho_bits = RHO_BYTES * BITS_PER_BYTE
        chunk_bits = CHUNK_BYTES * BITS_PER_BYTE
        tag_bits = TAG_BYTES * BITS_PER_BYTE

        self.assertEqual(rho_bits, 1336)
        self.assertEqual(tag_bits, 256)
        self.assertEqual(INDEX_BITS, 64)
        self.assertEqual((CHUNK_BYTES + RHO_BYTES - 1) // RHO_BYTES, 49)

        asymptotic_full_chunk_factor = Fraction(
            chunk_bits + 2 * rho_bits + tag_bits, chunk_bits
        )
        self.assertEqual(asymptotic_full_chunk_factor, Fraction(8549, 8183))

    def test_bound_simplifications_match_proof(self):
        tag_bits = TAG_BYTES * BITS_PER_BYTE
        capacity_bits = CAPACITY_BYTES * BITS_PER_BYTE

        self.assertEqual(tag_bits, 256)
        self.assertEqual(capacity_bits, 256)
        self.assertEqual(3 + 1, 1 << 2)
        self.assertEqual(1 - tag_bits - tag_bits, -511)

        for n in [0, 1, 2, 17, 1 << 10]:
            cmt_collision_numerator = n * (n - 1)
            cmt_indiff_numerator = n * (n + 1)
            self.assertEqual(
                cmt_collision_numerator + cmt_indiff_numerator,
                2 * n * n,
            )

        target_bits = 128
        self.assertEqual((capacity_bits - target_bits) // 2, 64)
        self.assertEqual(255 - target_bits, 127)
        self.assertEqual(254 - target_bits, 126)
        self.assertEqual(511 - target_bits, 383)


class TW128Tests(unittest.TestCase):
    def test_round_trips_boundary_sizes(self):
        sizes = [
            0,
            1,
            RHO_BYTES - 1,
            RHO_BYTES,
            RHO_BYTES + 1,
            CHUNK_BYTES - 1,
            CHUNK_BYTES,
            CHUNK_BYTES + 1,
            2 * CHUNK_BYTES,
            2 * CHUNK_BYTES + 1,
        ]
        for size in sizes:
            with self.subTest(size=size):
                plaintext = sample(size)
                sealed = encrypt(KEY, NONCE, plaintext, AD)
                self.assertEqual(len(sealed), len(plaintext) + TAG_BYTES)
                self.assertEqual(decrypt(KEY, NONCE, sealed, AD), plaintext)

    def test_ciphertext_tamper_fails(self):
        sealed = bytearray(encrypt(KEY, NONCE, sample(CHUNK_BYTES + 200), AD))
        sealed[CHUNK_BYTES + 10] ^= 0x01
        with self.assertRaises(InvalidTag):
            decrypt(KEY, NONCE, bytes(sealed), AD)

    def test_tag_tamper_fails(self):
        sealed = bytearray(encrypt(KEY, NONCE, sample(300), AD))
        sealed[-1] ^= 0x01
        with self.assertRaises(InvalidTag):
            decrypt(KEY, NONCE, bytes(sealed), AD)

    def test_associated_data_tamper_fails(self):
        sealed = encrypt(KEY, NONCE, sample(300), AD)
        with self.assertRaises(InvalidTag):
            decrypt(KEY, NONCE, sealed, AD + b"!")

    def test_detached_wrong_tag_length_fails_as_invalid_tag(self):
        sealed = encrypt(KEY, NONCE, sample(300), AD)
        ciphertext = sealed[:-TAG_BYTES]
        tag = sealed[-TAG_BYTES + 1 :]
        with self.assertRaises(InvalidTag):
            tw128.decrypt_detached(KEY, NONCE, ciphertext, AD, tag)

    def test_empty_message_no_leaf_call_count(self):
        # A single-chunk message elides the aggregation phase: the closing
        # MSG_LAST call emits the root tag directly. With non-empty associated
        # data an empty message produces three root duplex calls (INIT,
        # AD_LAST, MSG_LAST) rather than the four an AGG_LAST block would add.
        calls = count_encrypt_duplex_calls(b"")
        self.assertEqual(calls, 3)

    def test_empty_ad_elides_ad_phase_call_count(self):
        # With empty associated data the AD phase is elided (the init call
        # itself emits the chunk-0 keystream) and, for a single-chunk message,
        # the aggregation phase is elided too (the MSG_LAST call emits the
        # tag). An empty message therefore produces exactly two root duplex
        # calls (INIT, MSG_LAST).
        self.assertEqual(count_encrypt_duplex_calls(b"", b""), 2)

    def test_first_leaf_does_not_absorb_blank_ad(self):
        root_blocks = (CHUNK_BYTES + RHO_BYTES - 1) // RHO_BYTES
        expected_calls = 1 + 1 + root_blocks + 1 + 1 + 1
        self.assertEqual(
            count_encrypt_duplex_calls(sample(CHUNK_BYTES + 1)), expected_calls
        )


def _tv_cases():
    """Curated (name, key, nonce, ad, plaintext) inputs for the test vectors.

    Sizes are expressed in terms of the live constants so the cases track the
    parameter set, and exercise every block-splitting and tree boundary an
    implementor is likely to stumble over.
    """
    rho = tw128.RHO_BYTES
    chunk = tw128.CHUNK_BYTES
    key_zero = bytes(32)
    nonce_zero = bytes(32)
    key_ff = b"\xff" * 32
    nonce_ff = b"\xff" * 32

    # Plaintext sizes: empty/tag-only, sub-block, the RHO block boundary and
    # keystream chaining, the CHUNK root/leaf boundary, and one/two/three leaves
    # (exercising little-endian chunk_id and leaf-tag aggregation).
    pt_sizes = [
        ("empty", 0),
        ("1b", 1),
        ("32b", 32),
        ("rho-1", rho - 1),
        ("rho", rho),
        ("rho+1", rho + 1),
        ("2rho", 2 * rho),
        ("2rho+1", 2 * rho + 1),
        ("chunk-1", chunk - 1),
        ("chunk", chunk),
        ("chunk+1", chunk + 1),
        ("chunk+rho", chunk + rho),
        ("2chunk", 2 * chunk),
        ("2chunk+1", 2 * chunk + 1),
        ("3chunk+5", 3 * chunk + 5),
    ]

    # AD sizes: a nonempty AD absorbs at least one AD_LAST block; crossing RHO
    # forces AD_MORE + AD_LAST splitting. Paired with a short message so the AD
    # path is isolated and the inputs stay small enough to print in full. (An
    # empty AD elides the AD phase entirely; see the pt-*-ad-empty cases.)
    ad_sizes = [
        ("ad-1b", 1),
        ("ad-rho-1", rho - 1),
        ("ad-rho", rho),
        ("ad-rho+1", rho + 1),
        ("ad-2rho+3", 2 * rho + 3),
    ]

    cases = []
    for name, size in pt_sizes:
        cases.append((f"pt-{name}-ad-empty", KEY, NONCE, b"", sample(size)))
    for name, size in ad_sizes:
        cases.append((f"{name}-pt-16b", KEY, NONCE, sample(size), sample(16)))
    # Multi-block associated data with an empty message.
    cases.append(("ad-rho+1-pt-empty", KEY, NONCE, sample(rho + 1), b""))
    # Key/nonce extremes, with a multi-block plaintext that spans a leaf.
    cases.append(
        ("keys-zero", key_zero, nonce_zero, sample(rho + 1), sample(chunk + 1))
    )
    cases.append(("keys-ff", key_ff, nonce_ff, sample(rho + 1), sample(chunk + 1)))
    return cases


def _build_vectors():
    vectors = []
    for name, key, nonce, ad, plaintext in _tv_cases():
        ciphertext, tag = tw128.encrypt_detached(key, nonce, plaintext, ad)
        vectors.append(
            {
                "name": name,
                "key": key.hex(),
                "nonce": nonce.hex(),
                "ad": ad.hex(),
                "plaintext": plaintext.hex(),
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex(),
            }
        )
    return vectors


def _tex_field(raw):
    """Render one byte string for the paper: empty marker, full hex, or digest."""
    if len(raw) == 0:
        return r"$\varepsilon$"
    if len(raw) <= PAPER_FULL_HEX_MAX:
        return rf"\texttt{{{raw.hex()}}}"
    digest = hashlib.sha256(raw).hexdigest()
    return rf"{len(raw)} bytes, SHA-256\newline \texttt{{{digest}}}"


def _render_appendix_block(vectors_by_name):
    """Build the LaTeX between the appendix markers (leading/trailing newline)."""
    lines = [
        "",
        "% Generated from the repository test-vector harness; do not edit by hand.",
        "% The full byte strings are in tw128_tv.json at the repository root.",
        "",
    ]
    for index, (name, description) in enumerate(PAPER_VECTORS, start=1):
        vector = vectors_by_name[name]
        rows = [
            ("$K$", bytes.fromhex(vector["key"])),
            ("$N$", bytes.fromhex(vector["nonce"])),
            ("$A$", bytes.fromhex(vector["ad"])),
            ("$M$", bytes.fromhex(vector["plaintext"])),
            ("$C$", bytes.fromhex(vector["ciphertext"])),
            ("$T$", bytes.fromhex(vector["tag"])),
        ]
        lines.append(r"\noindent")
        lines.append(r"{\footnotesize")
        lines.append(r"\begin{tabular}{@{}l p{0.88\textwidth}@{}}")
        lines.append(r"\toprule")
        lines.append(
            rf"\multicolumn{{2}}{{@{{}}p{{0.94\textwidth}}@{{}}}}"
            rf"{{\textbf{{Vector {index}.}}~ {description}}} \\"
        )
        lines.append(r"\midrule")
        for symbol, raw in rows:
            lines.append(rf"  {symbol} & {_tex_field(raw)} \\")
        # Interior vectors are closed by the next vector's top rule; only the
        # last one needs its own bottom rule to close the appendix cleanly.
        if index == len(PAPER_VECTORS):
            lines.append(r"\bottomrule")
        lines.append(r"\end{tabular}}")
        lines.append("")
        lines.append(r"\medskip")
        lines.append("")
    return "\n".join(lines)


def _extract_appendix_block(text):
    """Return the text between the appendix markers, or None if absent."""
    if APPENDIX_BEGIN not in text or APPENDIX_END not in text:
        return None
    start = text.index(APPENDIX_BEGIN) + len(APPENDIX_BEGIN)
    end = text.index(APPENDIX_END)
    return text[start:end]


def _write_appendix_block(vectors_by_name):
    text = APPENDIX_PATH.read_text()
    if _extract_appendix_block(text) is None:
        raise ValueError(
            f"{APPENDIX_PATH.name} is missing the generated-vector markers"
        )
    prefix = text[: text.index(APPENDIX_BEGIN) + len(APPENDIX_BEGIN)]
    suffix = text[text.index(APPENDIX_END):]
    APPENDIX_PATH.write_text(
        prefix + _render_appendix_block(vectors_by_name) + suffix
    )


class TW128VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.built = _build_vectors()
        if UPDATE_TV:
            document = {
                "_comment": (
                    "TW128 known-answer test vectors. Regenerate with "
                    "`UPDATE_TW128=1 python -m pytest test_tw128.py`. Every byte "
                    "string is hex; the sealed output of encrypt() is "
                    "ciphertext || tag."
                ),
                "constants": {
                    "key_bytes": tw128.KEY_BYTES,
                    "nonce_bytes": tw128.NONCE_BYTES,
                    "tag_bytes": tw128.TAG_BYTES,
                    "rho_bytes": tw128.RHO_BYTES,
                    "chunk_bytes": tw128.CHUNK_BYTES,
                },
                "vectors": cls.built,
            }
            TV_PATH.write_text(json.dumps(document, indent=2) + "\n")
            _write_appendix_block({vector["name"]: vector for vector in cls.built})
        if not TV_PATH.exists():
            raise FileNotFoundError(
                f"{TV_PATH.name} is missing; regenerate it with "
                "`UPDATE_TW128=1 python -m pytest test_tw128.py`"
            )
        cls.document = json.loads(TV_PATH.read_text())
        cls.vectors = cls.document["vectors"]

    def test_vector_file_matches_cases(self):
        built_by_name = {vector["name"]: vector for vector in self.built}
        self.assertEqual(
            [vector["name"] for vector in self.vectors],
            [vector["name"] for vector in self.built],
            "tw128_tv.json is stale; regenerate with UPDATE_TW128=1",
        )
        for vector in self.vectors:
            built = built_by_name[vector["name"]]
            for field in ("key", "nonce", "ad", "plaintext"):
                self.assertEqual(
                    vector[field],
                    built[field],
                    f"input {field} drift for vector {vector['name']!r}; "
                    "regenerate with UPDATE_TW128=1",
                )

    def test_encrypt_matches_vectors(self):
        for vector in self.vectors:
            with self.subTest(name=vector["name"]):
                key = bytes.fromhex(vector["key"])
                nonce = bytes.fromhex(vector["nonce"])
                ad = bytes.fromhex(vector["ad"])
                plaintext = bytes.fromhex(vector["plaintext"])
                ciphertext = bytes.fromhex(vector["ciphertext"])
                tag = bytes.fromhex(vector["tag"])
                self.assertEqual(len(tag), TAG_BYTES)
                self.assertEqual(len(ciphertext), len(plaintext))
                self.assertEqual(encrypt(key, nonce, plaintext, ad), ciphertext + tag)
                self.assertEqual(
                    tw128.encrypt_detached(key, nonce, plaintext, ad),
                    (ciphertext, tag),
                )

    def test_decrypt_matches_vectors(self):
        for vector in self.vectors:
            with self.subTest(name=vector["name"]):
                key = bytes.fromhex(vector["key"])
                nonce = bytes.fromhex(vector["nonce"])
                ad = bytes.fromhex(vector["ad"])
                plaintext = bytes.fromhex(vector["plaintext"])
                ciphertext = bytes.fromhex(vector["ciphertext"])
                tag = bytes.fromhex(vector["tag"])
                self.assertEqual(decrypt(key, nonce, ciphertext + tag, ad), plaintext)
                self.assertEqual(
                    tw128.decrypt_detached(key, nonce, ciphertext, ad, tag),
                    plaintext,
                )

    def test_appendix_in_sync(self):
        built_by_name = {vector["name"]: vector for vector in self.built}
        for name, _ in PAPER_VECTORS:
            self.assertIn(
                name, built_by_name, f"paper vector {name!r} is not a generated case"
            )
        text = APPENDIX_PATH.read_text()
        on_disk = _extract_appendix_block(text)
        self.assertIsNotNone(
            on_disk,
            f"{APPENDIX_PATH.name} is missing the generated-vector markers",
        )
        self.assertEqual(
            on_disk,
            _render_appendix_block(built_by_name),
            f"{APPENDIX_PATH.name} is stale; regenerate with UPDATE_TW128=1",
        )


def count_encrypt_duplex_calls(plaintext, ad=AD):
    original_duplex = tw128.Duplex

    class CountingDuplex(original_duplex):
        calls = 0

        def duplexing_bits(self, *args, **kwargs):
            CountingDuplex.calls += 1
            return super().duplexing_bits(*args, **kwargs)

    try:
        tw128.Duplex = CountingDuplex
        encrypt(KEY, NONCE, plaintext, ad)
    finally:
        tw128.Duplex = original_duplex

    return CountingDuplex.calls


if __name__ == "__main__":
    unittest.main()
