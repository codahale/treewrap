# TreeWrap

> [!WARNING]
> TreeWrap/TW128 is an unreviewed research construction. This repository is a
> research artifact, not a production cryptographic library.
>
> The `tw128` package is hazmat code. It is not intended for deployment or real
> security use, has not been audited or standardized, and should not be used to
> protect real data.

This repository contains the TreeWrap paper draft and the `TW128` implementation used to evaluate the concrete
instantiation described there.

`TW128` is a tree-parallel authenticated-encryption construction built from keyed duplex transcripts over
`Keccak-p[1600,12]`. The repository includes:

- `paper/`: the LaTeX source for the paper draft (`main.tex` plus `sections/`), which builds `paper/main.pdf`.
- `tw128/`: an optimized Go library for `TW128`, with `amd64` and `arm64` backends plus a `purego` fallback.
- `tw128.py`: a compact Python reference implementation, with `duplex.py` and `keccak.py` as supporting modules.
- `tw128_tv.json`: deterministic test vectors.
- `test_tw128.py`: the Python test suite, which also generates the test vectors.
- `cmd/cpb/`: a benchmark tool that measures TW128 and AES-128-GCM performance in cycles per byte and wall-clock throughput, both from the same interleaved run.
- `refs/`: reference papers cited by the manuscript.

## TW128 Parameters

The concrete instantiation in this repo uses:

- 256-bit keys
- 256-bit nonces
- 256-bit final tags
- 256-bit hidden leaf tags
- 8183-byte chunks
- `Keccak-p[1600,12]` with rate `1344` and capacity `256`

## Go Library

The Go module path is `github.com/codahale/treewrap`, and the package import path is
`github.com/codahale/treewrap/tw128`.

The `tw128` package exposes a streaming interface:

```go
e := tw128.NewEncryptor(key, nonce, ad)
e.XORKeyStream(ciphertext, plaintext)
tag := e.Finalize()

d := tw128.NewDecryptor(key, nonce, ad)
d.XORKeyStream(plaintextOut, ciphertext)
expectedTag := d.Finalize()
```

Callers should compare `tag` and `expectedTag` in constant time.

## Development

Run the Go tests:

```sh
go test ./...
```

Run the Go benchmarks used for performance work:

```sh
go test -bench . ./tw128
```

Force the pure-Go backend:

```sh
go test -tags purego ./...
```

On `amd64`, the library detects AVX-512 at runtime and uses the AVX-512
permutation paths when available, falling back to AVX2 otherwise. Build with the
`tw128_disable_avx512` tag to compile out AVX-512 detection entirely, so the
AVX2 path is always used (for example, to benchmark the AVX2 backend or to run
on hosts where AVX-512 is unavailable or undesirable):

```sh
go test -tags tw128_disable_avx512 ./...
```

Verify the Python reference implementation against the checked-in vectors:

```sh
python3 -m unittest test_tw128
```

Regenerate the test vectors in `tw128_tv.json` (and the paper appendix):

```sh
UPDATE_TW128=1 python3 -m unittest test_tw128
```

## Notes

This repository is primarily a research codebase: the paper, the reference implementation, and the optimized Go library
are kept together so reviewers and readers can inspect the construction, verify test vectors, and reproduce benchmark
results from the same source tree.

Nothing in this repository should be treated as a recommendation for production
cryptography. If you need an AEAD for real systems, use a reviewed,
standardized, widely deployed construction instead.

The project is dual-licensed under MIT and Apache-2.0; see `LICENSE-MIT` and `LICENSE-APACHE`.
