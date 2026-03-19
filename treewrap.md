# TreeWrap

## Abstract

We introduce TreeWrap, a permutation-based authenticated-encryption construction that separates local chunk processing from final global authentication. Each message chunk is processed by a MonkeySpongeWrap-style keyed duplex transcript, called $`\mathsf{LeafWrap}`$, which outputs a ciphertext body chunk and a hidden leaf tag. The resulting leaf-tag vector is then authenticated together with the global associated data by a final keyed absorb-then-squeeze transcript, called $`\mathsf{TrunkSponge}`$. This decomposition is intended to support parallel chunk processing while preserving a simple final authentication layer.

We analyze TreeWrap in two settings. For authenticated encryption, we prove multi-user IND-CPA, INT-CTXT, and IND-CCA2 bounds in the keyed-duplex model of Mennink. This AE analysis is largely modular: the leaf-layer proof identifies $`\mathsf{LeafWrap}`$ with a reduced MonkeySpongeWrap transcript and imports the corresponding keyed-duplex/IXIF replacement, while the trunk layer is handled by a direct keyed-duplex/IXIF analysis. The main TreeWrap-specific AE step is a freshness lemma showing that, in the IXIF world, a fresh chunk body induces a fresh hidden leaf tag except with probability $`2^{-t_{\mathsf{leaf}}}`$. For commitment, we prove a CMT-4 bound in the public-permutation model by flattening the leaf and trunk layers into duplex and sponge transcripts, respectively. This yields a per-ciphertext commitment bound whose local term depends on the actual chunk lengths rather than only on the leaf-tag length.

We also give a concrete instantiation, $`\mathsf{TW128}`$, based on $`\mathrm{Keccak\text{-}p}[1600,12]`$ with 256-bit capacity, 8064-byte chunks, 256-bit leaf tags, and a 256-bit final tag. The resulting generic security target is 128 bits, with explicit multi-user AE bounds and explicit per-output CMT-4 bounds.

## 1. Introduction

TreeWrap is a permutation-based AEAD construction that separates local chunk processing from final global authentication. The construction applies a MonkeySpongeWrap-style keyed duplex transcript to each message chunk, producing a ciphertext body chunk and a hidden leaf tag, and then authenticates the resulting leaf-tag vector together with the global associated data using a final keyed trunk sponge. This leaf/trunk split is designed to make chunk processing embarrassingly parallel while keeping the final authentication transcript simple enough to analyze both in the keyed AE setting and in the public-permutation commitment setting.

On the AE side, most of the proof work is a modular application of [Men23] rather than a new keyed-duplex argument. The genuinely new technical pieces are the TreeWrap-specific freshness lemma for hidden leaf tags (Lemma 7.1) and the public-permutation CMT-4 analysis of Section 7.

The proof strategy follows the same decomposition. The AE analysis is carried out in the multi-user keyed-duplex model of [Men23]. At the leaf layer, Lemma 6.1 identifies $`\mathsf{LeafWrap}`$ with a reduced MonkeySpongeWrap transcript, and Theorem 6.2 imports the corresponding KD/IXIF replacement. Lemma 7.1 then supplies the TreeWrap-specific step needed for integrity: in the IXIF world, a fresh chunk body induces a fresh hidden leaf tag except with probability $`2^{-t_{\mathsf{leaf}}}`$. At the trunk layer, Corollary 4.6 gives a direct keyed-duplex/IXIF replacement for $`\mathsf{TrunkSponge}`$. These ingredients yield the IND-CPA and INT-CTXT theorems, and Theorem 5.3 derives IND-CCA2 from them by a BN00-style game hop using the multi-forgery integrity notion of Section 4.2.

The commitment analysis is deliberately separate from the keyed AE path. Because the CMT-4 adversary chooses both candidate keys and nonces, the proof does not use the keyed [Men23] bounds. Instead, it flattens the construction into public permutation transcripts. Lemma 7.2 handles the local leaf wrapper via the duplexing-sponge viewpoint of [BDPVA11], yielding a per-chunk collision term on the full local output pair $`(Y_i,T_i)`$. Lemma 7.3 handles the outer trunk transcript via a rooted-forest counting extension of the single-root sponge bound of [BDPVA08]. Theorem 5.4 then composes these two cases: a TreeWrap commitment collision either arises at the first differing chunk or at the final trunk combiner.

The remainder of the paper is organized as follows. Section 2 fixes notation, the keyed-duplex model, and the encoding conventions. Section 3 defines $`\mathsf{LeafWrap}`$, $`\mathsf{TrunkSponge}`$, and $`\mathsf{TreeWrap}`$, together with the AEAD wrapper. Section 4 gives the multi-user security experiments, the resource translation, and the imported external bounds. Section 5 states the main AE and CMT-4 theorems. Section 6 gives the imported AE adaptation sketches, and Section 7 contains the TreeWrap-specific proofs. Section 8 instantiates the construction as $`\mathsf{TW128}`$ using $`\mathrm{Keccak\text{-}p}[1600,12]`$, SP 800-185 encodings, 8064-byte chunks, 256-bit leaf tags, and a 256-bit final tag.

## 2. Preliminaries

### 2.1 Notation

Unless stated otherwise, all strings are bitstrings. We write $`\epsilon`$ for the empty string, $`|X|`$ for the bitlength of a string $`X`$, $`X \| Y`$ for concatenation, and $`\mathrm{left}_n(X)`$ for the leftmost $`n`$ bits of a string $`X`$ with $`|X| \ge n`$. For integers $`m \le n`$, write $`[m,n) := \{m,m+1,\ldots,n-1\}`$.

Chunk indices always start at $`0`$, while padded-block and transcript-block indices start at $`1`$. When a body string $`X`$ is partitioned into chunks of size $`B`$, we write $`X = X_0 \| \cdots \| X_{n-1}`$ for the canonical chunk decomposition, where $`n = \lceil |X|/B \rceil`$, each nonfinal chunk has length exactly $`B`$, the final chunk has length at most $`B`$, and $`n = 0`$ when $`X = \epsilon`$.

### 2.2 AEAD Syntax

An AEAD scheme consists of a pair of algorithms

```math
\mathsf{ENC}(K,U,A,P) \to C,
\qquad
\mathsf{DEC}(K,U,A,C) \to P \text{ or } \bot,
```

where $`K`$ is a secret key, $`U`$ is a nonce, $`A`$ is associated data, $`P`$ is a plaintext, and $`C`$ is a ciphertext. Correctness requires

```math
\mathsf{DEC}(K,U,A,\mathsf{ENC}(K,U,A,P)) = P
```

for all valid inputs.

### 2.3 Duplex / Underlying Primitive Model

#### 2.3.1 Keyed Duplex

We adopt the keyed duplex interface of [Men23, Algorithm 1], specialized to the case $`\alpha = 0`$ used throughout TreeWrap. Let $`b,c,r,k,\mu \in \mathbb{N}`$ with $`c + r = b`$ and $`k \le b`$. Let $`\mathcal{IV} \subseteq \{0,1\}^{b-k}`$ be an IV space, and let $`p \in \mathrm{Perm}(b)`$ be a $`b`$-bit permutation. The keyed duplex construction is denoted

```math
\mathsf{KD}[p]_K,
```

where the key array is

```math
K = (K[1], \ldots, K[\mu]) \in (\{0,1\}^k)^\mu.
```

In the single-key specialization $`\mu = 1`$, we identify $`K[1]`$ with a single key $`K \in \{0,1\}^k`$ and write $`\mathsf{KD}[p]_K`$ for the resulting instance.

It maintains a state $`S \in \{0,1\}^b`$ and exposes the following two interfaces.

```text
Algorithm KD[p]_K.init(δ, IV):
    S <- K[δ] || IV
```

```text
Algorithm KD[p]_K.duplex(flag, B):
    S <- p(S)
    Z <- left_r(S)
    S <- S xor ([flag] * (Z || 0^{b-r})) xor B
    return Z
```

Here $`\delta`$ ranges over $`\{1,\ldots,\mu\}`$, $`IV`$ ranges over $`\mathcal{IV}`$, $`\mathsf{flag}`$ ranges over $`\{\mathsf{true},\mathsf{false}\}`$, and $`B`$ ranges over $`\{0,1\}^b`$. When $`\mathsf{flag} = \mathsf{true}`$, the outer $`r`$ bits are overwritten; when $`\mathsf{flag} = \mathsf{false}`$, they are XOR-absorbed. This keyed duplex interface is the primitive on which both the TreeWrap outer combiner and the MonkeySpongeWrap-style LeafWrap transcript are built.

#### 2.3.2 Ideal IXIF Interface

For the authenticated-encryption proofs, we also use the ideal path-based interface $`\mathsf{IXIF}[\mathrm{ro}]`$ imported from [Men23]. Fix a random oracle

```math
\mathrm{ro} : \{0,1\}^* \to \{0,1\}^r
```

and a fixed injective encoding

```math
\mathrm{uid} : \{1,\ldots,\mu\} \to \{0,1\}^*.
```

The interface maintains a current transcript path $`\pi \in \{0,1\}^*`$ and exposes:

```text
Algorithm IXIF[ro].init(δ, IV):
    π <- uid(δ) || IV
```

```text
Algorithm IXIF[ro].duplex(flag, B):
    Z <- ro(π)
    D <- ([flag] * (Z || 0^{b-r})) xor B
    π <- π || D
    return Z
```

Thus $`\mathsf{IXIF}[\mathrm{ro}]`$ keeps the same control flow as the keyed duplex but replaces the permutation state by a transcript path. A repeated path returns the same deterministic oracle value, while a fresh path returns an independent uniform $`r`$-bit string. This is the ideal interface used by the imported KD/IXIF replacements of Section 4.6.

### 2.4 Encoding Conventions and Domain Separation

**Encodings.** We use two encoding components: a prefix-free injective string encoding $`\eta : \{0,1\}^* \to \{0,1\}^*`$ and a suffix-free injective integer encoding $`\nu : \mathbb{N} \to \{0,1\}^*`$.

**Derived IVs.** We assume a fixed-length nonce space $`\mathcal{U} \subseteq \{0,1\}^u`$ for some nonce length $`u \in \mathbb{N}`$, together with an injective IV-derivation map

```math
\mathsf{iv} : \mathcal{U} \times \mathbb{N} \to \mathcal{IV}.
```

TreeWrap reserves suffix $`0`$ for the outer trunk-sponge call and uses positive suffixes for chunk-local LeafWrap calls, so $`V_{\mathsf{out}}(U) := \mathsf{iv}(U,0)`$ and $`V_i(U) := \mathsf{iv}(U,i+1)`$. In concrete instantiations, $`\mathsf{iv}`$ may itself be built from the integer encoding $`\nu`$; Section 7 does this for $`\mathsf{TW128}`$.

**Outer encoding.** For the final TreeWrap combiner, define

```math
\mathsf{enc}_{\mathsf{out}}(A,T_0,\ldots,T_{n-1},n)
:=
\eta(A) \| T_0 \| \cdots \| T_{n-1} \| \nu(n).
```

Because $`\eta`$ is prefix-free, the leaf tags have fixed length $`t_{\mathsf{leaf}}`$, and $`\nu`$ is suffix-free, this outer encoding is injective in all of its arguments. Equivalently, one can parse $`\mathsf{enc}_{\mathsf{out}}`$ from right to left: strip the unique suffix $`\nu(n)`$, use the recovered value of $`n`$ to peel off exactly $`n`$ fixed-length leaf tags, and then recover the unique remaining prefix $`\eta(A)`$.

**Overhead notation.** For later resource accounting, we write $`|\eta(A)| \le |A| + \lambda_\eta(|A|)`$ and $`|\nu(n)| \le \lambda_\nu(n)`$ for encoding-overhead functions $`\lambda_\eta`$ and $`\lambda_\nu`$ associated with the chosen encodings.

**Padding and framing.** For any block length $`s \in \mathbb{N}`$ and any bitstring $`Z \in \{0,1\}^*`$, we write

```math
(Z_1,\ldots,Z_w) \gets \mathrm{pad}^{*}_{10^s*}(Z)
```

for the unique padded decomposition of $`Z`$ into $`s`$-bit blocks under the $`\mathrm{pad}10^*`$ convention of [Men23]. Thus each $`Z_j \in \{0,1\}^s`$, and

```math
\mathrm{left}_{|Z|}(Z_1 \| \cdots \| Z_w) = Z.
```

LeafWrap embeds each padded message or ciphertext block as $`Z_j \| 1 \| 0^{c-1}`$. These are full-state blocks of length $`b = r + c`$ and provide a dedicated transcript format for the body-processing phase. By contrast, the outer trunk sponge absorbs padded combiner blocks as $`W_j \| 0^c`$, that is, as ordinary rate-$`r`$ sponge blocks with an all-zero capacity suffix.

**Domain separation.** TreeWrap separates leaf and trunk calls in two ways. First, the proofs rely on disjoint IV namespaces: trunk calls use $`V_{\mathsf{out}}(U) = \mathsf{iv}(U,0)`$, while leaf calls use $`V_i(U) = \mathsf{iv}(U,i+1)`$. Second, even if the rate parts happen to coincide, the absorbed full-state blocks differ in format: LeafWrap uses a suffix $`1 \| 0^{c-1}`$, whereas TrunkSponge uses $`0^c`$. The later reductions use the IV separation as the primary argument and the block-format distinction as secondary transcript-format separation.

## 3. The TreeWrap Construction

### 3.1 Parameters

Let $`\mathsf{TreeWrap}`$ be parameterized by:

- a permutation $`p \in \mathrm{Perm}(b)`$,
- a width $`b`$,
- a rate $`r`$,
- a capacity $`c`$,
- a key length $`k`$,
- an IV space $`\mathcal{IV} \subseteq \{0,1\}^{b-k}`$,
- a nonce space $`\mathcal{U}`$,
- an injective IV-derivation map $`\mathsf{iv} : \mathcal{U} \times \mathbb{N} \to \mathcal{IV}`$,
- a chunk size $`B`$,
- a prefix-free injective string encoding $`\eta`$,
- a suffix-free injective integer encoding $`\nu`$,
- a leaf tag size $`t_{\mathsf{leaf}}`$,
- a tag size $`\tau`$.

These parameters satisfy $`c + r = b`$ and $`k \le b`$.

We write the resulting primitive as

```math
\mathsf{TreeWrap}_{p,b,r,c,k,\mathcal{IV},\mathcal{U},\mathsf{iv},B,\eta,\nu,t_{\mathsf{leaf}},\tau}.
```

When these parameters are fixed by context, we write simply $`\mathsf{TreeWrap}`$, $`\mathsf{TreeWrap.ENC}`$, and $`\mathsf{TreeWrap.DEC}`$.

In the algorithm blocks below, we use the ASCII spellings `ell`, `tau`, and `t_leaf` for the mathematical parameters $`\ell`$, $`\tau`$, and $`t_{\mathsf{leaf}}`$.

For readability, Section 3 presents the construction in the single-key setting. The multi-user AE analyses of Sections 4--6 lift these same algorithms to a key array $`K = (K[1],\ldots,K[\mu])`$ by selecting the active user index $`\delta`$ on each oracle query and then invoking the single-key algorithms under $`K[\delta]`$.

### 3.2 LeafWrap

LeafWrap is the chunk-local wrapper used inside TreeWrap. It has no local associated-data phase: chunk-local authentication is driven entirely by the body transcript and the leaf tag, while global associated data is incorporated only by the final TreeWrap combiner.

Conceptually, $`\mathsf{LeafWrap}[p]`$ is the message-processing core of $`\mathsf{MonkeySpongeWrap}[p]`$ from [Men23] with the associated-data phase removed and the two directions presented as a single symmetric transcript function parameterized by $`m \in \{\mathsf{enc},\mathsf{dec}\}`$.

#### 3.2.1 Definition

This is a TreeWrap-native construction defined directly in terms of the keyed duplex transcript. We denote it by

```math
\mathsf{LeafWrap}[p].
```

It takes $`(K,V,X,m) \in \{0,1\}^k \times \mathcal{IV} \times \{0,1\}^* \times \{\mathsf{enc},\mathsf{dec}\}`$ and returns $`(Y,T) \in \{0,1\}^{|X|} \times \{0,1\}^{t_{\mathsf{leaf}}}`$.

```text
Algorithm LeafWrap[p](K, V, X, m):
    (X~_1, ..., X~_w) <- pad*_{10^r*}(X)
    Y* <- ε
    T* <- ε
    instantiate KD[p]_(K) with α = 0
    KD.init(1, V)
    for j = 1 to w:
        flag <- (m = dec)
        Z~_j <- KD.duplex(flag, X~_j || 1 || 0^{c-1})
        Y* <- Y* || (Z~_j xor X~_j)
    for j = 1 to ceil(t_leaf / r):
        T* <- T* || KD.duplex(false, 0^b)
    Y <- left_|X|(Y*)
    T <- left_t_leaf(T*)
    return (Y, T)
```

Here the body-loop flag is set explicitly by $`\mathsf{flag} \gets [m = \mathsf{dec}]`$: encryption uses $`\mathsf{flag} = \mathsf{false}`$, while decryption uses $`\mathsf{flag} = \mathsf{true}`$. Thus encryption XOR-absorbs the padded body blocks and decryption runs the corresponding overwrite transcript. This is the transcript-level object used throughout the later reductions.

#### 3.2.2 Inversion

**Lemma 3.1 (LeafWrap Inversion).** For any fixed $`K`$ and $`V`$, if

```math
(Y,T) \gets \mathsf{LeafWrap}[p](K,V,X,\mathsf{enc}),
```

then

```math
(X,T) \gets \mathsf{LeafWrap}[p](K,V,Y,\mathsf{dec}).
```

In other words, the encryption and decryption modes of LeafWrap invert the body transformation while reproducing the same leaf tag.

**Proof sketch.** In the $`j`$th body step of encryption, the ciphertext block is $`Y_j = X_j \oplus Z_j`$, where $`Z_j`$ is the corresponding duplex squeeze output. Decryption feeds the same framed block $`Y_j \| 1 \| 0^{c-1}`$ with overwrite flag $`\mathsf{true}`$, so the absorbed full-state input becomes

```math
[\mathsf{true}] \cdot (Z_j \| 0^{b-r}) \oplus (Y_j \| 1 \| 0^{c-1})
=
X_j \| 1 \| 0^{c-1},
```

which is exactly the framed encryption-side body block. Thus the entire body transcript, and therefore the subsequent tag-squeezing transcript, is reproduced exactly.

### 3.3 TrunkSponge

The final TreeWrap combiner is a keyed absorb-then-squeeze transcript built directly from the keyed duplex. We denote it by

```math
\mathsf{TrunkSponge}[p].
```

In the single-key setting, it takes $`(K,IV,W) \in \{0,1\}^k \times \mathcal{IV} \times \{0,1\}^*`$ and returns $`T \in \{0,1\}^{\ell}`$.

```text
Algorithm TrunkSponge[p](K, IV, W; output length ell):
    (W~_1, ..., W~_w) <- pad*_{10^r*}(W)
    instantiate KD[p]_(K) with α = 0
    KD.init(1, IV)
    for i = 1 to w:
        KD.duplex(false, W~_i || 0^c)
    T* <- ε
    while |T*| < ell:
        T* <- T* || KD.duplex(false, 0^b)
    return left_ell(T*)
```

This construction absorbs only rate-sized blocks and appends $`0^c`$ in the capacity part on every absorption call. On the keyed side, it is a direct keyed-duplex transcript to which the generic KD/IXIF reduction of [Men23] applies. On the flat side, its absorb-then-squeeze behavior matches the ordinary sponge viewpoint of [BDPVA08], which is exactly what the CMT-4 analysis needs.

### 3.4 TreeWrap

TreeWrap applies LeafWrap independently to message chunks and then authenticates the resulting leaf tags with a final TrunkSponge call.

Its interface is

```math
\mathsf{TreeWrap}(K,U,A,X,m) \to (Y,T),
```

where $`Y \in \{0,1\}^{|X|}`$ and $`T \in \{0,1\}^{\tau}`$.

```text
Algorithm TreeWrap(K, U, A, X, m):
    n <- ceil(|X| / B)
    parse X according to the canonical chunking of Section 2.1
    // when n = 0, the chunk list is empty
    for i = 0 to n-1:
        V_i <- iv(U, i+1)
        (Y_i, T_i) <- LeafWrap[p](K, V_i, X_i, m)
    Y <- Y_0 || ... || Y_{n-1}
    V_out <- iv(U, 0)
    T <- TrunkSponge[p](K, V_out, enc_out(A, T_0, ..., T_{n-1}, n); output length tau)
    return (Y, T)
```

The chunking line uses the canonical decomposition of Section 2.1. In the pseudocode, $`\mathsf{enc\_out}`$ abbreviates $`\mathsf{enc}_{\mathsf{out}}`$. The IV-derivation map $`\mathsf{iv}`$ is used with suffix $`0`$ for the outer trunk-sponge IV and with suffixes $`1,2,\ldots,n`$ for the chunk-local LeafWrap IVs. The final tag depends on the nonce, the global associated data, the leaf tags, and the chunk count, but not directly on the mode flag. In particular, the ciphertext body $`Y`$ depends on $`(K,U,P)`$ but not on $`A`$; associated data is bound only through the final trunk-sponge tag.

### 3.5 AEAD Wrapper

We now package TreeWrap as a conventional AEAD interface.

#### 3.5.1 ENC

```math
\mathsf{TreeWrap.ENC}(K,U,A,P) \to C.
```

```text
Algorithm TreeWrap.ENC(K, U, A, P):
    (Y, T) <- TreeWrap(K, U, A, P, enc)
    return Y || T
```

#### 3.5.2 DEC

```math
\mathsf{TreeWrap.DEC}(K,U,A,C) \to \{0,1\}^* \cup \{\bot\}.
```

```text
Algorithm TreeWrap.DEC(K, U, A, C):
    if |C| < tau:
        return ⊥
    parse C as Y || T with |T| = tau
    (P, T') <- TreeWrap(K, U, A, Y, dec)
    if T = T':
        return P
    else:
        return ⊥
```

#### 3.5.3 Correctness

Correctness of TreeWrap follows from the corresponding inversion property of LeafWrap together with deterministic final tag derivation.

**Lemma 3.2 (TreeWrap Correctness).** For all valid inputs $`(K,U,A,P)`$,

```math
\mathsf{TreeWrap.DEC}(K,U,A,\mathsf{TreeWrap.ENC}(K,U,A,P)) = P.
```

**Proof sketch.** $`\mathsf{TreeWrap.ENC}`$ partitions $`P`$ into chunks $`P_0,\ldots,P_{n-1}`$ and computes

```math
V_i := \mathsf{iv}(U,i+1), \qquad (Y_i,T_i) \gets \mathsf{LeafWrap}[p](K,V_i,P_i,\mathsf{enc})
```

for each $`i \in [0,n)`$. By Lemma 3.1, $`\mathsf{TreeWrap.DEC}`$ recovers each chunk $`P_i`$ from the corresponding body chunk $`Y_i`$ and recomputes the same per-chunk tag $`T_i`$. Hence the encoded outer-combiner input

```math
\mathsf{enc}_{\mathsf{out}}(A, T_0, \ldots, T_{n-1}, n)
```

is identical in wrapping and unwrapping, and both procedures use the same outer IV $`V_{\mathsf{out}}(U) = \mathsf{iv}(U,0)`$. Therefore they derive the same final tag via $`\mathsf{TrunkSponge}[p]`$, tag verification succeeds, and the recovered plaintext is exactly $`P`$.

## 4. Security Model and Imported Bounds

For the AEAD notions of Sections 4.1--4.3, we work in the ideal-permutation model in the multi-user setting of [Men23]. Fix $`\mu \ge 1`$. Let $`p \gets \mathrm{Perm}(b)`$ be sampled uniformly at random, and let

```math
K = (K[1],\ldots,K[\mu]) \gets (\{0,1\}^k)^\mu
```

be a uniformly random key array. Unless stated otherwise, probabilities are taken over the random choices of $`p`$, $`K`$, and the adversary's internal randomness. We suppress the parameter $`\mu`$ from the advantage notation when it is fixed by context.

In the AEAD experiments below, the adversary additionally has primitive access to the sampled permutation via two oracles:

- $`\mathsf{Perm}(S) := p(S)`$,
- $`\mathsf{PermInv}(S) := p^{-1}(S)`$.

We write $`N`$ for the total number of primitive queries made to these two oracles.

In the AEAD experiments of Sections 4.1--4.3, adversaries are nonce-respecting on a per-user basis: they never repeat a nonce across encryption-type oracle queries addressed to the same user index $`\delta`$. Concretely:

- in the IND-CPA and IND-CCA2 left-right experiments, no two left-right queries for the same $`\delta`$ use the same nonce $`U`$;
- in the INT-CTXT experiment, no two encryption-oracle queries for the same $`\delta`$ use the same nonce $`U`$;
- decryption queries may repeat nonces.

For standard AEAD security notions, we use the adversarial resource measures $`q_e`$ for the number of encryption queries, $`q_f`$ for the number of final forgery candidates in the multi-forgery INT-CTXT experiment, $`q_d`$ for the number of decryption-oracle queries in the IND-CCA2 experiment, and $`\sigma`$ for total queried data complexity. For lower-level duplex and sponge analyses, we additionally use the resource measures of [Men23], including $`M`$, $`N`$, $`Q`$, $`Q_{IV}`$, $`L`$, $`\Omega`$, and $`\nu_{\mathsf{fix}}`$.

All user indices $`\delta`$ range over $`\{1,\ldots,\mu\}`$.

In the AEAD experiments below, $`\mathsf{TreeWrap}_p`$ denotes TreeWrap instantiated with the sampled permutation $`p`$; the active user key on a query with index $`\delta`$ is $`K[\delta]`$.

### 4.1 IND-CPA

We use the standard left-right indistinguishability experiment for nonce-respecting adversaries.

```text
Experiment IND-CPA_b^TreeWrap(A):
    p <- Perm(b)
    K <- ({0,1}^k)^μ

    Oracle LR(δ, U, A, P_0, P_1):
        require |P_0| = |P_1|
        return TreeWrap_p.ENC(K[δ], U, A, P_b)

    Oracle Perm(S):
        return p(S)

    Oracle PermInv(S):
        return p^{-1}(S)

    b' <- A^LR,Perm,PermInv
    return b'
```

The IND-CPA advantage is

```math
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cpa}}_{\mathsf{TreeWrap}}(\mathcal{A})
=
\left| \Pr[(\mathrm{IND}\text{-}\mathrm{CPA})^{\mathsf{TreeWrap}}_1(\mathcal{A}) = 1] - \Pr[(\mathrm{IND}\text{-}\mathrm{CPA})^{\mathsf{TreeWrap}}_0(\mathcal{A}) = 1] \right|.
```

### 4.2 INT-CTXT

Ciphertext integrity is defined by the following multi-forgery experiment.

```text
Experiment INT-CTXT^TreeWrap(A):
    p <- Perm(b)
    K <- ({0,1}^k)^μ
    Seen <- ∅

    Oracle Enc(δ, U, A, P):
        C <- TreeWrap_p.ENC(K[δ], U, A, P)
        Seen <- Seen ∪ {(δ, U, A, C)}
        return C

    Oracle Perm(S):
        return p(S)

    Oracle PermInv(S):
        return p^{-1}(S)

    F <- A^Enc,Perm,PermInv
    return [∃ (δ, U, A, C) in F :
              TreeWrap_p.DEC(K[δ], U, A, C) != ⊥
              and (δ, U, A, C) notin Seen]
```

The INT-CTXT advantage is

```math
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{A})
=
\Pr[(\mathrm{INT}\text{-}\mathrm{CTXT})^{\mathsf{TreeWrap}}(\mathcal{A}) = 1].
```

Here $`\mathcal{A}`$ may make its encryption and primitive queries adaptively before outputting the final candidate set $`F`$, and $`q_f := |F|`$ denotes the number of forgery candidates in that final output set across all users.

### 4.3 IND-CCA2

Chosen-ciphertext privacy is defined by the following left-right experiment with decryption access.

```text
Experiment IND-CCA2_b^TreeWrap(A):
    p <- Perm(b)
    K <- ({0,1}^k)^μ
    Seen <- ∅

    Oracle LR(δ, U, A, P_0, P_1):
        require |P_0| = |P_1|
        C <- TreeWrap_p.ENC(K[δ], U, A, P_b)
        Seen <- Seen ∪ {(δ, U, A, C)}
        return C

    Oracle Dec(δ, U, A, C):
        require (δ, U, A, C) notin Seen
        return TreeWrap_p.DEC(K[δ], U, A, C)

    Oracle Perm(S):
        return p(S)

    Oracle PermInv(S):
        return p^{-1}(S)

    b' <- A^LR,Dec,Perm,PermInv
    return b'
```

The IND-CCA2 advantage is

```math
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cca2}}_{\mathsf{TreeWrap}}(\mathcal{A})
=
\left| \Pr[(\mathrm{IND}\text{-}\mathrm{CCA2})^{\mathsf{TreeWrap}}_1(\mathcal{A}) = 1] - \Pr[(\mathrm{IND}\text{-}\mathrm{CCA2})^{\mathsf{TreeWrap}}_0(\mathcal{A}) = 1] \right|.
```

### 4.4 CMT-4

For commitment security, we adopt the encryption-based CMT-4 notion of [BH22]. The winning-input extractor is

```math
\mathsf{WiC}_4(K,U,A,P) = (K,U,A,P).
```

The corresponding collision experiment is

```text
Experiment CMT-4^TreeWrap(A):
    p <- Perm(b)

    Oracle Perm(S):
        return p(S)

    Oracle PermInv(S):
        return p^{-1}(S)

    ((K_1, U_1, A_1, P_1), (K_2, U_2, A_2, P_2)) <- A^Perm,PermInv
    if WiC_4(K_1, U_1, A_1, P_1) = WiC_4(K_2, U_2, A_2, P_2):
        return 0
    C_1 <- TreeWrap_p.ENC(K_1, U_1, A_1, P_1)
    C_2 <- TreeWrap_p.ENC(K_2, U_2, A_2, P_2)
    return [C_1 = C_2]
```

The CMT-4 advantage is

```math
\mathrm{Adv}^{\mathsf{cmt}\text{-}4}_{\mathsf{TreeWrap}}(\mathcal{A})
=
\Pr[(\mathrm{CMT}\text{-}4)^{\mathsf{TreeWrap}}(\mathcal{A}) = 1].
```

### 4.5 Induced Lower-Level Resources

We now record the lower-level resources induced by TreeWrap queries at the LeafWrap and outer trunk-sponge layers.

**Lemma 4.1 (Derived Internal-Keyed-Context Discipline).** Suppose the adversary is nonce-respecting at the TreeWrap encryption layer on a per-user basis. Then:

```math
V_{\mathsf{out}}(U) := \mathsf{iv}(U,0)
```

induces pairwise distinct outer keyed contexts $`(\delta,V_{\mathsf{out}}(U))`$ across encryption queries;

```math
V_i(U) := \mathsf{iv}(U,i+1)
```

induces pairwise distinct leaf keyed contexts $`(\delta,V_i(U))`$ across all encryption-side LeafWrap calls; and no outer keyed context equals any leaf keyed context.

**Proof.** All claims follow from per-user nonce-respecting behavior together with injectivity of the map $`(U,j) \mapsto \mathsf{iv}(U,j)`$ on $`\mathcal{U} \times \mathbb{N}`$. Distinct encryption queries for a fixed user $`\delta`$ use distinct nonces, and within a fixed encryption query the suffixes $`0,1,\ldots,n`$ are all different. Hence the corresponding derived keyed contexts are pairwise distinct. Repetitions of the bare IV string across different users are harmless because the idealized initialization path is $`\mathrm{uid}(\delta) \| IV`$, so different user indices still induce distinct keyed contexts.

For any bitstring $`Z \in \{0,1\}^*`$, define the number of rate-blocks after $`\mathrm{pad}10^*`$ padding by

```math
\omega_r(Z) := \left\lceil \frac{|Z|+1}{r} \right\rceil.
```

Also define the fixed tag-squeezing costs

```math
s_{\mathsf{leaf}} := \left\lceil \frac{t_{\mathsf{leaf}}}{r} \right\rceil,
\qquad
s_{\mathsf{out}} := \left\lceil \frac{\tau}{r} \right\rceil.
```

If a TreeWrap body string $`X`$ is partitioned into chunks

```math
X = X_0 \| \cdots \| X_{n-1},
```

then each induced LeafWrap call on $`X_i`$ performs exactly

```math
\omega_r(X_i) + s_{\mathsf{leaf}}
```

duplexing calls: $`\omega_r(X_i)`$ message/ciphertext-phase calls and $`s_{\mathsf{leaf}}`$ tag-squeezing calls. Accordingly, define

```math
\chi(X) := n,
```

```math
\sigma_{\mathsf{lw}}(X) := \sum_{i=0}^{n-1} \bigl(\omega_r(X_i) + s_{\mathsf{leaf}}\bigr).
```

If one later wishes to instantiate the imported LeafWrap bounds with explicit IV-length accounting, the derived leaf IVs contribute the quantity

```math
\iota_{\mathsf{lw}}(X) := \chi(X)\cdot (b-k).
```

This isolates the contribution of the derived leaf IVs to the lower-level LeafWrap resource tuple. In the multi-user setting, Section 2.3.2 additionally prefixes each initialization path by the encoded user index $`\delta`$ via $`\mathrm{uid}(\delta)`$; this contributes only a fixed per-initialization overhead independent of the message length, so we leave it implicit in the present abstract resource accounting.

For an adversary's encryption queries with plaintext bodies $`P^{(1)},\ldots,P^{(q_e)}`$ and decryption-side ciphertext bodies $`Y^{(1)},\ldots,Y^{(q_*)}`$, aggregated across all users, where $`q_*`$ denotes either the final-candidate count $`q_f`$ in INT-CTXT or the decryption-query count $`q_d`$ in IND-CCA2, we set

```math
\chi_e := \sum_{a=1}^{q_e} \chi(P^{(a)}),
\qquad
\chi_d := \sum_{b=1}^{q_*} \chi(Y^{(b)}),
```

```math
\sigma^{\mathsf{lw}}_e := \sum_{a=1}^{q_e} \sigma_{\mathsf{lw}}(P^{(a)}),
\qquad
\sigma^{\mathsf{lw}}_d := \sum_{b=1}^{q_*} \sigma_{\mathsf{lw}}(Y^{(b)}).
```

These are the natural resource measures for the LeafWrap reductions of Section 6.

At the outer layer, each TreeWrap encryption or decryption query performs one $`\mathsf{TrunkSponge}[p]`$ evaluation on the encoded combiner input

```math
W(A,X) := \mathsf{enc}_{\mathsf{out}}(A, T_0, \ldots, T_{n-1}, n),
```

where $`n = \chi(X)`$ and the $`T_i`$ are the corresponding leaf tags. By definition of $`\mathsf{enc}_{\mathsf{out}}`$,

```math
|W(A,X)| = |\eta(A)| + n \cdot t_{\mathsf{leaf}} + |\nu(n)|
\le
|A| + \lambda_\eta(|A|) + n \cdot t_{\mathsf{leaf}} + \lambda_\nu(n).
```

The total number of duplexing calls in this outer evaluation is therefore

```math
\sigma_{\mathsf{out}}(A,X) := \left\lceil \frac{|W(A,X)|+1}{r} \right\rceil + s_{\mathsf{out}}.
```

Accordingly, define

```math
q^{\mathsf{out}}_e := q_e,
\qquad
q^{\mathsf{out}}_d := q_*,
```

```math
\sigma^{\mathsf{out}}_e := \sum_{a=1}^{q_e} \sigma_{\mathsf{out}}(A^{(a)},P^{(a)}),
\qquad
\sigma^{\mathsf{out}}_d := \sum_{b=1}^{q_*} \sigma_{\mathsf{out}}(A'^{(b)},Y^{(b)}),
```

where $`(A^{(a)},P^{(a)})`$ and $`(A'^{(b)},Y^{(b)})`$ range over the encryption and decryption queries, respectively. These are the natural resource measures for the outer-combiner reductions.

### 4.6 Translation to Men23 Resources

When instantiating the imported results of [Men23], we keep the full $`\mu`$-user setting. For readability, write

```math
\mathrm{KD}^{(i)}_{\mathsf{Men23}}(\mu,M,Q,Q_{IV},L,\Omega,\nu_{\mathsf{fix}},N)
```

for the low-complexity keyed-duplex distinguishing bound obtained by instantiating the imported [Men23] security theorem with the displayed resource tuple. This shorthand is generic: the reduced LeafWrap and outer TrunkSponge imports below use different valid assignments of $`(M,Q,Q_{IV},L,\Omega,\nu_{\mathsf{fix}})`$. The simplified branch is valid in the regime $`M + N \le 0.1 \cdot 2^c`$; if this side condition is not met, one may instead use the corresponding general branch.

For the reduced MonkeySpongeWrap-style analysis of LeafWrap, define the decryption-side overwrite count

```math
\Omega_{\mathsf{lw},d} := \sigma^{\mathsf{lw}}_d - s_{\mathsf{leaf}} \chi_d
=
\sum_{b=1}^{q_*} \sum_{i=0}^{\chi(Y^{(b)})-1} \omega_r(Y^{(b)}_i),
```

where $`Y^{(b)}_i`$ denotes the $`i`$th chunk body in the $`b`$th decryption-side query.
Because $`\mathrm{pad}10^*`$ always produces at least one padded body block, every chunk contributes at least one body-phase call, so $`\omega_r(Y^{(b)}_i) \ge 1`$ and the displayed identity cleanly separates body-processing calls from the single leaf-tag squeeze in each local transcript.

**Lemma 4.2 (LeafWrap Resource Translation).** The reduced LeafWrap families induced by TreeWrap admit the following valid resource assignments in the notation of [Men23]:

- for the encryption-only family relevant to IND-CPA, one may take

  ```math
  M = \sigma^{\mathsf{lw}}_e,\quad
  Q = \chi_e,\quad
  Q_{IV} \le \mu,\quad
  L = 0,\quad
  \Omega = 0,\quad
  \nu_{\mathsf{fix}} = 0;
  ```

- for the bidirectional family relevant to INT-CTXT and IND-CCA2, one may take

  ```math
  M = \sigma^{\mathsf{lw}}_e + \sigma^{\mathsf{lw}}_d,\quad
  Q = \chi_e + \chi_d,\quad
  Q_{IV} \le \mu,\quad
  L \le \chi_d,\quad
  \Omega = \Omega_{\mathsf{lw},d},\quad
  \nu_{\mathsf{fix}} \le \max\!\bigl(\Omega_{\mathsf{lw},d} + \chi_e + \chi_d - 1, 0\bigr).
  ```

**Proof sketch.** For LeafWrap, each construction query corresponds to one initialization and a sequence of body-phase and squeezing duplex calls. In the encryption-only case, Lemma 4.1 gives pairwise distinct leaf keyed contexts $`(\delta,\mathsf{iv}(U,i+1))`$, so no repeated subpath can occur across encryption-side queries; moreover, encryption never uses overwrite calls, hence $`L = \Omega = \nu_{\mathsf{fix}} = 0`$. Across different users, the same bare IV may recur, but the idealized initialization paths are $`\mathrm{uid}(\delta) \| IV`$, so $`Q_{IV} \le \mu`$ is the correct bound. In the bidirectional case, the argument follows the proof of Theorem 7 of [Men23] mutatis mutandis. Distinct encryption-side leaf keyed contexts still eliminate encryption/encryption subpath repetition, while decryption-side queries may repeat keyed leaf contexts and contribute at most $`\chi_d`$ repeated subpaths. Because the reduced LeafWrap transcript has no local associated-data phase and $`\mathrm{pad}10^*`$ guarantees at least one body block per chunk, each decryption-side chunk contributes exactly $`\omega_r(Y^{(b)}_i)`$ overwrite body calls and exactly $`s_{\mathsf{leaf}}`$ non-overwriting squeeze calls, giving the stated identity for $`\Omega_{\mathsf{lw},d}`$.

The parameter $`\nu_{\mathsf{fix}}`$ is not merely the number of overwrite calls. By [Men23, Section 4.1], it counts duplexing calls for which the adversary can force the outer part of the duplex input to one fixed value, and this can happen either through overwrite or through a repeated subpath, where the corresponding squeeze output is already known from the earlier transcript. This is why [Men23, Theorem 7] concludes

```math
\nu_{\mathsf{fix}} \le \Omega + q_e + q_d - 1
```

rather than $`\nu_{\mathsf{fix}} \le \Omega`$. In reduced LeafWrap, the same path-counting argument carries over with $`q_e = \chi_e`$, $`q_d = \chi_d`$, and $`\Omega = \Omega_{\mathsf{lw},d}`$, because the only structural change is that the vacuous local associated-data phase has been removed. This yields exactly

```math
\nu_{\mathsf{fix}} \le \max\!\bigl(\Omega_{\mathsf{lw},d} + \chi_e + \chi_d - 1, 0\bigr).
```

The clamp at $`0`$ is only needed in the degenerate case $`\chi_e = \chi_d = \Omega_{\mathsf{lw},d} = 0`$, where no LeafWrap transcript occurs at all and $`\nu_{\mathsf{fix}}`$ must therefore be zero.

**Corollary 4.4 (Imported LeafWrap Encryption-Side KD/IXIF Bound).** If $`\sigma^{\mathsf{lw}}_e + N \le 0.1 \cdot 2^c`$, then the encryption-side LeafWrap real-to-IXIF replacement term of Theorem 6.2 can be instantiated as

```math
\epsilon_{\mathsf{lw}}^{\mathsf{enc}}(\mu,\chi_e,\sigma^{\mathsf{lw}}_e,N)
:=
\mathrm{KD}^{(i)}_{\mathsf{Men23}}(\mu,\sigma^{\mathsf{lw}}_e,\chi_e,\mu,0,0,0,N).
```

This is the encryption-only LeafWrap import under the resource assignment of Lemma 4.2.

**Corollary 4.5 (Imported LeafWrap Bidirectional KD/IXIF Bound).** If $`\sigma^{\mathsf{lw}}_e + \sigma^{\mathsf{lw}}_d + N \le 0.1 \cdot 2^c`$, then the bidirectional LeafWrap real-to-IXIF replacement term of Theorem 6.2 can be instantiated as

```math
\epsilon_{\mathsf{lw}}^{\mathsf{ae}}(\mu,\chi_e,\chi_d,\sigma^{\mathsf{lw}}_e,\sigma^{\mathsf{lw}}_d,N)
:=
\mathrm{KD}^{(i)}_{\mathsf{Men23}}(\mu,\sigma^{\mathsf{lw}}_e+\sigma^{\mathsf{lw}}_d,\chi_e+\chi_d,\mu,\chi_d,\Omega_{\mathsf{lw},d},\max\!\bigl(\Omega_{\mathsf{lw},d}+\chi_e+\chi_d-1,0\bigr),N).
```

This is the bidirectional LeafWrap import under the resource assignment of Lemma 4.2.

**Lemma 4.3 (Outer TrunkSponge Resource Translation).** The outer trunk-sponge families induced by TreeWrap admit the following valid resource assignments in the notation of [Men23]:

- for the encryption-only family relevant to IND-CPA, one may take

  ```math
  M = \sigma^{\mathsf{out}}_e,\quad
  Q = q^{\mathsf{out}}_e,\quad
  Q_{IV} \le \mu,\quad
  L = 0,\quad
  \Omega = 0,\quad
  \nu_{\mathsf{fix}} = 0;
  ```

- for the family with both encryption-side and decryption-side evaluations relevant to INT-CTXT and IND-CCA2, one may take

  ```math
  M = \sigma^{\mathsf{out}}_e + \sigma^{\mathsf{out}}_d,\quad
  Q = q^{\mathsf{out}}_e + q^{\mathsf{out}}_d,\quad
  Q_{IV} \le \mu,\quad
  L \le \sigma^{\mathsf{out}}_d,\quad
  \Omega = 0,\quad
  \nu_{\mathsf{fix}} = 0.
  ```

**Proof sketch.** Each $`\mathsf{TrunkSponge}[p]`$ evaluation contributes one initialization, $`\lceil (|W|+1)/r \rceil`$ absorption calls on blocks of the form $`\widetilde{W}_i \| 0^c`$, and $`s_{\mathsf{out}}`$ blank squeezing calls. All calls use flag $`\mathsf{false}`$, so $`\Omega = 0`$ throughout. For encryption-type queries, Lemma 4.1 implies that the derived outer keyed contexts $`(\delta,V_{\mathsf{out}}(U)) = (\delta,\mathsf{iv}(U,0))`$ are distinct, hence $`L = \nu_{\mathsf{fix}} = 0`$. Across different users, the same bare outer IV may recur, but again the idealized initialization paths are $`\mathrm{uid}(\delta) \| IV`$, so $`Q_{IV} \le \mu`$ is the correct bound. In the general case, repeated subpaths can arise only from decryption-side recomputations under reused outer keyed contexts, and their total number is bounded by the total number of decryption-side duplexing calls, namely $`\sigma^{\mathsf{out}}_d`$. Because absorbed blocks have the fixed form $`\widetilde{W}_i \| 0^c`$, each absorption call enters the permutation with rate part $`Z_i \oplus \widetilde{W}_i`$, where $`Z_i`$ is the unrevealed intermediate squeeze output of the keyed duplex. Even if the adversary determines $`\widetilde{W}_i`$ indirectly through the recomputed leaf tags, it does not observe $`Z_i`$ during absorption and therefore cannot choose $`\widetilde{W}_i`$ so as to force the outer part to one fixed value. Hence $`\nu_{\mathsf{fix}} = 0`$ remains valid.

**Corollary 4.6 (Imported Outer TrunkSponge KD/IXIF Bound).** If $`\sigma^{\mathsf{out}}_e + \sigma^{\mathsf{out}}_d + N \le 0.1 \cdot 2^c`$, then the outer-combiner real-to-IXIF replacement term can be instantiated as

```math
\epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,q^{\mathsf{out}}_d,\sigma^{\mathsf{out}}_e,\sigma^{\mathsf{out}}_d,N)
:=
\mathrm{KD}^{(i)}_{\mathsf{Men23}}(\mu,\sigma^{\mathsf{out}}_e+\sigma^{\mathsf{out}}_d,q^{\mathsf{out}}_e+q^{\mathsf{out}}_d,\mu,\sigma^{\mathsf{out}}_d,0,0,N).
```

This is the direct keyed-duplex import for the outer trunk-sponge transcript under the resource assignment of Lemma 4.3.

### 4.7 Rooted-Forest Sponge Collision Bound

For the outer CMT-4 analysis, we only need a bad-event bound for rooted transcript merging, not a full indifferentiability statement. We therefore import the single-root random-permutation sponge counting argument of [BDPVA08, Eq. (6)] and record the corresponding $`\rho`$-root extension directly.

**Lemma 4.7 (Rooted-Forest Sponge Collision Bound).** Fix $`\rho \ge 1`$ public roots. For each root, consider the rooted sponge tree obtained by following absorb/squeeze paths from that root as in [BDPVA08]. Let $`R_i`$ be the set of rooted nodes exposed after $`i`$ successful transcript or primitive-query extensions, and let $`O_i`$ be the set of already fixed full states encountered along those rooted paths. Define the bad event $`\mathsf{Merge}_{\rho}(M)`$ to be the event that, during the first $`M`$ such extensions, a new forward or inverse step lands on a previously exposed rooted node or previously fixed full state in a way that merges two distinct rooted transcripts. Then

Exactly as in the single-root counting of [BDPVA08], each safe extension contributes at most one new rooted node and at most one new full state. Hence, inductively,

```math
|R_i| \le \rho + i,
\qquad
|O_i| \le i,
```

for every $`i \ge 0`$. Repeating the one-root bad-event count with these cardinalities yields

```math
f_{P,\rho}(M)
:=
1 - \prod_{i=0}^{M-1} \frac{1-(\rho+i)2^{-c}}{1-i2^{-b}}.
```

Here the numerator bounds the probability that the next capacity slice avoids the at most $`\rho+i`$ exposed rooted nodes, while the denominator conditions on avoiding the at most $`i`$ previously fixed full states. Therefore

```math
\Pr[\mathsf{Merge}_{\rho}(M)] \le f_{P,\rho}(M).
```

Applying the same quadratic relaxation as in [BDPVA08, Eq. (6)] gives the explicit rooted-forest collision bound

```math
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M,\rho)
:=
\frac{(1-2^{-r})M^2 + (2\rho-1+2^{-r})M}{2^{c+1}}
```

in the regime $`M < 2^c`$. For $`\rho = 1`$, the product expression specializes to the original single-root counting bound and the displayed quadratic term recovers exactly [BDPVA08, Eq. (6)].

### 4.8 Imported Flat Duplex Bound

For the local CMT-4 analysis, the duplexing-sponge lemma of [BDPVA11, Lemma 3] allows us to reuse the same rooted-sponge bound for the flattened encryption-side LeafWrap transcript. This use is purely structural: the duplexing-sponge equivalence identifies the duplex transcript with the corresponding sponge transcript for every fixed input history, independent of how the adversary chooses keys, IVs, or message blocks. For an $`\ell`$-bit chunk body, define

```math
M_{\mathsf{lw}}(\ell,N)
:=
N + 2 \left(\left\lceil \frac{\ell+1}{r} \right\rceil + s_{\mathsf{leaf}}\right).
```

This quantity counts the adversary's primitive-query budget together with the two compared local LeafWrap transcripts, each of which consists of $`\lceil (\ell+1)/r \rceil`$ body calls and $`s_{\mathsf{leaf}}`$ blank squeeze calls. Since a local collision comparison involves at most two distinct roots $`(K,V)`$ and $`(K',V')`$, we set

```math
\epsilon_{\mathsf{lw}}^{\flat}(\ell,N)
:=
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{lw}}(\ell,N),2)
+
2^{-(\ell+t_{\mathsf{leaf}})}.
```

This is the concrete local CMT-4 term used below.

## 5. Main Results

For the IND-CPA and INT-CTXT path, we instantiate the imported [Men23] terms using Section 4.6. For CMT-4, both the local flat-duplex term and the outer flat-sponge term are now made explicit via Sections 4.8 and 4.7.

- Let $`\epsilon_{\mathsf{lw}}^{\mathsf{enc}}`$ be the explicit imported KD/IXIF term of Corollary 4.4.
- Let $`\epsilon_{\mathsf{lw}}^{\mathsf{ae}}`$ be the explicit imported KD/IXIF term of Corollary 4.5.
- Let $`\epsilon_{\mathsf{out}}^{\mathsf{ixif}}`$ be the explicit imported outer KD/IXIF term of Corollary 4.6.
- By Lemma 7.1 together with the derived keyed-context discipline of Lemma 4.1, the only additional local freshness failure in the INT-CTXT proof is the event that a fresh random leaf tag equals the unique prior leaf tag in the same keyed leaf context, which contributes at most $`2^{-t_{\mathsf{leaf}}}`$.
- Let $`\epsilon_{\mathsf{lw}}^{\flat}(\ell,N)`$ be the explicit local flat-duplex term of Section 4.8.
- Let $`\mathrm{Sponge}^{(i)}_{\mathsf{forest}}`$ be the explicit $`\rho`$-root flat-sponge term of Lemma 4.7.

### 5.1 IND-CPA Theorem

**Theorem 5.1 (IND-CPA).** Assume $`\sigma^{\mathsf{lw}}_e + N \le 0.1 \cdot 2^c`$ and $`\sigma^{\mathsf{out}}_e + N \le 0.1 \cdot 2^c`$. Then for every per-user nonce-respecting IND-CPA adversary $`\mathcal{A}`$ against the $`\mu`$-user TreeWrap experiment, there exists a pair of adversaries against the LeafWrap and outer trunk-sponge subclaims such that

```math
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cpa}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\epsilon_{\mathsf{lw}}^{\mathsf{enc}}(\mu,\chi_e,\sigma^{\mathsf{lw}}_e,N)
+
\epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,0,\sigma^{\mathsf{out}}_e,0,N).
```

Equivalently, in the low-total-complexity regime inherited from [Men23], TreeWrap privacy reduces to the encryption-side LeafWrap KD/IXIF replacement of Corollary 4.4 and the analogous outer trunk-sponge KD/IXIF replacement of Corollary 4.6.

### 5.2 INT-CTXT Theorem

**Theorem 5.2 (INT-CTXT).** Assume $`\sigma^{\mathsf{lw}}_e + \sigma^{\mathsf{lw}}_d + N \le 0.1 \cdot 2^c`$ and $`\sigma^{\mathsf{out}}_e + \sigma^{\mathsf{out}}_d + N \le 0.1 \cdot 2^c`$. Then for every per-user nonce-respecting INT-CTXT adversary $`\mathcal{A}`$ against the $`\mu`$-user TreeWrap experiment outputting at most $`q_f`$ forgery candidates, there exists a collection of adversaries against the LeafWrap and outer trunk-sponge subclaims such that

```math
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\epsilon_{\mathsf{lw}}^{\mathsf{ae}}(\mu,\chi_e,\chi_d,\sigma^{\mathsf{lw}}_e,\sigma^{\mathsf{lw}}_d,N)
+
\frac{q_f}{2^{t_{\mathsf{leaf}}}}
+
\epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,q^{\mathsf{out}}_d,\sigma^{\mathsf{out}}_e,\sigma^{\mathsf{out}}_d,N)
+
\frac{q_f}{2^{\tau}}.
```

Equivalently, in the same low-total-complexity regime, TreeWrap ciphertext integrity reduces to the bidirectional LeafWrap KD/IXIF replacement of Corollary 4.5, a union bound over the $`q_f`$ final forgery candidates for the local leaf-tag collision tail, and freshness of the outer trunk-sponge transcript on fresh keyed-context/input pairs as captured by Corollary 4.6.

### 5.3 IND-CCA2 Theorem

**Theorem 5.3 (IND-CCA2).** Let $`\mathcal{A}`$ be a per-user nonce-respecting IND-CCA2 adversary against the $`\mu`$-user TreeWrap experiment making at most $`q_d`$ decryption queries. Then there exist an IND-CPA adversary $`\mathcal{B}_1`$ and two INT-CTXT adversaries $`\mathcal{B}_{2,0}`$ and $`\mathcal{B}_{2,1}`$ such that

```math
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cca2}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cpa}}_{\mathsf{TreeWrap}}(\mathcal{B}_1)
+
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{B}_{2,0})
+
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{B}_{2,1}).
```

The reduction preserves the left-right and primitive-query transcripts exactly: $`\mathcal{B}_1`$ forwards all left-right and primitive queries of $`\mathcal{A}`$ unchanged and answers decryption queries locally with $`\bot`$, while each $`\mathcal{B}_{2,b}`$ forwards each left-right query $`(\delta,U,A,P_0,P_1)`$ as an encryption query on $`(\delta,U,A,P_b)`$, forwards primitive queries unchanged, answers decryption queries locally with $`\bot`$, and records all fresh decryption queries of $`\mathcal{A}`$ as its final INT-CTXT forgery set. Thus the encryption-side lower-level resources of the reductions are exactly those induced by the left-right transcript of $`\mathcal{A}`$, the primitive-query count remains $`N`$, and the only additional overhead is linear-time bookkeeping in the number of wrapper-oracle queries.

In particular, under the side conditions of Theorems 5.1 and 5.2 and using the aggregate decryption-side resources of $`\mathcal{A}`$ as the corresponding decryption-side resources of each INT-CTXT reduction,

```math
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cca2}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\epsilon_{\mathsf{lw}}^{\mathsf{enc}}(\mu,\chi_e,\sigma^{\mathsf{lw}}_e,N)
+
\epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,0,\sigma^{\mathsf{out}}_e,0,N)
+
2 \cdot \epsilon_{\mathsf{lw}}^{\mathsf{ae}}(\mu,\chi_e,\chi_d,\sigma^{\mathsf{lw}}_e,\sigma^{\mathsf{lw}}_d,N)
+
2 \cdot \epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,q^{\mathsf{out}}_d,\sigma^{\mathsf{out}}_e,\sigma^{\mathsf{out}}_d,N)
+
\frac{2 q_d}{2^{t_{\mathsf{leaf}}}}
+
\frac{2 q_d}{2^{\tau}},
```

with the resource parameters inherited from the reductions as described above.

The multi-forgery INT-CTXT formulation of Section 4.2 removes the previous index-guessing loss from the IND-CCA2 reduction. The remaining factor $`2`$ comes from the need to bound the bad-decryption event in both challenge branches $`b = 0`$ and $`b = 1`$ when converting the CCA distinguishing gap to the CPA gap plus integrity failure probabilities. This factor is not a bit-guessing loss: replacing $`\mathcal{B}_{2,0}`$ and $`\mathcal{B}_{2,1}`$ by a single reduction with a hidden random bit would recover only the average of the two bad-event probabilities and would therefore reintroduce the same factor $`2`$ when translated back to the absolute distinguishing gap. The final trunk tag still authenticates the derived leaf-tag vector rather than the transmitted body $`Y`$ itself, so the tighter generic EtM theorem of [BN00] does not apply directly; instead the above reduction proceeds through the TreeWrap-specific INT-CTXT theorem.

### 5.4 CMT-4 Theorem

**Theorem 5.4 (CMT-4).** Let

```math
\Theta := ((K_1,U_1,A_1,P_1),(K_2,U_2,A_2,P_2))
```

be any fixed distinct output pair in the support of a CMT-4 adversary's output distribution. If $`|P_1| \ne |P_2|`$, then the corresponding collision probability is zero because TreeWrap is length preserving. Otherwise let $`n := \chi(P_1) = \chi(P_2)`$, let

```math
P_1 = P_{1,0} \| \cdots \| P_{1,n-1}
```

be the canonical chunk decomposition, let $`\ell_i := |P_{1,i}|`$ for $`i = 0,\ldots,n-1`$, let $`\rho := |\{(K_1,U_1),(K_2,U_2)\}| \in \{1,2\}`$, and define

```math
M_{\mathsf{out}} := N + \sigma_{\mathsf{out}}(A_1,P_1) + \sigma_{\mathsf{out}}(A_2,P_2).
```

Assume $`M_{\mathsf{lw}}(\ell_i,N) < 2^c`$ for every $`i = 0,\ldots,n-1`$ and $`M_{\mathsf{out}} < 2^c`$. Then, over the random permutation $`p`$ alone,

```math
\Pr_p\!\bigl[\mathsf{TreeWrap}_p.\mathsf{ENC}(K_1,U_1,A_1,P_1)=\mathsf{TreeWrap}_p.\mathsf{ENC}(K_2,U_2,A_2,P_2)\bigr]
\le
\sum_{i=0}^{n-1} \epsilon_{\mathsf{lw}}^{\flat}(\ell_i,N)
+
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{out}},\rho)
+
2^{-\tau}.
```

Equivalently, for every fixed output profile $`\Theta`$, the corresponding TreeWrap commitment collision probability reduces either to a local encryption-side LeafWrap collision on the full chunk-output pair $`(Y_i,T_i)`$ at the first differing chunk or to a collision in the flattened outer combiner transcript. Consequently, if $`\Theta`$ denotes the random realized output pair of a CMT-4 adversary $`\mathcal{A}`$, then applying the pointwise bound above and averaging over the distribution of $`\Theta`$ gives

```math
\mathrm{Adv}^{\mathsf{cmt}\text{-}4}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\mathbb{E}_{\Theta}\!\left[
\sum_{i=0}^{n(\Theta)-1} \epsilon_{\mathsf{lw}}^{\flat}(\ell_i(\Theta),N)
+
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{out}}(\Theta),\rho(\Theta))
+
2^{-\tau}
\right],
```

where $`n(\Theta)`$, $`\ell_i(\Theta)`$, $`\rho(\Theta)`$, and $`M_{\mathsf{out}}(\Theta)`$ are extracted from the realized output pair exactly as above, with the convention that the bracketed quantity is $`0`$ when $`|P_1| \ne |P_2|`$.

## 6. Imported AE Sketches

This section contains proof sketches for the authenticated-encryption path. The keyed-duplex and BN00 machinery is imported rather than reproved here: the goal is to isolate how TreeWrap fits the [Men23] framework and how the resulting hybrid arguments compose. The genuinely TreeWrap-specific arguments are deferred to Section 7.

### 6.1 Imported Leaf and Trunk Adaptations

The LeafWrap analysis identifies $`\mathsf{LeafWrap}`$ with the reduced MonkeySpongeWrap transcript obtained by excising the vacuous local associated-data phase, and then imports the corresponding KD/IXIF replacement from [Men23]. The outer combiner uses the same keyed-duplex/IXIF paradigm, but its transcript is simpler because it consists only of absorb-then-squeeze calls with flag $`\mathsf{false}`$.

Let $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}]`$ denote the same transcript as $`\mathsf{LeafWrap}[p]`$, but with the keyed duplex $`\mathsf{KD}[p]`$ replaced by the ideal interface $`\mathsf{IXIF}[\mathrm{ro}]`$ of Section 2.3.2 (equivalently, the IXIF interface used in [Men23]). Thus

```math
\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}](K,V,X,m) \to (Y,T)
```

has exactly the same padding, framing bits, mode flag, and output convention as $`\mathsf{LeafWrap}[p]`$; only the transcript engine changes.

For later use, write the framed full-state blocks of a LeafWrap call as

```math
M_j(X) := \widetilde{X}_j \| 1 \| 0^{c-1}
```

for padded message blocks. If $`\pi_0`$ denotes the IXIF path immediately after

```math
\mathsf{IXIF.init}(1,V),
```

then encryption-side LeafWrap appends the sequence

```math
M_1(X),\ldots,M_w(X)
```

to the path before the tag-squeezing calls. The key decryption-side identity is that if a decryption-side body block $`\widetilde{Y}_j`$ yields IXIF output $`\widetilde{Z}_j`$ and recovered plaintext block $`\widetilde{X}_j = \widetilde{Y}_j \oplus \widetilde{Z}_j`$, then the IXIF path update is

```math
[\mathsf{true}] \cdot (\widetilde{Z}_j \| 0^{b-r}) \oplus (\widetilde{Y}_j \| 1 \| 0^{c-1})
=
\widetilde{X}_j \| 1 \| 0^{c-1}
=
M_j(X).
```

Hence encryption-side and decryption-side LeafWrap calls append the same framed message blocks precisely when they induce the same recovered plaintext transcript. The imported support is summarized by the following two statements.

**Lemma 6.1 (LeafWrap / Reduced MonkeySpongeWrap Transcript Correspondence).** Fix parameters $`p,b,r,c,k,t_{\mathsf{leaf}}`$. For any inputs $`K`$, $`V`$, and $`X`$, the keyed-duplex transcript of

```math
\mathsf{LeafWrap}[p](K,V,X,m)
```

with initialization

```math
\mathsf{KD.init}(1,V)
```

is identical to the reduced MonkeySpongeWrap transcript on nonce $`V`$ and input string $`X`$ obtained by excising the vacuous local associated-data phase, with the middle phase parameterized by $`m`$. Thus $`m = \mathsf{enc}`$ gives the reduced encryption transcript, $`m = \mathsf{dec}`$ gives the corresponding reduced decryption-side transcript with overwrite enabled in the middle phase, and the returned pair $`(Y,T)`$ is exactly the body/tag pair determined by that reduced transcript.

**Theorem 6.2 (Ported LeafWrap KD/IXIF Replacement).** For every distinguisher $`\mathcal{D}_{\mathsf{LW}}`$ attacking a family of LeafWrap transcripts under the keyed-context discipline induced by TreeWrap, there exists a distinguisher $`\mathcal{D}_{\mathsf{MSW}}`$ against the corresponding reduced MonkeySpongeWrap transcript family such that

```math
\mathrm{Adv}^{\mathsf{real}\text{-}\mathsf{ixif}}_{\mathsf{LeafWrap}}(\mathcal{D}_{\mathsf{LW}})
=
\mathrm{Adv}^{\mathsf{real}\text{-}\mathsf{ixif}}_{\mathsf{MonkeySpongeWrap}}(\mathcal{D}_{\mathsf{MSW}}),
```

with matching transcript resources after interpreting each LeafWrap call as the corresponding reduced MonkeySpongeWrap call on the same leaf IV $`V`$. Consequently, the LeafWrap real-to-IXIF replacement is bounded by the corresponding KD/IXIF term imported from [Men23], with the unused local associated-data resources deleted from the accounting. In TreeWrap, the relevant keyed contexts are $`(\delta,V_i)`$ with $`V_i = \mathsf{iv}(U,i+1)`$.

For the outer combiner, let $`\mathsf{TrunkSponge}^{\mathsf{IXIF}}[\mathrm{ro}]`$ denote the same absorb-then-squeeze transcript as $`\mathsf{TrunkSponge}[p]`$, but with the keyed duplex replaced by $`\mathsf{IXIF}[\mathrm{ro}]`$. Because every absorbed block has the fixed form $`\widetilde{W}_j \| 0^c`$ and every call uses flag $`\mathsf{false}`$, Corollary 4.6 applies directly to this transcript family. These imported statements are the only ingredients used in the AE sketches below, together with the TreeWrap-specific freshness lemma of Section 7.1. Throughout Sections 6.2 and 6.3, the imported duplex bounds are used exactly in the form fixed in Section 4.6, namely the $`\mu`$-user, low-complexity branch of [Men23].

### 6.2 IND-CPA Sketch

Fix a per-user nonce-respecting IND-CPA adversary $`\mathcal{A}`$, and for each challenge bit $`b \in \{0,1\}`$ define the following three games. In all three games, $`\mathcal{A}`$ additionally retains primitive access to $`p`$ and $`p^{-1}`$.

- $`H_0^b`$ is the real IND-CPA experiment.
- $`H_1^b`$ is obtained from $`H_0^b`$ by replacing, for each encryption query $`(\delta,U,A,P_0,P_1)`$, every encryption-side LeafWrap call by $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}]`$ under the derived leaf keyed contexts $`(\delta,V_i)`$ with $`V_i = \mathsf{iv}(U,i+1)`$, while keeping the outer tag computation real.
- $`H_2^b`$ is obtained from $`H_1^b`$ by replacing the outer combiner

  ```math
  \mathsf{TrunkSponge}[p](K[\delta], \mathsf{iv}(U,0), \mathsf{enc}_{\mathsf{out}}(A, T_0, \ldots, T_{n-1}, n))
  ```

  by $`\mathsf{TrunkSponge}^{\mathsf{IXIF}}[\mathrm{ro}]`$ on the same outer keyed-context/input pair.

For the first hop, Lemma 4.1 shows that a per-user nonce-respecting TreeWrap adversary induces a nonce-respecting family of chunk-encryption queries at the LeafWrap layer, so Corollary 4.4 applies. Thus the first replacement changes the overall left-right distinguishing gap by at most

```math
\epsilon_{\mathsf{lw}}^{\mathsf{enc}}(\mu,\chi_e,\sigma^{\mathsf{lw}}_e,N).
```

For the second hop, Corollary 4.6 applies to the outer trunk-sponge family, so the second replacement changes the overall left-right distinguishing gap by at most

```math
\epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,0,\sigma^{\mathsf{out}}_e,0,N).
```

It remains to analyze $`H_2^b`$. In this game, the chunk layer is answered by IXIF under fresh leaf keyed contexts, so the concatenated chunk bodies are distributed independently of $`b`$ except for the public chunk lengths. The outer tag is computed by $`\mathsf{TrunkSponge}^{\mathsf{IXIF}}[\mathrm{ro}]`$ on the pair

```math
((\delta,\mathsf{iv}(U,0)), \mathsf{enc}_{\mathsf{out}}(A, T_0, \ldots, T_{n-1}, n)),
```

and by per-user nonce respect this outer keyed context is fresh for every encryption query. The IXIF oracle used for the leaf and trunk replacements is sampled independently of the real permutation $`p`$, so the primitive transcript is unchanged across the hybrids and remains shared between $`H_2^0`$ and $`H_2^1`$. Hence every outer evaluation in $`H_2^b`$ occurs on a fresh IXIF path and returns an independent uniform $`\tau`$-bit string, while the primitive oracle answers are identical in both games. Consequently, the entire view of $`\mathcal{A}`$ in $`H_2^0`$ and $`H_2^1`$ is identical up to public lengths, and therefore

```math
\Pr[H_2^1(\mathcal{A}) = 1] = \Pr[H_2^0(\mathcal{A}) = 1].
```

Combining this final equality with the two distinguishing-gap bounds above yields Theorem 5.1.

### 6.3 INT-CTXT Sketch

Fix a per-user nonce-respecting INT-CTXT adversary $`\mathcal{A}`$, and define three games. In all three games, $`\mathcal{A}`$ additionally retains primitive access to $`p`$ and $`p^{-1}`$.

- $`H_0`$ is the real INT-CTXT experiment.
- $`H_1`$ is obtained from $`H_0`$ by replacing, for each wrapper query with user index $`\delta`$ and nonce $`U`$, every encryption-side and decryption-side LeafWrap call by $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}]`$ under the derived leaf keyed contexts $`(\delta,V_i)`$ with $`V_i = \mathsf{iv}(U,i+1)`$, while keeping the outer tag computation real.
- $`H_2`$ is obtained from $`H_1`$ by replacing the outer combiner

  ```math
  \mathsf{TrunkSponge}[p](K[\delta], \mathsf{iv}(U,0), \mathsf{enc}_{\mathsf{out}}(A, T_0, \ldots, T_{n-1}, n))
  ```

  by $`\mathsf{TrunkSponge}^{\mathsf{IXIF}}[\mathrm{ro}]`$ on the same outer keyed-context/input pair, both on encryption and on decryption-side recomputation.

For the first hop, Lemma 4.1 gives the required keyed-context discipline at the leaf layer, and Corollary 4.5 therefore yields

```math
\left| \Pr[H_0(\mathcal{A}) = 1] - \Pr[H_1(\mathcal{A}) = 1] \right|
\le
\epsilon_{\mathsf{lw}}^{\mathsf{ae}}(\mu,\chi_e,\chi_d,\sigma^{\mathsf{lw}}_e,\sigma^{\mathsf{lw}}_d,N).
```

For the second hop, Corollary 4.6 yields

```math
\left| \Pr[H_1(\mathcal{A}) = 1] - \Pr[H_2(\mathcal{A}) = 1] \right|
\le
\epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,q^{\mathsf{out}}_d,\sigma^{\mathsf{out}}_e,\sigma^{\mathsf{out}}_d,N).
```

It remains to bound the forgery probability in $`H_2`$. Let

```math
F = \bigl\{(\delta^{(1)},U^{(1)},A^{(1)},C^{(1)}),\ldots,(\delta^{(q_f)},U^{(q_f)},A^{(q_f)},C^{(q_f)})\bigr\}
```

denote the final forgery set output by $`\mathcal{A}`$, and for each $`d \in [1,q_f]`$ write

```math
C^{(d)} = Y^{(d)} \| T^{(d)}.
```

For each candidate, either some chunk body is fresh in its keyed leaf context or all chunk bodies replay prior encryptions in their respective contexts. In the fresh-body case, Lemma 7.1 implies that either a fresh leaf-tag collision occurs, contributing at most $`2^{-t_{\mathsf{leaf}}}`$, or the outer keyed-context/input pair is fresh. In the all-replay case, the recomputed leaf-tag vector is fixed by prior encryptions, so either the full ciphertext is a replay or the outer keyed-context/input pair is still fresh. In every non-replay case, the adversary must predict the value of $`\mathsf{TrunkSponge}^{\mathsf{IXIF}}[\mathrm{ro}]`$ on a fresh outer keyed-context/input pair, which contributes at most $`2^{-\tau}`$. Therefore, for each fixed $`d`$,

```math
\Pr[(\delta^{(d)},U^{(d)},A^{(d)},C^{(d)}) \text{ is a valid fresh forgery in } H_2]
\le
2^{-t_{\mathsf{leaf}}} + 2^{-\tau}.
```

Taking a union bound over the at most $`q_f`$ final candidates gives

```math
\Pr[H_2(\mathcal{A}) = 1]
\le
\frac{q_f}{2^{t_{\mathsf{leaf}}}} + \frac{q_f}{2^{\tau}}.
```

Combining this bound with the two hybrid transitions yields Theorem 5.2.

### 6.4 IND-CCA2 Sketch

Fix a per-user nonce-respecting IND-CCA2 adversary $`\mathcal{A}`$, and for each bit $`b \in \{0,1\}`$ let $`G_b`$ denote the game obtained from the real IND-CCA2 experiment by answering every decryption query with $`\bot`$ while leaving the left-right and primitive oracles unchanged. Up to the first accepting fresh decryption query, the games $`\mathrm{IND}\text{-}\mathrm{CCA2}^{\mathsf{TreeWrap}}_b`$ and $`G_b`$ are identical. Hence, by the standard game-hopping argument of [BN00],

```math
\left|
\Pr[(\mathrm{IND}\text{-}\mathrm{CCA2})^{\mathsf{TreeWrap}}_b(\mathcal{A}) = 1]
-
\Pr[G_b(\mathcal{A}) = 1]
\right|
\le
\Pr[\mathsf{Bad}_b],
```

where $`\mathsf{Bad}_b`$ is the event that $`\mathcal{A}`$ submits some fresh ciphertext to the decryption oracle that would be accepted in the real bit-$`b`$ experiment.

The game pair $`G_0,G_1`$ is exactly an IND-CPA experiment with a dummy decryption oracle. Therefore there is an IND-CPA adversary $`\mathcal{B}_1`$ that forwards all left-right and primitive queries of $`\mathcal{A}`$ unchanged and answers decryption queries locally with $`\bot`$, such that

```math
\Pr[G_b(\mathcal{A}) = 1]
=
\Pr[(\mathrm{IND}\text{-}\mathrm{CPA})^{\mathsf{TreeWrap}}_b(\mathcal{B}_1) = 1]
```

for each $`b`$. This reduction preserves the entire left-right transcript and the primitive-query transcript exactly, so it preserves $`q_e`$, $`N`$, and the induced encryption-side lower-level resources.

It remains to bound $`\Pr[\mathsf{Bad}_b]`$. Define an INT-CTXT adversary $`\mathcal{B}_{2,b}`$ as follows:

- on a left-right query $`(\delta,U,A,P_0,P_1)`$ from $`\mathcal{A}`$, forward the encryption query $`(\delta,U,A,P_b)`$ to the INT-CTXT encryption oracle and return the result;
- forward every primitive query of $`\mathcal{A}`$ unchanged;
- answer every decryption query of $`\mathcal{A}`$ locally with $`\bot`$;
- record every fresh decryption query $`(\delta,U,A,C)`$ of $`\mathcal{A}`$ and output the set of all such recorded queries as the final INT-CTXT forgery set.

This simulation is exactly the dead-decryption game $`G_b`$. If $`\mathsf{Bad}_b`$ occurs, then some fresh decryption query made by $`\mathcal{A}`$ is accepted in the real bit-$`b`$ experiment, and therefore the final forgery set output by $`\mathcal{B}_{2,b}`$ contains a valid INT-CTXT forgery. Hence

```math
\Pr[\mathsf{Bad}_b]
\le
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{B}_{2,b}).
```

This use of INT-CTXT is compatible with Section 4.2 because the multi-forgery experiment permits the adversary to interact adaptively with its encryption and primitive oracles before outputting the final set $`F`$.

Combining the two game hops for $`b=0`$ and $`b=1`$ yields

```math
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cca2}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cpa}}_{\mathsf{TreeWrap}}(\mathcal{B}_1)
+
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{B}_{2,0})
+
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{B}_{2,1}),
```

which is Theorem 5.3. Substituting Theorems 5.1 and 5.2 with the inherited resource bounds gives the displayed instantiated IND-CCA2 bound.

## 7. TreeWrap Proofs

This section contains the TreeWrap-specific arguments: the hidden-leaf-tag freshness lemma needed for authenticity and the public-permutation commitment analysis.

### 7.1 Hidden Leaf-Tag Freshness

**Lemma 7.1 (IXIF Path Divergence and Leaf-Tag Freshness).** Fix a leaf context $`(K,V)`$, and consider all prior encryption-side calls to $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}]`$ in that context. Let

```math
\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}](K,V,Y,\mathsf{dec}) = (X,T).
```

Then exactly one of the following holds:

1. the body $`Y`$ coincides with a prior encryption-side output body in the same context, in which case the entire local transcript is reproduced and the returned pair $`(X,T)`$ equals the previously defined pair for that body;
2. the body $`Y`$ is fresh in that context, in which case there exists a first body-block index $`j^\star`$ at which the decryption-side framed message block $`M_{j^\star}(X)`$ is fresh relative to all prior encryption-side transcripts, the IXIF path diverges at that point, and every subsequent squeeze query used to form $`T`$ is made on a fresh path.

In the second case, except for transcript-collision bad events already charged to the KD/IXIF replacement, the returned leaf tag $`T`$ is a fresh random $`t_{\mathsf{leaf}}`$-bit string from the adversary's point of view.

**Proof.** The mechanics are entirely local. Because the IXIF path after initialization is determined by the fixed context $`(K,V)`$, all prior agreement between an encryption-side and decryption-side call is captured by equality of the framed blocks appended to that path. The identity above shows that a decryption-side body call appends the recovered plaintext frame $`M_j(X)`$, not the ciphertext frame. Therefore, if a decryption-side call reproduces a prior encryption-side body, it reproduces the same framed message sequence and hence the same subsequent squeeze paths and leaf tag. In the IXIF world this implication is exact: a repeated path is answered by the same deterministic random-oracle value attached to that path.

For the fresh-body case, let $`\pi_j`$ denote the IXIF path after the first $`j`$ body-phase calls of the decryption-side transcript, and let $`\pi^{(a)}_j`$ denote the corresponding path prefix for a prior encryption-side transcript $`a`$ in the same context. Choose $`j^\star`$ as the first index for which the framed block $`M_{j^\star}(X)`$ is not equal to the framed block at position $`j^\star`$ of any prior encryption-side transcript with prefix $`\pi_{j^\star-1}`$. Then $`\pi_{j^\star-1}`$ is still an old path prefix, but

```math
\pi_{j^\star} = \pi_{j^\star-1} \| M_{j^\star}(X)
```

is fresh: if it were equal to some prior $`\pi^{(a)}_{j^\star}`$, then by prefix equality one would have both $`\pi_{j^\star-1} = \pi^{(a)}_{j^\star-1}`$ and $`M_{j^\star}(X) = M_{j^\star}(X^{(a)})`$, contradicting the choice of $`j^\star`$. This covers both kinds of first divergence: either the two transcripts first differ on an actual framed block, or one transcript reaches its padding block before the other, in which case the differing padded block itself witnesses freshness. From that point onward, freshness propagates by a simple prefix argument: if a path $`\pi`$ is fresh, then every extension $`\pi \| B`$ is fresh as well, because a repeated extension would have a repeated prefix $`\pi`$. Hence every subsequent body-phase path and every later blank-squeeze path is fresh. Since IXIF answers each fresh path with an independent random-oracle value, the squeezed tag material and hence the returned leaf tag are fresh as well. In TreeWrap, Lemma 4.1 implies that a fixed keyed leaf context can contain at most one prior encryption-side transcript, so the probability that this fresh random leaf tag recreates the unique prior leaf tag in that context is at most $`2^{-t_{\mathsf{leaf}}}`$.

### 7.2 CMT-4 Proof

Proof idea: decompose any TreeWrap ciphertext collision into either a local chunk-transcript collision or a final combiner
collision.

Unlike the AE security arguments, the CMT-4 analysis does not use the keyed IXIF reductions of Section 4.6. This is necessary because in the CMT-4 experiment the adversary chooses the candidate keys and nonces, so these values cannot be treated as hidden keyed parameters. Instead, both layers are analyzed in a flat transcript model. For the local chunk wrapper, the encryption-side LeafWrap call is flattened to the sequence of framed duplex inputs determined by the key, the leaf IV, and the padded chunk blocks. In TreeWrap, this leaf IV is the derived value $`V_i = \mathsf{iv}(U,i+1)`$. The intended justification for this step is the duplexing-sponge viewpoint of [BDPVA11]: by the duplexing-sponge lemma, a duplex transcript is equivalent to a cascade of sponge evaluations on the accumulated framed input history. For the trunk derivation, the proof uses the plain sponge viewpoint of [BDPVA08] after flattening the outer trunk-sponge transcript to a single injectively encoded input string.

In this subsection, the adversary also retains primitive access to $`p`$ and $`p^{-1}`$, exactly as in the AE experiments. The resulting primitive-query count is denoted by $`N`$ and is absorbed into the flat symbolic terms below.

Let

```math
\mathsf{LeafWrap}^{\flat}[p](K,V,X)
```

denote the encryption-side LeafWrap transcript viewed in this flat model: the initialization is determined by the tuple $`(K,V)`$, the padded message blocks are embedded as the framed full-state blocks

```math
M_j(X) := \widetilde{X}_j \| 1 \| 0^{c-1},
```

and the output pair $`(Y,T)`$ is obtained from the resulting sequence of duplex squeezes exactly as in encryption-mode LeafWrap.

**Lemma 7.2 (LeafWrap Flat-Transcript Collision Bound).** Consider two encryption-side LeafWrap inputs

```math
(K,V,X) \ne (K',V',X').
```

If

```math
\mathsf{LeafWrap}^{\flat}[p](K,V,X)
=
\mathsf{LeafWrap}^{\flat}[p](K',V',X')
=(Y,T),
```

let $`\ell := |Y|`$ and assume $`M_{\mathsf{lw}}(\ell,N) < 2^c`$. Then either the two flattened local transcripts collide under the duplexing-sponge reduction of [BDPVA11] in the presence of at most $`N`$ primitive queries, or two distinct ideal local transcript histories produce the same full local output pair $`(Y,T)`$. By Section 4.8, the first event is bounded by

```math
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{lw}}(\ell,N),2),
```

and the second contributes the residual ideal-output collision term

```math
2^{-(\ell+t_{\mathsf{leaf}})}.
```

Hence

```math
\Pr[\text{local collision on an }\ell\text{-bit chunk}]
\le
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{lw}}(\ell,N),2)
+
2^{-(\ell+t_{\mathsf{leaf}})}
=
\epsilon_{\mathsf{lw}}^{\flat}(\ell,N).
```

Let

```math
\mathsf{TrunkSponge}^{\flat}[p](K,U,A,T_0,\ldots,T_{n-1},n)
```

denote the final TreeWrap tag derivation viewed in the flattened sponge model: the keyed initialization is determined by $`(K,\mathsf{iv}(U,0))`$, the absorbed input is the combiner string $`\mathsf{enc}_{\mathsf{out}}(A,T_0,\ldots,T_{n-1},n)`$, and the output is the leftmost $`\tau`$ bits of the resulting sponge-style evaluation.

**Lemma 7.3 (Flattened Outer-Combiner Collision Bound).** Consider two distinct outer combiner inputs

```math
(K,U,A,T_0,\ldots,T_{n-1},n)
\ne
(K',U',A',T'_0,\ldots,T'_{n'-1},n').
```

If

```math
\mathsf{TrunkSponge}^{\flat}[p](K,U,A,T_0,\ldots,T_{n-1},n)
=
\mathsf{TrunkSponge}^{\flat}[p](K',U',A',T'_0,\ldots,T'_{n'-1},n'),
```

let

```math
\rho := |\{(K,U),(K',U')\}| \in \{1,2\},
```

let

```math
M_{\mathsf{out}}
:=
N
+
\left\lceil \frac{|\mathsf{enc}_{\mathsf{out}}(A,T_0,\ldots,T_{n-1},n)|+1}{r} \right\rceil
+
\left\lceil \frac{|\mathsf{enc}_{\mathsf{out}}(A',T'_0,\ldots,T'_{n'-1},n')|+1}{r} \right\rceil
+
2 s_{\mathsf{out}},
```

and assume $`M_{\mathsf{out}} < 2^c`$. Then either the bad event $`\mathsf{Merge}_{\rho}(M_{\mathsf{out}})`$ occurs for the two rooted outer transcripts, or two distinct ideal combiner transcript inputs collide on the same truncated output. The first event is bounded by

```math
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{out}},\rho)
```

via the rooted-forest counting of Lemma 4.7, and the second event contributes the generic truncation term $`2^{-\tau}`$. Hence

```math
\Pr[\text{outer collision}]
\le
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{out}},\rho)
+
2^{-\tau}.
```

**Proof sketch.** In the flattened view, each outer evaluation consists of a public root state determined by $`(K,\mathsf{iv}(U,0))`$ followed by a rate-$`r`$ absorb-then-squeeze transcript on the string $`\mathsf{enc}_{\mathsf{out}}(A,T_0,\ldots,T_{n-1},n)`$. Thus the two evaluations expose rooted sponge paths from $`\rho`$ public roots, where

```math
\rho := |\{(K,U),(K',U')\}| \in \{1,2\}.
```

Lemma 4.7 defines the bad event $`\mathsf{Merge}_{\rho}(M_{\mathsf{out}})`$ that two distinct rooted transcripts merge during the first $`M_{\mathsf{out}}`$ safe extensions, and proves the bound

```math
\Pr[\mathsf{Merge}_{\rho}(M_{\mathsf{out}})]
\le
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{out}},\rho).
```

Conditioned on the complement of this event, root-labeled transcript prefixes remain injective, so the two distinct flattened combiner inputs induce distinct ideal sponge inputs. Their $`\tau`$-bit truncated outputs therefore collide only with the generic truncation probability $`2^{-\tau}`$.

Let

```math
\mathsf{TreeWrap.ENC}(K, U, A, P) = Y \| T
```

and

```math
\mathsf{TreeWrap.ENC}(K', U', A', P') = Y \| T
```

for two distinct tuples. By canonical chunking, the common ciphertext body $`Y`$ determines the same chunk sequence $`Y_0, ..., Y_{n-1}`$ and hence the same chunk count $`n`$ in both encryptions.

For each chunk position $`i`$, define the local leaf IVs and local outputs by

```math
V_i := \mathsf{iv}(U,i+1),
\qquad
V'_i := \mathsf{iv}(U',i+1),
```

```math
\mathsf{LeafWrap}[p](K, V_i, P_i, \mathsf{enc}) = (Y_i, T_i),
\qquad
\mathsf{LeafWrap}[p](K', V'_i, P'_i, \mathsf{enc}) = (Y_i, T'_i).
```

If there exists a first index $`j`$ such that

```math
(K,V_j,P_j) \ne (K',V'_j,P'_j),
```

then the two distinct local inputs at position $`j`$ produce the same local output pair

```math
(Y_j,T_j) = (Y_j,T'_j),
```

and Lemma 7.2 applies directly. Thus the contribution of this case is bounded by

```math
\epsilon_{\mathsf{lw}}^{\flat}(|Y_j|,N),
```

that is, by the local flat-duplex term plus the full-output collision tail $`2^{-(|Y_j|+t_{\mathsf{leaf}})}`$ at the first differing chunk. Taking a union bound over the at most $`n`$ chunk positions yields the local contribution

```math
\sum_{i=0}^{n-1} \epsilon_{\mathsf{lw}}^{\flat}(|Y_i|,N)
```

of Theorem 5.4.

It remains to consider the complementary case, namely that for every chunk position $`i`$,

```math
(K,V_i,P_i) = (K',V'_i,P'_i).
```

If $`n > 0`$, this equality at every chunk position forces $`K = K'`$ and $`P_i = P'_i`$ for all $`i`$, hence $`P = P'`$. It also forces $`V_i = V'_i`$ for every $`i`$, and since $`V_i = \mathsf{iv}(U,i+1)`$ with injective IV derivation, one obtains $`U = U'`$. Thus, when $`n > 0`$, the overall tuples can still be distinct only if $`A \ne A'`$. If $`n = 0`$, there are no local positions at all, $`P = P' = \epsilon`$, and tuple distinctness again lies entirely in the outer input through $`(K,U,A) \ne (K',U',A')`$. In either case all local transcripts agree, and in particular $`T_i = T'_i`$ for all $`i`$. Because the overall tuples are distinct while the common body fixes $`n`$, the outer flattened combiner inputs

```math
(K,U,A,T_0,\ldots,T_{n-1},n)
\ne
(K',U',A',T_0,\ldots,T_{n-1},n)
```

are distinct. Equivalently, the two outer transcripts

```math
\mathsf{TrunkSponge}^{\flat}[p](K,U,A,T_0,\ldots,T_{n-1},n)
```

and

```math
\mathsf{TrunkSponge}^{\flat}[p](K',U',A',T_0,\ldots,T_{n-1},n)
```

are evaluated on distinct flattened inputs. Since the final TreeWrap tags are equal, Lemma 7.3 applies and bounds this case by

```math
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{out}},\rho) + 2^{-\tau}.
```

Therefore, for every fixed output pair $`\Theta`$, the corresponding successful CMT-4 event reduces either to a first-differing-chunk collision bounded by Lemma 7.2 or to a distinct-input outer-combiner collision bounded by Lemma 7.3. Summing these contributions yields the conditional bound of Theorem 5.4, and averaging over the adversary's random output pair gives the displayed expectation bound on $`\mathrm{Adv}^{\mathsf{cmt}\text{-}4}`$.

## 8. TW128 Instantiation

We instantiate TreeWrap as a concrete octet-oriented scheme $`\mathsf{TW128}`$ based on the twelve-round Keccak permutation from [FIPS202]. The goal of this instantiation is a 128-bit security target with a 256-bit outer authentication tag, a 256-bit leaf tag, and a 48-rate-block chunk size.

The parameter choices are:

- permutation: $`p = \mathrm{Keccak\text{-}p}[1600,12]`$;
- width: $`b = 1600`$;
- capacity: $`c = 256`$;
- rate: $`r = 1344`$;
- key length: $`k = 256`$;
- IV space: $`\mathcal{IV} = \{0,1\}^{1344}`$;
- nonce space: $`\mathcal{U} = \{0,1\}^{128}`$;
- chunk size: $`B = 64512`$ bits $`= 8064`$ bytes $`= 48 \cdot 168`$ bytes;
- leaf tag size: $`t_{\mathsf{leaf}} = 256`$;
- final tag size: $`\tau = 256`$;
- associated-data encoding: $`\eta = \mathrm{encode\_string}`$ from [SP800185];
- integer encoding: $`\nu = \mathrm{right\_encode}`$ from [SP800185].

Although $`\mathrm{encode\_string}`$ and $`\mathrm{right\_encode}`$ are specified on bit strings in [SP800185], $`\mathsf{TW128}`$ operates on octet strings throughout. Concretely, $`\mathsf{TW128.ENC}`$ takes a 32-byte key, a 16-byte nonce, an octet-string associated-data input, and an octet-string plaintext, and returns an octet-string ciphertext of length $`|P| + 32`$ bytes; $`\mathsf{TW128.DEC}`$ has the corresponding octet-string ciphertext interface. This matches the intended software interface and keeps the encoding layer aligned with the byte-oriented presentation of SP 800-185.

The only remaining concrete formatting choice is the embedding of the user nonce and chunk counter into the $`b-k = 1344`$-bit IV field expected by the keyed duplex. Define the concrete IV-derivation map

```math
\mathsf{iv}^{\mathsf{TW128}} : \mathcal{U} \times \{0,\ldots,2^{1208}-1\} \to \mathcal{IV}
```

by

```math
\mathsf{iv}^{\mathsf{TW128}}(U,j)
:=
0^{1344 - 128 - |\nu(j)|} \| U \| \nu(j),
```

which is well defined exactly for suffix values $`0 \le j \le 2^{1208}-1`$. Equivalently, on inputs with canonical chunk count $`n`$ one requires $`n \le 2^{1208}-1`$. In particular,

```math
V_{\mathsf{out}}(U) := \mathsf{iv}^{\mathsf{TW128}}(U,0),
\qquad
V_i(U) := \mathsf{iv}^{\mathsf{TW128}}(U,i+1).
```

Because the nonce length is fixed and $`\nu = \mathrm{right\_encode}`$ is injective, this yields an injective embedding of the outer-IV and leaf-IV namespaces into the 1344-bit IV field. The resulting size bound is not restrictive in practice: it allows up to $`2^{1208}`$ distinct suffix values, far beyond any realistic number of chunks. Outside this range the concrete IV embedding is undefined, so $`\mathsf{TW128.ENC}`$ and $`\mathsf{TW128.DEC}`$ are defined only on inputs whose canonical chunk count satisfies $`\chi(P) \le 2^{1208}-1`$.

Under this concrete embedding, every instantiated trunk or leaf keyed context contributes a full 1344-bit IV string to the lower-level duplex initialization. Thus the abstract bookkeeping quantity of Section 4.5 specializes to

```math
\iota_{\mathsf{lw}}^{\mathsf{TW128}}(X) = 1344 \cdot \chi(X),
```

and each outer trunk invocation likewise contributes one 1344-bit IV. In the low-complexity [Men23] branch imported in Section 4.6, however, the AE bounds depend on initialization only through the keyed-context count $`Q_{IV}`$ rather than through a separate IV-bit-length parameter. Accordingly, this concrete padding choice affects the AE terms only by fixing an explicit injective embedding into the 1344-bit IV field.

For $`\mathsf{TW128}`$, both the leaf tag and the final tag fit within a single $`r = 1344`$-bit squeeze block, so

```math
s_{\mathsf{leaf}} = s_{\mathsf{out}} = 1.
```

Thus raising the leaf tag from 128 to 256 bits does not change the local LeafWrap transcript length: each chunk still performs one blank squeeze for its leaf tag. The only concrete cost is that the outer trunk transcript absorbs an additional $`128n`$ bits across the $`n`$ internal leaf tags. This tradeoff is favorable for $`\mathsf{TW128}`$, because it materially strengthens the INT-CTXT guessing term while leaving the local CMT-4 analysis unchanged apart from the already negligible ideal collision tail.

Likewise, each full chunk has length $`|Y_i| = 64512`$ bits, so the sharpened ideal local collision tail in Lemma 7.2 becomes

```math
2^{-(|Y_i| + t_{\mathsf{leaf}})} = 2^{-64768}
```

for every full chunk. The sharpened local CMT-4 analysis therefore remains far stronger than the 128-bit target even after the leaf-tag length is chosen for AE margin rather than for commitment alone.

For the duplex-merger part of the same term, a full chunk satisfies

```math
M_{\mathsf{lw}}(64512,N)
=
N + 2 \left(\left\lceil \frac{64512+1}{1344} \right\rceil + 1\right)
=
N + 100,
```

since the exact-rate chunk still incurs one additional padded body block and one blank squeeze per local transcript. Therefore the full-chunk local CMT-4 term is

```math
\epsilon_{\mathsf{lw}}^{\flat}(64512,N)
=
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(N+100,2)
+
2^{-64768}.
```

If the final chunk has length $`\lambda`$ bits, where $`0 < \lambda \le 64512`$ and $`\lambda`$ is a multiple of $`8`$, then the corresponding local term is

```math
\epsilon_{\mathsf{lw}}^{\flat}(\lambda,N)
=
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}\!\left(N + 2 \left(\left\lceil \frac{\lambda+1}{1344} \right\rceil + 1\right),2\right)
+
2^{-(\lambda+256)}.
```

This makes the per-ciphertext nature of Theorem 5.4 explicit. The ideal-output collision tail is least favorable for the shortest nonempty last chunk, but because $`\mathsf{TW128}`$ is octet-oriented one always has $`\lambda \ge 8`$, so even that worst case is only $`2^{-264}`$. At the same time, the duplex-merger term improves as $`\lambda`$ decreases, since $`M_{\mathsf{lw}}(\lambda,N)`$ is monotone increasing in $`\lambda`$.

The empty-message case is the degenerate endpoint $`n = 0`$. Then TreeWrap makes no LeafWrap calls, the ciphertext body is empty, and the outer combiner input reduces to

```math
\mathsf{enc}_{\mathsf{out}}(A,0) = \eta(A) \| \nu(0).
```

Accordingly,

```math
\sigma_{\mathsf{out}}(A,\epsilon)
=
\left\lceil \frac{|\eta(A)| + |\nu(0)| + 1}{1344} \right\rceil + 1,
```

the local CMT-4 sum is empty, and Theorem 5.4 specializes to the pure outer trunk-sponge term

```math
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{out}},\rho) + 2^{-256}
```

with

```math
M_{\mathsf{out}}
=
N + \sigma_{\mathsf{out}}(A_1,\epsilon) + \sigma_{\mathsf{out}}(A_2,\epsilon).
```

For the outer CMT-4 term, Theorem 5.4 now uses

```math
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{out}},\rho) + 2^{-256}
=
\frac{(1-2^{-1344})M_{\mathsf{out}}^2 + (2\rho-1+2^{-1344})M_{\mathsf{out}}}{2^{257}}
+
2^{-256},
```

where

```math
M_{\mathsf{out}} = N + \sigma_{\mathsf{out}}(A_1,P_1) + \sigma_{\mathsf{out}}(A_2,P_2),
\qquad
\rho \le 2.
```

In practice this is extremely close to

```math
\frac{M_{\mathsf{out}}^2}{2^{257}} + 2^{-256},
```

so the outer contribution also matches the intended 128-bit generic target.

Substituting these parameters into Theorems 5.1, 5.2, and 5.4 yields the concrete parameterized security statements for $`\mathsf{TW128}`$. On the AE side, these remain $`\mu`$-user, $`N`$-query formulas: the imported KD/IXIF terms of Theorems 5.1 and 5.2 retain their explicit dependence on both $`\mu`$ and $`N`$, so a fully numeric deployment claim must fix concrete caps for those quantities and then evaluate the imported [Men23] expressions. The present section therefore fixes the algorithmic parameters and the exact terms to be evaluated, but does not bake in deployment-specific values of $`\mu`$ or $`N`$. Under any such concrete caps satisfying the low-complexity side conditions of Section 4.6, the dominant generic terms remain capacity-limited and target the intended 128-bit level, while the commitment bound inherits the same 128-bit target through the combination of the 256-bit outer tag and the sharpened per-chunk local collision term.

**Corollary 8.1 (TW128 Security).** Let $`\mathcal{A}`$ be an adversary against $`\mathsf{TW128}`$ in the corresponding $`\mu`$-user experiment, and let the induced lower-level resources be as in Sections 4.5 and 4.6. Throughout this corollary, all wrapper inputs are assumed to lie in the defined domain of $`\mathsf{TW128}`$; equivalently, every queried or extracted message has canonical chunk count at most $`2^{1208}-1`$.

- If $`\sigma^{\mathsf{lw}}_e + N \le 0.1 \cdot 2^{256}`$ and $`\sigma^{\mathsf{out}}_e + N \le 0.1 \cdot 2^{256}`$, then

  ```math
  \mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cpa}}_{\mathsf{TW128}}(\mathcal{A})
  \le
  \epsilon_{\mathsf{lw}}^{\mathsf{enc}}(\mu,\chi_e,\sigma^{\mathsf{lw}}_e,N)
  +
  \epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,0,\sigma^{\mathsf{out}}_e,0,N),
  ```

  where the imported [Men23] terms are evaluated with $`(b,r,c,k) = (1600,1344,256,256)`$ and the concrete 1344-bit IV embedding defined above.

- If $`\sigma^{\mathsf{lw}}_e + \sigma^{\mathsf{lw}}_d + N \le 0.1 \cdot 2^{256}`$ and $`\sigma^{\mathsf{out}}_e + \sigma^{\mathsf{out}}_d + N \le 0.1 \cdot 2^{256}`$, then

  ```math
  \mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TW128}}(\mathcal{A})
  \le
  \epsilon_{\mathsf{lw}}^{\mathsf{ae}}(\mu,\chi_e,\chi_d,\sigma^{\mathsf{lw}}_e,\sigma^{\mathsf{lw}}_d,N)
  +
  \epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,q^{\mathsf{out}}_d,\sigma^{\mathsf{out}}_e,\sigma^{\mathsf{out}}_d,N)
  +
  \frac{2 q_f}{2^{256}}.
  ```

- Consequently, under the same side conditions, IND-CCA2 specializes to

  ```math
  \mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cca2}}_{\mathsf{TW128}}(\mathcal{A})
  \le
  \epsilon_{\mathsf{lw}}^{\mathsf{enc}}(\mu,\chi_e,\sigma^{\mathsf{lw}}_e,N)
  +
  \epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,0,\sigma^{\mathsf{out}}_e,0,N)
  +
  2 \cdot \epsilon_{\mathsf{lw}}^{\mathsf{ae}}(\mu,\chi_e,\chi_d,\sigma^{\mathsf{lw}}_e,\sigma^{\mathsf{lw}}_d,N)
  +
  2 \cdot \epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,q^{\mathsf{out}}_d,\sigma^{\mathsf{out}}_e,\sigma^{\mathsf{out}}_d,N)
  +
  \frac{4 q_d}{2^{256}}.
  ```

- For any fixed CMT-4 output pair $`\Theta`$ with chunk lengths $`\ell_0,\ldots,\ell_{n-1}`$, and with $`M_{\mathsf{out}}(\Theta)`$ and $`\rho(\Theta)`$ extracted from $`\Theta`$ exactly as in Theorem 5.4, if $`M_{\mathsf{lw}}(\ell_i,N) < 2^{256}`$ for all $`i`$ and $`M_{\mathsf{out}}(\Theta) < 2^{256}`$, then

  ```math
  \Pr_p[\mathsf{TreeWrap}_p.\mathsf{ENC}(K_1,U_1,A_1,P_1)=\mathsf{TreeWrap}_p.\mathsf{ENC}(K_2,U_2,A_2,P_2)]
  \le
  \sum_{i=0}^{n-1} \left(
      \mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{lw}}(\ell_i,N),2)
      +
      2^{-(\ell_i+256)}
  \right)
  +
  \mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{out}}(\Theta),\rho(\Theta))
  +
  2^{-256}.
  ```

  In particular, each full 8064-byte chunk contributes

  ```math
  \mathrm{Sponge}^{(i)}_{\mathsf{forest}}(N+100,2) + 2^{-64768},
  ```

  and the empty-message case contributes only the outer trunk-sponge term.

### 8.2 Worked TW128 Examples

As a concrete illustration, consider first a single-user deployment with $`\mu = 1`$, empty associated data, $`2^{20}`$ encryption queries, and a $`2^{20}`$-byte plaintext in each query. This corresponds to a total wrapped plaintext volume of $`2^{40}`$ bytes (one tebibyte). Each message decomposes into $`131`$ chunks, so the induced resources are

```math
\chi_e = 137{,}363{,}456,
\qquad
\sigma^{\mathsf{lw}}_e = 6{,}868{,}172{,}800,
\qquad
q^{\mathsf{out}}_e = 2^{20},
\qquad
\sigma^{\mathsf{out}}_e = 27{,}262{,}976.
```

If one further grants the adversary a primitive-query budget of $`N = 2^{40}`$ and a decryption/final-forgery cap of $`q_d = q_f = 2^{32}`$, then the dominant low-complexity terms of the imported [Men23] expressions evaluate to approximately $`2^{-156.3}`$ at the leaf layer and $`2^{-171.4}`$ at the trunk layer, while the explicit TW128 guessing term is only

```math
\frac{2 q_f}{2^{256}} = 2^{-223}.
```

Thus, at a one-tebibyte single-user scale, the concrete TW128 bounds remain comfortably below the intended $`2^{-128}`$ target.

As a stress point, keep the same single-user, empty-AD, one-mebibyte message shape but scale to about $`2.69 \cdot 10^9`$ encryption queries, for a total wrapped plaintext volume of approximately $`2.82 \cdot 10^{15}`$ bytes (about $`2.50`$ PiB). Then

```math
\chi_e = 351{,}843{,}720{,}830,
\qquad
\sigma^{\mathsf{lw}}_e \approx 2^{44},
\qquad
\sigma^{\mathsf{out}}_e = 69{,}831{,}578{,}180.
```

If the primitive-query budget is scaled to the same order, namely $`N = \sigma^{\mathsf{lw}}_e`$, then the dominant imported leaf term rises to approximately $`2^{-129.7}`$ and the dominant imported trunk term to approximately $`2^{-144.7}`$. This identifies the rough single-user throughput scale at which the generic TW128 margin starts to approach, but still remains below, the intended $`2^{-128}`$ security level under an aggressive public-permutation query model.

## 9. Conclusion

TreeWrap shows that a chunk-parallel permutation-based AEAD can be analyzed cleanly by splitting the construction into a local wrapper and a final trunk authenticator. On the AE side, this decomposition lets the proof reuse the keyed-duplex/IXIF machinery of [Men23] at both layers while isolating the one TreeWrap-specific step needed for integrity: a fresh chunk body yields a fresh hidden leaf tag except with the expected guessing probability. On the commitment side, the same decomposition supports a separate public-permutation analysis in which the local and outer transcripts are flattened and bounded by duplexing-sponge and sponge arguments, respectively.

The concrete $`\mathsf{TW128}`$ instantiation shows that this proof strategy leads to a practically parameterized scheme based on twelve-round Keccak, 8064-byte chunks, 256-bit leaf tags, and a 256-bit final tag. Its AE guarantees remain explicitly multi-user and parameterized by the imported keyed-duplex bounds, while its commitment guarantee specializes to an explicit per-output collision bound with especially strong terms on full chunks. Together, these results provide a complete proof framework for TreeWrap and a concrete target instantiation for further evaluation.

## References

[BDPVA08] Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. *On the Indifferentiability of the Sponge Construction*. In Nigel P. Smart, editor, *Advances in Cryptology -- EUROCRYPT 2008*, volume 4965 of *Lecture Notes in Computer Science*, pages 181-197. Springer, 2008.

[BDPVA11] Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. *Duplexing the Sponge: Single-Pass Authenticated Encryption and Other Applications*. In Ali Miri and Serge Vaudenay, editors, *Selected Areas in Cryptography -- SAC 2011*, volume 7118 of *Lecture Notes in Computer Science*, pages 320-337. Springer, 2012.

[BH22] Mihir Bellare and Viet Tung Hoang. *Efficient Schemes for Committing Authenticated Encryption*. In Orr Dunkelman and Stefan Dziembowski, editors, *Advances in Cryptology -- EUROCRYPT 2022, Part II*, volume 13276 of *Lecture Notes in Computer Science*, pages 845-875. Springer, 2022.

[BN00] Mihir Bellare and Chanathip Namprempre. *Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm*. In Tatsuaki Okamoto, editor, *Advances in Cryptology -- ASIACRYPT 2000*, volume 1976 of *Lecture Notes in Computer Science*, pages 531-545. Springer, 2000.

[FIPS202] National Institute of Standards and Technology. *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions*. Federal Information Processing Standards Publication 202, 2015. <https://doi.org/10.6028/NIST.FIPS.202>

[SP800185] John Kelsey, Shu-jen Chang, and Ray Perlner. *SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash*. NIST Special Publication 800-185, 2016. <https://doi.org/10.6028/NIST.SP.800-185>

[Men23] Bart Mennink. *Understanding the Duplex and Its Security*. *IACR Transactions on Symmetric Cryptology*, 2023(2): 1-46, 2023.
