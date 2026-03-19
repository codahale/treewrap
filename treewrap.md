# TreeWrap

## Abstract

## 1. Introduction

## 2. Preliminaries

### 2.1 Notation

Unless stated otherwise, all strings are bitstrings. We write $`\epsilon`$ for the empty string, $`|X|`$ for the bitlength of a string $`X`$, and $`X \| Y`$ for concatenation. For $`n \in \mathbb{N}`$ and a string $`X`$ with $`|X| \ge n`$, $`\mathrm{left}_n(X)`$ denotes the leftmost $`n`$ bits of $`X`$.

For a string $`X \in \{0,1\}^m`$ and an integer $`\alpha \in [0,m)`$, write $`\mathrm{rot}_\alpha(X)`$ for the cyclic rotation of $`X`$ by $`\alpha`$ positions.

For integers $`m \le n`$, write

```math
[m,n) := \{m,m+1,\ldots,n-1\}.
```

Chunk indices always start at $`0`$, while padded-block and transcript-block indices start at $`1`$.

When a body string $`X`$ is partitioned into chunks of size $`B`$, we write

```math
X = X_0 \| \cdots \| X_{n-1}
```

for the canonical chunk decomposition, where $`n = \lceil |X|/B \rceil`$, each nonfinal chunk has length exactly $`B`$, the final chunk has length at most $`B`$, and $`n = 0`$ when $`X = \epsilon`$.

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

We adopt the keyed duplex interface of [Men23, Algorithm 1]. Let $`b,c,r,k,\mu,\alpha \in \mathbb{N}`$ with $`c + r = b`$, $`k \le b`$, and $`\alpha \le b-k`$. Let $`\mathcal{IV} \subseteq \{0,1\}^{b-k}`$ be an IV space, and let $`p \in \mathrm{Perm}(b)`$ be a $`b`$-bit permutation. The keyed duplex construction is denoted

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
    S <- rot_α(K[δ] || IV)
```

```text
Algorithm KD[p]_K.duplex(flag, B):
    S <- p(S)
    Z <- left_r(S)
    S <- S xor ([flag] * (Z || 0^{b-r})) xor B
    return Z
```

Here $`\delta`$ ranges over $`\{1,\ldots,\mu\}`$, $`IV`$ ranges over $`\mathcal{IV}`$, $`\mathsf{flag}`$ ranges over $`\{\mathsf{true},\mathsf{false}\}`$, and $`B`$ ranges over $`\{0,1\}^b`$. When $`\mathsf{flag} = \mathsf{true}`$, the outer $`r`$ bits are overwritten; when $`\mathsf{flag} = \mathsf{false}`$, they are XOR-absorbed. This keyed duplex interface is the primitive on which both the TreeWrap outer combiner and the MonkeySpongeWrap-style LeafWrap transcript are built.

### 2.4 Encoding Conventions and Domain Separation

We use two encoding components:

- a prefix-free injective string encoding

  ```math
  \eta : \{0,1\}^* \to \{0,1\}^*,
  ```

- a suffix-free injective integer encoding

  ```math
  \nu : \mathbb{N} \to \{0,1\}^*.
  ```

The integer encoding $`\nu`$ is used both for internal IV derivation and for the final chunk-count field in the outer combiner. We assume a fixed-length nonce space $`\mathcal{U} \subseteq \{0,1\}^u`$ for some nonce length $`u` \in \mathbb{N}`$. TreeWrap reserves suffix $`0`$ for the outer trunk-sponge call and uses positive suffixes for chunk-local LeafWrap calls:

```math
V_{\mathsf{out}}(U) := U \| \nu(0),
\qquad
V_i(U) := U \| \nu(i+1).
```

We assume that $`V_{\mathsf{out}}(U) \in \mathcal{IV}`$ and $`V_i(U) \in \mathcal{IV}`$ for all $`U \in \mathcal{U}`$ and $`i \in \mathbb{N}`$. Because $`\mathcal{U}`$ is fixed-length and $`\nu`$ is suffix-free, the map

```math
(U,j) \mapsto U \| \nu(j)
```

is injective on $`\mathcal{U} \times \mathbb{N}`$.

For the final TreeWrap combiner, define

```math
\mathsf{enc}_{\mathsf{out}}(A,T_0,\ldots,T_{n-1},n)
:=
\eta(A) \| T_0 \| \cdots \| T_{n-1} \| \nu(n).
```

Because $`\eta`$ is prefix-free, the leaf tags have fixed length $`t_{\mathsf{leaf}}`$, and $`\nu`$ is suffix-free, this outer encoding is injective in all of its arguments.
Equivalently, one can parse $`\mathsf{enc}_{\mathsf{out}}`$ from right to left: strip the unique suffix $`\nu(n)`$, use the recovered value of $`n`$ to peel off exactly $`n`$ fixed-length leaf tags, and then recover the unique remaining prefix $`\eta(A)`$.

For later resource accounting, we write

```math
|\eta(A)| \le |A| + \lambda_\eta(|A|),
\qquad
|\nu(n)| \le \lambda_\nu(n),
```

for encoding-overhead functions $`\lambda_\eta`$ and $`\lambda_\nu`$ associated with the chosen encodings.

For any block length $`s \in \mathbb{N}`$ and any bitstring $`Z \in \{0,1\}^*`$, we write

```math
(Z_1,\ldots,Z_w) \gets \mathrm{pad}^{*}_{10^s*}(Z)
```

for the unique padded decomposition of $`Z`$ into $`s`$-bit blocks under the $`\mathrm{pad}10^*`$ convention of [Men23]. Thus each $`Z_j \in \{0,1\}^s`$, and

```math
\mathrm{left}_{|Z|}(Z_1 \| \cdots \| Z_w) = Z.
```

LeafWrap embeds each padded message or ciphertext block as

```math
Z_j \| 1 \| 0^{c-1}.
```

These encodings are full-state blocks of length $`b = r + c`$ and provide a dedicated transcript format for the body-processing phase.

By contrast, the outer trunk sponge absorbs padded combiner blocks as

```math
W_j \| 0^c,
```

that is, as ordinary rate-$`r`$ sponge blocks with an all-zero capacity suffix.

TreeWrap therefore separates leaf and trunk calls in two ways. First, the proofs rely on disjoint IV namespaces: trunk calls use $`V_{\mathsf{out}}(U) = U \| \nu(0)`$, while leaf calls use $`V_i(U) = U \| \nu(i+1)`$. Second, even if the rate parts happen to coincide, the absorbed full-state blocks differ in format: LeafWrap uses a suffix $`1 \| 0^{c-1}`$, whereas TrunkSponge uses $`0^c`$. The later reductions use the IV separation as the primary argument and the block-format distinction as secondary transcript-format separation.

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
- a chunk size $`B`$,
- a prefix-free injective string encoding $`\eta`$,
- a suffix-free injective integer encoding $`\nu`$,
- a leaf tag size $`t_{\mathsf{leaf}}`$,
- a tag size $`\tau`$.

These parameters satisfy $`c + r = b`$ and $`k \le b`$.

TreeWrap instantiates keyed duplexes without a key offset, that is, with $`\alpha = 0`$.

We write the resulting primitive as

```math
\mathsf{TreeWrap}_{p,b,r,c,k,\mathcal{U},B,\eta,\nu,t_{\mathsf{leaf}},\tau}.
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
    parse X as X_0 || ... || X_{n-1}
    for i = 0 to n-1:
        V_i <- U || ν(i+1)
        (Y_i, T_i) <- LeafWrap[p](K, V_i, X_i, m)
    Y <- Y_0 || ... || Y_{n-1}
    V_out <- U || ν(0)
    T <- TrunkSponge[p](K, V_out, enc_out(A, T_0, ..., T_{n-1}, n); output length tau)
    return (Y, T)
```

The chunking line uses the canonical decomposition of Section 2.1. In the pseudocode, $`\mathsf{enc\_out}`$ abbreviates $`\mathsf{enc}_{\mathsf{out}}`$. The suffix $`0`$ is reserved for the outer trunk-sponge IV, and the chunk-local LeafWrap IVs use suffixes $`1,2,\ldots,n`$. The final tag depends on the nonce, the global associated data, the leaf tags, and the chunk count, but not directly on the mode flag.

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
V_i := U \| \nu(i+1), \qquad (Y_i,T_i) \gets \mathsf{LeafWrap}[p](K,V_i,P_i,\mathsf{enc})
```

for each $`i \in [0,n)`$. By Lemma 3.1, $`\mathsf{TreeWrap.DEC}`$ recovers each chunk $`P_i`$ from the corresponding body chunk $`Y_i`$ and recomputes the same per-chunk tag $`T_i`$. Hence the encoded outer-combiner input

```math
\mathsf{enc}_{\mathsf{out}}(A, T_0, \ldots, T_{n-1}, n)
```

is identical in wrapping and unwrapping, and both procedures use the same outer IV $`V_{\mathsf{out}}(U) = U \| \nu(0)`$. Therefore they derive the same final tag via $`\mathsf{TrunkSponge}[p]`$, tag verification succeeds, and the recovered plaintext is exactly $`P`$.

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

For standard AEAD security notions, we use the adversarial resource measures $`q_e`$ for the number of encryption queries, $`q_d`$ for the relevant decryption-side count, and $`\sigma`$ for total queried data complexity. Concretely, $`q_d`$ denotes the number of final forgery candidates in the multi-forgery INT-CTXT experiment and the number of decryption-oracle queries in the IND-CCA2 experiment. For lower-level duplex and sponge analyses, we additionally use the resource measures of [Men23], including $`M`$, $`N`$, $`Q`$, $`Q_{IV}`$, $`L`$, $`\Omega`$, and $`\nu_{\mathsf{fix}}`$.

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

Here $`\mathcal{A}`$ may make its encryption and primitive queries adaptively before outputting the final candidate set $`F`$, and $`q_d := |F|`$ denotes the number of forgery candidates in that final output set across all users.

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
V_{\mathsf{out}}(U) := U \| \nu(0)
```

induces pairwise distinct outer keyed contexts $`(\delta,V_{\mathsf{out}}(U))`$ across encryption queries;

```math
V_i(U) := U \| \nu(i+1)
```

induces pairwise distinct leaf keyed contexts $`(\delta,V_i(U))`$ across all encryption-side LeafWrap calls; and no outer keyed context equals any leaf keyed context.

**Proof.** All claims follow from per-user nonce-respecting behavior together with injectivity of the map $`(U,j) \mapsto U \| \nu(j)`$ on $`\mathcal{U} \times \mathbb{N}`$. Distinct encryption queries for a fixed user $`\delta`$ use distinct nonces, and within a fixed encryption query the suffixes $`0,1,\ldots,n`$ are all different. Hence the corresponding derived keyed contexts are pairwise distinct. Repetitions of the bare IV string across different users are harmless because [Men23] keys each initialization path by the user index $`\delta`$ as well.

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
\iota_{\mathsf{lw}}(U,X) := \sum_{i=0}^{n-1} |U \| \nu(i+1)|
=
\chi(X)\cdot |U| + \sum_{j=1}^{n} |\nu(j)|.
```

This isolates the contribution of the chunk-index encoding $`\nu`$ to the lower-level LeafWrap resource tuple. In the multi-user setting, [Men23] additionally prefixes each initialization path by the encoded user index $`\delta`$; this contributes only a fixed per-initialization overhead independent of the message length, so we leave it implicit in the present abstract resource accounting.

For an adversary's encryption queries with plaintext bodies $`P^{(1)},\ldots,P^{(q_e)}`$ and decryption-side ciphertext bodies $`Y^{(1)},\ldots,Y^{(q_d)}`$, aggregated across all users, we set

```math
\chi_e := \sum_{a=1}^{q_e} \chi(P^{(a)}),
\qquad
\chi_d := \sum_{b=1}^{q_d} \chi(Y^{(b)}),
```

```math
\sigma^{\mathsf{lw}}_e := \sum_{a=1}^{q_e} \sigma_{\mathsf{lw}}(P^{(a)}),
\qquad
\sigma^{\mathsf{lw}}_d := \sum_{b=1}^{q_d} \sigma_{\mathsf{lw}}(Y^{(b)}).
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
q^{\mathsf{out}}_d := q_d,
```

```math
\sigma^{\mathsf{out}}_e := \sum_{a=1}^{q_e} \sigma_{\mathsf{out}}(A^{(a)},P^{(a)}),
\qquad
\sigma^{\mathsf{out}}_d := \sum_{b=1}^{q_d} \sigma_{\mathsf{out}}(A'^{(b)},Y^{(b)}),
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
\sum_{b=1}^{q_d} \sum_{i=0}^{\chi(Y^{(b)})-1} \omega_r(Y^{(b)}_i),
```

where $`Y^{(b)}_i`$ denotes the $`i`$th chunk body in the $`b`$th decryption query.

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

**Proof sketch.** For LeafWrap, each construction query corresponds to one initialization and a sequence of body-phase and squeezing duplex calls. In the encryption-only case, Lemma 4.1 gives pairwise distinct leaf keyed contexts $`(\delta,U \| \nu(i+1))`$, so no repeated subpath can occur across encryption-side queries; moreover, encryption never uses overwrite calls, hence $`L = \Omega = \nu_{\mathsf{fix}} = 0`$. Across different users, the same bare IV may recur, but [Men23] counts initialization paths as $`\mathrm{encode}[\delta] \| IV`$, so $`Q_{IV} \le \mu`$ is the correct bound. In the bidirectional case, the argument follows the proof of Theorem 7 of [Men23] mutatis mutandis. Distinct encryption-side leaf keyed contexts still eliminate encryption/encryption subpath repetition, while decryption-side queries may repeat keyed leaf contexts and contribute at most $`\chi_d`$ repeated subpaths. Because the reduced LeafWrap transcript has no local associated-data phase, each decryption-side query contributes exactly its body-processing calls to $`\Omega`$ and exactly $`s_{\mathsf{leaf}}`$ non-overwriting squeeze calls, giving the stated identity for $`\Omega_{\mathsf{lw},d}`$.

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

**Proof sketch.** Each $`\mathsf{TrunkSponge}[p]`$ evaluation contributes one initialization, $`\lceil (|W|+1)/r \rceil`$ absorption calls on blocks of the form $`\widetilde{W}_i \| 0^c`$, and $`s_{\mathsf{out}}`$ blank squeezing calls. All calls use flag $`\mathsf{false}`$, so $`\Omega = 0`$ throughout. For encryption-type queries, Lemma 4.1 implies that the derived outer keyed contexts $`(\delta,V_{\mathsf{out}}(U)) = (\delta,U \| \nu(0))`$ are distinct, hence $`L = \nu_{\mathsf{fix}} = 0`$. Across different users, the same bare outer IV may recur, but again [Men23] counts initialization paths as $`\mathrm{encode}[\delta] \| IV`$, so $`Q_{IV} \le \mu`$ is the correct bound. In the general case, repeated subpaths can arise only from decryption-side recomputations under reused outer keyed contexts, and their total number is bounded by the total number of decryption-side duplexing calls, namely $`\sigma^{\mathsf{out}}_d`$. Because absorbed blocks have the fixed form $`\widetilde{W}_i \| 0^c`$ and no intermediate squeeze output is exposed during absorption, the adversary never fixes the outer part of the state in the sense of [Men23], so $`\nu_{\mathsf{fix}} = 0`$ remains valid. Although the adversary chooses the ciphertext body and thereby indirectly determines the absorbed trunk blocks through the recomputed leaf tags, it never observes any intermediate trunk-sponge squeeze output during absorption and therefore cannot solve for trunk-block values that would force a desired outer part.

**Corollary 4.6 (Imported Outer TrunkSponge KD/IXIF Bound).** If $`\sigma^{\mathsf{out}}_e + \sigma^{\mathsf{out}}_d + N \le 0.1 \cdot 2^c`$, then the outer-combiner real-to-IXIF replacement term can be instantiated as

```math
\epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,q^{\mathsf{out}}_d,\sigma^{\mathsf{out}}_e,\sigma^{\mathsf{out}}_d,N)
:=
\mathrm{KD}^{(i)}_{\mathsf{Men23}}(\mu,\sigma^{\mathsf{out}}_e+\sigma^{\mathsf{out}}_d,q^{\mathsf{out}}_e+q^{\mathsf{out}}_d,\mu,\sigma^{\mathsf{out}}_d,0,0,N).
```

This is the direct keyed-duplex import for the outer trunk-sponge transcript under the resource assignment of Lemma 4.3.

### 4.7 Imported Flat Sponge Bound

For the outer CMT-4 analysis, we use the random-permutation sponge bound of [BDPVA08, Eq. (6)] together with an explicit $`\rho`$-root forest variant. In the simulator proof of [BDPVA08], the single-root case starts from one rooted supernode and maintains two exclusion sets: a rooted set $`R`$ and an outer-state set $`O`$. In the present setting, the simulator instead starts from $`\rho`$ public rooted supernodes. After $`i`$ successful transcript extensions, the same inductive argument gives

```math
|R_i| \le \rho + i,
\qquad
|O_i| \le i,
```

because each new forward or inverse extension contributes at most one new rooted node and at most one new outer state, exactly as in [BDPVA08]. Repeating the bad-event counting with these sizes yields the rooted-forest analogue

```math
f_{P,\rho}(M)
:=
1 - \prod_{i=0}^{M-1} \frac{1-(\rho+i)2^{-c}}{1-i2^{-b}}.
```

Here the numerator is the probability that the next randomly chosen capacity slice avoids the at most $`\rho+i`$ rooted supernodes, while the denominator is the probability that the next full-state sample avoids the at most $`i`$ previously fixed full states. The simulator itself is obtained by the same construction as in [BDPVA08], but with its rooted-path tables keyed by a pair consisting of the root identifier and the path suffix. Distinct roots start from distinct full keyed-initialization states because the pairs $`(K,U \| \nu(0))`$ are distinct and the keyed-duplex initialization is deterministic, so the rooted forest cannot merge before the adversary creates an actual transcript collision. Thus every forward or inverse query performs exactly the same local consistency checks as in the one-root case, with at most a linear factor $`O(\rho)`$ additional work for root lookup. In particular, the simulator remains polynomial-time; in the TreeWrap application one always has $`\rho \in \{1,2\}`$. Applying the same quadratic relaxation as in [BDPVA08, Eq. (6)] then gives the explicit upper bound

```math
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M,\rho)
:=
\frac{(1-2^{-r})M^2 + (2\rho-1+2^{-r})M}{2^{c+1}}
```

in the regime $`M < 2^c`$. For $`\rho = 1`$, the product expression specializes to the original single-root simulator bound and the displayed quadratic term recovers exactly [BDPVA08, Eq. (6)].

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
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{lw}}(\ell,N),2)
+
2^{-(\ell+t_{\mathsf{leaf}})}.
```

This is the concrete local CMT-4 term used below.

## 5. Main Results

For the IND-CPA and INT-CTXT path, we instantiate the imported [Men23] terms using Section 4.6. For CMT-4, both the local flat-duplex term and the outer flat-sponge term are now made explicit via Sections 4.8 and 4.7.

- Let $`\epsilon_{\mathsf{lw}}^{\mathsf{enc}}`$ be the explicit imported KD/IXIF term of Corollary 4.4.
- Let $`\epsilon_{\mathsf{lw}}^{\mathsf{ae}}`$ be the explicit imported KD/IXIF term of Corollary 4.5.
- Let $`\epsilon_{\mathsf{out}}^{\mathsf{ixif}}`$ be the explicit imported outer KD/IXIF term of Corollary 4.6.
- By Lemma 6.3 together with the derived keyed-context discipline of Lemma 4.1, the only additional local freshness failure in the INT-CTXT proof is the event that a fresh random leaf tag equals the unique prior leaf tag in the same keyed leaf context, which contributes at most $`2^{-t_{\mathsf{leaf}}}`$.
- Let $`\epsilon_{\mathsf{lw}}^{\flat}(\ell,N)`$ be the explicit local flat-duplex term of Section 4.8.
- Let $`\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}`$ be the explicit $`\rho`$-root flat-sponge term of Section 4.7.

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

**Theorem 5.2 (INT-CTXT).** Assume $`\sigma^{\mathsf{lw}}_e + \sigma^{\mathsf{lw}}_d + N \le 0.1 \cdot 2^c`$ and $`\sigma^{\mathsf{out}}_e + \sigma^{\mathsf{out}}_d + N \le 0.1 \cdot 2^c`$. Then for every per-user nonce-respecting INT-CTXT adversary $`\mathcal{A}`$ against the $`\mu`$-user TreeWrap experiment outputting at most $`q_d`$ forgery candidates, there exists a collection of adversaries against the LeafWrap and outer trunk-sponge subclaims such that

```math
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\epsilon_{\mathsf{lw}}^{\mathsf{ae}}(\mu,\chi_e,\chi_d,\sigma^{\mathsf{lw}}_e,\sigma^{\mathsf{lw}}_d,N)
+
\frac{q_d}{2^{t_{\mathsf{leaf}}}}
+
\epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,q^{\mathsf{out}}_d,\sigma^{\mathsf{out}}_e,\sigma^{\mathsf{out}}_d,N)
+
\frac{q_d}{2^{\tau}}.
```

Equivalently, in the same low-total-complexity regime, TreeWrap ciphertext integrity reduces to the bidirectional LeafWrap KD/IXIF replacement of Corollary 4.5, a union bound over the $`q_d`$ final forgery candidates for the local leaf-tag collision tail, and freshness of the outer trunk-sponge transcript on fresh keyed-context/input pairs as captured by Corollary 4.6.

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

be any fixed distinct output pair of the CMT-4 adversary. If $`|P_1| \ne |P_2|`$, then the corresponding collision probability is zero because TreeWrap is length preserving. Otherwise let $`n := \chi(P_1) = \chi(P_2)`$, let

```math
P_1 = P_{1,0} \| \cdots \| P_{1,n-1}
```

be the canonical chunk decomposition, let $`\ell_i := |P_{1,i}|`$ for $`i = 0,\ldots,n-1`$, let $`\rho := |\{(K_1,U_1),(K_2,U_2)\}| \in \{1,2\}`$, and define

```math
M_{\mathsf{out}} := N + \sigma_{\mathsf{out}}(A_1,P_1) + \sigma_{\mathsf{out}}(A_2,P_2).
```

Assume $`M_{\mathsf{lw}}(\ell_i,N) < 2^c`$ for every $`i = 0,\ldots,n-1`$ and $`M_{\mathsf{out}} < 2^c`$. Then

```math
\Pr_p\!\bigl[\mathsf{TreeWrap}_p.\mathsf{ENC}(K_1,U_1,A_1,P_1)=\mathsf{TreeWrap}_p.\mathsf{ENC}(K_2,U_2,A_2,P_2)\bigr]
\le
\sum_{i=0}^{n-1} \epsilon_{\mathsf{lw}}^{\flat}(\ell_i,N)
+
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{out}},\rho)
+
2^{-\tau}.
```

Equivalently, for every fixed output profile $`\Theta`$, the corresponding TreeWrap commitment collision probability reduces either to a local encryption-side LeafWrap collision on the full chunk-output pair $`(Y_i,T_i)`$ at the first differing chunk or to a collision in the flattened outer combiner transcript. Consequently, if $`\Theta`$ denotes the random output pair of a CMT-4 adversary $`\mathcal{A}`$, then

```math
\mathrm{Adv}^{\mathsf{cmt}\text{-}4}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\mathbb{E}_{\Theta}\!\left[
\sum_{i=0}^{n(\Theta)-1} \epsilon_{\mathsf{lw}}^{\flat}(\ell_i(\Theta),N)
+
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{out}}(\Theta),\rho(\Theta))
+
2^{-\tau}
\right],
```

where $`n(\Theta)`$, $`\ell_i(\Theta)`$, $`\rho(\Theta)`$, and $`M_{\mathsf{out}}(\Theta)`$ are extracted from the realized output pair exactly as above, with the convention that the bracketed quantity is $`0`$ when $`|P_1| \ne |P_2|`$.

## 6. Supporting Lemmas and Proofs

### 6.1 Supporting Lemmas

The LeafWrap analysis splits into two parts. The first part is borrowed from [Men23]: identify LeafWrap with the reduced MonkeySpongeWrap transcript obtained by excising the vacuous local associated-data phase, and replace the real keyed duplex by the ideal IXIF interface. The second part is specific to TreeWrap: once in the IXIF world, show that a fresh chunk body induces a fresh hidden leaf tag. The outer combiner uses the same keyed-duplex/IXIF paradigm, but its transcript is simpler because it consists only of absorb-then-squeeze calls with flag $`\mathsf{false}`$. The CMT-4 proof does not rely on this keyed IXIF machinery and is handled separately in Section 6.5.

Let $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}]`$ denote the same transcript as $`\mathsf{LeafWrap}[p]`$, but with the keyed duplex $`\mathsf{KD}[p]`$ replaced by the ideal interface $`\mathsf{IXIF}[\mathrm{ro}]`$ of [Men23]. Thus

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

Hence encryption-side and decryption-side LeafWrap calls append the same framed message blocks precisely when they induce the same recovered plaintext transcript.

The intended supporting statements are as follows.

**Lemma 6.1 (LeafWrap / Reduced MonkeySpongeWrap Transcript Correspondence).** Fix parameters $`p,b,r,c,k,t_{\mathsf{leaf}}`$. For any inputs $`K`$, $`V`$, and $`X`$, the keyed-duplex transcript of

```math
\mathsf{LeafWrap}[p](K,V,X,m)
```

with initialization

```math
\mathsf{KD.init}(1,V)
```

is identical to the reduced MonkeySpongeWrap transcript on nonce $`V`$ and input string $`X`$ obtained by excising the vacuous local associated-data phase, with the middle phase parameterized by $`m`$. In particular:

- when $`m = \mathsf{enc}`$, the transcript coincides with the reduced encryption transcript;
- when $`m = \mathsf{dec}`$, the transcript coincides with the corresponding reduced decryption-side transcript, with overwrite enabled in the middle phase.

In both cases, the message-processing and tag-squeezing phases match exactly, and the output pair $`(Y,T)`$ returned by LeafWrap is exactly the body/tag pair determined by that reduced transcript.

**Theorem 6.2 (Ported LeafWrap KD/IXIF Replacement).** For every distinguisher $`\mathcal{D}_{\mathsf{LW}}`$ attacking a family of LeafWrap transcripts under the keyed-context discipline induced by TreeWrap, there exists a distinguisher $`\mathcal{D}_{\mathsf{MSW}}`$ against the corresponding reduced MonkeySpongeWrap transcript family such that

```math
\mathrm{Adv}^{\mathsf{real}\text{-}\mathsf{ixif}}_{\mathsf{LeafWrap}}(\mathcal{D}_{\mathsf{LW}})
=
\mathrm{Adv}^{\mathsf{real}\text{-}\mathsf{ixif}}_{\mathsf{MonkeySpongeWrap}}(\mathcal{D}_{\mathsf{MSW}}),
```

with matching transcript resources after interpreting each LeafWrap call as the corresponding reduced MonkeySpongeWrap call on the same leaf IV $`V`$. Consequently, the LeafWrap real-to-IXIF replacement is bounded by the corresponding KD/IXIF term imported from [Men23], with the unused local associated-data resources deleted from the accounting. This is the portion of the argument borrowed directly from [Men23]: once Lemma 6.1 identifies LeafWrap with the reduced MonkeySpongeWrap transcript, the keyed-duplex security proof yields a replacement of the real duplex by IXIF at the LeafWrap API level. In TreeWrap, the relevant keyed contexts are $`(\delta,V_i)`$ with $`V_i = U \| \nu(i+1)`$.

**Lemma 6.3 (IXIF Path Divergence and Leaf-Tag Freshness).** Fix a leaf context $`(K,V)`$, and consider all prior encryption-side calls to $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}]`$ in that context. Let

```math
\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}](K,V,Y,\mathsf{dec}) = (X,T).
```

Then exactly one of the following holds:

1. the body $`Y`$ coincides with a prior encryption-side output body in the same context, in which case the entire local transcript is reproduced and the returned pair $`(X,T)`$ equals the previously defined pair for that body;
2. the body $`Y`$ is fresh in that context, in which case there exists a first body-block index $`j^\star`$ at which the decryption-side framed message block $`M_{j^\star}(X)`$ is fresh relative to all prior encryption-side transcripts, the IXIF path diverges at that point, and every subsequent squeeze query used to form $`T`$ is made on a fresh path.

In the second case, except for transcript-collision bad events already charged to the KD/IXIF replacement, the returned leaf tag $`T`$ is a fresh random $`t_{\mathsf{leaf}}`$-bit string from the adversary's point of view.

The mechanics behind Lemma 6.3 are entirely local. Because the IXIF path after initialization is determined by the fixed context $`(K,V)`$, all prior agreement between an encryption-side and decryption-side call is captured by equality of the framed blocks appended to that path. The identity above shows that a decryption-side body call appends the recovered plaintext frame $`M_j(X)`$, not the ciphertext frame. Therefore, if a decryption-side call reproduces a prior encryption-side body, it reproduces the same framed message sequence and hence the same subsequent squeeze paths and leaf tag. In the IXIF world this implication is exact: a repeated path is answered by the same deterministic random-oracle value attached to that path.

For the fresh-body case, let $`\pi_j`$ denote the IXIF path after the first $`j`$ body-phase calls of the decryption-side transcript, and let $`\pi^{(a)}_j`$ denote the corresponding path prefix for a prior encryption-side transcript $`a`$ in the same context. Choose $`j^\star`$ as the first index for which the framed block $`M_{j^\star}(X)`$ is not equal to the framed block at position $`j^\star`$ of any prior encryption-side transcript with prefix $`\pi_{j^\star-1}`$. Then $`\pi_{j^\star-1}`$ is still an old path prefix, but

```math
\pi_{j^\star} = \pi_{j^\star-1} \| M_{j^\star}(X)
```

is fresh: if it were equal to some prior $`\pi^{(a)}_{j^\star}`$, then by prefix equality one would have both $`\pi_{j^\star-1} = \pi^{(a)}_{j^\star-1}`$ and $`M_{j^\star}(X) = M_{j^\star}(X^{(a)})`$, contradicting the choice of $`j^\star`$. From that point onward, freshness propagates by a simple prefix argument: if a path $`\pi`$ is fresh, then every extension $`\pi \| B`$ is fresh as well, because a repeated extension would have a repeated prefix $`\pi`$. Hence every subsequent body-phase path and every later blank-squeeze path is fresh. Since IXIF answers each fresh path with an independent random-oracle value, the squeezed tag material and hence the returned leaf tag are fresh as well. In TreeWrap, Lemma 4.1 implies that a fixed keyed leaf context can contain at most one prior encryption-side transcript, so the probability that this fresh random leaf tag recreates the unique prior leaf tag in that context is at most $`2^{-t_{\mathsf{leaf}}}`$.

For the outer combiner, let $`\mathsf{TrunkSponge}^{\mathsf{IXIF}}[\mathrm{ro}]`$ denote the same absorb-then-squeeze transcript as $`\mathsf{TrunkSponge}[p]`$, but with the keyed duplex replaced by $`\mathsf{IXIF}[\mathrm{ro}]`$. Because every absorbed block has the fixed form $`\widetilde{W}_j \| 0^c`$ and every call uses flag $`\mathsf{false}`$, Corollary 4.6 applies directly to this transcript family. Moreover, if the outer keyed-context/input pair $`((\delta,V_{\mathsf{out}}),W)`$ is fresh, then the corresponding IXIF path is fresh and the returned $`\tau`$-bit trunk tag is uniformly random from the adversary's point of view.

The role of these statements is as follows. The IND-CPA proof uses Lemma 6.1 and Theorem 6.2 on the encryption side only, together with the direct outer $`\mathsf{TrunkSponge} \to \mathsf{IXIF}`$ replacement of Corollary 4.6. The INT-CTXT proof uses Lemma 6.1 and Theorem 6.2 to move the chunk layer to the IXIF world and then applies Lemma 6.3 to conclude that any fresh chunk body yields a fresh hidden leaf tag and, except with probability $`2^{-t_{\mathsf{leaf}}}`$, a fresh outer keyed-context/input pair. By contrast, the CMT-4 proof requires a flat local collision claim for the map

```math
(K,V,X) \mapsto (Y,T),
```

and that claim is not supplied by [Men23].

The release-of-unverified-plaintext caveat discussed in [Men23] is not part of the present AE security claims. Although LeafWrap includes a decryption-style transcript as an internal proof object, the external $`\mathsf{TreeWrap.DEC}`$ interface releases plaintext only after final tag verification. Accordingly, the TreeWrap reductions use the KD/IXIF replacement of [Men23], but the final authenticity step is recast in terms of hidden leaf-tag freshness rather than public release of unverified plaintext.

Throughout Sections 6.2 and 6.3, the imported duplex bounds are used exactly in the form fixed in Section 4.6, namely the $`\mu`$-user, low-complexity branch of [Men23].

### 6.2 Proof of IND-CPA

Fix a per-user nonce-respecting IND-CPA adversary $`\mathcal{A}`$, and for each challenge bit $`b \in \{0,1\}`$ define the following three games. In all three games, $`\mathcal{A}`$ additionally retains primitive access to $`p`$ and $`p^{-1}`$.

- $`H_0^b`$ is the real IND-CPA experiment.
- $`H_1^b`$ is obtained from $`H_0^b`$ by replacing, for each encryption query $`(\delta,U,A,P_0,P_1)`$, every encryption-side LeafWrap call by $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}]`$ under the derived leaf keyed contexts $`(\delta,V_i)`$ with $`V_i = U \| \nu(i+1)`$, while keeping the outer tag computation real.
- $`H_2^b`$ is obtained from $`H_1^b`$ by replacing the outer combiner

  ```math
  \mathsf{TrunkSponge}[p](K[\delta], U \| \nu(0), \mathsf{enc}_{\mathsf{out}}(A, T_0, \ldots, T_{n-1}, n))
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
((\delta,U \| \nu(0)), \mathsf{enc}_{\mathsf{out}}(A, T_0, \ldots, T_{n-1}, n)),
```

and by per-user nonce respect this outer keyed context is fresh for every encryption query. Hence every outer evaluation in $`H_2^b`$ occurs on a fresh IXIF path and returns an independent uniform $`\tau`$-bit string. The primitive oracle answers are identical in $`H_2^0`$ and $`H_2^1`$ because both games use the same sampled permutation. Consequently, the entire view of $`\mathcal{A}`$ in $`H_2^0`$ and $`H_2^1`$ is identical up to public lengths, and therefore

```math
\Pr[H_2^1(\mathcal{A}) = 1] = \Pr[H_2^0(\mathcal{A}) = 1].
```

Combining this final equality with the two distinguishing-gap bounds above yields Theorem 5.1.

### 6.3 Proof of INT-CTXT

Fix a per-user nonce-respecting INT-CTXT adversary $`\mathcal{A}`$, and define three games. In all three games, $`\mathcal{A}`$ additionally retains primitive access to $`p`$ and $`p^{-1}`$.

- $`H_0`$ is the real INT-CTXT experiment.
- $`H_1`$ is obtained from $`H_0`$ by replacing, for each wrapper query with user index $`\delta`$ and nonce $`U`$, every encryption-side and decryption-side LeafWrap call by $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}]`$ under the derived leaf keyed contexts $`(\delta,V_i)`$ with $`V_i = U \| \nu(i+1)`$, while keeping the outer tag computation real.
- $`H_2`$ is obtained from $`H_1`$ by replacing the outer combiner

  ```math
  \mathsf{TrunkSponge}[p](K[\delta], U \| \nu(0), \mathsf{enc}_{\mathsf{out}}(A, T_0, \ldots, T_{n-1}, n))
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
F = \bigl\{(\delta^{(1)},U^{(1)},A^{(1)},C^{(1)}),\ldots,(\delta^{(q_d)},U^{(q_d)},A^{(q_d)},C^{(q_d)})\bigr\}
```

denote the final forgery set output by $`\mathcal{A}`$, and for each $`d \in [1,q_d]`$ write

```math
C^{(d)} = Y^{(d)} \| T^{(d)}.
```

Consider any candidate $`(\delta^{(d)},U^{(d)},A^{(d)},C^{(d)})`$ that is accepted by decryption in this game and not previously returned by the encryption oracle.

Write the corresponding decryption-side chunk parsing as

```math
Y^{(d)} = Y^{(d)}_0 \| \cdots \| Y^{(d)}_{n_d-1},
```

and let

```math
T^{(d)}_0,\ldots,T^{(d)}_{n_d-1}
```

denote the recomputed leaf tags for these chunks.

If some chunk body $`Y^{(d)}_i`$ is fresh under its leaf keyed context $`(\delta^{(d)},V_i(U^{(d)}))`$, then Lemma 6.3 implies that the recomputed leaf tag at that position is a fresh random $`t_{\mathsf{leaf}}`$-bit string. Because Lemma 4.1 guarantees that there is at most one prior encryption-side transcript in that keyed leaf context, this fresh value coincides with the unique prior leaf tag there with probability at most $`2^{-t_{\mathsf{leaf}}}`$. Except for that event, the recomputed leaf-tag vector differs from every prior encryption-side vector and the outer keyed context/input pair

```math
((\delta^{(d)},U^{(d)} \| \nu(0)), \mathsf{enc}_{\mathsf{out}}(A^{(d)}, T^{(d)}_0, \ldots, T^{(d)}_{n_d-1}, n_d))
```

is fresh.

Otherwise every chunk body reproduces a prior encryption-side body in its own leaf context. Then each local transcript and each local leaf tag is reproduced exactly, so the entire vector $`(T^{(d)}_0,\ldots,T^{(d)}_{n_d-1})`$ is fixed by prior encryptions. This leaves two subcases. If the resulting outer keyed context/input pair is fresh, then the adversary must still predict the value of $`\mathsf{TrunkSponge}^{\mathsf{IXIF}}[\mathrm{ro}]`$ on a fresh outer keyed-context/input pair, which occurs with probability at most $`2^{-\tau}`$. If instead the outer keyed context/input pair coincides with one from a prior encryption query and $`A^{(d)} = A`$ for that query, then the full ciphertext is a replay, contradicting freshness. Finally, if a fresh leaf-tag collision causes the leaf-tag vector to match a prior one while $`A^{(d)} \ne A`$, then the outer keyed context/input pair is still fresh because $`\mathsf{enc}_{\mathsf{out}}`$ is injective in its associated-data argument.

Thus every valid fresh forgery candidate in $`H_2`$ falls into exactly one of three cases:

- some chunk body is fresh and no leaf-tag collision occurs, in which case the outer keyed context/input pair is fresh and the trunk tag must be guessed;
- a fresh leaf-tag collision occurs, which contributes the explicit $`2^{-t_{\mathsf{leaf}}}`$ term;
- all leaf tags replay exactly, in which case either the ciphertext is a replay or the outer keyed context/input pair is fresh and the trunk tag must be guessed.

In particular, apart from the explicit leaf-tag-collision event, every valid fresh forgery candidate in $`H_2`$ requires the adversary to predict the value of $`\mathsf{TrunkSponge}^{\mathsf{IXIF}}[\mathrm{ro}]`$ on a fresh outer keyed-context/input pair. Therefore, for each fixed $`d`$,

```math
\Pr[(\delta^{(d)},U^{(d)},A^{(d)},C^{(d)}) \text{ is a valid fresh forgery in } H_2]
\le
2^{-t_{\mathsf{leaf}}} + 2^{-\tau}.
```

Taking a union bound over the at most $`q_d`$ final candidates gives

```math
\Pr[H_2(\mathcal{A}) = 1]
\le
\frac{q_d}{2^{t_{\mathsf{leaf}}}} + \frac{q_d}{2^{\tau}}.
```

Combining this bound with the two hybrid transitions yields Theorem 5.2.

### 6.4 Proof of IND-CCA2

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

This use of INT-CTXT is compatible with Section 4.2 because the multi-forgery experiment permits the adversary to interact adaptively with its encryption and primitive oracles before outputting the final set $`F`$. The reduction preserves the encryption-side and primitive-query transcripts exactly and incurs only local bookkeeping overhead in the decryption transcript. Its final forgery set is formed from the decryption queries of $`\mathcal{A}`$, so its decryption-side lower-level resources are safely upper-bounded by the aggregate decryption-side resources of $`\mathcal{A}`$.

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

### 6.5 Proof of CMT-4

Proof idea: decompose any TreeWrap ciphertext collision into either a local chunk-transcript collision or a final combiner
collision.

Unlike the AE security arguments, the CMT-4 analysis does not use the keyed IXIF reductions of Section 4.6. This is necessary because in the CMT-4 experiment the adversary chooses the candidate keys and nonces, so these values cannot be treated as hidden keyed parameters. Instead, both layers are analyzed in a flat transcript model. For the local chunk wrapper, the encryption-side LeafWrap call is flattened to the sequence of framed duplex inputs determined by the key, the leaf IV, and the padded chunk blocks. In TreeWrap, this leaf IV is the derived value $`V_i = U \| \nu(i+1)`$. The intended justification for this step is the duplexing-sponge viewpoint of [BDPVA11]: by the duplexing-sponge lemma, a duplex transcript is equivalent to a cascade of sponge evaluations on the accumulated framed input history. For the trunk derivation, the proof uses the plain sponge viewpoint of [BDPVA08] after flattening the outer trunk-sponge transcript to a single injectively encoded input string.

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

**Lemma 6.4 (LeafWrap Flat-Transcript Collision Bound).** Consider two encryption-side LeafWrap inputs

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
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{lw}}(\ell,N),2),
```

and the second contributes the residual ideal-output collision term

```math
2^{-(\ell+t_{\mathsf{leaf}})}.
```

Hence

```math
\Pr[\text{local collision on an }\ell\text{-bit chunk}]
\le
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{lw}}(\ell,N),2)
+
2^{-(\ell+t_{\mathsf{leaf}})}
=
\epsilon_{\mathsf{lw}}^{\flat}(\ell,N).
```

Let

```math
\mathsf{TrunkSponge}^{\flat}[p](K,U,A,T_0,\ldots,T_{n-1},n)
```

denote the final TreeWrap tag derivation viewed in the flattened sponge model: the keyed initialization is determined by $`(K,U \| \nu(0))`$, the absorbed input is the combiner string $`\mathsf{enc}_{\mathsf{out}}(A,T_0,\ldots,T_{n-1},n)`$, and the output is the leftmost $`\tau`$ bits of the resulting sponge-style evaluation.

**Lemma 6.5 (Flattened Outer-Combiner Collision Bound).** Consider two distinct outer combiner inputs

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

and assume $`M_{\mathsf{out}} < 2^c`$. Then either the two flattened combiner transcripts merge in the underlying sponge graph, or two distinct ideal combiner transcript inputs collide on the same truncated output. The first event is bounded by

```math
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{out}},\rho)
```

via the rooted-forest counting of Section 4.7, and the second event contributes the generic truncation term $`2^{-\tau}`$. Hence

```math
\Pr[\text{outer collision}]
\le
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{out}},\rho)
+
2^{-\tau}.
```

**Proof sketch.** In the flattened view, each outer evaluation consists of a public root state determined by $`(K,U \| \nu(0))`$ followed by a rate-$`r`$ absorb-then-squeeze transcript on the string $`\mathsf{enc}_{\mathsf{out}}(A,T_0,\ldots,T_{n-1},n)`$. When there are $`\rho`$ distinct outer roots, the simulator graph of [BDPVA08] becomes a rooted forest rather than a rooted tree. One labels each path by its root identifier together with its block sequence, so rooted paths remain injective exactly as in the one-root case. The permutation simulator still excludes rooted supernodes when answering inverse queries, and it still selects new rooted forward images outside $`R \cup O`$. The only quantitative change is that the rooted exclusion set starts at size $`\rho`$ rather than $`1`$, so after $`i`$ successful extensions one has $`|R_i| \le \rho + i`$ and $`|O_i| \le i`$. Section 4.7 records the resulting exact product bound

```math
f_{P,\rho}(M_{\mathsf{out}})
=
1 - \prod_{i=0}^{M_{\mathsf{out}}-1} \frac{1-(\rho+i)2^{-c}}{1-i2^{-b}},
```

whose quadratic relaxation is precisely $`\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{out}},\rho)`$. Conditioned on no merger, the two distinct flattened combiner transcripts behave as distinct random-oracle inputs, and their $`\tau`$-bit truncated outputs collide with probability exactly $`2^{-\tau}`$.

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
V_i := U \| \nu(i+1),
\qquad
V'_i := U' \| \nu(i+1),
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

and Lemma 6.4 applies directly. Thus the contribution of this case is bounded by

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

If $`n > 0`$, this equality at every chunk position forces $`K = K'`$ and $`P_i = P'_i`$ for all $`i`$, hence $`P = P'`$. It also forces $`V_i = V'_i`$ for every $`i`$, and since $`V_i = U \| \nu(i+1)`$ with injective suffix encoding, one obtains $`U = U'`$. Thus, when $`n > 0`$, the overall tuples can still be distinct only if $`A \ne A'`$. If $`n = 0`$, there are no local positions at all, $`P = P' = \epsilon`$, and tuple distinctness again lies entirely in the outer input through $`(K,U,A) \ne (K',U',A')`$. In either case all local transcripts agree, and in particular $`T_i = T'_i`$ for all $`i`$. Because the overall tuples are distinct while the common body fixes $`n`$, the outer flattened combiner inputs

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

are evaluated on distinct flattened inputs. Since the final TreeWrap tags are equal, Lemma 6.5 applies and bounds this case by

```math
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{out}},\rho) + 2^{-\tau}.
```

Therefore, for every fixed output pair $`\Theta`$, the corresponding successful CMT-4 event reduces either to a first-differing-chunk collision bounded by Lemma 6.4 or to a distinct-input outer-combiner collision bounded by Lemma 6.5. Summing these contributions yields the conditional bound of Theorem 5.4, and averaging over the adversary's random output pair gives the displayed expectation bound on $`\mathrm{Adv}^{\mathsf{cmt}\text{-}4}`$.

## 7. TW128 Instantiation

We instantiate TreeWrap as a concrete octet-oriented scheme $`\mathsf{TW128}`$ based on the twelve-round Keccak permutation from [FIPS202]. The goal of this instantiation is a 128-bit security target with a 256-bit outer authentication tag and a 48-rate-block chunk size.

The parameter choices are:

- permutation: $`p = \mathrm{Keccak\text{-}p}[1600,12]`$;
- width: $`b = 1600`$;
- capacity: $`c = 256`$;
- rate: $`r = 1344`$;
- key length: $`k = 256`$;
- nonce space: $`\mathcal{U} = \{0,1\}^{128}`$;
- chunk size: $`B = 64512`$ bits $`= 8064`$ bytes $`= 48 \cdot 168`$ bytes;
- leaf tag size: $`t_{\mathsf{leaf}} = 128`$;
- final tag size: $`\tau = 256`$;
- associated-data encoding: $`\eta = \mathrm{encode\_string}`$ from [SP800185];
- integer encoding: $`\nu = \mathrm{right\_encode}`$ from [SP800185].

Although $`\mathrm{encode\_string}`$ and $`\mathrm{right\_encode}`$ are specified on bit strings in [SP800185], $`\mathsf{TW128}`$ operates on octet strings throughout. This matches the intended software interface and keeps the encoding layer aligned with the byte-oriented presentation of SP 800-185.

The only remaining concrete formatting choice is the embedding of the user nonce and chunk counter into the $`b-k = 1344`$-bit IV field expected by the keyed duplex. For $`j \in \mathbb{N}`$, define

```math
\mathsf{IV}^{\mathsf{TW128}}_j(U)
:=
0^{1344 - 128 - |\nu(j)|} \| U \| \nu(j),
```

whenever $`128 + |\nu(j)| \le 1344`$. In particular,

```math
V_{\mathsf{out}}(U) := \mathsf{IV}^{\mathsf{TW128}}_0(U),
\qquad
V_i(U) := \mathsf{IV}^{\mathsf{TW128}}_{i+1}(U).
```

Because the nonce length is fixed and $`\nu = \mathrm{right\_encode}`$ is injective, this yields an injective embedding of the outer-IV and leaf-IV namespaces into the 1344-bit IV field. The size bound is not restrictive in practice: it allows up to $`2^{1208}`$ distinct suffix values, far beyond any realistic number of chunks.

Under this concrete embedding, every instantiated trunk or leaf keyed context contributes a full 1344-bit IV string to the lower-level duplex initialization. Thus the abstract bookkeeping quantity of Section 4.5 specializes to

```math
\iota_{\mathsf{lw}}^{\mathsf{TW128}}(X) = 1344 \cdot \chi(X),
```

and each outer trunk invocation likewise contributes one 1344-bit IV. In the low-complexity [Men23] branch imported in Section 4.6, however, the AE bounds depend on initialization only through the keyed-context count $`Q_{IV}`$ rather than through a separate IV-bit-length parameter. Accordingly, this concrete padding choice affects the AE terms only by fixing an explicit injective embedding into the 1344-bit IV field.

For $`\mathsf{TW128}`$, both the leaf tag and the final tag fit within a single $`r = 1344`$-bit squeeze block, so

```math
s_{\mathsf{leaf}} = s_{\mathsf{out}} = 1.
```

Likewise, each full chunk has length $`|Y_i| = 64512`$ bits, so the sharpened ideal local collision tail in Lemma 6.4 becomes

```math
2^{-(|Y_i| + t_{\mathsf{leaf}})} = 2^{-64640}
```

for every full chunk. This is why a 128-bit leaf tag is sufficient for the $`\mathsf{TW128}`$ commitment target once the local CMT-4 analysis is phrased in terms of collisions on the full local output pair $`(Y_i,T_i)`$ rather than on the leaf tag alone.

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
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(N+100,2)
+
2^{-64640}.
```

If the final chunk has length $`\lambda`$ bits, where $`0 < \lambda \le 64512`$ and $`\lambda`$ is a multiple of $`8`$, then the corresponding local term is

```math
\epsilon_{\mathsf{lw}}^{\flat}(\lambda,N)
=
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}\!\left(N + 2 \left(\left\lceil \frac{\lambda+1}{1344} \right\rceil + 1\right),2\right)
+
2^{-(\lambda+128)}.
```

This makes the per-ciphertext nature of Theorem 5.4 explicit. The ideal-output collision tail is least favorable for the shortest nonempty last chunk, but because $`\mathsf{TW128}`$ is octet-oriented one always has $`\lambda \ge 8`$, so even that worst case is only $`2^{-136}`$. At the same time, the duplex-merger term improves as $`\lambda`$ decreases, since $`M_{\mathsf{lw}}(\lambda,N)`$ is monotone increasing in $`\lambda`$.

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
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{out}},\rho) + 2^{-256}
```

with

```math
M_{\mathsf{out}}
=
N + \sigma_{\mathsf{out}}(A_1,\epsilon) + \sigma_{\mathsf{out}}(A_2,\epsilon).
```

For the outer CMT-4 term, Theorem 5.4 now uses

```math
\mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{out}},\rho) + 2^{-256}
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

**Corollary 7.1 (TW128 Security).** Let $`\mathcal{A}`$ be an adversary against $`\mathsf{TW128}`$ in the corresponding $`\mu`$-user experiment, and let the induced lower-level resources be as in Sections 4.5 and 4.6.

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
  \frac{q_d}{2^{128}}
  +
  \epsilon_{\mathsf{out}}^{\mathsf{ixif}}(\mu,q^{\mathsf{out}}_e,q^{\mathsf{out}}_d,\sigma^{\mathsf{out}}_e,\sigma^{\mathsf{out}}_d,N)
  +
  \frac{q_d}{2^{256}}.
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
  \frac{2 q_d}{2^{128}}
  +
  \frac{2 q_d}{2^{256}}.
  ```

- For any fixed CMT-4 output pair $`\Theta`$ with chunk lengths $`\ell_0,\ldots,\ell_{n-1}`$, and with $`M_{\mathsf{out}}(\Theta)`$ and $`\rho(\Theta)`$ extracted from $`\Theta`$ exactly as in Theorem 5.4, if $`M_{\mathsf{lw}}(\ell_i,N) < 2^{256}`$ for all $`i`$ and $`M_{\mathsf{out}}(\Theta) < 2^{256}`$, then

  ```math
  \Pr_p[\mathsf{TreeWrap}_p.\mathsf{ENC}(K_1,U_1,A_1,P_1)=\mathsf{TreeWrap}_p.\mathsf{ENC}(K_2,U_2,A_2,P_2)]
  \le
  \sum_{i=0}^{n-1} \left(
      \mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{lw}}(\ell_i,N),2)
      +
      2^{-(\ell_i+128)}
  \right)
  +
  \mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(M_{\mathsf{out}}(\Theta),\rho(\Theta))
  +
  2^{-256}.
  ```

  In particular, each full 8064-byte chunk contributes

  ```math
  \mathrm{Sponge}^{(i)}_{\mathsf{BDPVA08}}(N+100,2) + 2^{-64640},
  ```

  and the empty-message case contributes only the outer trunk-sponge term.

## 8. Conclusion

## References

[BDPVA08] Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. *On the Indifferentiability of the Sponge Construction*. In Nigel P. Smart, editor, *Advances in Cryptology -- EUROCRYPT 2008*, volume 4965 of *Lecture Notes in Computer Science*, pages 181-197. Springer, 2008.

[BDPVA11] Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. *Duplexing the Sponge: Single-Pass Authenticated Encryption and Other Applications*. In Ali Miri and Serge Vaudenay, editors, *Selected Areas in Cryptography -- SAC 2011*, volume 7118 of *Lecture Notes in Computer Science*, pages 320-337. Springer, 2012.

[BH22] Mihir Bellare and Viet Tung Hoang. *Efficient Schemes for Committing Authenticated Encryption*. In Orr Dunkelman and Stefan Dziembowski, editors, *Advances in Cryptology -- EUROCRYPT 2022, Part II*, volume 13276 of *Lecture Notes in Computer Science*, pages 845-875. Springer, 2022.

[BN00] Mihir Bellare and Chanathip Namprempre. *Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm*. In Tatsuaki Okamoto, editor, *Advances in Cryptology -- ASIACRYPT 2000*, volume 1976 of *Lecture Notes in Computer Science*, pages 531-545. Springer, 2000.

[FIPS202] National Institute of Standards and Technology. *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions*. Federal Information Processing Standards Publication 202, 2015. <https://doi.org/10.6028/NIST.FIPS.202>

[SP800185] John Kelsey, Shu-jen Chang, and Ray Perlner. *SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash*. NIST Special Publication 800-185, 2016. <https://doi.org/10.6028/NIST.SP.800-185>

[Men23] Bart Mennink. *Understanding the Duplex and Its Security*. *IACR Transactions on Symmetric Cryptology*, 2023(2): 1-46, 2023.
