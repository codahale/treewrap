# TreeWrap

## Abstract

We introduce TreeWrap, a permutation-based authenticated-encryption
construction that separates local chunk processing from a keyed trunk
transcript. The first chunk and the global associated data are processed by a
keyed duplex transcript called $`\mathsf{TrunkWrap}`$, while the remaining
chunks are processed independently by a MonkeySpongeWrap-style keyed duplex
transcript called $`\mathsf{LeafWrap}`$, which outputs a ciphertext body chunk
and a hidden leaf tag. For multi-chunk messages, the resulting leaf tag vector
is then absorbed back into the trunk transcript before the final tag is
squeezed. This decomposition is intended to preserve the short-message latency
of a single serial keyed duplex while still supporting parallel processing of
the remaining chunks. In that sense, TreeWrap can be read as transporting the
efficiency pattern of KangarooTwelve [K12] into the keyed setting and the AEAD
problem domain.

We analyze TreeWrap in two settings. For authenticated encryption, we prove
multi-user IND-CPA, INT-CTXT, and IND-CCA2 bounds in the keyed-duplex model of
Mennink. This AE analysis is largely modular: the leaf-layer proof identifies
$`\mathsf{LeafWrap}`$ with a reduced MonkeySpongeWrap transcript and imports
the corresponding keyed-duplex/IXIF replacement, while the trunk layer is
handled by a direct keyed-duplex/IXIF analysis. The main TreeWrap-specific AE
step is a freshness lemma showing that, in the IXIF world, either a fresh trunk
prefix or a fresh remaining chunk forces a fresh final tag path, except for the
explicit leaf-tag collision and final-tag guessing terms. For commitment, we
prove a CMT-4 bound in the public-permutation model by flattening the leaf and
trunk layers into duplex and sponge transcripts, respectively. This extends
ordinary key commitment to full commitment of the AEAD tuple and yields a
per-ciphertext commitment bound whose local term depends on the actual chunk
lengths rather than only on the leaf-tag length.

We also give a concrete instantiation, $`\mathsf{TW128}`$, based on
$`\mathrm{Keccak\text{-}p}[1600,12]`$ with 256-bit capacity, 8128-byte chunks,
256-bit leaf tags, and a 256-bit final tag. The resulting generic security
target is 128 bits, with explicit multi-user AE bounds and explicit per-output
CMT-4 bounds.

## 1. Introduction

TreeWrap is a permutation-based AEAD construction that separates processing of
the remaining chunks from a keyed trunk transcript. The construction handles
the associated data, the first chunk, and the final authentication tag inside a
serial keyed duplex called $`\mathsf{TrunkWrap}`$, while the remaining chunks
are processed independently by $`\mathsf{LeafWrap}`$, each producing a
ciphertext body chunk and a hidden leaf tag. This leaf/trunk split is designed
to improve the short-message path while still making the remaining chunks
embarrassingly parallel and keeping the final authentication transcript simple
enough to analyze both in the keyed AE setting and in the public-permutation
commitment setting.

At a design level, this is deliberately close in spirit to KangarooTwelve
[K12]: a serial trunk handles the short-message path and the global framing,
while remaining chunks can be processed in parallel and fed back as short
chaining values. The point of departure is that TreeWrap brings this efficiency
pattern into a keyed-duplex AEAD setting rather than an unkeyed tree-hashing
setting. Accordingly, TreeWrap uses keyed IV namespaces and duplex
padding/framing in place of Sakura coding, and it targets authenticated
encryption and commitment rather than hashing.

### 1.1 Design Rationale

TreeWrap is guided by four design goals.

First, short-message latency matters. The construction therefore keeps the
associated data, the first chunk, and the final tag in one serial `TrunkWrap`
transcript. This is not only an implementation choice: it also ensures that
every nonempty message contributes a body phase to the trunk transcript, so the
one-chunk integrity path reduces directly to trunk-prefix freshness.

Second, long-message throughput matters. Chunks after the first are therefore
handled by independent `LeafWrap` calls under disjoint IVs, so the bulk of a
long message can be processed in parallel and returned to the trunk only as a
vector of short hidden tags.

Third, proof modularity matters. The leaf layer is deliberately kept as close
as possible to the reduced MonkeySpongeWrap transcript already analyzed in
[Men23], while the trunk layer is a direct keyed-duplex family. This split is
what lets the authenticated-encryption analysis reuse the imported KD/IXIF
machinery rather than re-proving a monolithic new duplex mode from scratch.

Fourth, one of the attractions of duplex-based designs is that they admit a
natural commitment story. The same transcript structure that supports the AE
proofs can also be flattened into public-permutation histories, giving a direct
route to a CMT-4 analysis within the same permutation-based framework rather
than through a separate authenticator family. In particular, this extends the
usual key-commitment guarantee to full commitment of the AEAD parameters.

On the AE side, most of the proof work is a modular application of [Men23]
rather than a new keyed-duplex argument. The genuinely new technical pieces are
the TreeWrap-specific authenticity freshness split of Lemma 7.1 and the
public-permutation CMT-4 analysis of Section 7.

### 1.2 Related Work

At the structural level, TreeWrap is closest to KangarooTwelve [K12] and to
tree-style hash modes such as ParallelHash [SP800185]. These constructions use
a serial top-level transcript together with parallel subcomputations on long
inputs. TreeWrap borrows that efficiency pattern, but moves it from the unkeyed
hashing/XOF setting to keyed authenticated encryption. The main difference is
therefore not only keyed initialization but also framing: rather than
Sakura-style tree coding, TreeWrap uses derived keyed IVs together with duplex
padding and phase trailers to separate the trunk and leaf transcripts.

Among keyed Keccak-family designs, Keyak [Keyak16] is the closest relative in
spirit. Both designs use `Keccak-p[1600,12]`, both exploit parallel local
processing, and both ultimately authenticate the whole message through a serial
top-level transcript. The modes are nevertheless quite different in three
respects. First, Keyak is a session-oriented full-state keyed-duplex design
built around the Motorist mode, with persistent parallel pistons and a knot
operation that feeds chaining values back across lanes; TreeWrap instead
targets one-shot AEAD. Second, Motorist's piston/knot structure requires a
dedicated analysis, whereas TreeWrap's leaf and trunk layers each reduce
directly to the Men23 KD/IXIF framework, keeping the proof substantially
smaller. Third, Keyak fixes its parallelism at design time (the number of
pistons is a Motorist parameter), while TreeWrap selects parallelism at
runtime: the chunk size is a fixed constant, so any number of remaining chunks
can be dispatched in parallel as hardware resources allow, scaling from
embedded targets up to wide SIMD pipelines without changing the mode
definition.

Closer to the modern permutation-based AEAD landscape, Xoodyak [Xoo20] and
Ascon [Ascon21, SP800232] are serial duplex-based designs that prioritize
compactness and lightweight deployment over chunk-parallel throughput. Xoodyak
offers a versatile Cyclist interface over Xoodoo[12], while Ascon is now the
standardized NIST lightweight AEAD family. TreeWrap differs from both by making
parallel message decomposition a first-class design goal: it keeps the
associated data and the first chunk on the trunk path, and pushes only the
remaining chunks into independent leaf transcripts.

Outside the permutation-based family, AEGIS-128L and AEGIS-256 [AEGIS] achieve
very high throughput on platforms with AES-NI or similar hardware acceleration.
TreeWrap differs in two ways: it does not require dedicated hardware
instructions, since Keccak-p is a bitwise construction that performs well in
pure software and in SIMD pipelines; and its duplex-based structure admits a
direct CMT-4 commitment analysis, whereas commitment for AEGIS-family designs
remains an active area of investigation.

On the proof side, the closest antecedent is [Men23]. The leaf layer is
deliberately kept close to the reduced MonkeySpongeWrap transcript analyzed
there, while the trunk layer remains a direct keyed-duplex family so that both
halves fit the same KD/IXIF framework. The commitment analysis instead follows
the encryption-based CMT-4 notion of [BH22] and the public-permutation
flattening/counting lineage of [BDPVA08, BDPVA11]. In this sense, the novelty
of TreeWrap is not a new generic duplex theorem, but a construction that
combines imported keyed-duplex bounds with a separate chunk-length-sensitive
commitment analysis.

The proof strategy follows the same decomposition. The AE analysis is carried
out in the multi-user keyed-duplex model of [Men23]. At the leaf layer, Lemma
6.1 identifies the $`\mathsf{LeafWrap}`$ family on chunks $`i \ge 1`$ with a
reduced MonkeySpongeWrap transcript, and Theorem 6.2 imports the corresponding
KD/IXIF replacement. A TreeWrap-specific freshness lemma then handles the
interaction between fresh leaf tags and the trunk transcript. At the trunk
layer, Corollaries 4.6 and 4.7 give the encryption-side and bidirectional
keyed-duplex/IXIF replacements for $`\mathsf{TrunkWrap}`$. These ingredients
yield the IND-CPA and INT-CTXT theorems, and Theorem 5.3 derives IND-CCA2 from
them by a BN00-style game hop using the multi-forgery integrity notion of
Section 4.2.

The commitment analysis is deliberately separate from the keyed AE path.
Because the CMT-4 adversary chooses both candidate keys and nonces, the proof
does not use the keyed [Men23] bounds. Instead, it flattens the construction
into public permutation transcripts. Lemma 7.2 handles the leaf wrapper via the
duplexing-sponge viewpoint of [BDPVA11], yielding a per-chunk collision term on
the full local output pair $`(Y_i,T_i)`$. Lemma 7.3 handles the trunk-local
transcript via a rooted-forest counting extension of the single-root sponge
bound of [BDPVA08]. Theorem 5.4 then composes these two cases: a TreeWrap
commitment collision either arises at the first differing remaining chunk
handled by $`\mathsf{LeafWrap}`$ or at the trunk-local transcript.

The remainder of the paper is organized as follows. Section 2 fixes notation,
the keyed-duplex model, and the encoding conventions. Section 3 defines
$`\mathsf{LeafWrap}`$, $`\mathsf{TrunkWrap}`$, and $`\mathsf{TreeWrap}`$,
together with the AEAD wrapper. Section 4 gives the multi-user security
experiments, the resource translation, and the imported external bounds.
Section 5 states the main AE and CMT-4 theorems. Section 6 gives the imported
AE adaptation sketches, and Section 7 contains the TreeWrap-specific proofs.
Section 8 instantiates the construction as $`\mathsf{TW128}`$ using
$`\mathrm{Keccak\text{-}p}[1600,12]`$, SP 800-185 encodings, 8128-byte chunks,
256-bit leaf tags, and a 256-bit final tag.

## 2. Preliminaries

### 2.1 Notation

Unless stated otherwise, all strings are bitstrings. We write $`\epsilon`$ for
the empty string, $`|X|`$ for the bitlength of a string $`X`$, $`X \| Y`$ for
concatenation, and $`\mathrm{left}_n(X)`$ for the leftmost $`n`$ bits of a
string $`X`$ with $`|X| \ge n`$. For integers $`m \le n`$, write $`[m,n) :=
\{m,m+1,\ldots,n-1\}`$.

Chunk indices always start at $`0`$, while padded-block and transcript-block
indices start at $`1`$. When a body string $`X`$ is partitioned into chunks of
size $`B`$, we write $`X = X_0 \| \cdots \| X_{n-1}`$ for the canonical chunk
decomposition, where $`n = \lceil |X|/B \rceil`$, each nonfinal chunk has
length exactly $`B`$, the final chunk has length at most $`B`$, and $`n = 0`$
when $`X = \epsilon`$.

### 2.2 AEAD Syntax

An AEAD scheme consists of a pair of algorithms

```math
\mathsf{ENC}(K,U,A,P) \to C,
\qquad
\mathsf{DEC}(K,U,A,C) \to P \text{ or } \bot,
```

where $`K`$ is a secret key, $`U`$ is a nonce, $`A`$ is associated data, $`P`$
is a plaintext, and $`C`$ is a ciphertext. Correctness requires

```math
\mathsf{DEC}(K,U,A,\mathsf{ENC}(K,U,A,P)) = P
```

for all valid inputs.

### 2.3 Duplex / Underlying Primitive Model

#### 2.3.1 Keyed Duplex

We adopt the keyed duplex interface of [Men23, Algorithm 1], specialized to the
case $`\alpha = 0`$ used throughout TreeWrap. Let $`b,c,r,k,\mu \in
\mathbb{N}`$ with $`c + r = b`$ and $`k \le b`$. Let $`\mathcal{IV} \subseteq
\{0,1\}^{b-k}`$ be an IV space, and let $`p \in \mathrm{Perm}(b)`$ be a
$`b`$-bit permutation. The keyed duplex construction is denoted

```math
\mathsf{KD}[p]_K,
```

where the key array is

```math
K = (K[1], \ldots, K[\mu]) \in (\{0,1\}^k)^\mu.
```

In the single-key specialization $`\mu = 1`$, we identify $`K[1]`$ with a
single key $`K \in \{0,1\}^k`$ and write $`\mathsf{KD}[p]_K`$ for the resulting
instance.

It maintains a state $`S \in \{0,1\}^b`$ and exposes the following two
interfaces.

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

Here $`\delta`$ ranges over $`\{1,\ldots,\mu\}`$, $`IV`$ ranges over
$`\mathcal{IV}`$, $`\mathsf{flag}`$ ranges over
$`\{\mathsf{true},\mathsf{false}\}`$, and $`B`$ ranges over $`\{0,1\}^b`$. When
$`\mathsf{flag} = \mathsf{true}`$, the outer $`r`$ bits are overwritten; when
$`\mathsf{flag} = \mathsf{false}`$, they are XOR-absorbed. This keyed duplex
interface is the primitive on which both the TreeWrap trunk transcript and the
MonkeySpongeWrap-style LeafWrap transcript are built.

#### 2.3.2 Ideal IXIF Interface

For the authenticated-encryption proofs, we also use the ideal path-based
interface $`\mathsf{IXIF}[\mathrm{ro}]`$ imported from [Men23]. Fix a random
oracle

```math
\mathrm{ro} : \{0,1\}^* \to \{0,1\}^r
```

and a fixed-width injective encoding

```math
\mathrm{uid} : \{1,\ldots,\mu\} \to \{0,1\}^{w_{\mathsf{uid}}},
\qquad
w_{\mathsf{uid}} \ge \lceil \log_2 \mu \rceil.
```

The interface maintains a current transcript path $`\pi \in \{0,1\}^*`$ and
exposes:

```text
Algorithm IXIF[ro].init(δ, IV):
    π <- uid(δ) || IV
```

Because $`\mathrm{uid}`$ has fixed width, the concatenation $`(\delta,IV)
\mapsto \mathrm{uid}(\delta) \| IV`$ is injective in the user index and the
keyed context.

```text
Algorithm IXIF[ro].duplex(flag, B):
    Z <- ro(π)
    D <- ([flag] * (Z || 0^{b-r})) xor B
    π <- π || D
    return Z
```

Thus $`\mathsf{IXIF}[\mathrm{ro}]`$ keeps the same control flow as the keyed
duplex but replaces the permutation state by a transcript path. A repeated path
returns the same deterministic oracle value, while a fresh path returns an
independent uniform $`r`$-bit string. This is the ideal interface used by the
imported KD/IXIF replacements of Section 4.6.

### 2.4 Encoding Conventions and Domain Separation

**Derived IVs.** We assume a fixed-length nonce space $`\mathcal{U} \subseteq
\{0,1\}^u`$ for some nonce length $`u \in \mathbb{N}`$, together with an
injective IV-derivation map

```math
\mathsf{iv} : \mathcal{U} \times \mathbb{N} \to \mathcal{IV}.
```

TreeWrap reserves suffix $`0`$ for the trunk call and uses positive suffixes
for `LeafWrap` calls on the remaining chunks, so $`V_{\mathsf{tr}}(U) :=
\mathsf{iv}(U,0)`$ and $`V_i(U) := \mathsf{iv}(U,i)`$ for $`i \ge 1`$. In
concrete instantiations, $`\mathsf{iv}`$ may itself be built from an injective
integer encoding such as $`\mathrm{right\_encode}`$; Section 8 does this for
$`\mathsf{TW128}`$.

**Trunk phase framing.** Fix two distinct nonempty bitstrings
$`\lambda_{\mathsf{ad}}, \lambda_{\mathsf{tc}} \in \{0,1\}^+`$. For the trunk
transcript, these serve as phase trailers for the associated-data phase and the
leaf-tag phase, respectively. We write

```math
\mathrm{pad}^{\mathsf{ad}}_{10^r*}(Z) := \mathrm{pad}_{10^r*}(Z \| \lambda_{\mathsf{ad}}),
\qquad
\mathrm{pad}^{\mathsf{tc}}_{10^r*}(Z) := \mathrm{pad}_{10^r*}(Z \| \lambda_{\mathsf{tc}}).
```

When leaf calls are present on chunks $`i \ge 1`$, the final trunk phase
absorbs the string

```math
T_1 \| \cdots \| T_{n-1}.
```

Because the leaf tags have fixed length $`t_{\mathsf{leaf}}`$ and the message
length determines the canonical chunk count, this final-phase string is
injective in the leaf tag vector once the ciphertext length is fixed. Together
with the distinct phase trailers and the explicit omission or presence of the
associated-data phase, the overall trunk transcript is injective in the tuple
$`(A,X_0,T_1,\ldots,T_{n-1})`$.

**Overhead notation.** For later resource accounting, write

```math
d_{\mathsf{ad}} := |\lambda_{\mathsf{ad}}|,
\qquad
d_{\mathsf{tc}} := |\lambda_{\mathsf{tc}}|.
```

**Padding and framing.** For any block length $`s \in \mathbb{N}`$ and any
bitstring $`Z \in \{0,1\}^*`$, we write

```math
(Z_1,\ldots,Z_w) \gets \mathrm{pad}^{*}_{10^s*}(Z)
```

for the unique padded decomposition of $`Z`$ into $`s`$-bit blocks under the
$`\mathrm{pad}10^*`$ convention of [Men23]. Thus each $`Z_j \in \{0,1\}^s`$,
and

```math
\mathrm{left}_{|Z|}(Z_1 \| \cdots \| Z_w) = Z.
```

LeafWrap embeds each padded message or ciphertext block as $`Z_j \| 1 \|
0^{c-1}`$. These are full-state blocks of length $`b = r + c`$ and provide a
dedicated transcript format for the body-processing phase. By contrast, the
trunk absorb phases process associated-data blocks and leaf-tag blocks as $`W_j
\| 0^c`$, that is, as ordinary rate-$`r`$ sponge blocks with an all-zero
capacity suffix.

**Domain separation.** TreeWrap relies on three separation mechanisms. First,
the proofs rely on disjoint IV namespaces to separate leaf and trunk calls: the
trunk uses $`V_{\mathsf{tr}}(U) = \mathsf{iv}(U,0)`$, while leaf calls on
chunks $`i \ge 1`$ use $`V_i(U) = \mathsf{iv}(U,i)`$. Second, within the trunk
transcript, the optional associated-data phase and the optional leaf-tag phase
are terminated by distinct trailers $`\lambda_{\mathsf{ad}}`$ and
$`\lambda_{\mathsf{tc}}`$. Third, body-processing phases and absorb phases are
distinguished by their capacity-part framing: body phases (in both the trunk
and leaf transcripts) use the suffix $`1 \| 0^{c-1}`$, whereas absorb phases
use $`0^c`$. This third mechanism separates phases within a transcript, not
leaf from trunk; the leaf/trunk distinction is carried entirely by the IV
namespaces of the first mechanism. The later reductions use the IV separation
as the primary argument and the block-format distinction as secondary
transcript-format separation.

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
- a leaf tag size $`t_{\mathsf{leaf}}`$,
- a tag size $`\tau`$.

These parameters satisfy $`c + r = b`$ and $`k \le b`$.

We write the resulting primitive as

```math
\mathsf{TreeWrap}_{p,b,r,c,k,\mathcal{IV},\mathcal{U},\mathsf{iv},B,t_{\mathsf{leaf}},\tau}.
```

and fix the trunk-phase trailers $`\lambda_{\mathsf{ad}}`$ and
$`\lambda_{\mathsf{tc}}`$ from Section 2.4.

When these parameters are fixed by context, we write simply
$`\mathsf{TreeWrap}`$, $`\mathsf{TreeWrap.ENC}`$, and
$`\mathsf{TreeWrap.DEC}`$.

In the algorithm blocks below, we use the ASCII spellings `ell`, `tau`, and
`t_leaf` for the mathematical parameters $`\ell`$, $`\tau`$, and
$`t_{\mathsf{leaf}}`$.

For readability, Section 3 presents the construction in the single-key setting.
The multi-user AE analyses of Sections 4--6 lift these same algorithms to a key
array $`K = (K[1],\ldots,K[\mu])`$ by selecting the active user index
$`\delta`$ on each oracle query and then invoking the single-key algorithms
under $`K[\delta]`$.

### 3.2 LeafWrap

LeafWrap is the wrapper used for chunks after the first. It has no local
associated-data phase: authentication of those chunks is driven entirely by the
body transcript and the hidden leaf tag, while global associated data is
incorporated only by the trunk transcript that processes the first chunk.

Conceptually, $`\mathsf{LeafWrap}[p]`$ is the message-processing core of
$`\mathsf{MonkeySpongeWrap}[p]`$ from [Men23] with the associated-data phase
removed and the two directions presented as a single symmetric transcript
function parameterized by $`m \in \{\mathsf{enc},\mathsf{dec}\}`$. This
omission of per-chunk associated data is deliberate: it keeps the local
transcript as close as possible to the reduced MonkeySpongeWrap form used in
the imported proof and routes all associated-data binding through the trunk
layer instead.

#### 3.2.1 Definition

This is a TreeWrap-native construction defined directly in terms of the keyed
duplex transcript. We denote it by

```math
\mathsf{LeafWrap}[p].
```

It takes $`(K,V,X,m) \in \{0,1\}^k \times \mathcal{IV} \times \{0,1\}^* \times
\{\mathsf{enc},\mathsf{dec}\}`$ and returns $`(Y,T) \in \{0,1\}^{|X|} \times
\{0,1\}^{t_{\mathsf{leaf}}}`$.

```text
Algorithm LeafWrap[p](K, V, X, m):
    Y* <- ε
    T* <- ε
    instantiate KD[p]_(K) with α = 0
    KD.init(1, V)
    if m = enc:
        (X~_1, ..., X~_w) <- pad*_{10^r*}(X)
        for j = 1 to w:
            Z~_j <- KD.duplex(false, X~_j || 1 || 0^{c-1})
            Y* <- Y* || (Z~_j xor X~_j)
    else:
        parse X as X_1 || ... || X_u || X_vis
        with |X_j| = r for j = 1,...,u and |X_vis| = d, where 0 <= d < r
        for j = 1 to u:
            Z~_j <- KD.duplex(true, X_j || 1 || 0^{c-1})
            Y* <- Y* || (Z~_j xor X_j)
        let Z~_{u+1} be the squeeze output of the next overwrite call
        Y_vis <- left_d(Z~_{u+1} xor X_vis)
        Y~_{u+1} <- Y_vis || 1 || 0^{r-d-1}
        X~_{u+1} <- Z~_{u+1} xor Y~_{u+1}
        complete the next overwrite call with X~_{u+1} || 1 || 0^{c-1}
        Y* <- Y* || Y_vis
    for j = 1 to ceil(t_leaf / r):
        T* <- T* || KD.duplex(false, 0^b)
    Y <- left_|X|(Y*)
    T <- left_t_leaf(T*)
    return (Y, T)
```

Encryption XOR-absorbs the padded body blocks directly. Decryption uses the
same overwrite transcript on all fully visible $`r`$-bit body blocks, and on
the final body step reconstructs the unique hidden full ciphertext block
consistent with the visible ciphertext suffix, the next squeeze output, and
$`\mathrm{pad}10^*`$ before completing the overwrite update. When $`d = 0`$,
this last step reconstructs the hidden all-padding block. This is the
transcript-level object used throughout the later reductions.

#### 3.2.2 Inversion

**Lemma 3.1 (LeafWrap Inversion).** For any fixed $`K`$ and $`V`$, if

```math
(Y,T) \gets \mathsf{LeafWrap}[p](K,V,X,\mathsf{enc}),
```

then

```math
(X,T) \gets \mathsf{LeafWrap}[p](K,V,Y,\mathsf{dec}).
```

In other words, the encryption and decryption modes of LeafWrap invert the body
transformation while reproducing the same leaf tag.

**Proof sketch.** Let $`\widetilde X_1,\ldots,\widetilde X_w`$ be the padded
plaintext blocks and let
$`\widetilde Y_j := \widetilde Z_j \oplus \widetilde X_j`$ be the corresponding
full ciphertext blocks in the encryption transcript. For every fully visible
body block, decryption feeds the same framed block
$`\widetilde Y_j \| 1 \| 0^{c-1}`$ with overwrite flag $`\mathsf{true}`$, so the
absorbed full-state input becomes

```math
[\mathsf{true}] \cdot (\widetilde Z_j \| 0^{b-r})
\oplus
(\widetilde Y_j \| 1 \| 0^{c-1})
=
\widetilde X_j \| 1 \| 0^{c-1},
```

which is exactly the framed encryption-side body block. On the final body step,
only the visible suffix $`Y_{\mathrm{vis}} = \mathrm{left}_d(\widetilde Y_w)`$
is returned to the caller, where $`d < r`$ and $`d = 0`$ covers the hidden
all-padding case. Decryption first obtains the same next squeeze output
$`\widetilde Z_w`$, reconstructs
$`X_{\mathrm{vis}} = \mathrm{left}_d(\widetilde Z_w \oplus Y_{\mathrm{vis}})`$,
sets
$`\widetilde X_w = X_{\mathrm{vis}} \| 1 \| 0^{r-d-1}`$,
reconstructs
$`\widetilde Y_w = \widetilde Z_w \oplus \widetilde X_w`$,
and then performs the overwrite update with
$`\widetilde Y_w \| 1 \| 0^{c-1}`$. The same algebra therefore yields
$`\widetilde X_w \| 1 \| 0^{c-1}`$ on the final step as well. Thus the entire
body transcript, and therefore the subsequent tag-squeezing transcript, is
reproduced exactly.

### 3.3 TrunkWrap

TreeWrap handles the empty-message path, the first chunk, and the final
authentication tag through a second keyed-duplex transcript, denoted by

```math
\mathsf{TrunkWrap}[p].
```

In the single-key setting, it is factored into three procedures:

- initialization on the trunk IV $`\mathsf{iv}(U,0)`$ with an optional
  associated-data absorb phase,
- body processing for the first chunk,
- finalization by optional absorption of the later hidden leaf tags followed
  by squeezing the final tag.

`TrunkWrap` is therefore a single serial keyed-duplex transcript that may
contain up to four nonempty regions after initialization:

1. an optional associated-data absorb phase,
2. an optional first-chunk body phase,
3. an optional leaf-tag absorb phase,
4. the final squeeze phase.

```text
Algorithm TrunkWrap.init[p](K, V, A):
    instantiate KD[p]_(K) with α = 0
    KD.init(1, V)
    if A ≠ ε:
        (A~_1, ..., A~_u) <- pad^{ad}_{10^r*}(A)
        for j = 1 to u:
            KD.duplex(false, A~_j || 0^c)
    return KD
```

```text
Algorithm TrunkWrap.body(KD, X, m):
    let Y be the output of the LeafWrap body-phase transcript on X and m,
        executed using the current keyed-duplex object KD in place of a fresh
        initialization
    return (Y, KD)
```

```text
Algorithm TrunkWrap.finalize(KD, T_1, ..., T_m; output length ell):
    if m > 0:
        Σ <- T_1 || ... || T_m
        (S~_1, ..., S~_v) <- pad^{tc}_{10^r*}(Σ)
        for j = 1 to v:
            KD.duplex(false, S~_j || 0^c)
    T* <- ε
    while |T*| < ell:
        T* <- T* || KD.duplex(false, 0^b)
    return left_ell(T*)
```

The associated-data phase may be omitted entirely when $`A = \epsilon`$, and
the leaf-tag absorb phase may be omitted when there are no leaf calls on chunks
$`i \ge 1`$. The trunk body phase uses the same $`1 \| 0^{c-1}`$ framing as
$`\mathsf{LeafWrap}`$, while the absorb phases use $`0^c`$ framing. On the
keyed side, `TrunkWrap` is again a direct keyed-duplex transcript to which the
generic KD/IXIF reduction of [Men23] applies. On the flat side, the trunk
transcript can be flattened to an ordinary rooted sponge history for the CMT-4
analysis.

### 3.4 TreeWrap

TreeWrap uses `TrunkWrap` for the empty-message path and the first chunk, and
uses `LeafWrap` only for remaining chunks. The hidden leaf tags are then fed
back into the trunk transcript before the final squeeze.

Placing chunk $`0`$ inside the trunk is not only a latency optimization. It is
also what makes the $`n = 1`$ integrity path reduce directly to trunk-prefix
freshness: every nonempty message contributes a body phase to the trunk
transcript, so one-chunk forgeries are handled by the same trunk argument as
the empty-message and multi-chunk cases.

Its interface is

```math
\mathsf{TreeWrap}(K,U,A,X,m) \to (Y,T),
```

where $`Y \in \{0,1\}^{|X|}`$ and $`T \in \{0,1\}^{\tau}`$.

```text
Algorithm TreeWrap(K, U, A, X, m):
    n <- ceil(|X| / B)
    if n = 0:
        D_0 <- TrunkWrap.init[p](K, iv(U,0), A)
        T <- TrunkWrap.finalize(D_0; output length tau)
        return (ε, T)
    parse X according to the canonical chunking of Section 2.1
    D_0 <- TrunkWrap.init[p](K, iv(U,0), A)
    (Y_0, D_0) <- TrunkWrap.body(D_0, X_0, m)
    for i = 1 to n-1:
        V_i <- iv(U, i)
        (Y_i, T_i) <- LeafWrap[p](K, V_i, X_i, m)
    Y <- Y_0 || ... || Y_{n-1}
    T <- TrunkWrap.finalize(D_0, T_1, ..., T_{n-1}; output length tau)
    return (Y, T)
```

The chunking line uses the canonical decomposition of Section 2.1. The
IV-derivation map $`\mathsf{iv}`$ is used with suffix $`0`$ for the trunk IV
and with suffixes $`1,2,\ldots,n-1`$ for the `LeafWrap` IVs on chunks
$`1,\ldots,n-1`$. The first ciphertext body chunk $`Y_0`$ is produced inside
the trunk transcript and therefore depends on the associated-data prefix $`A`$
as well as on $`(K,U,X_0)`$; later ciphertext body chunks $`Y_i`$ for $`i \ge
1`$ depend only on their local LeafWrap inputs.

TreeWrap is nonce-based and not nonce-misuse resistant. If the same key and
nonce are reused, then all derived leaf IVs repeat and the trunk IV also
repeats. Later chunks therefore exhibit the usual two-time-pad failure
immediately, and the same is true of the first chunk whenever the associated
data transcript also repeats. This design therefore targets the standard
nonce-respecting model rather than nonce-misuse resistance. Achieving NMR would
require a different construction, such as an SIV-style two-pass design, which
would work against the present single-pass chunked interface. In practice,
implementations should use any standard per-key nonce-generation strategy, such
as a persistent counter or uniformly random 128-bit nonces subject to the usual
birthday-bound collision risk. For the concrete $`\mathsf{TW128}`$
instantiation, the 1344-bit IV field leaves ample room for a wider nonce
encoding as well: moving from 128-bit to 256-bit nonces would only change the
concrete IV embedding, not the duplex rate, capacity, or permutation-call
counts.

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

Correctness of TreeWrap follows from the corresponding inversion property of
LeafWrap together with deterministic final tag derivation.

**Lemma 3.2 (TreeWrap Correctness).** For all valid inputs $`(K,U,A,P)`$,

```math
\mathsf{TreeWrap.DEC}(K,U,A,\mathsf{TreeWrap.ENC}(K,U,A,P)) = P.
```

**Proof sketch.** If $`P = \epsilon`$, then both procedures execute only
`TrunkWrap.init` on $`(K,\mathsf{iv}(U,0),A)`$ followed by
`TrunkWrap.finalize`, so they derive the same tag and return the empty string.

Assume now $`P \ne \epsilon`$ and let

```math
P = P_0 \| \cdots \| P_{n-1}
```

be the canonical chunk decomposition. The encryption algorithm computes

```math
(Y_0,D_0) \gets \mathsf{TrunkWrap.body}(D_0,P_0,\mathsf{enc}),
\qquad
(Y_i,T_i) \gets \mathsf{LeafWrap}[p](K,\mathsf{iv}(U,i),P_i,\mathsf{enc})
```

for each $`i = 1,\ldots,n-1`$. By Lemma 3.1, decryption reproduces the same
leaf tags $`T_i`$ and recovers each remaining chunk $`P_i`$ from $`Y_i`$,
including the final truncated body block through the same hidden-tail
reconstruction. The trunk body phase is defined to use exactly the same
body-processing transcript as LeafWrap, starting from the current trunk duplex
state, so the same argument shows that `TrunkWrap.body` recovers
$`P_0`$ from $`Y_0`$ while reproducing the same post-body trunk state. Hence
both the optional associated-data phase and the optional leaf-tag absorb phase
of `TrunkWrap` are identical in wrapping and unwrapping, and both procedures
use the same trunk IV $`\mathsf{iv}(U,0)`$. Therefore they derive the same
final tag via `TrunkWrap.finalize`, tag verification succeeds, and the
recovered plaintext is exactly $`P`$.

## 4. Security Model and Imported Bounds

For the AEAD notions of Sections 4.1--4.3, we work in the ideal-permutation
model in the multi-user setting of [Men23]. Fix $`\mu \ge 1`$. Let $`p \gets
\mathrm{Perm}(b)`$ be sampled uniformly at random, and let

```math
K = (K[1],\ldots,K[\mu]) \gets (\{0,1\}^k)^\mu
```

be a uniformly random key array. Unless stated otherwise, probabilities are
taken over the random choices of $`p`$, $`K`$, and the adversary's internal
randomness. We suppress the parameter $`\mu`$ from the advantage notation when
it is fixed by context.

In the AEAD experiments below, the adversary additionally has primitive access
to the sampled permutation via two oracles:

- $`\mathsf{Perm}(S) := p(S)`$,
- $`\mathsf{PermInv}(S) := p^{-1}(S)`$.

We write $`N`$ for the total number of primitive queries made to these two
oracles.

In the AEAD experiments of Sections 4.1--4.3, adversaries are nonce-respecting
on a per-user basis: they never repeat a nonce across encryption-type oracle
queries addressed to the same user index $`\delta`$. Concretely:

- in the IND-CPA and IND-CCA2 left-right experiments, no two left-right
  queries for the same $`\delta`$ use the same nonce $`U`$;
- in the INT-CTXT experiment, no two encryption-oracle queries for the same
  $`\delta`$ use the same nonce $`U`$;
- decryption queries may repeat nonces.

For standard AEAD security notions, we use the adversarial resource measures
$`q_e`$ for the number of encryption queries, $`q_f`$ for the number of final
forgery candidates in the multi-forgery INT-CTXT experiment, $`q_d`$ for the
number of decryption-oracle queries in the IND-CCA2 experiment, and $`\sigma`$
for total queried data complexity. For lower-level duplex and sponge analyses,
we additionally use the resource measures of [Men23], including $`M`$, $`N`$,
$`Q`$, $`Q_{IV}`$, $`L`$, $`\Omega`$, and $`\nu_{\mathsf{fix}}`$.

All user indices $`\delta`$ range over $`\{1,\ldots,\mu\}`$.

In the AEAD experiments below, $`\mathsf{TreeWrap}_p`$ denotes TreeWrap
instantiated with the sampled permutation $`p`$; the active user key on a query
with index $`\delta`$ is $`K[\delta]`$.

### 4.1 IND-CPA

We use the standard left-right indistinguishability experiment for
nonce-respecting adversaries.

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

Ciphertext integrity is defined by the following multi-forgery experiment. We
use the multi-forgery form so that the IND-CCA2 reduction of Section 6.4 can
record all fresh decryption attempts of the adversary and output them together,
rather than paying an additional index-guessing loss to select one candidate in
advance.

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

Here $`\mathcal{A}`$ may make its encryption and primitive queries adaptively
before outputting the final candidate set $`F`$, and $`q_f := |F|`$ denotes the
number of forgery candidates in that final output set across all users.

### 4.3 IND-CCA2

Chosen-ciphertext privacy is defined by the following left-right experiment
with decryption access.

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

For commitment security, we adopt the encryption-based CMT-4 notion of [BH22].
The winning-input extractor is

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

We now record the lower-level resources induced by TreeWrap queries at the leaf
and trunk layers.

For readability, the main resource symbols used below are:

| Symbol | Meaning |
| --- | --- |
| $`\chi_{\mathsf{leaf}}(X)`$ | number of remaining chunks of $`X`$ handled by `LeafWrap` |
| $`\sigma_{\mathsf{leaf}}(X)`$ | total leaf duplex calls on those remaining chunks |
| $`q^{\mathsf{tr}}_e, q^{\mathsf{tr}}_d`$ | number of trunk evaluations on the encryption and decryption sides |
| $`\sigma^{\mathsf{tr}}_e, \sigma^{\mathsf{tr}}_d`$ | total trunk duplex calls on the encryption and decryption sides |
| $`L_{\mathsf{tr}}`$ | induced repeated-subpath count for the bidirectional trunk family |
| $`\Omega_{\mathsf{lw},d}, \Omega^{\mathsf{tr}}_d`$ | decryption-side overwrite counts for the leaf and trunk families |
| $`q_f`$ | final forgery-candidate count in the multi-forgery INT-CTXT game |
| $`q_*`$ | generic decryption-side wrapper count: $`q_f`$ in INT-CTXT and $`q_d`$ in IND-CCA2 |

Throughout Sections 4--8, lower-case $`\sigma`$ denotes a duplex-call count,
while upper-case $`\Sigma`$ is reserved for a concatenated leaf-tag suffix in
the trunk-local proofs.

**Lemma 4.1 (Derived Internal-Keyed-Context Discipline).** Suppose the
adversary is nonce-respecting at the TreeWrap encryption layer on a per-user
basis. Then

```math
V_{\mathsf{tr}}(U) := \mathsf{iv}(U,0)
```

induces pairwise distinct trunk keyed contexts $`(\delta,V_{\mathsf{tr}}(U))`$
across encryption queries;

```math
V_i(U) := \mathsf{iv}(U,i), \qquad i \ge 1
```

induces pairwise distinct leaf keyed contexts $`(\delta,V_i(U))`$ across all
encryption-side LeafWrap calls; and no trunk keyed context equals any leaf
keyed context.

**Proof.** All claims follow from per-user nonce-respecting behavior together
with injectivity of the map $`(U,j) \mapsto \mathsf{iv}(U,j)`$ on $`\mathcal{U}
\times \mathbb{N}`$. Distinct encryption queries for a fixed user $`\delta`$
use distinct nonces, and within a fixed encryption query the suffixes
$`0,1,\ldots,n-1`$ are all different. Hence the corresponding derived keyed
contexts are pairwise distinct. Repetitions of the bare IV string across
different users are harmless because the idealized initialization path is
$`\mathrm{uid}(\delta) \| IV`$, so different user indices still induce distinct
keyed contexts.

For any bitstring $`Z \in \{0,1\}^*`$, define the number of rate-blocks after
$`\mathrm{pad}10^*`$ padding by

```math
\omega_r(Z) := \left\lceil \frac{|Z|+1}{r} \right\rceil.
```

Also define the fixed squeezing costs

```math
s_{\mathsf{leaf}} := \left\lceil \frac{t_{\mathsf{leaf}}}{r} \right\rceil,
\qquad
s_{\mathsf{tr}} := \left\lceil \frac{\tau}{r} \right\rceil.
```

If a TreeWrap body string $`X`$ is partitioned into chunks

```math
X = X_0 \| \cdots \| X_{n-1},
```

then the leaf calls perform exactly

```math
\omega_r(X_i) + s_{\mathsf{leaf}}
```

duplexing calls on each remaining chunk $`X_i`$ with $`i \ge 1`$:
$`\omega_r(X_i)`$ body calls and $`s_{\mathsf{leaf}}`$ tag-squeezing calls.
Accordingly, define

```math
\chi_{\mathsf{leaf}}(X) := \max(n-1,0),
```

```math
\sigma_{\mathsf{leaf}}(X) := \sum_{i=1}^{n-1} \bigl(\omega_r(X_i) + s_{\mathsf{leaf}}\bigr).
```

Thus $`\chi_{\mathsf{leaf}}(X)`$ counts the number of remaining chunks handled
by LeafWrap, and $`\sigma_{\mathsf{leaf}}(X)`$ counts the corresponding leaf
duplex calls.

At the trunk layer, each TreeWrap encryption or decryption query performs one
`TrunkWrap[p]` evaluation with an optional associated-data phase, an optional
first-chunk body phase, an optional leaf-tag absorb phase, and a final squeeze
phase. Define the associated-data cost

```math
\alpha_r(A) := \mathbf{1}_{A \ne \epsilon} \cdot \left\lceil \frac{|A| + d_{\mathsf{ad}} + 1}{r} \right\rceil,
```

the first-chunk body cost

```math
\beta_r(X)
:=
\begin{cases}
0, & \text{if } n = 0,\\
\omega_r(X_0), & \text{if } n \ge 1,
\end{cases}
```

and the leaf-tag absorb cost

```math
\gamma_r(X)
:=
\mathbf{1}_{n \ge 2} \cdot \left\lceil \frac{(n-1)t_{\mathsf{leaf}} + d_{\mathsf{tc}} + 1}{r} \right\rceil.
```

The total number of trunk duplex calls in one TreeWrap evaluation is then

```math
\sigma_{\mathsf{tr}}(A,X)
:=
\alpha_r(A) + \beta_r(X) + \gamma_r(X) + s_{\mathsf{tr}}.
```

On decryption-side trunk evaluations, overwrite occurs only in the first-chunk
body phase. Accordingly, define the trunk overwrite count

```math
\Omega_{\mathsf{tr},d}(Y) := \beta_r(Y).
```

For an adversary's encryption queries with plaintext bodies
$`P^{(1)},\ldots,P^{(q_e)}`$ and decryption-side ciphertext bodies
$`Y^{(1)},\ldots,Y^{(q_*)}`$, aggregated across all users, where $`q_*`$
denotes either the final-candidate count $`q_f`$ in INT-CTXT or the
decryption-query count $`q_d`$ in IND-CCA2, we set

```math
\chi_{\mathsf{leaf},e} := \sum_{a=1}^{q_e} \chi_{\mathsf{leaf}}(P^{(a)}),
\qquad
\chi_{\mathsf{leaf},d} := \sum_{b=1}^{q_*} \chi_{\mathsf{leaf}}(Y^{(b)}),
```

```math
\sigma^{\mathsf{leaf}}_e := \sum_{a=1}^{q_e} \sigma_{\mathsf{leaf}}(P^{(a)}),
\qquad
\sigma^{\mathsf{leaf}}_d := \sum_{b=1}^{q_*} \sigma_{\mathsf{leaf}}(Y^{(b)}),
```

```math
q^{\mathsf{tr}}_e := q_e,
\qquad
q^{\mathsf{tr}}_d := q_*,
```

```math
\sigma^{\mathsf{tr}}_e := \sum_{a=1}^{q_e} \sigma_{\mathsf{tr}}(A^{(a)},P^{(a)}),
\qquad
\sigma^{\mathsf{tr}}_d := \sum_{b=1}^{q_*} \sigma_{\mathsf{tr}}(A'^{(b)},Y^{(b)}),
```

```math
\Omega^{\mathsf{tr}}_d := \sum_{b=1}^{q_*} \Omega_{\mathsf{tr},d}(Y^{(b)}).
```

For the bidirectional trunk family, let $`L_{\mathsf{tr}}`$ denote the induced
number of trunk duplexing calls whose subpaths repeat prior trunk subpaths in
the same keyed context. This is exactly the Men23 resource parameter $`L`$ for
that family, and we keep it explicit rather than replacing it by a coarser
wrapper-level upper bound.

These are the natural lower-level resources for the imported leaf and trunk
analyses.

### 4.6 Translation to Men23 Resources

When instantiating the imported results of [Men23], we keep the full
$`\mu`$-user setting. Because TreeWrap always uses keyed-duplex initialization
with $`\alpha = 0`$, the low-complexity branch of [Men23, Theorem 1, Eq. (5)]
specializes to

```math
\mathrm{KD}^{(i)}_{\mathsf{Men23}}(\mu,M,Q,Q_{IV},L,\Omega,\nu_{\mathsf{fix}},N)
:=
\frac{(L+\Omega)N}{2^c}
+
\frac{2 \nu_{r,c}^{2(M-L)}(N+1)}{2^c}
+
\frac{\binom{L+\Omega+1}{2}}{2^c}
+
\frac{(M-L-Q)Q}{2^b-Q}
+
\frac{M(M-L-1)}{2^b}
+
\frac{Q(M-L-Q)}{2^{\min\{c+k,b\}}}
+
\frac{Q_{IV}N}{2^k}
+
\frac{\binom{\mu}{2}}{2^k}.
```

Here $`\nu_{r,c}^{X}`$ is the multicollision limit function imported from
[Men23, Section 4.2]. The parameter $`\nu_{\mathsf{fix}}`$ is retained in the
argument list only to keep the shorthand aligned with the full [Men23] resource
tuple; it does not appear in this low-complexity branch. This shorthand is
exactly the low-complexity branch of [Men23, Theorem 1, Eq. (5)]; the
alternative [Men23, Theorem 2, Eq. (6)] introduces additional
$`\nu_{\mathsf{fix}}`$-dependent terms that are not used here. The simplified
branch is valid in the regime $`M + N \le 0.1 \cdot 2^c`$; if this side
condition is not met, one may instead use the corresponding general branch.

For the reduced MonkeySpongeWrap-style analysis of the leaf family, define the
decryption-side overwrite count

```math
\Omega_{\mathsf{lw},d} := \sigma^{\mathsf{leaf}}_d - s_{\mathsf{leaf}} \chi_{\mathsf{leaf},d}.
```

Because $`\mathrm{pad}10^*`$ always produces at least one padded body block,
every leaf contributes at least one body-phase call.

**Lemma 4.2 (Leaf Resource Translation).** The reduced leaf families induced by
TreeWrap admit the following valid resource assignments in the notation of
[Men23]:

- for the encryption-only family relevant to IND-CPA, one may take

  ```math
  M = \sigma^{\mathsf{leaf}}_e,\quad
  Q = \chi_{\mathsf{leaf},e},\quad
  Q_{IV} \le \mu,\quad
  L = 0,\quad
  \Omega = 0,\quad
  \nu_{\mathsf{fix}} = 0;
  ```

- for the bidirectional family relevant to INT-CTXT and IND-CCA2, one may take

  ```math
  M = \sigma^{\mathsf{leaf}}_e + \sigma^{\mathsf{leaf}}_d,\quad
  Q = \chi_{\mathsf{leaf},e} + \chi_{\mathsf{leaf},d},\quad
  Q_{IV} \le \mu,\quad
  L \le \chi_{\mathsf{leaf},d},\quad
  \Omega = \Omega_{\mathsf{lw},d},\quad
  \nu_{\mathsf{fix}} \le \max\!\bigl(\Omega_{\mathsf{lw},d} + \chi_{\mathsf{leaf},e} + \chi_{\mathsf{leaf},d} - 1, 0\bigr).
  ```

**Proof sketch.** This is the same reduced `LeafWrap` bookkeeping as in the
current TreeWrap proof, except that only remaining chunks are included.
Distinct encryption-side leaf keyed contexts eliminate encryption/encryption
subpath repetition, while decryption-side leaf queries may repeat keyed
contexts and contribute at most $`\chi_{\mathsf{leaf},d}`$ repeated subpaths.
Because $`\mathsf{iv}`$ is injective, a raw IV identifies a unique $`(U,j)`$
pair; same-user decryption-side repeats of that pair are accounted for by
$`L`$, while across distinct users a fixed raw IV can appear under at most
$`\mu`$ user labels, giving $`Q_{IV} \le \mu`$. The same path-counting argument
as in [Men23, Theorem 7] then yields the stated bound on
$`\nu_{\mathsf{fix}}`$. This bound is slightly conservative, but that does not
affect the concrete theorems here because $`\nu_{\mathsf{fix}}`$ does not
appear in the low-complexity branch of [Men23, Theorem 1, Eq. (5)] instantiated
in Section 4.6.

**Corollary 4.4 (Imported Leaf Encryption-Side KD/IXIF Bound).** If
$`\sigma^{\mathsf{leaf}}_e + N \le 0.1 \cdot 2^c`$, then the encryption-side
leaf real-to-IXIF replacement term can be instantiated as

```math
\epsilon_{\mathsf{leaf}}^{\mathsf{enc}}(\mu,\chi_{\mathsf{leaf},e},\sigma^{\mathsf{leaf}}_e,N)
:=
\mathrm{KD}^{(i)}_{\mathsf{Men23}}(\mu,\sigma^{\mathsf{leaf}}_e,\chi_{\mathsf{leaf},e},\mu,0,0,0,N).
```

**Corollary 4.5 (Imported Leaf Bidirectional KD/IXIF Bound).** If
$`\sigma^{\mathsf{leaf}}_e + \sigma^{\mathsf{leaf}}_d + N \le 0.1 \cdot 2^c`$,
then the bidirectional leaf real-to-IXIF replacement term can be instantiated
as

```math
\epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,N)
:=
\mathrm{KD}^{(i)}_{\mathsf{Men23}}(\mu,\sigma^{\mathsf{leaf}}_e+\sigma^{\mathsf{leaf}}_d,\chi_{\mathsf{leaf},e}+\chi_{\mathsf{leaf},d},\mu,\chi_{\mathsf{leaf},d},\Omega_{\mathsf{lw},d},\max\!\bigl(\Omega_{\mathsf{lw},d}+\chi_{\mathsf{leaf},e}+\chi_{\mathsf{leaf},d}-1,0\bigr),N).
```

**Lemma 4.3 (TrunkWrap Resource Translation).** The trunk families induced by
TreeWrap admit the following valid resource assignments in the notation of
[Men23]:

- for the encryption-only family relevant to IND-CPA, one may take

  ```math
  M = \sigma^{\mathsf{tr}}_e,\quad
  Q = q^{\mathsf{tr}}_e,\quad
  Q_{IV} \le \mu,\quad
  L = 0,\quad
  \Omega = 0,\quad
  \nu_{\mathsf{fix}} = 0;
  ```

- for the family with both encryption-side and decryption-side evaluations
  relevant to INT-CTXT and IND-CCA2, one may take

  ```math
  M = \sigma^{\mathsf{tr}}_e + \sigma^{\mathsf{tr}}_d,\quad
  Q = q^{\mathsf{tr}}_e + q^{\mathsf{tr}}_d,\quad
  Q_{IV} \le \mu,\quad
  L = L_{\mathsf{tr}},\quad
  \Omega = \Omega^{\mathsf{tr}}_d,\quad
  \nu_{\mathsf{fix}} \le \max(\Omega^{\mathsf{tr}}_d + q^{\mathsf{tr}}_e + q^{\mathsf{tr}}_d - 1,0).
  ```

**Proof sketch.** Each `TrunkWrap[p]` evaluation is one serial keyed-duplex
transcript under the keyed context $`(\delta,\mathsf{iv}(U,0))`$. The
transcript may have an optional AD absorb phase, then an optional first-chunk
body phase, then an optional leaf-tag absorb phase, followed by the final
squeeze phase. Only the first-chunk body phase uses overwrite on decryption;
all other trunk calls use flag $`\mathsf{false}`$.

In the encryption-only family, pairwise distinct trunk keyed contexts eliminate
repeated subpaths and encryption never uses overwrite, so $`L = \Omega =
\nu_{\mathsf{fix}} = 0`$. In the bidirectional family, repeated subpaths can
arise only from decryption-side recomputations under reused trunk keyed
contexts. A single replayed trunk evaluation may contribute many repeated
subpaths before diverging, so we keep the exact induced overlap count explicit
and set $`L = L_{\mathsf{tr}}`$. The overwrite contribution is exactly the
first-chunk body cost, so $`\Omega^{\mathsf{tr}}_d = \sum_{b=1}^{q_*}
\beta_r(Y^{(b)})`$. The same Men23 path-counting argument then gives the stated
bound on $`\nu_{\mathsf{fix}}`$.

**Corollary 4.6 (Imported TrunkWrap Encryption-Side KD/IXIF Bound).** If
$`\sigma^{\mathsf{tr}}_e + N \le 0.1 \cdot 2^c`$, then the trunk
encryption-side real-to-IXIF replacement term can be instantiated as

```math
\epsilon_{\mathsf{tr}}^{\mathsf{enc}}(\mu,q^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_e,N)
:=
\mathrm{KD}^{(i)}_{\mathsf{Men23}}(\mu,\sigma^{\mathsf{tr}}_e,q^{\mathsf{tr}}_e,\mu,0,0,0,N).
```

**Corollary 4.7 (Imported TrunkWrap Bidirectional KD/IXIF Bound).** If
$`\sigma^{\mathsf{tr}}_e + \sigma^{\mathsf{tr}}_d + N \le 0.1 \cdot 2^c`$, then
the trunk bidirectional real-to-IXIF replacement term can be instantiated as

```math
\epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,L_{\mathsf{tr}},N)
:=
\mathrm{KD}^{(i)}_{\mathsf{Men23}}(\mu,\sigma^{\mathsf{tr}}_e+\sigma^{\mathsf{tr}}_d,q^{\mathsf{tr}}_e+q^{\mathsf{tr}}_d,\mu,L_{\mathsf{tr}},\Omega^{\mathsf{tr}}_d,\max(\Omega^{\mathsf{tr}}_d+q^{\mathsf{tr}}_e+q^{\mathsf{tr}}_d-1,0),N).
```

### 4.8 Rooted-Forest Sponge Collision Bound

For the trunk-local CMT-4 analysis, we only need a bad-event bound for rooted
transcript merging, not a full indifferentiability statement. We therefore
import the single-root random-permutation sponge counting argument of [BDPVA08,
Eq. (6)] and record the corresponding $`\rho`$-root extension directly.

**Lemma 4.8 (Rooted-Forest Sponge Collision Bound).** Fix $`\rho \ge 1`$ public
roots. For each root, consider the rooted sponge tree obtained by following
absorb/squeeze paths from that root as in [BDPVA08]. Let $`R_i`$ be the set of
rooted nodes exposed after $`i`$ successful transcript or primitive-query
extensions, and let $`O_i`$ be the set of already fixed full states encountered
along those rooted paths. Define the bad event $`\mathsf{Merge}_{\rho}(M)`$ to
be the event that, during the first $`M`$ such extensions, a new forward or
inverse step lands on a previously exposed rooted node or previously fixed full
state in a way that merges two distinct rooted transcripts. Then

```math
\Pr[\mathsf{Merge}_{\rho}(M)] \le f_{P,\rho}(M),
```

where

```math
f_{P,\rho}(M)
:=
1 - \prod_{i=0}^{M-1} \frac{1-(\rho+i)2^{-c}}{1-i2^{-b}}.
```

Moreover, in the regime $`M < 2^c`$,

```math
f_{P,\rho}(M)
\le
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M,\rho)
:=
\frac{(1-2^{-r})M^2 + (2\rho-1+2^{-r})M}{2^{c+1}}.
```

**Proof sketch.** Exactly as in the single-root counting of [BDPVA08], each
safe extension contributes at most one new rooted node and at most one new full
state. Hence, inductively,

```math
|R_i| \le \rho + i,
\qquad
|O_i| \le i,
```

for every $`i \ge 0`$. Repeating the one-root bad-event count with these
cardinalities yields the displayed product bound. Here the numerator bounds the
probability that the next capacity slice avoids the at most $`\rho+i`$ exposed
rooted nodes, while the denominator conditions on avoiding the at most $`i`$
previously fixed full states. Applying the same quadratic relaxation as in
[BDPVA08, Eq. (6)] gives the displayed explicit rooted-forest collision bound.
For $`\rho = 1`$, the product expression specializes to the original
single-root counting bound and the quadratic term recovers exactly [BDPVA08,
Eq. (6)].

### 4.9 Imported Flat Duplex Bound

For the local CMT-4 analysis, the duplexing-sponge lemma of [BDPVA11, Lemma 3]
allows us to reuse the same rooted-sponge bound for the flattened
encryption-side LeafWrap transcript. This use is purely structural: the
duplexing-sponge equivalence identifies the duplex transcript with the
corresponding sponge transcript for every fixed input history, independent of
how the adversary chooses keys, IVs, or message blocks. For an $`\ell`$-bit
chunk body, define

```math
M_{\mathsf{lw}}(\ell,N)
:=
N + 2 \left(\left\lceil \frac{\ell+1}{r} \right\rceil + s_{\mathsf{leaf}}\right).
```

This quantity counts the adversary's primitive-query budget together with the
two compared local LeafWrap transcripts, each of which consists of $`\lceil
(\ell+1)/r \rceil`$ body calls and $`s_{\mathsf{leaf}}`$ blank squeeze calls.
Since a local collision comparison involves at most two distinct roots
$`(K,V)`$ and $`(K',V')`$, we set

```math
\epsilon_{\mathsf{lw}}^{\flat}(\ell,N)
:=
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{lw}}(\ell,N),2)
+
2^{-(\ell+t_{\mathsf{leaf}})}.
```

This is the concrete local CMT-4 term used below.

## 5. Main Results

For authenticated encryption, we instantiate the imported [Men23] terms using
Section 4.6. For commitment, the leaf local term is the explicit flat-duplex
quantity of Section 4.9, while the trunk-local term combines the rooted-forest
sponge count of Lemma 4.8 with an explicit ideal-output collision tail on the
observed trunk output.

- Let $`\epsilon_{\mathsf{leaf}}^{\mathsf{enc}}`$ be the explicit imported
  leaf encryption-side KD/IXIF term of Corollary 4.4.
- Let $`\epsilon_{\mathsf{leaf}}^{\mathsf{ae}}`$ be the explicit imported
  leaf bidirectional KD/IXIF term of Corollary 4.5.
- Let $`\epsilon_{\mathsf{tr}}^{\mathsf{enc}}`$ and
  $`\epsilon_{\mathsf{tr}}^{\mathsf{ae}}`$ be the explicit imported trunk
  KD/IXIF terms of Corollaries 4.6 and 4.7, respectively, with the
  bidirectional term evaluated at the induced trunk overlap count
  $`L_{\mathsf{tr}}`$.
- By Lemma 7.1 together with the keyed-context discipline of Lemma 4.1, the
  only additional explicit integrity failures beyond these imported KD/IXIF
  terms are the event that a fresh leaf tag matches some previously exposed
  leaf tag on the same keyed path, contributing at most
  $`2^{-t_{\mathsf{leaf}}}`$ per final forgery candidate, and the final trunk-
  tag guessing event, contributing at most $`2^{-\tau}`$ per final forgery
  candidate.
- Let $`\epsilon_{\mathsf{lw}}^{\flat}(\ell,N)`$ be the explicit leaf
  flat-duplex term of Section 4.9.
- Let $`\mathrm{Sponge}^{(i)}_{\mathsf{forest}}`$ be the explicit rooted-forest
  sponge term of Lemma 4.8.

### 5.1 IND-CPA Theorem

**Theorem 5.1 (IND-CPA).** Assume $`\sigma^{\mathsf{tr}}_e + N \le 0.1 \cdot
2^c`$ and $`\sigma^{\mathsf{leaf}}_e + N \le 0.1 \cdot 2^c`$. Then for every
per-user nonce-respecting IND-CPA adversary $`\mathcal{A}`$ against the
$`\mu`$-user TreeWrap experiment,

```math
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cpa}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\epsilon_{\mathsf{tr}}^{\mathsf{enc}}(\mu,q^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_e,N)
+
\epsilon_{\mathsf{leaf}}^{\mathsf{enc}}(\mu,\chi_{\mathsf{leaf},e},\sigma^{\mathsf{leaf}}_e,N).
```

Equivalently, in the low-total-complexity regime inherited from [Men23],
TreeWrap privacy reduces to the direct trunk KD/IXIF replacement of Corollary
4.6 together with the reduced leaf KD/IXIF replacement of Corollary 4.4. The
trunk term governs the entire $`n = 0`$ path, the entire $`n = 1`$ path, and
the first-chunk prefix of every longer message; the leaf term is charged only
for chunks $`i \ge 1`$ and therefore vanishes identically on messages of at
most one chunk.

### 5.2 INT-CTXT Theorem

**Theorem 5.2 (INT-CTXT).** Assume $`\sigma^{\mathsf{tr}}_e +
\sigma^{\mathsf{tr}}_d + N \le 0.1 \cdot 2^c`$ and $`\sigma^{\mathsf{leaf}}_e +
\sigma^{\mathsf{leaf}}_d + N \le 0.1 \cdot 2^c`$. Then for every per-user
nonce-respecting multi-forgery INT-CTXT adversary $`\mathcal{A}`$ against the
$`\mu`$-user TreeWrap experiment outputting at most $`q_f`$ final forgery
candidates,

```math
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,L_{\mathsf{tr}},N)
+
\epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,N)
+
\frac{q_f}{2^{t_{\mathsf{leaf}}}}
+
\frac{q_f}{2^{\tau}}.
```

The explicit $`2^{-t_{\mathsf{leaf}}}`$ tail appears only when a fresh later
chunk induces a hidden leaf tag collision. Every $`n = 0`$ or $`n = 1`$ forgery
is governed entirely by the trunk term and the final $`2^{-\tau}`$ trunk-tag
guess.

### 5.3 IND-CCA2 Theorem

**Theorem 5.3 (IND-CCA2).** Let $`\mathcal{A}`$ be a per-user nonce-respecting
IND-CCA2 adversary against the $`\mu`$-user TreeWrap experiment making at most
$`q_d`$ decryption queries. Then there exist an IND-CPA adversary
$`\mathcal{B}_1`$ and two INT-CTXT adversaries $`\mathcal{B}_{2,0}`$ and
$`\mathcal{B}_{2,1}`$ such that

```math
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cca2}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cpa}}_{\mathsf{TreeWrap}}(\mathcal{B}_1)
+
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{B}_{2,0})
+
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{B}_{2,1}).
```

The reduction preserves the left-right and primitive-query transcripts exactly:
$`\mathcal{B}_1`$ forwards all left-right and primitive queries of
$`\mathcal{A}`$ unchanged and answers decryption queries locally with $`\bot`$,
while each $`\mathcal{B}_{2,b}`$ forwards world-$`b`$ encryptions, answers
decryption queries locally with $`\bot`$, and records all fresh decryption
queries of $`\mathcal{A}`$ as its final INT-CTXT forgery set. Thus the
encryption-side lower-level resources of the reductions are exactly those
induced by the left-right transcript of $`\mathcal{A}`$, the primitive-query
count remains $`N`$, and the only additional overhead is linear-time
bookkeeping in the number of wrapper-oracle queries.

In particular, under the side conditions of Theorems 5.1 and 5.2 and using the
aggregate decryption-side resources of $`\mathcal{A}`$ as the corresponding
decryption-side resources of each INT-CTXT reduction,

```math
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cca2}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\epsilon_{\mathsf{tr}}^{\mathsf{enc}}(\mu,q^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_e,N)
+
\epsilon_{\mathsf{leaf}}^{\mathsf{enc}}(\mu,\chi_{\mathsf{leaf},e},\sigma^{\mathsf{leaf}}_e,N)
+
2 \cdot \epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,L_{\mathsf{tr}},N)
+
2 \cdot \epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,N)
+
\frac{2 q_d}{2^{t_{\mathsf{leaf}}}}
+
\frac{2 q_d}{2^{\tau}},
```

with the resource parameters inherited from the reductions as described above.

The multi-forgery INT-CTXT formulation of Section 4.2 removes the old
index-guessing loss from the IND-CCA2 reduction. The remaining factor $`2`$
comes from the need to bound the bad-decryption event in both challenge
branches $`b = 0`$ and $`b = 1`$ when converting the CCA distinguishing gap to
the CPA gap plus integrity failure probabilities. This factor is not a
bit-guessing loss: replacing $`\mathcal{B}_{2,0}`$ and $`\mathcal{B}_{2,1}`$ by
a single reduction with a hidden random bit would recover only the average of
the two bad-event probabilities and would therefore reintroduce the same factor
$`2`$ when translated back to the absolute distinguishing gap.

### 5.4 CMT-4 Theorem

**Theorem 5.4 (CMT-4).** Let

```math
\Theta := ((K_1,U_1,A_1,P_1),(K_2,U_2,A_2,P_2))
```

be any fixed distinct output pair in the support of a CMT-4 adversary's output
distribution. If $`|P_1| \ne |P_2|`$, then the corresponding collision
probability is zero because TreeWrap is length preserving. Otherwise let $`n :=
\chi(P_1) = \chi(P_2)`$, let

```math
P_\nu = P_{\nu,0} \| \cdots \| P_{\nu,n-1},
\qquad
\nu \in \{1,2\},
```

be the canonical chunk decompositions, let $`\rho := |\{(K_1,U_1),(K_2,U_2)\}|
\in \{1,2\}`$, and define the induced leaf-tag suffixes

```math
\Sigma_\nu
:=
\begin{cases}
\epsilon, & \text{if } n \le 1,\\
T_{\nu,1} \| \cdots \| T_{\nu,n-1}, & \text{if } n \ge 2,
\end{cases}
```

where $`T_{\nu,j}`$ is the hidden leaf tag produced by the $`\nu`$-th tuple at
remaining chunk index $`j \ge 1`$. Set

```math
\epsilon_{\mathsf{leaf}}^{\mathsf{first}}(\Theta,N)
:=
\begin{cases}
\epsilon_{\mathsf{lw}}^{\flat}(|P_{1,j^\star}|,N), & \text{if } j^\star := \min\{j \ge 1 : (K_1,\mathsf{iv}(U_1,j),P_{1,j}) \ne (K_2,\mathsf{iv}(U_2,j),P_{2,j})\} \text{ exists},\\
0, & \text{otherwise}.
\end{cases}
```

Thus the leaf term is charged only for the first differing remaining chunk
$`j^\star \ge 1`$, and vanishes identically when $`n \le 1`$ or when all leaf
local inputs agree. For the trunk-local term, define

```math
M_{\mathsf{tr}}^{\flat}(\Theta,N)
:=
N + \sigma_{\mathsf{tr}}(A_1,P_1) + \sigma_{\mathsf{tr}}(A_2,P_2),
```

```math
\delta_{\mathsf{tr}}(\Theta)
:=
\begin{cases}
2^{-\tau}, & \text{if } n = 0,\\
2^{-(|Y_0|+\tau)}, & \text{if } n \ge 1,
\end{cases}
```

```math
\epsilon_{\mathsf{tr}}^{\mathsf{flat}}(\Theta,N)
:=
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{tr}}^{\flat}(\Theta,N),\rho)
+
\delta_{\mathsf{tr}}(\Theta).
```

Assume $`M_{\mathsf{tr}}^{\flat}(\Theta,N) < 2^c`$ and, when
$`\epsilon_{\mathsf{leaf}}^{\mathsf{first}}(\Theta,N) \ne 0`$, assume also
$`M_{\mathsf{lw}}(|P_{1,j^\star}|,N) < 2^c`$. Then, for every fixed output pair
$`\Theta`$ and every realized prior transcript of the adversary's primitive and
wrapper-oracle queries consistent with $`\Theta`$, the conditional collision
probability over the remaining random permutation choices satisfies

```math
\Pr\!\bigl[\mathsf{TreeWrap}_p.\mathsf{ENC}(K_1,U_1,A_1,P_1)=\mathsf{TreeWrap}_p.\mathsf{ENC}(K_2,U_2,A_2,P_2)\bigr]
\le
\epsilon_{\mathsf{tr}}^{\mathsf{flat}}(\Theta,N)
+
\epsilon_{\mathsf{leaf}}^{\mathsf{first}}(\Theta,N).
```

Equivalently, for every fixed output profile $`\Theta`$ and every fixed prior
transcript, the corresponding TreeWrap commitment collision probability reduces
either to a leaf collision on the full local output pair $`(Y_j,T_j)`$ at the
first differing remaining chunk or to a collision on the observed trunk-local
output. The same pointwise estimate therefore remains valid after conditioning
on the adversary's adaptively generated prior transcript, because Lemma 4.8 and
Section 4.9 bound bad rooted extensions relative to the already exposed rooted
nodes and full states. Consequently, if $`\Theta`$ denotes the random realized
output pair of a CMT-4 adversary $`\mathcal{A}`$, then conditioning first on
the realized prior transcript and then averaging over the joint distribution of
that transcript and $`\Theta`$ gives

```math
\mathrm{Adv}^{\mathsf{cmt}\text{-}4}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\mathbb{E}_{\Theta}\!\left[
\epsilon_{\mathsf{tr}}^{\mathsf{flat}}(\Theta,N)
+
\epsilon_{\mathsf{leaf}}^{\mathsf{first}}(\Theta,N)
\right],
```

with the convention that the bracketed quantity is $`0`$ when $`|P_1| \ne
|P_2|`$.

## 6. Imported AE Sketches

This section contains proof sketches for the authenticated-encryption path. The
keyed-duplex and BN00 machinery is imported rather than reproved here: the goal
is to isolate how TreeWrap fits the [Men23] framework and how the resulting
hybrid arguments compose. The genuinely TreeWrap-specific arguments are
deferred to Section 7.

### 6.1 Imported Leaf and Trunk Adaptations

The leaf analysis identifies $`\mathsf{LeafWrap}`$ with the reduced
MonkeySpongeWrap transcript obtained by excising the vacuous local
associated-data phase, and then imports the corresponding KD/IXIF replacement
from [Men23]. The trunk transcript is handled directly as a keyed-duplex family
under the keyed contexts $`(\delta,\mathsf{iv}(U,0))`$ and therefore uses
Corollary 4.6 without any additional reduction.

Let $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}_{\mathsf{leaf}}]`$ denote
the same leaf transcript as $`\mathsf{LeafWrap}[p]`$, but with the keyed duplex
$`\mathsf{KD}[p]`$ replaced by the ideal interface
$`\mathsf{IXIF}[\mathrm{ro}_{\mathsf{leaf}}]`$ of Section 2.3.2. Thus

```math
\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}_{\mathsf{leaf}}](K,V,X,m) \to (Y,T)
```

has exactly the same padding, framing bits, mode flag, and output convention as
$`\mathsf{LeafWrap}[p]`$; only the transcript engine changes.

For later use, write the framed full-state blocks of a leaf call as

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

to the path before the tag-squeezing calls. The key decryption-side identity is
that if a decryption-side body block $`\widetilde{Y}_j`$ yields IXIF output
$`\widetilde{Z}_j`$ and recovered plaintext block $`\widetilde{X}_j =
\widetilde{Y}_j \oplus \widetilde{Z}_j`$, then the IXIF path update is

```math
[\mathsf{true}] \cdot (\widetilde{Z}_j \| 0^{b-r}) \oplus (\widetilde{Y}_j \| 1 \| 0^{c-1})
=
\widetilde{X}_j \| 1 \| 0^{c-1}
=
M_j(X).
```

Hence encryption-side and decryption-side leaf calls append the same framed
message blocks precisely when they induce the same recovered plaintext
transcript. The imported support is summarized by the following two statements.

**Lemma 6.1 (Leaf / Reduced MonkeySpongeWrap Transcript Correspondence).** Fix
parameters $`p,b,r,c,k,t_{\mathsf{leaf}}`$. For any inputs $`K`$, $`V`$, and
$`X`$, the keyed-duplex transcript of

```math
\mathsf{LeafWrap}[p](K,V,X,m)
```

with initialization

```math
\mathsf{KD.init}(1,V)
```

is identical to the reduced MonkeySpongeWrap transcript on nonce $`V`$ and
input string $`X`$ obtained by excising the vacuous local associated-data
phase, with the middle phase parameterized by $`m`$. Thus $`m = \mathsf{enc}`$
gives the reduced encryption transcript, $`m = \mathsf{dec}`$ gives the
corresponding reduced decryption-side transcript with overwrite enabled in the
middle phase, and the returned pair $`(Y,T)`$ is exactly the body/tag pair
determined by that reduced transcript.

This excision does not alter the structural preconditions used by [Men23]:
every reduced leaf transcript still makes at least one padded body call after
initialization, even when $`X = \epsilon`$, and at least one subsequent squeeze
call because $`t_{\mathsf{leaf}} > 0`$ implies $`s_{\mathsf{leaf}} \ge 1`$.

**Theorem 6.2 (Ported Leaf KD/IXIF Replacement).** For every distinguisher
$`\mathcal{D}_{\mathsf{LW}}`$ attacking a family of leaf transcripts under the
keyed-context discipline induced by TreeWrap, there exists a distinguisher
$`\mathcal{D}_{\mathsf{MSW}}`$ against the corresponding reduced
MonkeySpongeWrap transcript family such that

```math
\mathrm{Adv}^{\mathsf{real}\text{-}\mathsf{ixif}}_{\mathsf{LeafWrap}}(\mathcal{D}_{\mathsf{LW}})
=
\mathrm{Adv}^{\mathsf{real}\text{-}\mathsf{ixif}}_{\mathsf{MonkeySpongeWrap}}(\mathcal{D}_{\mathsf{MSW}}),
```

with matching transcript resources after interpreting each leaf call as the
corresponding reduced MonkeySpongeWrap call on the same leaf IV $`V`$.
Consequently, the leaf real-to-IXIF replacement is bounded by the corresponding
KD/IXIF term imported from [Men23], with the unused local associated-data
resources deleted from the accounting. In TreeWrap, the relevant keyed contexts
are $`(\delta,V_i)`$ with $`V_i = \mathsf{iv}(U,i)`$ and $`i \ge 1`$.

For the trunk layer, let
$`\mathsf{TrunkWrap}^{\mathsf{IXIF}}[\mathrm{ro}_{\mathsf{tr}}]`$ denote the
same transcript as $`\mathsf{TrunkWrap}[p]`$, but with the keyed duplex
replaced by $`\mathsf{IXIF}[\mathrm{ro}_{\mathsf{tr}}]`$. A trunk evaluation in
this ideal world still consists of an optional absorb phase on $`A \|
\lambda_{\mathsf{ad}}`$, an optional first-chunk body phase on $`X_0`$, an
optional absorb phase on $`T_1 \| \cdots \| T_m \| \lambda_{\mathsf{tc}}`$, and
one final squeeze phase. Because this is already a keyed-duplex family under
the contexts $`(\delta,\mathsf{iv}(U,0))`$, Corollaries 4.6 and 4.7 apply
directly in the encryption-only and bidirectional settings, respectively. These
imported statements are the only ingredients used in the AE sketches below,
together with the TreeWrap-specific freshness lemma of Section 7.1.

The leaf and trunk ideal families use independent random oracles
$`\mathrm{ro}_{\mathsf{leaf}}`$ and $`\mathrm{ro}_{\mathsf{tr}}`$, so the two
replacements do not share an ideal transcript engine. Throughout Sections 6.2
and 6.3, the imported duplex bounds are used exactly in the form fixed in
Section 4.6, namely the $`\mu`$-user, low-complexity branch of [Men23]. The two
KD/IXIF hops compose sequentially because the leaf and trunk layers are
distinct keyed-duplex families under separate IV namespaces, and their ideal
replacements are driven by independent random oracles. In the leaf hop, a leaf
distinguisher forwards leaf calls to its own oracle while evaluating the trunk
internally via $`p`$; the trunk is identical in both worlds and contributes no
gap. In the trunk hop, a trunk distinguisher has
$`\mathrm{ro}_{\mathsf{leaf}}`$ hardwired and evaluates the already-idealized
leaf family internally to obtain the leaf tags, then feeds those tags as
ordinary inputs to its trunk oracle. Because $`\mathrm{ro}_{\mathsf{leaf}}`$ is
independent of both $`p`$ and $`\mathrm{ro}_{\mathsf{tr}}`$, the leaf tags are
deterministic functions of $`\mathrm{ro}_{\mathsf{leaf}}`$ and the query
inputs, and are therefore fixed values from the trunk oracle's perspective. The
imported trunk bound (Corollary 4.6 or 4.7) thus holds for every fixed
realization of $`\mathrm{ro}_{\mathsf{leaf}}`$, and hence also in expectation.
In the bidirectional setting, decryption-side leaf calls are likewise evaluated
internally via $`\mathrm{ro}_{\mathsf{leaf}}`$ before the resulting trunk query
is forwarded; the Men23 bound permits the distinguisher arbitrary internal
computation, so this does not violate any precondition of Corollary 4.7.

### 6.2 IND-CPA Sketch

Fix a per-user nonce-respecting IND-CPA adversary $`\mathcal{A}`$, and for each
challenge bit $`b \in \{0,1\}`$ define the following three games. In all three
games, $`\mathcal{A}`$ additionally retains primitive access to $`p`$ and
$`p^{-1}`$.

- $`H_0^b`$ is the real IND-CPA experiment.
- $`H_1^b`$ is obtained from $`H_0^b`$ by replacing, for each encryption
  query $`(\delta,U,A,P_0,P_1)`$, every leaf call on chunks
  $`i \ge 1`$ by $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}_{\mathsf{leaf}}]`$ under the
  derived keyed contexts $`(\delta,V_i)`$ with
  $`V_i = \mathsf{iv}(U,i)`$, while keeping the trunk transcript real.
- $`H_2^b`$ is obtained from $`H_1^b`$ by replacing the trunk evaluation

  ```math
  \mathsf{TrunkWrap}[p](K[\delta], \mathsf{iv}(U,0), A, P_{b,0}, T_1, \ldots, T_{n-1})
  ```

  by $`\mathsf{TrunkWrap}^{\mathsf{IXIF}}[\mathrm{ro}_{\mathsf{tr}}]`$ on the same keyed
  context and transcript inputs.

For the first hop, Lemma 4.1 shows that a per-user nonce-respecting TreeWrap
adversary induces a nonce-respecting family of leaf encryption queries, so
Corollary 4.4 applies. Thus the first replacement changes the overall
left-right distinguishing gap by at most

```math
\epsilon_{\mathsf{leaf}}^{\mathsf{enc}}(\mu,\chi_{\mathsf{leaf},e},\sigma^{\mathsf{leaf}}_e,N).
```

For the second hop, Corollary 4.6 applies to the trunk family, so the second
replacement changes the overall left-right distinguishing gap by at most

```math
\epsilon_{\mathsf{tr}}^{\mathsf{enc}}(\mu,q^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_e,N).
```

It remains to analyze $`H_2^b`$. In this game:

- the trunk keyed context is always $`(\delta,\mathsf{iv}(U,0))`$;
- the leaf keyed contexts are
  $`(\delta,\mathsf{iv}(U,j))`$ for $`j \ge 1`$;
- per-user nonce respect and injectivity of $`\mathsf{iv}`$ ensure that every
  encryption query occurs on fresh keyed paths inside these two families.

Hence the IXIF outputs seen by the adversary are independent of the challenge
bit except through public lengths and message structure. More explicitly, every
fresh body-phase IXIF path returns an independent uniform $`r`$-bit string, so
each ciphertext body block is obtained by XORing the corresponding plaintext
block with a fresh uniform mask. Thus the visible body chunks reveal only their
public lengths and chunk structure, not the challenge bit. Likewise, every
fresh squeeze path returns an independent uniform string, so the final trunk
tag is uniformly distributed on its fresh path. Concretely:

- for $`n = 0`$, the game consists only of a fresh trunk tag path;
- for $`n = 1`$, it consists of fresh trunk body masks followed by a fresh
  trunk tag path;
- for $`n > 1`$, it consists of those trunk paths together with independent
  fresh leaf body masks and fresh leaf tag paths.

The ideal leaf oracle $`\mathrm{ro}_{\mathsf{leaf}}`$ and the ideal trunk
oracle $`\mathrm{ro}_{\mathsf{tr}}`$ are sampled independently of the real
permutation $`p`$ and independently of one another, so the primitive transcript
is unchanged across the hybrids and remains shared between $`H_2^0`$ and
$`H_2^1`$. This independence is load-bearing: without it, the primitive oracle
or a shared ideal transcript engine could couple the two final games.
Consequently, the entire view of $`\mathcal{A}`$ in $`H_2^0`$ and $`H_2^1`$ is
identical up to public lengths, and therefore

```math
\Pr[H_2^1(\mathcal{A}) = 1] = \Pr[H_2^0(\mathcal{A}) = 1].
```

Combining this final equality with the two distinguishing-gap bounds above
yields Theorem 5.1.

### 6.3 INT-CTXT Sketch

Fix a per-user nonce-respecting INT-CTXT adversary $`\mathcal{A}`$, and define
three games. In all three games, $`\mathcal{A}`$ additionally retains primitive
access to $`p`$ and $`p^{-1}`$.

- $`H_0`$ is the real INT-CTXT experiment.
- $`H_1`$ is obtained from $`H_0`$ by replacing, for each wrapper query with
  user index $`\delta`$ and nonce $`U`$, every leaf encryption-side and
  decryption-side call by $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}_{\mathsf{leaf}}]`$
  under the keyed contexts $`(\delta,\mathsf{iv}(U,j))`$ with $`j \ge 1`$,
  while keeping the trunk transcript real.
- $`H_2`$ is obtained from $`H_1`$ by replacing every trunk evaluation by
  $`\mathsf{TrunkWrap}^{\mathsf{IXIF}}[\mathrm{ro}_{\mathsf{tr}}]`$ on the same trunk keyed
  context and transcript inputs, both on encryption and on decryption-side
  recomputation.

For the first hop, Lemma 4.1 gives the required keyed-context discipline at the
leaf layer, and Corollary 4.5 therefore yields

```math
\left| \Pr[H_0(\mathcal{A}) = 1] - \Pr[H_1(\mathcal{A}) = 1] \right|
\le
\epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,N).
```

For the second hop, Corollary 4.7 yields

```math
\left| \Pr[H_1(\mathcal{A}) = 1] - \Pr[H_2(\mathcal{A}) = 1] \right|
\le
\epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,L_{\mathsf{tr}},N).
```

It remains to bound the forgery probability in $`H_2`$. Let

```math
F = \bigl\{(\delta^{(1)},U^{(1)},A^{(1)},C^{(1)}),\ldots,(\delta^{(q_f)},U^{(q_f)},A^{(q_f)},C^{(q_f)})\bigr\}
```

denote the final forgery set output by $`\mathcal{A}`$, and for each $`d \in
[1,q_f]`$ write

```math
C^{(d)} = Y^{(d)} \| T^{(d)}.
```

For each candidate, the TreeWrap-specific freshness split of Lemma 7.1 yields
exactly one of the following branches.

- If $`n = 0`$, freshness means that the associated-data transcript in the
  trunk keyed context is fresh, so the adversary must guess a fresh
  $`\tau`$-bit trunk tag.
- If $`n = 1`$, the candidate either induces a fresh trunk prefix
  $`(A,X_0)`$ in the trunk keyed context, in which case the adversary must
  again guess the final trunk tag, or it is a replay.
- If $`n > 1`$, either the trunk prefix is fresh, or some leaf is fresh,
  or every keyed subtranscript replays. In the fresh trunk-prefix branch the
  final trunk squeeze path is fresh, costing $`2^{-\tau}`$. In the fresh
  leaf branch, either a hidden leaf tag collision occurs, costing
  at most $`2^{-t_{\mathsf{leaf}}}`$, or the absorbed leaf-tag phase of the
  trunk transcript is fresh, so the adversary must again guess the final tag,
  costing $`2^{-\tau}`$. In the replay branch, the candidate cannot witness
  freshness.

Therefore, for each fixed $`d`$,

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

Fix a per-user nonce-respecting IND-CCA2 adversary $`\mathcal{A}`$, and for
each bit $`b \in \{0,1\}`$ let $`G_b`$ denote the game obtained from the real
IND-CCA2 experiment by answering every decryption query with $`\bot`$ while
leaving the left-right and primitive oracles unchanged. Up to the first
accepting fresh decryption query, the games
$`\mathrm{IND}\text{-}\mathrm{CCA2}^{\mathsf{TreeWrap}}_b`$ and $`G_b`$ are
identical. Hence, by the standard game-hopping argument of [BN00],

```math
\left|
\Pr[(\mathrm{IND}\text{-}\mathrm{CCA2})^{\mathsf{TreeWrap}}_b(\mathcal{A}) = 1]
-
\Pr[G_b(\mathcal{A}) = 1]
\right|
\le
\Pr[\mathsf{Bad}_b],
```

where $`\mathsf{Bad}_b`$ is the event that $`\mathcal{A}`$ submits some fresh
ciphertext to the decryption oracle that would be accepted in the real
bit-$`b`$ experiment.

The game pair $`G_0,G_1`$ is exactly an IND-CPA experiment with a dummy
decryption oracle. Therefore there is an IND-CPA adversary $`\mathcal{B}_1`$
that forwards all left-right and primitive queries of $`\mathcal{A}`$ unchanged
and answers decryption queries locally with $`\bot`$, such that

```math
\Pr[G_b(\mathcal{A}) = 1]
=
\Pr[(\mathrm{IND}\text{-}\mathrm{CPA})^{\mathsf{TreeWrap}}_b(\mathcal{B}_1) = 1]
```

for each $`b`$. This reduction preserves the entire left-right transcript and
the primitive-query transcript exactly, so it preserves $`q_e`$, $`N`$, and the
induced encryption-side lower-level resources.

It remains to bound $`\Pr[\mathsf{Bad}_b]`$. Define an INT-CTXT adversary
$`\mathcal{B}_{2,b}`$ as follows:

- on a left-right query $`(\delta,U,A,P_0,P_1)`$ from $`\mathcal{A}`$,
  forward the encryption query $`(\delta,U,A,P_b)`$ to the INT-CTXT
  encryption oracle and return the result;
- forward every primitive query of $`\mathcal{A}`$ unchanged;
- answer every decryption query of $`\mathcal{A}`$ locally with $`\bot`$;
- record every fresh decryption query $`(\delta,U,A,C)`$ of $`\mathcal{A}`$
  and output the set of all such recorded queries as the final INT-CTXT
  forgery set.

This simulation is exactly the dead-decryption game $`G_b`$. If
$`\mathsf{Bad}_b`$ occurs, then some fresh decryption query made by
$`\mathcal{A}`$ is accepted in the real bit-$`b`$ experiment, and therefore the
final forgery set output by $`\mathcal{B}_{2,b}`$ contains a valid INT-CTXT
forgery. Hence

```math
\Pr[\mathsf{Bad}_b]
\le
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{B}_{2,b}).
```

This use of INT-CTXT is compatible with Section 4.2 because the multi-forgery
experiment permits the adversary to interact adaptively with its encryption and
primitive oracles before outputting the final set $`F`$.

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

which is Theorem 5.3. Substituting Theorems 5.1 and 5.2 with the inherited
resource bounds gives the displayed instantiated IND-CCA2 bound.

## 7. TreeWrap Proofs

This section contains the TreeWrap-specific arguments: the authenticity
freshness split needed for the AE path and the public-permutation commitment
analysis.

### 7.1 Authenticity Freshness Split

**Lemma 7.1 (TreeWrap Authenticity Freshness Split).** Fix any final IXIF game
obtained after replacing the real trunk and leaf families by their IXIF
counterparts. Let $`(Y,T)`$ be any valid fresh forgery candidate, and let $`Y =
Y_0 \| \cdots \| Y_{n-1}`$ be its canonical chunk decomposition. Then exactly
one of the following cases holds.

1. **Fresh trunk transcript.**
   Either $`n = 0`$ and the associated-data string $`A`$ is fresh in the trunk
   keyed context $`(\delta,\mathsf{iv}(U,0))`$, or $`n \ge 1`$ and the trunk
   prefix $`(A,X_0)`$ is fresh in that keyed context. Then the final trunk
   squeeze path is fresh, so the adversary must predict a fresh $`\tau`$-bit
   trunk tag, costing $`2^{-\tau}`$.

2. **Fresh leaf.**
   Some remaining chunk $`X_j`$ with $`j \ge 1`$ is fresh in its keyed context
   $`(\delta,\mathsf{iv}(U,j))`$. Then either its hidden leaf tag
   matches some previously exposed leaf tag for that transcript path,
   costing at most $`2^{-t_{\mathsf{leaf}}}`$, or the leaf-tag absorb phase
   of the trunk transcript is fresh, so the adversary must again predict a
   fresh $`\tau`$-bit trunk tag, costing $`2^{-\tau}`$.

3. **Replay.**
   The trunk transcript and every leaf transcript replay a prior
   encryption in the same keyed contexts, in which case the candidate is a
   replay and cannot witness freshness.

Consequently, a union bound over at most $`q_f`$ final candidates contributes
the explicit tail

```math
\frac{q_f}{2^{t_{\mathsf{leaf}}}} + \frac{q_f}{2^{\tau}}.
```

**Proof.** Fix one final forgery candidate and compare it against the set of
prior encryption transcripts in the same keyed contexts. There are two keyed
families to inspect:

- the trunk keyed context $`(\delta,\mathsf{iv}(U,0))`$, whose transcript
  consists of the optional AD phase, the optional first-chunk body phase, the
  optional leaf-tag absorb phase, and the final squeeze phase;
- the leaf keyed contexts $`(\delta,\mathsf{iv}(U,j))`$ for $`j \ge 1`$.

If $`n = 0`$, freshness means exactly that the associated-data transcript in
the trunk keyed context is fresh. Then the final trunk squeeze path is fresh in
IXIF and the adversary must guess the $`\tau`$-bit final tag.

Assume now $`n \ge 1`$. If the trunk prefix $`(A,X_0)`$ is fresh in the trunk
keyed context, then the trunk transcript diverges before its final squeeze
phase, so every later trunk path is fresh and the adversary again has only a
$`2^{-\tau}`$ chance of guessing the final tag.

Otherwise the trunk prefix replays a prior transcript in the same keyed
context. If some remaining chunk $`X_j`$ is fresh in its own keyed context
$`(\delta,\mathsf{iv}(U,j))`$, then the corresponding leaf IXIF path is fresh
at the first divergent body block or at the first position where the padded
lengths differ. In more detail, if $`\pi_t`$ denotes the leaf path after $`t`$
body calls, then the first divergence occurs either because a framed body block
$`M_t(X_j)`$ differs from every prior framed block with the same prefix, or
because one transcript reaches its padding block before the other. In either
case the differing padded block itself witnesses freshness of the next path,
and freshness then propagates to all later extensions by the prefix property of
IXIF paths. Hence the hidden leaf tag $`T_j`$ is uniform on a fresh IXIF
squeeze path. By per-user nonce-respecting behavior and the keyed-context
discipline of Lemma 4.1, at most one prior encryption query produced a leaf tag
under the same keyed context $`(\delta,\mathsf{iv}(U,j))`$, and the INT-CTXT
experiment exposes no decryption-side leaf tags to the adversary. Therefore the
collision target set has size at most one, and $`T_j`$ collides with the single
previously exposed leaf tag with probability at most
$`2^{-t_{\mathsf{leaf}}}`$. On the complement of that collision event, the
absorbed leaf-tag phase of the trunk transcript differs at or before the first
block containing $`T_j`$, so the final trunk squeeze path is fresh and the
adversary must still guess the final tag, costing $`2^{-\tau}`$.

If neither the trunk prefix nor any leaf is fresh, then every keyed
subtranscript replays a prior encryption exactly. The whole candidate is then a
replay and cannot witness freshness. Applying a union bound over the at most
$`q_f`$ final candidates gives the displayed tail.

### 7.2 Leaf Flat Collision Bound

For the leaf part of the public-permutation commitment analysis, write

```math
\mathsf{LeafWrap}^{\flat}[p](K,V,X)
```

for the encryption-side leaf transcript viewed in the flat model: the
initialization is determined by the tuple $`(K,V)`$, the padded message blocks
are embedded as the framed full-state blocks

```math
M_j(X) := \widetilde{X}_j \| 1 \| 0^{c-1},
```

and the output pair $`(Y,T)`$ is obtained from the resulting sequence of duplex
squeezes exactly as in encryption-mode LeafWrap.

**Lemma 7.2 (Leaf Flat Collision Bound).** Consider two encryption-side leaf
inputs

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

let $`\ell := |Y|`$ and assume $`M_{\mathsf{lw}}(\ell,N) < 2^c`$. Then either
the two flattened local transcripts collide under the duplexing-sponge
reduction of [BDPVA11] in the presence of at most $`N`$ primitive queries, or
two distinct ideal local transcript histories produce the same full local
output pair $`(Y,T)`$. By Section 4.9, the first event is bounded by

```math
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{lw}}(\ell,N),2),
```

and the second contributes the residual ideal-output collision term

```math
2^{-(\ell+t_{\mathsf{leaf}})}.
```

Hence

```math
\Pr[\text{local collision on an }\ell\text{-bit remaining chunk}]
\le
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{lw}}(\ell,N),2)
+
2^{-(\ell+t_{\mathsf{leaf}})}
=
\epsilon_{\mathsf{lw}}^{\flat}(\ell,N).
```

**Proof.** This is exactly the encryption-side flat-duplex argument already
used in Section 4.9, now restricted to chunks $`j \ge 1`$. The duplexing-sponge
identity of [BDPVA11] is purely structural, so it applies in the
public-permutation setting regardless of how the adversary chooses keys,
derived leaf IVs, or the bodies of those chunks. The resulting rooted-sponge
bad event is bounded by the explicit leaf term of Section 4.9, and the residual
ideal collision probability is the full-output term
$`2^{-(\ell+t_{\mathsf{leaf}})}`$.

### 7.3 Flat TrunkWrap Collision Bound

Let

```math
\mathsf{TrunkWrap}^{\flat}[p](K,U,A,P_0,\Sigma)
```

denote the trunk-local encryption transcript viewed in the flattened sponge
model: the keyed initialization is determined by $`(K,\mathsf{iv}(U,0))`$, the
absorbed transcript consists of an optional associated-data phase on $`A \|
\lambda_{\mathsf{ad}}`$, an optional first-chunk body phase on $`P_0`$ using
the same body framing as $`\mathsf{LeafWrap}`$, an optional leaf-tag phase on
$`\Sigma \| \lambda_{\mathsf{tc}}`$, and a final squeeze phase. Its observed
output is $`T`$ when $`P_0 = \epsilon`$ and the pair $`(Y_0,T)`$ when $`P_0 \ne
\epsilon`$.

**Lemma 7.3 (Flat TrunkWrap Collision Bound).** Let $`\Theta`$ be as in Theorem
5.4, and extract $`n`$, $`\Sigma_\nu`$, and $`\delta_{\mathsf{tr}}(\Theta)`$
exactly as there. Let

```math
\Xi_\nu
:=
\begin{cases}
(K_\nu,U_\nu,A_\nu,\epsilon,\epsilon), & \text{if } n = 0,\\
(K_\nu,U_\nu,A_\nu,P_{\nu,0},\Sigma_\nu), & \text{if } n \ge 1,
\end{cases}
\qquad
\nu \in \{1,2\},
```

and assume $`\Xi_1 \ne \Xi_2`$. If

```math
\mathsf{TrunkWrap}^{\flat}[p](\Xi_1)
=
\mathsf{TrunkWrap}^{\flat}[p](\Xi_2)
```

on the observed trunk output, let

```math
\rho := |\{(K_1,U_1),(K_2,U_2)\}| \in \{1,2\},
```

let

```math
M_{\mathsf{tr}}^{\flat}(\Theta,N)
:=
N + \sigma_{\mathsf{tr}}(A_1,P_1) + \sigma_{\mathsf{tr}}(A_2,P_2),
```

and assume $`M_{\mathsf{tr}}^{\flat}(\Theta,N) < 2^c`$. Then

```math
\Pr[\mathsf{TrunkWrap}^{\flat}[p](\Xi_1)=\mathsf{TrunkWrap}^{\flat}[p](\Xi_2)]
\le
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{tr}}^{\flat}(\Theta,N),\rho)
+
\delta_{\mathsf{tr}}(\Theta)
=
\epsilon_{\mathsf{tr}}^{\mathsf{flat}}(\Theta,N).
```

**Proof.** This is an encryption-only local comparison, so the trunk flat term
is cleaner than the bidirectional AE trunk import. Every encryption-side trunk
call uses flag $`\mathsf{false}`$, including the first-chunk body phase, so the
entire transcript is a serial absorb-then-squeeze duplex history. By the
duplexing-sponge identity of [BDPVA11], flattening this history yields a rooted
sponge transcript with public roots determined by $`(K_1,\mathsf{iv}(U_1,0))`$
and $`(K_2,\mathsf{iv}(U_2,0))`$.

The total number of primitive and flattened transcript calls is bounded by
$`M_{\mathsf{tr}}^{\flat}(\Theta,N)`$, and the number of public roots is
exactly $`\rho`$. Hence Lemma 4.8 bounds the rooted-forest bad event by

```math
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{tr}}^{\flat}(\Theta,N),\rho).
```

Conditioned on the complement of that bad event, distinct trunk-local inputs
yield distinct rooted transcript histories. This injectivity comes from the
combination of root separation through the IV derivation, explicit phase
trailers $`\lambda_{\mathsf{ad}}`$ and $`\lambda_{\mathsf{tc}}`$, and the body
framing $`\widetilde{X}_j \| 1 \| 0^{c-1}`$ that separates the first-chunk body
phase from the absorb-style phases. Therefore a collision on the observed trunk
output can only occur through an ideal-output collision on that observed
output: $`2^{-\tau}`$ when $`n = 0`$, and $`2^{-(|Y_0|+\tau)}`$ when $`n \ge
1`$. This is exactly the term $`\delta_{\mathsf{tr}}(\Theta)`$.

### 7.4 Proof of Theorem 5.4

Let

```math
\mathsf{TreeWrap.ENC}(K, U, A, P) = Y \| T
```

and

```math
\mathsf{TreeWrap.ENC}(K', U', A', P') = Y \| T
```

for two distinct tuples. By canonical chunking, the common ciphertext body
$`Y`$ determines the same chunk sequence $`Y_0,\ldots,Y_{n-1}`$ and hence the
same chunk count $`n`$ in both encryptions.

If $`n = 0`$, there are no leaf evaluations at all, so the collision is purely
a trunk-local collision and Lemma 7.3 gives the claimed bound immediately. If
$`n = 1`$, the whole observed ciphertext is already the observed trunk output
$`(Y_0,T)`$, so Lemma 7.3 again applies directly and the leaf term vanishes.

Assume now $`n > 1`$. First consider the case that the trunk-local prefixes
differ:

```math
(K_1,U_1,A_1,P_{1,0}) \ne (K_2,U_2,A_2,P_{2,0}).
```

Then the corresponding trunk-local inputs $`\Xi_1`$ and $`\Xi_2`$ are distinct
regardless of whether the leaf-tag suffixes $`\Sigma_1`$ and $`\Sigma_2`$
agree. Since the final ciphertexts collide, their observed trunk outputs
collide as well, so Lemma 7.3 bounds this branch by
$`\epsilon_{\mathsf{tr}}^{\mathsf{flat}}(\Theta,N)`$.

It remains to consider the case that the trunk-local prefixes agree, namely

```math
(K_1,U_1,A_1,P_{1,0}) = (K_2,U_2,A_2,P_{2,0}).
```

If there exists a first later index $`j^\star \ge 1`$ such that

```math
(K_1,\mathsf{iv}(U_1,j^\star),P_{1,j^\star})
\ne
(K_2,\mathsf{iv}(U_2,j^\star),P_{2,j^\star}),
```

then there are two subcases.

1. The distinct leaf inputs at position $`j^\star`$ produce the same
   local output pair

   ```math
   (Y_{j^\star},T_{1,j^\star}) = (Y_{j^\star},T_{2,j^\star}).
   ```

   Then Lemma 7.2 applies directly and contributes exactly
   $`\epsilon_{\mathsf{leaf}}^{\mathsf{first}}(\Theta,N)`$.

2. The two local outputs at $`j^\star`$ differ. Because the full ciphertext
   bodies are equal, the common observed body chunk $`Y_{j^\star}`$ is the
   same in both encryptions, so the difference must lie in the hidden
   leaf tags: $`T_{1,j^\star} \ne T_{2,j^\star}`$. Hence the leaf-tag
   suffixes satisfy $`\Sigma_1 \ne \Sigma_2`$, so the trunk-local inputs
   $`\Xi_1`$ and $`\Xi_2`$ are distinct. The common final ciphertext therefore
   implies a collision on distinct observed trunk outputs, which Lemma 7.3
   bounds by $`\epsilon_{\mathsf{tr}}^{\mathsf{flat}}(\Theta,N)`$.

Finally, if no such later index $`j^\star`$ exists, then every leaf input
agrees, the trunk-local prefixes agree by assumption, and therefore all local
inputs agree. Injectivity of the IV derivation then forces $`K_1 = K_2`$, $`U_1
= U_2`$, and $`P_1 = P_2`$, while trunk-prefix equality already gives $`A_1 =
A_2`$, contradicting tuple distinctness. Hence this case cannot occur.

Therefore every successful collision event lies in the union of a trunk-local
collision event bounded by Lemma 7.3 and a first-differing leaf collision event
bounded by Lemma 7.2. Adding these two bounds gives the conditional estimate of
Theorem 5.4, and averaging over the adversary's random output pair yields the
displayed expectation bound on $`\mathrm{Adv}^{\mathsf{cmt}\text{-}4}`$.

## 8. TW128 Instantiation

We instantiate TreeWrap as a concrete octet-oriented scheme $`\mathsf{TW128}`$
based on the twelve-round Keccak permutation from [FIPS202]. The goal of this
instantiation is a 128-bit security target with a 256-bit final tag, a 256-bit
leaf tag, and an empirically tuned chunk size of 8128 bytes. The choice of
$`\mathrm{Keccak\text{-}p}[1600,12]`$ is not novel to TreeWrap: it follows the
software-oriented KangarooTwelve and TurboSHAKE precedent of [K12, RFC9861],
which likewise uses the twelve-round permutation rather than full-round
$`\mathrm{Keccak\text{-}f}[1600]`$. This is the same permutation choice the
Keccak designers are currently advancing for high-speed unkeyed hash and XOF
constructions, i.e. in settings that rely directly on public-permutation
quality rather than on hidden-key assumptions. For TreeWrap, the motivation is
correspondingly pragmatic: strong software throughput together with
straightforward SIMD-friendly parallel implementations on current AMD64 and
ARM64 processors. The chunk size is chosen on the same pragmatic basis: it is
not forced by the proof model, but selected as a concrete software parameter
after backend tuning rather than from permutation-count arithmetic alone.

The parameter choices are:

- permutation: $`p = \mathrm{Keccak\text{-}p}[1600,12]`$;
- width: $`b = 1600`$;
- capacity: $`c = 256`$;
- rate: $`r = 1344`$;
- key length: $`k = 256`$;
- IV space: $`\mathcal{IV} = \{0,1\}^{1344}`$;
- nonce space: $`\mathcal{U} = \{0,1\}^{128}`$;
- chunk size: $`B = 65024`$ bits $`= 8128`$ bytes;
- leaf tag size: $`t_{\mathsf{leaf}} = 256`$;
- final tag size: $`\tau = 256`$;
- associated-data phase trailer: $`\lambda_{\mathsf{ad}} = \mathtt{00}`$;
- leaf-tag phase trailer: $`\lambda_{\mathsf{tc}} = \mathtt{01}`$;
- IV-suffix encoding: $`\nu = \mathrm{right\_encode}`$ from [SP800185].

Although $`\mathrm{right\_encode}`$ is specified on bit strings in [SP800185],
$`\mathsf{TW128}`$ operates on octet strings throughout. Concretely,
$`\mathsf{TW128.ENC}`$ takes a 32-byte key, a 16-byte nonce, an octet-string
associated-data input, and an octet-string plaintext, and returns an
octet-string ciphertext of length $`|P| + 32`$ bytes; $`\mathsf{TW128.DEC}`$
has the corresponding octet-string ciphertext interface. The trunk phase
trailers $`\lambda_{\mathsf{ad}} = \mathtt{00}`$ and $`\lambda_{\mathsf{tc}} =
\mathtt{01}`$ are therefore also interpreted as single octets. This matches the
intended software interface and keeps the framing layer aligned with the
byte-oriented presentation of SP 800-185. For the multi-user AE proofs, the
user index is encoded separately by the fixed-width map $`\mathrm{uid}`$ of
Section 2.3.2 when forming IXIF paths; this is part of the ideal transcript
model only and does not alter the concrete 32-byte key interface of
$`\mathsf{TW128}`$.

The only remaining concrete formatting choice is the embedding of the user
nonce and suffix value into the $`b-k = 1344`$-bit IV field expected by the
keyed duplex. Define the concrete IV-derivation map

```math
\mathsf{iv}^{\mathsf{TW128}} : \mathcal{U} \times \{0,\ldots,2^{1208}-1\} \to \mathcal{IV}
```

by

```math
\mathsf{iv}^{\mathsf{TW128}}(U,j)
:=
0^{1344 - 128 - |\nu(j)|} \| U \| \nu(j),
```

which is well defined exactly for suffix values $`0 \le j \le 2^{1208}-1`$. In
the present design the trunk always uses $`j = 0`$, while leaf calls on chunks
$`i \ge 1`$ use $`j = i`$. Thus

```math
V_{\mathsf{tr}}(U) := \mathsf{iv}^{\mathsf{TW128}}(U,0),
\qquad
V_i(U) := \mathsf{iv}^{\mathsf{TW128}}(U,i)
\quad\text{for } i \ge 1.
```

Because the nonce length is fixed and $`\nu = \mathrm{right\_encode}`$ is
injective, this yields an injective embedding of the trunk and leaf IV
namespaces into the 1344-bit IV field. The resulting size bound is not
restrictive in practice: it allows up to $`2^{1208}`$ distinct suffix values,
far beyond any realistic number of chunks. Outside this range the concrete IV
embedding is undefined, so $`\mathsf{TW128.ENC}`$ and $`\mathsf{TW128.DEC}`$
are defined only on inputs whose canonical chunk count satisfies $`\chi(P) \le
2^{1208}`$. More generally, the same 1344-bit IV budget would easily
accommodate a 256-bit nonce variant with the same rate, capacity, and
duplex-call counts; only the concrete IV-embedding map would change.

For $`\mathsf{TW128}`$, both the leaf tag and the final trunk tag fit within a
single $`r = 1344`$-bit squeeze block, so

```math
s_{\mathsf{leaf}} = s_{\mathsf{tr}} = 1.
```

Thus raising the leaf tag from 128 to 256 bits does not change the local leaf
transcript length: each remaining chunk still performs one blank squeeze for
its hidden tag. The concrete cost appears only in the trunk later- tag phase,
which absorbs an additional $`128 \max(\chi(P)-1,0)`$ bits across the leaf tag
vector. This tradeoff is favorable for $`\mathsf{TW128}`$, because it
materially strengthens the INT-CTXT guessing term while leaving the leaf CMT-4
analysis unchanged apart from the already negligible ideal collision tail.

For the leaf resource accounting of Section 4.5, a full remaining chunk has
length $`65024`$ bits, so

```math
\omega_r(65024) = \left\lceil \frac{65024+1}{1344} \right\rceil = 49,
\qquad
\omega_r(65024) + s_{\mathsf{leaf}} = 50.
```

Hence the full-chunk leaf local CMT-4 term of Lemma 7.2 is

```math
\epsilon_{\mathsf{lw}}^{\flat}(65024,N)
=
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(N+100,2)
+
2^{-65280},
```

because

```math
M_{\mathsf{lw}}(65024,N)
=
N + 2 \left(\left\lceil \frac{65024+1}{1344} \right\rceil + 1\right)
=
N + 100,
```

since the exact-rate chunk still incurs one additional padded body block and
one blank squeeze per local transcript. If the final remaining chunk has length
$`\lambda`$ bits, where $`0 < \lambda \le 65024`$ and $`\lambda`$ is a multiple
of $`8`$, then the corresponding local term is

```math
\epsilon_{\mathsf{lw}}^{\flat}(\lambda,N)
=
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}\!\left(N + 2 \left(\left\lceil \frac{\lambda+1}{1344} \right\rceil + 1\right),2\right)
+
2^{-(\lambda+256)}.
```

This makes the per-ciphertext nature of Theorem 5.4 explicit. The ideal-output
collision tail is least favorable for the shortest nonempty last remaining
chunk, but because $`\mathsf{TW128}`$ is octet-oriented one always has
$`\lambda \ge 8`$, so even that worst case is only $`2^{-264}`$. At the same
time, the duplex-merger term improves as $`\lambda`$ decreases, since
$`M_{\mathsf{lw}}(\lambda,N)`$ is monotone increasing in $`\lambda`$.

For the trunk side, the Section 4.5 bookkeeping specializes to

```math
\alpha_r(A)
=
\mathbf{1}_{A \ne \epsilon} \cdot \left\lceil \frac{|A| + 8 + 1}{1344} \right\rceil,
```

```math
\beta_r(P)
:=
\begin{cases}
0, & \text{if } \chi(P)=0,\\
\left\lceil \frac{|P_0|+1}{1344} \right\rceil, & \text{if } \chi(P)\ge1,
\end{cases}
```

```math
\gamma_r(P)
:=
\mathbf{1}_{\chi(P)\ge2} \cdot \left\lceil \frac{(\chi(P)-1)256 + 8 + 1}{1344} \right\rceil,
```

and therefore

```math
\sigma_{\mathsf{tr}}(A,P)
=
 \alpha_r(A) + \beta_r(P) + \gamma_r(P) + 1.
```

Thus:

- the empty-message path costs $`\sigma_{\mathsf{tr}}(A,\epsilon)=\alpha_r(A)+1`$;
- a one-chunk full-block message with empty associated data costs

  ```math
  \sigma_{\mathsf{tr}}(\epsilon,P)
  =
  49 + 1
  =
  50;
  ```

- a message of $`n`$ full chunks with empty associated data costs

  ```math
  \sigma_{\mathsf{tr}}(\epsilon,P)
  =
  49
  +
  \left\lceil \frac{(n-1)256+9}{1344} \right\rceil
  +

  1,

  ```

because the trunk carries the entire associated-data phase, the first chunk,
the optional leaf-tag absorb phase, and the final squeeze.

The trunk-local CMT-4 term of Theorem 5.4 is therefore

```math
\epsilon_{\mathsf{tr}}^{\mathsf{flat}}(\Theta,N)
=
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M_{\mathsf{tr}}^{\flat}(\Theta,N),\rho)
+
\delta_{\mathsf{tr}}(\Theta),
```

with

```math
M_{\mathsf{tr}}^{\flat}(\Theta,N)
=
N + \sigma_{\mathsf{tr}}(A_1,P_1) + \sigma_{\mathsf{tr}}(A_2,P_2),
\qquad
\rho \le 2,
```

and

```math
\delta_{\mathsf{tr}}(\Theta)
=
\begin{cases}
2^{-256}, & \text{if } \chi(P_1)=0,\\
2^{-(|Y_0|+256)}, & \text{if } \chi(P_1)\ge1.
\end{cases}
```

In particular:

- for the empty-message case, the leaf term vanishes and the trunk-local
  contribution is

  ```math
  \mathrm{Sponge}^{(i)}_{\mathsf{forest}}(N+\sigma_{\mathsf{tr}}(A_1,\epsilon)+\sigma_{\mathsf{tr}}(A_2,\epsilon),\rho)
  +
  2^{-256};
  ```

- for a one-chunk full-block comparison with empty associated data on both
  sides, one has $`M_{\mathsf{tr}}^{\flat}(\Theta,N)=N+100`$ and
  $`\delta_{\mathsf{tr}}(\Theta)=2^{-65280}`$.

The rooted-forest part itself is

```math
\mathrm{Sponge}^{(i)}_{\mathsf{forest}}(M,\rho)
=
\frac{(1-2^{-1344})M^2 + (2\rho-1+2^{-1344})M}{2^{257}},
```

which is extremely close to $`M^2/2^{257}`$ at all practical scales. Thus the
trunk-local contribution also matches the intended 128-bit generic target.

Substituting these parameters into Theorems 5.1, 5.2, and 5.4 yields the
concrete parameterized security statements for $`\mathsf{TW128}`$. On the AE
side, these remain $`\mu`$-user, $`N`$-query formulas: the imported KD/IXIF
terms of Theorems 5.1 and 5.2 retain their explicit dependence on both $`\mu`$
and $`N`$, so a fully numeric deployment claim must fix concrete caps for those
quantities and then evaluate the imported [Men23] expressions. The present
section therefore fixes the algorithmic parameters and the exact terms to be
evaluated, but does not bake in deployment-specific values of $`\mu`$ or $`N`$.
Under any such concrete caps satisfying the low-complexity side conditions of
Section 4.6, the dominant generic terms remain capacity-limited and target the
intended 128-bit level, while the commitment bound inherits the same 128-bit
target through the combination of the 256-bit final tag and the sharpened
per-chunk local collision terms.

**Corollary 8.1 (TW128 Security).** Let $`\mathcal{A}`$ be an adversary against
$`\mathsf{TW128}`$ in the corresponding $`\mu`$-user experiment, and let the
induced lower-level resources be as in Sections 4.5 and 4.6. Throughout this
corollary, all wrapper inputs are assumed to lie in the defined domain of
$`\mathsf{TW128}`$; equivalently, every queried or extracted message has
canonical chunk count at most $`2^{1208}`$.

- If $`\sigma^{\mathsf{tr}}_e + N \le 0.1 \cdot 2^{256}`$ and
  $`\sigma^{\mathsf{leaf}}_e + N \le 0.1 \cdot 2^{256}`$, then

  ```math
  \mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cpa}}_{\mathsf{TW128}}(\mathcal{A})
  \le
  \epsilon_{\mathsf{tr}}^{\mathsf{enc}}(\mu,q^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_e,N)
  +
  \epsilon_{\mathsf{leaf}}^{\mathsf{enc}}(\mu,\chi_{\mathsf{leaf},e},\sigma^{\mathsf{leaf}}_e,N),
  ```

  where the imported [Men23] terms are evaluated with
  $`(b,r,c,k) = (1600,1344,256,256)`$ and the concrete 1344-bit IV embedding
  defined above.

- If $`\sigma^{\mathsf{tr}}_e + \sigma^{\mathsf{tr}}_d + N \le 0.1 \cdot 2^{256}`$
  and
  $`\sigma^{\mathsf{leaf}}_e + \sigma^{\mathsf{leaf}}_d + N \le 0.1 \cdot 2^{256}`$,
  then

  ```math
  \mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TW128}}(\mathcal{A})
  \le
  \epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,L_{\mathsf{tr}},N)
  +
  \epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,N)
  +
  \frac{2 q_f}{2^{256}}.
  ```

- Consequently, under the same side conditions, IND-CCA2 specializes to

  ```math
  \mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cca2}}_{\mathsf{TW128}}(\mathcal{A})
  \le
  \epsilon_{\mathsf{tr}}^{\mathsf{enc}}(\mu,q^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_e,N)
  +
  \epsilon_{\mathsf{leaf}}^{\mathsf{enc}}(\mu,\chi_{\mathsf{leaf},e},\sigma^{\mathsf{leaf}}_e,N)
  +
  2 \cdot \epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,L_{\mathsf{tr}},N)
  +
  2 \cdot \epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,N)
  +
  \frac{4 q_d}{2^{256}}.
  ```

- For any fixed CMT-4 output pair $`\Theta`$ with chunk lengths
  $`\ell_0,\ldots,\ell_{n-1}`$, and with
  $`M_{\mathsf{tr}}^{\flat}(\Theta,N)`$,
  $`\rho(\Theta)`$, and
  $`\epsilon_{\mathsf{leaf}}^{\mathsf{first}}(\Theta,N)`$ extracted from
  $`\Theta`$ exactly as in Theorem 5.4, where $`j^\star`$ denotes the first
  differing later index when it exists, if
  $`M_{\mathsf{tr}}^{\flat}(\Theta,N) < 2^{256}`$ and, when
  $`\epsilon_{\mathsf{leaf}}^{\mathsf{first}}(\Theta,N) \ne 0`$, also
  $`M_{\mathsf{lw}}(\ell_{j^\star},N) < 2^{256}`$, then

  ```math
  \Pr_p[\mathsf{TreeWrap}_p.\mathsf{ENC}(K_1,U_1,A_1,P_1)=\mathsf{TreeWrap}_p.\mathsf{ENC}(K_2,U_2,A_2,P_2)]
  \le
  \epsilon_{\mathsf{tr}}^{\mathsf{flat}}(\Theta,N)
  +
  \epsilon_{\mathsf{leaf}}^{\mathsf{first}}(\Theta,N).
  ```

  In particular, if the leaf term is nonzero and the first differing
  remaining chunk is a full 8128-byte chunk, then the leaf contribution is

  ```math
  \mathrm{Sponge}^{(i)}_{\mathsf{forest}}(N+100,2) + 2^{-65280},
  ```

  while the empty-message and one-chunk cases are governed entirely by the
  trunk-local term.

### 8.2 Worked TW128 Examples

To keep the arithmetic reproducible on the page, we evaluate the leading
low-complexity term visible in the imported [Men23] expressions rather than
only quoting the final numerical exponents. For both the leaf import and the
direct keyed-duplex import used by $`\mathsf{TrunkWrap}`$, the leading capacity
term has the form

```math
\frac{2 \nu_{r,c}^{2M}(N+1)}{2^c},
```

where $`M`$ is the relevant total number of duplexing calls and
$`\nu_{r,c}^{2M}`$ is the transcript-combinatorial factor of [Men23, Section
4.2]. For $`\mathsf{TW128}`$, we have $`(b,r,c) = (1600,1344,256)`$. In both
examples below, $`2M < 2^r`$, so the simple bound of [Men23, Section 4.2] gives

```math
\nu_{1344,256}^{2M}
\le
\left\lceil \frac{1600}{1344-\log_2(2M)} \right\rceil
= 2.
```

As a concrete illustration, consider first a single-user deployment with $`\mu
= 1`$, empty associated data, $`2^{20}`$ encryption queries, and a
$`2^{20}`$-byte plaintext in each query. This corresponds to a total wrapped
plaintext volume of $`2^{40}`$ bytes (one tebibyte). Each message decomposes
into $`130`$ chunks, so each message contributes one trunk evaluation on chunk
$`0`$ and $`129`$ leaf evaluations on chunks $`1,\ldots,129`$. The leaf-side
call count per message is

```math
128 \cdot 50 + 2 = 6402,
```

because the first $`128`$ leaf chunks are full 8128-byte chunks and the final
leaf chunk has length $`64`$ bytes. The induced resources are therefore

```math
\chi_{\mathsf{leaf},e} = 135{,}266{,}304,
\qquad
\sigma^{\mathsf{leaf}}_e = 6{,}712{,}983{,}552,
\qquad
q^{\mathsf{tr}}_e = 2^{20},
\qquad
\sigma^{\mathsf{tr}}_e = 78{,}643{,}200.
```

Here the trunk count follows from
$`\sigma_{\mathsf{tr}}(\epsilon,P) = 49 + 25 + 1 = 75`$
per message: one full first chunk costs $`49`$ body calls, the
absorbed vector of $`129`$ leaf tags costs $`\lceil (129 \cdot 256 + 9)/1344
\rceil = 25`$ absorb calls, and the final squeeze contributes one more call.

If one further grants the adversary a primitive-query budget of $`N = 2^{40}`$
and a decryption/final-forgery cap of $`q_d = q_f = 2^{32}`$, then

```math
2 \sigma^{\mathsf{leaf}}_e = 13{,}425{,}967{,}104 < 2^{34},
\qquad
2 \sigma^{\mathsf{tr}}_e = 157{,}286{,}400 < 2^{28},
```

so both leading imported terms use $`\nu_{1344,256}^{2M} \le 2`$. Hence the
leading leaf-side imported term of Corollary 4.4 is bounded by

```math
\frac{2 \nu_{1344,256}^{2\sigma^{\mathsf{leaf}}_e}(N+1)}{2^{256}}
\le
\frac{4(2^{40}+1)}{2^{256}}

< 2^{-214},
```

and the same estimate applies to the leading trunk-side imported term of
Corollary 4.6. In this single-user example the pairwise-user term
$`\binom{\mu}{2}/2^{256}`$ vanishes identically, because $`\mu = 1`$,

while the explicit TW128 guessing term is only

```math
\frac{2 q_f}{2^{256}} = 2^{-223}.
```

All remaining visible imported terms carry denominators $`2^{512}`$ or
$`2^{1600}`$ and are therefore far smaller. Thus, at a one-tebibyte single-
user scale, the concrete TW128 bounds remain comfortably below the intended
$`2^{-128}`$ target.

The preceding example is already representative of realistic deployment scales.
If one instead asks for the actual edge of the visible $`\mathsf{TW128}`$ AE
margin in the low-complexity regime, the answer is not a larger wrapped-data
volume but a much larger primitive-query budget. Indeed, for the same one-
tebibyte single-user workload above, the leading imported term remains

```math
\frac{2 \nu_{1344,256}^{2M}(N+1)}{2^{256}}
\le
\frac{4(N+1)}{2^{256}},
```

so it reaches the $`2^{-128}`$ scale only when $`N`$ itself approaches
$`2^{126}`$. Concretely, if one keeps the same message shape and data volume as
above but grants

```math
N = 2^{126},
```

then the leading leaf-side and trunk-side imported terms both become

```math
\frac{4(2^{126}+1)}{2^{256}} \approx 2^{-128},
```

while the pairwise-user term still vanishes for the same reason:

```math
\frac{\binom{\mu}{2}}{2^{256}} = 0
\qquad
(\text{for } \mu = 1).
```

Likewise, the explicit integrity-guessing term reaches the same scale only when

```math
\frac{2 q_f}{2^{256}} \approx 2^{-128},
```

that is, when $`q_f`$ approaches $`2^{127}`$. In other words, for
$`\mathsf{TW128}`$ the practical AE margin is not volume-limited at realistic
scales; the visible edge of the bound appears only under astronomically large
primitive-query or forgery budgets.

## 9. Conclusion

TreeWrap shows that a chunk-parallel permutation-based AEAD can be analyzed
cleanly by splitting the construction into a trunk transcript and a family of
leaf transcripts. On the AE side, this decomposition lets the proof reuse the
keyed-duplex/IXIF machinery of [Men23] for both `TrunkWrap` and the leaf family
while isolating the one TreeWrap-specific step needed for integrity: a fresh
remaining chunk yields a fresh hidden leaf tag except with the expected
guessing probability, while fresh trunk prefixes are handled directly at the
trunk layer. On the commitment side, the same decomposition supports a separate
public-permutation analysis in which the trunk-local and leaf local transcripts
are flattened and bounded by rooted-forest sponge arguments.

The concrete $`\mathsf{TW128}`$ instantiation shows that this proof strategy
leads to a practically parameterized scheme based on twelve-round Keccak,
8128-byte chunks, 256-bit leaf tags, and a 256-bit final tag. Its AE guarantees
remain explicitly multi-user and parameterized by the imported keyed-duplex
bounds, while its commitment guarantee specializes to an explicit per-output
collision bound with especially strong terms on full chunks and on
short-message trunk-local paths. Together, these results provide a complete
proof framework for TreeWrap and a concrete target instantiation for further
evaluation.

## References

[BDPVA08] Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche.
*On the Indifferentiability of the Sponge Construction*. In Nigel P. Smart,
editor, *Advances in Cryptology -- EUROCRYPT 2008*, volume 4965 of *Lecture
Notes in Computer Science*, pages 181-197. Springer, 2008.

[BDPVA11] Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche.
*Duplexing the Sponge: Single-Pass Authenticated Encryption and Other
Applications*. In Ali Miri and Serge Vaudenay, editors, *Selected Areas in
Cryptography -- SAC 2011*, volume 7118 of *Lecture Notes in Computer Science*,
pages 320-337. Springer, 2012.

[BH22] Mihir Bellare and Viet Tung Hoang. *Efficient Schemes for Committing
Authenticated Encryption*. In Orr Dunkelman and Stefan Dziembowski, editors,
*Advances in Cryptology -- EUROCRYPT 2022, Part II*, volume 13276 of *Lecture
Notes in Computer Science*, pages 845-875. Springer, 2022.

[BN00] Mihir Bellare and Chanathip Namprempre. *Authenticated Encryption:
Relations among Notions and Analysis of the Generic Composition Paradigm*. In
Tatsuaki Okamoto, editor, *Advances in Cryptology -- ASIACRYPT 2000*, volume
1976 of *Lecture Notes in Computer Science*, pages 531-545. Springer, 2000.

[Ascon21] Christoph Dobraunig, Maria Eichlseder, Florian Mendel, and Martin
Schläffer. *Ascon v1.2: Lightweight Authenticated Encryption and Hashing*.
*Journal of Cryptology*, 34(3): Article 33, 2021.
<https://doi.org/10.1007/s00145-021-09398-9>

[FIPS202] National Institute of Standards and Technology. *SHA-3 Standard:
Permutation-Based Hash and Extendable-Output Functions*. Federal Information
Processing Standards Publication 202, 2015.
<https://doi.org/10.6028/NIST.FIPS.202>

[K12] Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche, Ronny Van
Keer, and Benoît Viguier. *KangarooTwelve: Fast Hashing Based on Keccak-p*. In
Pooya Farshim and Steven Guilley, editors, *Applied Cryptography and Network
Security*, volume 10892 of *Lecture Notes in Computer Science*, pages 400-418.
Springer, 2018. <https://doi.org/10.1007/978-3-319-93387-0_21>

[Keyak16] Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche, and
Ronny Van Keer. *CAESAR Submission: Keyak v2*. Document version 2.2, September
15, 2016. <https://keccak.team/files/Keyakv2-doc2.2.pdf>

[RFC9861] Benoit Viguier, David Wong, Gilles Van Assche, Quynh Dang, and Joan
Daemen. *KangarooTwelve and TurboSHAKE*. RFC 9861, 2025.
<https://www.rfc-editor.org/rfc/rfc9861.html>

[SP800185] John Kelsey, Shu-jen Chang, and Ray Perlner. *SHA-3 Derived
Functions: cSHAKE, KMAC, TupleHash, and ParallelHash*. NIST Special Publication
800-185, 2016. <https://doi.org/10.6028/NIST.SP.800-185>

[SP800232] Meltem Sönmez Turan, Kerry McKay, Jinkeon Kang, John Kelsey, and
Donghoon Chang. *Ascon-Based Lightweight Cryptography Standards for Constrained
Devices: Authenticated Encryption, Hash, and Extendable Output Functions*. NIST
Special Publication 800-232, 2025. <https://doi.org/10.6028/NIST.SP.800-232>

[Men23] Bart Mennink. *Understanding the Duplex and Its Security*. *IACR
Transactions on Symmetric Cryptology*, 2023(2): 1-46, 2023.

[Xoo20] Joan Daemen, Seth Hoffert, Michaël Peeters, Gilles Van Assche, and
Ronny Van Keer. *Xoodyak, a Lightweight Cryptographic Scheme*. *IACR
Transactions on Symmetric Cryptology*, 2020(S1): 60-87, 2020.
<https://doi.org/10.13154/tosc.v2020.is1.60-87>
