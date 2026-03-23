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
efficiency pattern of KangarooTwelve [BDPVAVKV18] into the keyed setting and the AEAD
problem domain.

We analyze TreeWrap in two settings. For authenticated encryption, we prove
multi-user IND-CPA, INT-CTXT, and IND-CCA2 bounds in the keyed-duplex model of
Mennink. This AE analysis is largely modular: the leaf-layer proof identifies
$`\mathsf{LeafWrap}`$ with a reduced MonkeySpongeWrap transcript and ports the
corresponding keyed-duplex/IXIF replacement argument, while the trunk layer is
handled by a direct keyed-duplex/IXIF analysis. The main TreeWrap-specific AE
step is a canonical-schedule authenticity lemma showing that, in the IXIF
world, every valid fresh candidate either forces a fresh final trunk-tag path
or an earliest hidden leaf-tag collision, except for the explicit guessing
terms. For commitment, we keep the same canonical schedule but switch to a
public-permutation view: each encryption is flattened, the resulting schedule
is mapped to prefix-sponge queries, and the probabilistic step is then
imported from the random-permutation sponge indifferentiability bound. The
remaining TreeWrap-specific work is a short injectivity argument and a
tag-routed endgame. This extends ordinary key commitment to full commitment of
the AEAD tuple without introducing a separate authenticator family.
This commitment proof exposes one framing bit in the prefix-sponge view, but
the imported random-permutation sponge bound still leaves the concrete
$`\mathsf{TW128}`$ commitment term at the intended 128-bit birthday scale.

We also give a concrete instantiation, $`\mathsf{TW128}`$, based on
$`\mathrm{Keccak\text{-}p}[1600,12]`$ with 256-bit capacity, 8128-byte chunks,
256-bit leaf tags, and a 256-bit final tag. The resulting generic security
target is 128 bits, together with multi-user AE bounds and explicit CMT-4
bounds.

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
[BDPVAVKV18]: a serial trunk handles the short-message path and the global framing,
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
proofs can also be flattened into public-permutation histories and then viewed
as a short prefix-sponge transcript under the same canonical schedule. This
gives a direct route to a CMT-4 analysis within the same permutation-based
framework rather than through a separate authenticator family. In particular,
this extends the usual key-commitment guarantee to full commitment of the AEAD
parameters.

On the AE side, most of the proof work is a modular application of [Men23]
rather than a new keyed-duplex argument. The genuinely new technical pieces are
the TreeWrap-specific authenticity freshness split of Lemma 7.1 and the
public-permutation CMT-4 analysis of Sections 4.8--4.10 and 7.

### 1.2 Related Work

At the structural level, TreeWrap is closest to KangarooTwelve [BDPVAVKV18] and to
tree-style hash modes such as ParallelHash [SP800185]. These constructions use
a serial top-level transcript together with parallel subcomputations on long
inputs. TreeWrap borrows that efficiency pattern, but moves it from the unkeyed
hashing/XOF setting to keyed authenticated encryption. The main difference is
therefore not only keyed initialization but also framing: rather than
Sakura-style tree coding, TreeWrap uses derived keyed IVs together with duplex
padding and phase trailers to separate the trunk and leaf transcripts.

Among keyed Keccak-family designs, Keyak [BDPVAVK16] is the closest relative in
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

Closer to the modern permutation-based AEAD landscape, Xoodyak [DHPVAVK20] and
Ascon [DEMS21, SP800232] are serial duplex-based designs that prioritize
compactness and lightweight deployment over chunk-parallel throughput. Xoodyak
offers a versatile Cyclist interface over Xoodoo[12], while Ascon is now the
standardized NIST lightweight AEAD family. TreeWrap differs from both by making
parallel message decomposition a first-class design goal: it keeps the
associated data and the first chunk on the trunk path, and pushes only the
remaining chunks into independent leaf transcripts.

Outside the permutation-based family, AEGIS-128L and AEGIS-256 [WP13]
achieve very high throughput on platforms with AES-NI or similar hardware
acceleration. TreeWrap differs in two ways: it does not require dedicated
hardware instructions, since Keccak-p is a bitwise construction that performs
well in pure software and in SIMD pipelines; and its duplex-based structure
admits a direct CMT-4 commitment analysis within the present framework, whereas
recent analysis of AEGIS-family commitment shows security at most at the
CMT-1 level [IR23].

On the proof side, the closest antecedent is [Men23]. The leaf layer is
deliberately kept close to the reduced MonkeySpongeWrap transcript analyzed
there, while the trunk layer remains a direct keyed-duplex family so that both
halves fit the same KD/IXIF framework. The commitment analysis instead follows
the encryption-based CMT-4 notion of [BH22] and the public-permutation
flattening/duplex lineage of [BDPVA11] together with the sponge
indifferentiability line of [BDPVA08]. In this sense, the novelty of TreeWrap
is not a new generic duplex theorem, but a construction that combines a ported
leaf KD/IXIF bound, imported trunk keyed-duplex bounds, and a separate global
commitment analysis under a canonical TreeWrap schedule.

The proof strategy follows the same decomposition. The AE analysis is carried
out in the multi-user keyed-duplex model of [Men23]. At the leaf layer, Lemma
6.1 identifies the $`\mathsf{LeafWrap}`$ family on chunks $`i \ge 1`$ with a
reduced MonkeySpongeWrap transcript, and Theorem 6.2 ports the corresponding
KD/IXIF replacement bound. A TreeWrap-specific freshness lemma then handles the
interaction between fresh leaf tags and the trunk transcript. At the trunk
layer, Corollaries 4.6 and 4.7 give the encryption-side and bidirectional
keyed-duplex/IXIF replacements for $`\mathsf{TrunkWrap}`$. These ingredients
yield the IND-CPA and INT-CTXT theorems, and Theorem 5.3 derives IND-CCA2 from
them by a BN00-style game hop using the multi-forgery integrity notion of
Section 4.2.

The commitment analysis is deliberately separate from the keyed AE path.
Because the CMT-4 adversary chooses both candidate keys and nonces, the proof
does not use the keyed [Men23] bounds. Instead, it flattens the construction
into public-permutation transcripts under the canonical TreeWrap schedule and
then maps that schedule to prefix-sponge queries. The local wrapper lemma is in
the lineage of [BDPVA11], while the actual probabilistic replacement step uses
the random-permutation sponge indifferentiability bound of [BDPVA08]. The
remaining TreeWrap-specific argument is then a short injectivity-plus-tag
endgame. Theorem 5.4 packages these ingredients into the final CMT-4 bound.

The remainder of the paper is organized as follows. Section 2 fixes notation,
the keyed-duplex model, and the encoding conventions. Section 3 defines
$`\mathsf{LeafWrap}`$, $`\mathsf{TrunkWrap}`$, and $`\mathsf{TreeWrap}`$,
together with the AEAD wrapper. Section 4 gives the multi-user security
experiments, the resource translation, and the imported external bounds.
Section 5 states the main AE and CMT-4 theorems. Section 6 gives the imported
AE adaptation sketches, and Section 7 contains the TreeWrap-specific proofs.
Section 8 instantiates the construction as $`\mathsf{TW128}`$ using
$`\mathrm{Keccak\text{-}p}[1600,12]`$, SP 800-185 encodings [SP800185], 8128-byte chunks,
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
\mathbb{N}`$ with $`c + r = b`$ and $`k \le r`$. Let
$`\mathcal{IV}_{\mathsf{rate}} \subseteq \{0,1\}^{r-k}`$ be a rate-side IV
payload space, and define the admissible keyed-duplex IV image

```math
\mathcal{IV}
:=
\{ V \| 0^c : V \in \mathcal{IV}_{\mathsf{rate}} \}
\subseteq
\{0,1\}^{b-k}.
```

Let $`p \in \mathrm{Perm}(b)`$ be a $`b`$-bit permutation. The keyed duplex
construction is denoted

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
MonkeySpongeWrap-style LeafWrap transcript are built. The interface is thus
exactly the [Men23] keyed duplex, but TreeWrap restricts admissible IVs to the
structured image $`V \| 0^c`$: the final $`c`$ bits are fixed zeros and are not
treated as semantic IV payload.

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
injective rate-side IV-derivation map

```math
\mathsf{iv}_{\mathsf{rate}} : \mathcal{U} \times \mathbb{N}
\to \mathcal{IV}_{\mathsf{rate}}.
```

The actual keyed-duplex IVs are then defined by

```math
\mathsf{iv}(U,j)
:=
\mathsf{iv}_{\mathsf{rate}}(U,j) \| 0^c
\in
\mathcal{IV}.
```

TreeWrap reserves suffix $`0`$ for the trunk call and uses positive suffixes
for `LeafWrap` calls on the remaining chunks, so

```math
v_{\mathsf{tr}}(U) := \mathsf{iv}_{\mathsf{rate}}(U,0),
\qquad
v_i(U) := \mathsf{iv}_{\mathsf{rate}}(U,i), \quad i \ge 1,
```

and the corresponding keyed-duplex IVs are

```math
V_{\mathsf{tr}}(U) := \mathsf{iv}(U,0) = v_{\mathsf{tr}}(U) \| 0^c,
\qquad
V_i(U) := \mathsf{iv}(U,i) = v_i(U) \| 0^c.
```

In concrete instantiations, $`\mathsf{iv}_{\mathsf{rate}}`$ may itself be built
from an injective integer encoding such as $`\mathrm{right\_encode}`$; Section
8 does this for $`\mathsf{TW128}`$.

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
- a rate-side IV payload space
  $`\mathcal{IV}_{\mathsf{rate}} \subseteq \{0,1\}^{r-k}`$,
- an admissible keyed-duplex IV image
  $`\mathcal{IV} := \{ V \| 0^c : V \in \mathcal{IV}_{\mathsf{rate}} \}
  \subseteq \{0,1\}^{b-k}`$,
- a nonce space $`\mathcal{U}`$,
- an injective rate-side IV-derivation map
  $`\mathsf{iv}_{\mathsf{rate}} : \mathcal{U} \times \mathbb{N}
  \to \mathcal{IV}_{\mathsf{rate}}`$,
- a chunk size $`B`$,
- a leaf tag size $`t_{\mathsf{leaf}}`$,
- a tag size $`\tau`$.

These parameters satisfy

```math
c + r = b,
\qquad
k \le r,
\qquad
t_{\mathsf{leaf}} > 0,
\qquad
\tau > 0.
```

For brevity, later sections continue to write
$`\mathsf{iv}(U,j) := \mathsf{iv}_{\mathsf{rate}}(U,j) \| 0^c`$ for the actual
keyed-duplex IV fed to $`\mathsf{KD.init}`$.

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
    Y* <- ε
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
    Y <- left_|X|(Y*)
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
transcript can be flattened to a public-permutation transcript and then
rewrapped as prefix-sponge queries for the CMT-4 analysis.

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
instantiation, the 1088-bit rate-side IV payload leaves ample room for a wider nonce
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
| $`Q_{\mathsf{IV,leaf}}, Q_{\mathsf{IV,tr}}`$ | induced maximum raw-IV initialization multiplicities for the bidirectional leaf and trunk families |
| $`L_{\mathsf{tr}}`$ | induced repeated-subpath count for the bidirectional trunk family |
| $`\Omega_{\mathsf{lw},d}, \Omega^{\mathsf{tr}}_d`$ | decryption-side overwrite counts for the leaf and trunk families |
| $`q_f`$ | final forgery-candidate count in the multi-forgery INT-CTXT game |
| $`q_*`$ | generic decryption-side wrapper count: $`q_f`$ in INT-CTXT and $`q_d`$ in IND-CCA2 |

Throughout Sections 4--8, lower-case $`\sigma`$ denotes a duplex-call count,
while upper-case $`\Sigma`$ is reserved for concatenated hidden leaf-tag
vectors.

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

For the bidirectional leaf family, let $`Q_{\mathsf{IV,leaf}}`$ denote the
induced maximum number of leaf initialization calls for a single raw IV. Because
decryption may repeat a leaf keyed context $`(\delta,\mathsf{iv}(U,j))`$ many
times for fixed $`j \ge 1`$, we keep this Men23 resource parameter explicit as
well.

For the bidirectional trunk family, let $`L_{\mathsf{tr}}`$ denote the induced
number of trunk duplexing calls whose subpaths repeat prior trunk subpaths in
the same keyed context. This is exactly the Men23 resource parameter $`L`$ for
that family, and we keep it explicit rather than replacing it by a coarser
wrapper-level upper bound.

Likewise, let $`Q_{\mathsf{IV,tr}}`$ denote the induced maximum number of trunk
initialization calls for a single raw IV in the bidirectional trunk family.
Because decryption may repeat a trunk keyed context $`(\delta,\mathsf{iv}(U,0))`$
many times, we keep this Men23 resource parameter explicit as well.

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
[Men23]. For the encryption-only family, these coincide with the resource
assignments used in the proof of [Men23, Theorem 7] for `MonkeySpongeWrap`,
specialized to the reduced family $`\mathsf{MSW}^{\mathsf{red}}`$ of Section 6.1
and re-expressed in the present wrapper-level notation. For the bidirectional
family, we keep the raw-IV multiplicity explicit rather than substituting the
coarser upper bound $`Q_{IV} \le \mu`$:

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
  Q_{IV} = Q_{\mathsf{IV,leaf}},\quad
  L \le \chi_{\mathsf{leaf},d},\quad
  \Omega = \Omega_{\mathsf{lw},d},\quad
  \nu_{\mathsf{fix}} \le \max\!\bigl(\Omega_{\mathsf{lw},d} + \chi_{\mathsf{leaf},e} + \chi_{\mathsf{leaf},d} - 1, 0\bigr).
  ```

**Proof sketch.** By Lemma 6.1 and Theorem 6.2, every leaf transcript is
exactly a transcript of the reduced `MonkeySpongeWrap` family
$`\mathsf{MSW}^{\mathsf{red}}`$ under the keyed contexts
$`(\delta,\mathsf{iv}(U,j))`$ for $`j \ge 1`$. The present quantities
$`\chi_{\mathsf{leaf},e}`$, $`\chi_{\mathsf{leaf},d}`$,
$`\sigma^{\mathsf{leaf}}_e`$, and $`\sigma^{\mathsf{leaf}}_d`$ are precisely
the `Men23` query-count and duplex-call parameters $`q_e`$, $`q_d`$,
$`\sigma_e`$, and $`\sigma_d`$ for that reduced family. On the encryption side,
per-user nonce-respecting behavior still gives $`Q_{IV} \le \mu`$ exactly as in
the proof of [Men23, Theorem 7]. In the bidirectional family, however,
decryption-side nonce reuse can repeat a raw leaf IV $`\mathsf{iv}(U,j)`$, so
the coarse substitution $`Q_{IV} \le \mu`$ used in the displayed `Men23`
bookkeeping is not valid here. We therefore keep the exact induced multiplicity
$`Q_{\mathsf{IV,leaf}}`$ explicit. The remaining assignments
$`L \le \chi_{\mathsf{leaf},d}`$ and $`\Omega = \Omega_{\mathsf{lw},d}`$ are
the same path-counting and overwrite-counting bounds imported from the proof of
[Men23, Theorem 7] and its accompanying Remark 5, specialized to the reduced
family. The displayed bound on
$`\nu_{\mathsf{fix}}`$ is the same path-counting upper bound, specialized to the
reduced family and slightly conservatively rewritten in the current notation.
This conservatism does not affect the concrete theorems here because
$`\nu_{\mathsf{fix}}`$ does not appear in the low-complexity branch of
[Men23, Theorem 1, Eq. (5)] instantiated in Section 4.6. For the bidirectional
leaf term itself, Corollary 4.5 below uses the same simplification as
[Men23, Theorem 7, Eq. (34)] but keeps the $`Q_{IV}N/2^k`$ term explicit as
$`Q_{\mathsf{IV,leaf}}N/2^k`$ rather than substituting $`Q_{IV} \le \mu`$.

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
\epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,Q_{\mathsf{IV,leaf}},N)
:=
\frac{2\nu_{r,c}^{2\sigma^{\mathsf{leaf}}}(N+1)}{2^c}
+
\frac{\sigma^{\mathsf{leaf}}_d N + (\sigma^{\mathsf{leaf}}_d)^2}{2^c}
+
\frac{q^{\mathsf{leaf}}(\sigma^{\mathsf{leaf}}-q^{\mathsf{leaf}})}{2^b-q^{\mathsf{leaf}}}
+
\frac{2\binom{\sigma^{\mathsf{leaf}}}{2}}{2^b}
+
\frac{q^{\mathsf{leaf}}(\sigma^{\mathsf{leaf}}-q^{\mathsf{leaf}})}{2^{\min\{c+k,b\}}}
+
\frac{Q_{\mathsf{IV,leaf}} N}{2^k}
+
\frac{\binom{\mu}{2}}{2^k},
```

where

```math
\sigma^{\mathsf{leaf}} := \sigma^{\mathsf{leaf}}_e + \sigma^{\mathsf{leaf}}_d,
\qquad
q^{\mathsf{leaf}} := \chi_{\mathsf{leaf},e} + \chi_{\mathsf{leaf},d}.
```

This is the same conservative specialization as the low-complexity expression
obtained in the proof of [Men23, Theorem 7, Eq. (34)], specialized to the
reduced family $`\mathsf{MSW}^{\mathsf{red}}`$ and rewritten in the present
notation, except that the raw-IV multiplicity term is kept explicit as
$`Q_{\mathsf{IV,leaf}} N / 2^k`$ rather than further upper bounded by
$`\mu N / 2^k`$.

For a fully wrapper-level explicit instantiation, one may conservatively bound

```math
Q_{\mathsf{IV,leaf}} \le \mu + q_*.
```

Indeed, per-user nonce-respecting permits at most one encryption-side leaf
initialization for a fixed raw IV and user label, contributing at most
$`\mu`$ such initializations in total, while each decryption-side wrapper query
contributes at most one additional initialization for that same raw IV.

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
  Q_{IV} = Q_{\mathsf{IV,tr}},\quad
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
\nu_{\mathsf{fix}} = 0`$. Per-user nonce-respecting also ensures that a fixed
raw trunk IV can appear alongside at most $`\mu`$ user labels in the
encryption-only family, giving $`Q_{IV} \le \mu`$. In the bidirectional family,
repeated subpaths can arise only from decryption-side recomputations under
reused trunk keyed contexts. A single replayed trunk evaluation may contribute
many repeated subpaths before diverging, so we keep the exact induced overlap
count explicit and set $`L = L_{\mathsf{tr}}`$. For the same reason, repeated decryption-side
initializations under a fixed raw IV are not absorbed elsewhere in the generic
Men23 bookkeeping, so we keep the exact induced initialization multiplicity
explicit and set $`Q_{IV} = Q_{\mathsf{IV,tr}}`$. The overwrite contribution is
exactly the first-chunk body cost, so
$`\Omega^{\mathsf{tr}}_d = \sum_{b=1}^{q_*} \beta_r(Y^{(b)})`$. The same Men23
path-counting argument then gives the stated bound on
$`\nu_{\mathsf{fix}}`$.

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
\epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,Q_{\mathsf{IV,tr}},L_{\mathsf{tr}},N)
:=
\mathrm{KD}^{(i)}_{\mathsf{Men23}}(\mu,\sigma^{\mathsf{tr}}_e+\sigma^{\mathsf{tr}}_d,q^{\mathsf{tr}}_e+q^{\mathsf{tr}}_d,Q_{\mathsf{IV,tr}},L_{\mathsf{tr}},\Omega^{\mathsf{tr}}_d,\max(\Omega^{\mathsf{tr}}_d+q^{\mathsf{tr}}_e+q^{\mathsf{tr}}_d-1,0),N).
```

For a fully wrapper-level explicit instantiation, one may conservatively bound

```math
Q_{\mathsf{IV,tr}} \le \mu + q^{\mathsf{tr}}_d.
```

Indeed, per-user nonce-respecting permits at most one encryption-side trunk
initialization for a fixed raw IV and user label, contributing at most
$`\mu`$ such initializations in total, while each decryption query contributes
at most one additional trunk initialization.

Likewise, because repeated trunk subpaths arise only from decryption-side trunk
duplexing calls, one always has

```math
L_{\mathsf{tr}} \le \sigma^{\mathsf{tr}}_d.
```

### 4.7 Canonical TreeWrap Schedule

For the later TreeWrap-specific arguments on both the AE and commitment sides,
it is convenient to fix one common ordered view of a TreeWrap evaluation. This
schedule is independent of whether the transcript engine is the real keyed
duplex, the IXIF ideal interface, or the flattened public-permutation
transcript used in the commitment analysis.

Fix an input tuple $`(K,U,A,P)`$, and let

```math
P = P_0 \| \cdots \| P_{n-1}
```

be its canonical chunk decomposition, with $`n = 0`$ when $`P = \epsilon`$.
When the chunk size $`B`$ is fixed by context, we write

```math
\chi(P) := n.
```

The canonical TreeWrap schedule consists of the following ordered stages:

1. trunk initialization under the keyed context
   $`(K,\mathsf{iv}(U,0))`$;
2. the optional trunk associated-data phase on $`A \| \lambda_{\mathsf{ad}}`$;
3. the optional trunk first-chunk body phase on $`P_0`$;
4. for each $`j = 1,\ldots,n-1`$ in increasing order, the leaf transcript on
   chunk $`P_j`$ under the keyed context $`(K,\mathsf{iv}(U,j))`$;
5. the optional trunk absorb phase on the leaf-tag vector
   $`T_1 \| \cdots \| T_{n-1} \| \lambda_{\mathsf{tc}}`$;
6. the final trunk squeeze phase.

On decryption-side recomputation, we use this same stage order. Only the local
transcript engine changes: trunk or leaf stages are evaluated in decryption
mode where appropriate, but the schedule itself is unchanged.

Within this schedule, a **visible output block** is any caller-visible body
output block (including the final truncated body suffix, when present) or the
final trunk tag block. The hidden leaf tags $`T_1,\ldots,T_{n-1}`$ are
internal schedule values and are not visible output blocks.

For later global transcript accounting, define the aggregate TreeWrap schedule
cost

```math
\sigma_{\mathsf{tw}}(A,P)
:=
\sigma_{\mathsf{tr}}(A,P) + \sigma_{\mathsf{leaf}}(P).
```

This counts the total number of transcript-extension calls executed by one
TreeWrap evaluation under the canonical schedule: the trunk contribution
$`\sigma_{\mathsf{tr}}(A,P)`$ accounts for stages 2, 3, 5, and 6 together with
their implied trunk initialization, while $`\sigma_{\mathsf{leaf}}(P)`$
accounts for all stage-4 leaf transcripts.

### 4.8 Global Flat TreeWrap Transcript

For commitment security, we flatten an entire TreeWrap encryption under the
canonical schedule of Section 4.7. The resulting public-permutation view is
still TreeWrap-specific, but it is deterministic and purely transcript based:
no bad-event accounting happens in this step.

Set

```math
\hat r := r+1,
\qquad
\hat c := c-1.
```

Because TreeWrap restricts admissible keyed-duplex IVs to
$`\mathsf{iv}(U,j)=\mathsf{iv}_{\mathsf{rate}}(U,j)\|0^c`$, every local
initialization state has the form

```math
K \| \mathsf{iv}(U,j)
=
K \| \mathsf{iv}_{\mathsf{rate}}(U,j) \| 0^c
=
\bigl(K \| \mathsf{iv}_{\mathsf{rate}}(U,j) \| 0\bigr)\|0^{\hat c}.
```

Likewise, every later trunk or leaf full-state input block has the form
$`W\|0^c`$ or $`W\|1\|0^{c-1}`$, and therefore lives in the first
$`\hat r=r+1`$ state bits together with an all-zero $`\hat c`$-bit suffix.

Fix a tuple $`(K,U,A,P)`$, write

```math
P = P_0 \| \cdots \| P_{n-1},
\qquad
n := \chi(P),
```

and define the full flattened TreeWrap encryption transcript

```math
\mathsf{TW}^{\flat}[p](K,U,A,P)
```

as follows.

1. The trunk transcript is initialized at state
   $`K\|\mathsf{iv}(U,0)`$.
2. The optional trunk associated-data phase absorbs the padded blocks of
   $`A\|\lambda_{\mathsf{ad}}`$, each as a full-state block of the form
   $`W\|0^c`$.
3. If $`n \ge 1`$, the trunk first-chunk body phase processes $`P_0`$ through
   the framed full-state blocks $`\widetilde{X}\|1\|0^{c-1}`$, yielding the
   visible body chunk $`Y_0`$.
4. For each $`j=1,\ldots,n-1`$ in increasing order, an independent leaf
   transcript is initialized at state $`K\|\mathsf{iv}(U,j)`$ and processes
   $`P_j`$ through its framed full-state body blocks
   $`\widetilde{X}\|1\|0^{c-1}`$, yielding the visible body chunk $`Y_j`$ and
   the hidden leaf tag $`T_j`$.
5. If $`n \ge 2`$, the trunk absorbs the padded blocks of the leaf-tag vector
   $`T_1\|\cdots\|T_{n-1}\|\lambda_{\mathsf{tc}}`$, each as a full-state block
   of the form $`W\|0^c`$.
6. The trunk performs its final squeeze and outputs the final tag $`T`$.

The ciphertext read off from $`\mathsf{TW}^{\flat}[p](K,U,A,P)`$ is

```math
Y \| T,
\qquad
Y :=
\begin{cases}
\epsilon, & \text{if } n = 0,\\
Y_0, & \text{if } n = 1,\\
Y_0 \| \cdots \| Y_{n-1}, & \text{if } n \ge 2.
\end{cases}
```

Here the $`Y_j`$ are exactly the visible output blocks of the canonical
schedule, while the leaf tags $`T_1,\ldots,T_{n-1}`$ remain internal values.

**Lemma 4.8 (Global Flattening of TreeWrap Encryption).** For every fixed
tuple $`(K,U,A,P)`$, the real encryption transcript
$`\mathsf{TreeWrap}_p.\mathsf{ENC}(K,U,A,P)`$ and the flattened transcript
$`\mathsf{TW}^{\flat}[p](K,U,A,P)`$ expose exactly the same primitive
evaluations in the canonical schedule and produce exactly the same ciphertext.

**Proof sketch.** Every trunk or leaf evaluation in encryption mode uses
$`\mathsf{flag}=\mathsf{false}`$, so each call has the form
$`S \leftarrow p(S)`$, $`Z \leftarrow \mathrm{left}_r(S)`$,
$`S \leftarrow S \oplus B`$. The initialization states are exactly the keyed
states $`K\|\mathsf{iv}(U,j)`$, and every later block is one of the framed
full-state blocks described above. Chaining these updates in the fixed order of
Section 4.7 gives the same ordered permutation evaluations and the same visible
outputs as the real encryption. Hence the flattened transcript exposes the same
primitive calls and returns the same ciphertext.

### 4.9 Prefix-Sponge Wrapper and Imported Ideality

The commitment proof does not analyze $`\mathsf{TW}^{\flat}`$ directly.
Instead, it uses a short local wrapper that maps each flattened trunk or leaf
transcript to queries to a public-permutation sponge view at the effective
parameters $`(\hat r,\hat c)=(r+1,c-1)`$, in the duplex-to-sponge lineage of
[BDPVA11, Lemma 3].

For any full-state block of the form $`X\|0^{\hat c}`$ with
$`X \in \{0,1\}^{\hat r}`$, write

```math
\mathrm{pref}_{\hat r}(X\|0^{\hat c}) := X.
```

Define the corresponding block-aligned prefix-sponge view

```math
\mathsf{PS}_{\hat r}[p]
```

as follows. It starts from the all-zero state $`0^b`$. For each absorbed
$`\hat r`$-bit block $`X`$, it updates the state by
$`S \leftarrow p(S \oplus (X\|0^{\hat c}))`$. After any absorbed prefix, it may
return the leftmost $`\ell`$ bits of the current outer $`r`$ bits, for any
$`0 \le \ell \le r`$.

For a flattened trunk or leaf transcript, the absorbed prefix blocks of
$`\mathsf{PS}_{\hat r}[p]`$ are defined as follows.

- Each initialization under keyed context $`(K,\mathsf{iv}(U,j))`$ contributes
  the first absorbed block

  ```math
  I_{K,U,j}
  :=
  K \| \mathsf{iv}_{\mathsf{rate}}(U,j) \| 0
  \in
  \{0,1\}^{\hat r}.
  ```

- Each later full-state block $`B = W\|\beta\|0^{c-1}`$ contributes the
  absorbed block $`\mathrm{pref}_{\hat r}(B)=W\|\beta`$.

Thus every visible body block, every hidden leaf tag, and the final trunk tag
is associated with one query to $`\mathsf{PS}_{\hat r}[p]`$ on the current
prefix of the relevant local trunk or leaf block string.

The framing bit that distinguishes body blocks from absorb blocks is therefore
counted inside the absorbed prefix rather than inside the hidden suffix. This
is why the wrapper uses $`\hat c = c-1`$. The imported [BDPVA08] denominator is
still $`2^{\hat c+1}`$, so the leading capacity term remains $`2^{-c}`$ even
though one bit has moved from the hidden suffix into the effective rate.

**Lemma 4.9 (TreeWrap Schedule as Prefix-Sponge Queries).** For every fixed
tuple $`(K,U,A,P)`$, the flattened transcript
$`\mathsf{TW}^{\flat}[p](K,U,A,P)`$ induces a deterministically defined family
of queries to $`\mathsf{PS}_{\hat r}[p]`$ such that:

1. each trunk or leaf initialization contributes the absorbed block
   $`I_{K,U,j}`$;
2. each later absorb/body step contributes the $`\hat r`$-bit prefix of the
   corresponding full-state block;
3. every visible body block, every hidden leaf tag, and the final trunk tag is
   exactly the corresponding truncated output of $`\mathsf{PS}_{\hat r}[p]`$ on
   the relevant absorbed prefix; and
4. the induced permutation transcript is identical to that of
   $`\mathsf{TW}^{\flat}[p](K,U,A,P)`$.

**Proof sketch.** The first visible output of a trunk or leaf transcript is
produced after one permutation call from the initialized state
$`K\|\mathsf{iv}(U,j)=I_{K,U,j}\|0^{\hat c}`$, which is exactly the
block-aligned prefix-sponge state obtained after absorbing $`I_{K,U,j}`$ from
$`0^b`$. Afterwards, each TreeWrap duplex step applies one permutation call and
then XORs one block of the form $`X\|0^{\hat c}`$ into the current state,
where $`X=\mathrm{pref}_{\hat r}(B)`$. This is exactly the state update of
$`\mathsf{PS}_{\hat r}[p]`$ on the next absorbed block $`X`$. Induction over
the canonical schedule therefore shows that the two views have the same
intermediate states, the same visible outputs, and the same hidden leaf tags.

For a fixed compared tuple pair

```math
\Theta := ((K_1,U_1,A_1,P_1),(K_2,U_2,A_2,P_2)),
```

let $`M_{\mathsf{tw}}(\Theta,N)`$ denote the total sponge-query cost in the
sense of [BDPVA08] of the two
query families induced by Lemma 4.9 together with the adversary's at most
$`N`$ direct permutation queries. Thus every direct primitive query contributes
$`1`$ to the cost, and every induced query to the prefix-sponge view is charged
exactly by the corresponding sponge-query cost at effective parameters
$`(\hat r,\hat c)`$.

Concretely, in the terminology of [BDPVA08, Section 3.5], a direct query to
$`p`$ or $`p^{-1}`$ costs $`1`$, while a prefix-sponge query on an absorbed
prefix of $`h`$ blocks with requested output length $`\ell`$ costs

```math
h + \left\lceil \frac{\ell}{\hat r} \right\rceil.
```

Throughout TreeWrap, every visible body block, hidden leaf tag, and final trunk
tag has output length at most $`\hat r`$, so every induced query of prefix
length $`h`$ costs exactly $`h+1`$.

Writing

```math
S_\nu := \sigma_{\mathsf{tw}}(A_\nu,P_\nu)
\qquad
(\nu \in \{1,2\}),
```

one obtains the closed-form upper bound

```math
M_{\mathsf{tw}}(\Theta,N)
\le
N
+
\frac{S_1(S_1+3)}{2}
+
\frac{S_2(S_2+3)}{2}.
```

Indeed, each local trunk or leaf transcript of schedule length $`s`$ induces
at most one nonempty prefix-sponge query at each prefix length
$`h \in \{1,\ldots,s\}`$, and each such query has [BDPVA08] cost $`h+1`$
because its requested output length is at most $`\hat r`$. Hence one local
transcript contributes at most
$`\sum_{h=1}^s (h+1) = s(s+3)/2`$, and summing over all local transcripts in
the two compared encryptions gives the stated estimate.

Write

```math
\epsilon_{\mathsf{ideal}}(M)
```

for the resulting random-permutation sponge replacement bound obtained from
[BDPVA08, Theorem 2] at parameters $`(\hat r,\hat c)=(r+1,c-1)`$. In the
low-complexity regime $`M \ll 2^{\hat c}`$, one may use the approximation

```math
\epsilon_{\mathsf{ideal}}(M)
\lesssim
\frac{(1-2^{-\hat r})M^2 + (1+2^{-\hat r})M}{2^{\hat c+1}}.
```

For a CMT-4 adversary $`\mathcal{A}`$ that makes at most $`N`$ primitive
queries, write

```math
M_{\mathsf{tw}}^{\max}(\mathcal{A},N)
:=
\max_{\Theta \in \mathrm{Supp}(\mathcal{A})} M_{\mathsf{tw}}(\Theta,N),
```

where the support ranges over all tuple pairs that can be output by
$`\mathcal{A}`$ after at most $`N`$ primitive queries.

**Lemma 4.10 (Imported Sponge Ideality for the CMT-4 Experiment).** Let
$`\mathcal{A}`$ be any CMT-4 adversary that makes at most $`N`$ primitive
queries. Consider the real CMT-4 experiment and the idealized experiment in
which, after $`\mathcal{A}`$ outputs its tuple pair, the two compared
encryptions are answered by ideal random-oracle outputs on the prefix-sponge
query families furnished by Lemma 4.9. Then the change in the success
probability of $`\mathcal{A}`$ is at most
$`\epsilon_{\mathsf{ideal}}(M_{\mathsf{tw}}^{\max}(\mathcal{A},N))`$.

**Proof sketch.** Lemma 4.9 turns the compared flattened encryptions into a
family of adaptive queries to a block-aligned sponge view at effective
parameters $`(\hat r,\hat c)`$, together with the adversary's direct
permutation queries. A distinguisher can therefore run $`\mathcal{A}`$ on the
real permutation, wait until $`\mathcal{A}`$ outputs its tuple pair, and then
realize the two compared encryptions via the corresponding prefix-sponge query
families. The resulting total sponge-query cost is bounded by
$`M_{\mathsf{tw}}^{\max}(\mathcal{A},N)`$ by construction. This is exactly the
type of public-permutation interaction controlled by the random-permutation
sponge indifferentiability theorem of [BDPVA08, Theorem 2], so we use that
theorem as an imported black-box replacement step and write the resulting
advantage bound as
$`\epsilon_{\mathsf{ideal}}(M_{\mathsf{tw}}^{\max}(\mathcal{A},N))`$.

## 5. Main Results

For authenticated encryption, we instantiate the imported [Men23] terms using
Section 4.6. For commitment, Sections 4.8--4.10 now provide the global
flattened-transcript framework: a deterministic flattening step, a local
prefix-sponge wrapper, and one imported sponge-ideality term for the whole
two-run comparison. Section 7 will pair this imported term with the
TreeWrap-specific injectivity and tag-endgame arguments.

- Let $`\epsilon_{\mathsf{leaf}}^{\mathsf{enc}}`$ be the explicit imported
  leaf encryption-side KD/IXIF term of Corollary 4.4.
- Let $`\epsilon_{\mathsf{leaf}}^{\mathsf{ae}}`$ be the explicit imported
  leaf bidirectional KD/IXIF term of Corollary 4.5.
- Let $`\epsilon_{\mathsf{tr}}^{\mathsf{enc}}`$ and
  $`\epsilon_{\mathsf{tr}}^{\mathsf{ae}}`$ be the explicit imported trunk
  KD/IXIF terms of Corollaries 4.6 and 4.7, respectively, with the
  bidirectional term evaluated at the induced trunk initialization multiplicity
  $`Q_{\mathsf{IV,tr}}`$ and overlap count $`L_{\mathsf{tr}}`$.
- By Lemma 7.1 together with the keyed-context discipline of Lemma 4.1, the
  only additional explicit integrity failures beyond these imported KD/IXIF
  terms are the event that a fresh leaf tag matches some previously exposed
  leaf tag on the same keyed path, contributing at most
  $`2^{-t_{\mathsf{leaf}}}`$ per final forgery candidate, and the final trunk-
  tag guessing event, contributing at most $`2^{-\tau}`$ per final forgery
  candidate.
- Let $`M_{\mathsf{tw}}(\Theta,N)`$ be the total prefix-sponge cost of
  Section 4.9 for a fixed compared tuple pair $`\Theta`$ and primitive-query
  budget $`N`$.
- Let $`M_{\mathsf{tw}}^{\max}(\mathcal{A},N)`$ be the resulting adversary-level
  deterministic upper bound of Section 4.9 for a CMT-4 adversary
  $`\mathcal{A}`$ making at most $`N`$ primitive queries.
- Let $`\epsilon_{\mathsf{ideal}}(M_{\mathsf{tw}}^{\max}(\mathcal{A},N))`$ be
  the imported random-permutation sponge term of Lemma 4.10.

For the AE hybrids, define the primitive-query budgets seen by the leaf hop as

```math
N_{\mathsf{leaf}}^{\mathsf{enc}} := N + \sigma^{\mathsf{tr}}_e,
\qquad
N_{\mathsf{leaf}}^{\mathsf{ae}} := N + \sigma^{\mathsf{tr}}_e + \sigma^{\mathsf{tr}}_d.
```

These reflect that, in the leaf KD/IXIF replacement, the reduction must realize
the unchanged real trunk transcript internally via primitive calls. By
contrast, the trunk hop hardwires the already-idealized leaf family and
therefore uses the adversary's original primitive-query budget $`N`$.

### 5.1 IND-CPA Theorem

**Theorem 5.1 (IND-CPA).** Assume $`\sigma^{\mathsf{tr}}_e + N \le 0.1 \cdot
2^c`$ and $`\sigma^{\mathsf{leaf}}_e + N_{\mathsf{leaf}}^{\mathsf{enc}} \le
0.1 \cdot 2^c`$. Then for every per-user nonce-respecting IND-CPA adversary
$`\mathcal{A}`$ against the $`\mu`$-user TreeWrap experiment,

```math
\mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cpa}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\epsilon_{\mathsf{tr}}^{\mathsf{enc}}(\mu,q^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_e,N)
+
\epsilon_{\mathsf{leaf}}^{\mathsf{enc}}(\mu,\chi_{\mathsf{leaf},e},\sigma^{\mathsf{leaf}}_e,N_{\mathsf{leaf}}^{\mathsf{enc}}).
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
\sigma^{\mathsf{leaf}}_d + N_{\mathsf{leaf}}^{\mathsf{ae}} \le 0.1 \cdot 2^c`$.
Then for every per-user nonce-respecting multi-forgery INT-CTXT adversary
$`\mathcal{A}`$ against the $`\mu`$-user TreeWrap experiment outputting at most
$`q_f`$ final forgery candidates,

```math
\mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,Q_{\mathsf{IV,tr}},L_{\mathsf{tr}},N)
+
\epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,Q_{\mathsf{IV,leaf}},N_{\mathsf{leaf}}^{\mathsf{ae}})
+
\frac{q_f}{2^{\min\{t_{\mathsf{leaf}},\tau\}}}.
```

The explicit tail is governed by the larger of the two canonical-schedule
endgame costs: $`2^{-t_{\mathsf{leaf}}}`$ appears only when a fresh later chunk
induces a hidden leaf tag collision, while every $`n = 0`$ or $`n = 1`$ forgery
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

This is a pure dead-decryption composition theorem in the sense of [BN00]:
$`\mathcal{B}_1`$ inherits the schedule-based IND-CPA analysis of Theorem 5.1,
and each $`\mathcal{B}_{2,b}`$ inherits the schedule-based INT-CTXT analysis of
Theorem 5.2 without any further TreeWrap-specific transcript reasoning at the
CCA2 layer.

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
\epsilon_{\mathsf{leaf}}^{\mathsf{enc}}(\mu,\chi_{\mathsf{leaf},e},\sigma^{\mathsf{leaf}}_e,N_{\mathsf{leaf}}^{\mathsf{enc}})
+
2 \cdot \epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,Q_{\mathsf{IV,tr}},L_{\mathsf{tr}},N)
+
2 \cdot \epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,Q_{\mathsf{IV,leaf}},N_{\mathsf{leaf}}^{\mathsf{ae}})
+
\frac{2 q_d}{2^{\min\{t_{\mathsf{leaf}},\tau\}}},
```

with the resource parameters inherited from the reductions as described above.

The multi-forgery INT-CTXT formulation of Section 4.2 removes the
index-guessing loss from the IND-CCA2 reduction. The remaining factor $`2`$
comes from the need to bound the bad-decryption event in both challenge
branches $`b = 0`$ and $`b = 1`$ when converting the CCA distinguishing gap to
the CPA gap plus integrity failure probabilities. This factor is not a
bit-guessing loss: replacing $`\mathcal{B}_{2,0}`$ and $`\mathcal{B}_{2,1}`$ by
a single reduction with a hidden random bit would recover only the average of
the two bad-event probabilities and would therefore reintroduce the same factor
$`2`$ when translated back to the absolute distinguishing gap.

### 5.4 CMT-4 Theorem

**Theorem 5.4 (CMT-4).** Let $`\mathcal{A}`$ be a CMT-4 adversary against
TreeWrap that makes at most $`N`$ primitive queries. Then

```math
\mathrm{Adv}^{\mathsf{cmt}\text{-}4}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\epsilon_{\mathsf{ideal}}(M_{\mathsf{tw}}^{\max}(\mathcal{A},N))
+
\frac{1}{2^{\min\{t_{\mathsf{leaf}}+1,\tau\}}}.
```

The first term is the imported experiment-level random-permutation sponge
replacement term of Lemma 4.10 at effective parameters
$`(\hat r,\hat c)=(r+1,c-1)`$. The second term is the remaining TreeWrap-
specific ideal-world tail established in Section 7: in the ideal post-output
world, if the adversary's two tuples have unequal message lengths then
ciphertext collision is impossible, while every distinct equal-length tuple
pair is bounded by the injectivity-plus-tag endgame of Lemmas 7.2 and 7.3.

## 6. Imported AE Sketches

This section contains proof sketches for the authenticated-encryption path. The
keyed-duplex and BN00 machinery is imported rather than reproved here: the goal
is to isolate how TreeWrap fits the [Men23] framework and how the resulting
hybrid arguments compose. The genuinely TreeWrap-specific arguments are
deferred to Section 7.

### 6.1 Imported Leaf and Trunk Adaptations

The leaf analysis proceeds through an explicit reduced MonkeySpongeWrap family.
For later use, write the framed full-state blocks of a leaf call as

```math
M_j(X) := \widetilde{X}_j \| 1 \| 0^{c-1}
```

for padded message blocks. Define

```math
\mathsf{MSW}^{\mathsf{red}}[p](K,V,X,m) \to (Y,T)
```

to be the reduced MonkeySpongeWrap family obtained from [Men23] by deleting the
local associated-data phase and retaining only:

- keyed-duplex initialization $`\mathsf{KD.init}(1,V)`$;
- the middle body phase on the framed full-state blocks $`M_1(X),\ldots,M_w(X)`$,
  with overwrite enabled exactly when $`m=\mathsf{dec}`$;
- the final $`s_{\mathsf{leaf}}`$ blank squeezes that produce the hidden leaf
  tag.

The trunk transcript is handled directly as a keyed-duplex family under the
keyed contexts $`(\delta,\mathsf{iv}(U,0))`$ and therefore uses Corollaries 4.6
and 4.7 without any additional reduction.

Let $`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}_{\mathsf{leaf}}]`$ denote
the same leaf transcript as $`\mathsf{LeafWrap}[p]`$, but with the keyed duplex
$`\mathsf{KD}[p]`$ replaced by the ideal interface
$`\mathsf{IXIF}[\mathrm{ro}_{\mathsf{leaf}}]`$ of Section 2.3.2. Thus

```math
\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}_{\mathsf{leaf}}](K,V,X,m) \to (Y,T)
```

has exactly the same padding, framing bits, mode flag, and output convention as
$`\mathsf{LeafWrap}[p]`$; only the transcript engine changes.

If $`\pi_0`$ denotes the IXIF path immediately after

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

**Lemma 6.1 (Leaf / Reduced MonkeySpongeWrap Family Correspondence).** Fix
parameters $`p,b,r,c,k,t_{\mathsf{leaf}}`$. For any inputs $`K`$, $`V`$, and
$`X`$, the keyed-duplex transcript of

```math
\mathsf{LeafWrap}[p](K,V,X,m)
```

with initialization

```math
\mathsf{KD.init}(1,V)
```

is identical to the transcript of

```math
\mathsf{MSW}^{\mathsf{red}}[p](K,V,X,m).
```

Thus $`m = \mathsf{enc}`$ gives the reduced encryption transcript, $`m =
\mathsf{dec}`$ gives the corresponding reduced decryption-side transcript with
overwrite enabled in the middle phase, and the returned pair $`(Y,T)`$ is
exactly the body/tag pair determined by that reduced family.

This excision does not alter the structural preconditions used by [Men23]:
every reduced leaf transcript still makes at least one padded body call after
initialization, even when $`X = \epsilon`$, and at least one subsequent squeeze
call because $`t_{\mathsf{leaf}} > 0`$ implies $`s_{\mathsf{leaf}} \ge 1`$.

**Theorem 6.2 (Ported Leaf KD/IXIF Replacement).** For every distinguisher
$`\mathcal{D}_{\mathsf{LW}}`$ attacking a family of leaf transcripts under the
keyed-context discipline induced by TreeWrap, there exists a distinguisher
$`\mathcal{D}_{\mathsf{MSW}^{\mathsf{red}}}`$ against the corresponding reduced
MonkeySpongeWrap family such that

```math
\mathrm{Adv}^{\mathsf{real}\text{-}\mathsf{ixif}}_{\mathsf{LeafWrap}}(\mathcal{D}_{\mathsf{LW}})
=
\mathrm{Adv}^{\mathsf{real}\text{-}\mathsf{ixif}}_{\mathsf{MSW}^{\mathsf{red}}}(\mathcal{D}_{\mathsf{MSW}^{\mathsf{red}}}),
```

with matching transcript resources after interpreting each leaf call as the
corresponding call to $`\mathsf{MSW}^{\mathsf{red}}`$ on the same leaf IV $`V`$.
Consequently, the leaf real-to-IXIF replacement is bounded by the corresponding
KD/IXIF term imported from [Men23], with the unused local associated-data
resources deleted from the accounting. This is exactly the reduced family whose
wrapper-level resources are translated in Lemma 4.2 and bounded in
Corollaries 4.4 and 4.5. In TreeWrap, the relevant keyed contexts are
$`(\delta,V_i)`$ with $`V_i = \mathsf{iv}(U,i)`$ and $`i \ge 1`$.

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
distinguisher forwards leaf calls to its own oracle while realizing the
unchanged trunk transcript internally via direct primitive calls to $`p`$; this
adds exactly $`\sigma^{\mathsf{tr}}_e`$ primitive queries in the encryption-only
setting and $`\sigma^{\mathsf{tr}}_e + \sigma^{\mathsf{tr}}_d`$ in the
bidirectional setting to the primitive-query parameter of the imported leaf
bound, but it contributes no distinguishing gap because the trunk is identical
in both worlds. In the trunk hop, a trunk distinguisher has
$`\mathrm{ro}_{\mathsf{leaf}}`$ hardwired and evaluates the already-idealized
leaf family internally to obtain the leaf tags, then feeds those tags as
ordinary inputs to its trunk oracle. Because $`\mathrm{ro}_{\mathsf{leaf}}`$ is
independent of both $`p`$ and $`\mathrm{ro}_{\mathsf{tr}}`$, the leaf tags are
deterministic functions of $`\mathrm{ro}_{\mathsf{leaf}}`$ and the query
inputs, and are therefore fixed values from the trunk oracle's perspective. The
imported trunk bound (Corollary 4.6 or 4.7) depends only on the induced trunk
resource measures and not on any distributional property of these fixed trunk
inputs. It therefore holds for every fixed realization of
$`\mathrm{ro}_{\mathsf{leaf}}`$, and hence also in expectation.
In the bidirectional setting, decryption-side leaf calls are likewise evaluated
internally via $`\mathrm{ro}_{\mathsf{leaf}}`$ before the resulting trunk query
is forwarded; the Men23 bound permits the distinguisher arbitrary internal
computation, so this does not violate any precondition of Corollary 4.7. By
contrast with the leaf hop, this trunk simulation requires no additional
primitive queries beyond the adversary's own $`N`$.

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
Corollary 4.4 applies. The corresponding leaf distinguisher must additionally
realize the unchanged trunk transcript via $`p`$, so its primitive-query budget
is $`N_{\mathsf{leaf}}^{\mathsf{enc}} = N + \sigma^{\mathsf{tr}}_e`$. Thus the
first replacement changes the overall left-right distinguishing gap by at most

```math
\epsilon_{\mathsf{leaf}}^{\mathsf{enc}}(\mu,\chi_{\mathsf{leaf},e},\sigma^{\mathsf{leaf}}_e,N_{\mathsf{leaf}}^{\mathsf{enc}}).
```

For the second hop, Corollary 4.6 applies to the trunk family, so the second
replacement changes the overall left-right distinguishing gap by at most

```math
\epsilon_{\mathsf{tr}}^{\mathsf{enc}}(\mu,q^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_e,N).
```

It remains to analyze $`H_2^b`$. We record the schedule-based ideal privacy
property of this final game explicitly.

**Lemma 6.3 (Ideal TreeWrap Privacy Under the Canonical Schedule).** In the
final ideal game $`H_2^b`$, fix any left-right query
$`(\delta,U,A,P_0,P_1)`$ and let $`C_b`$ be the returned ciphertext on the
challenge-side plaintext $`P_b`$. Then every visible output block of $`C_b`$,
in the sense of the canonical TreeWrap schedule of Section 4.7, is produced on
a fresh IXIF path. Consequently the distribution of $`C_b`$ depends only on the
public chunk structure and visible block lengths of the query, not on the
challenge bit $`b`$.

**Proof.** By Lemma 4.1, per-user nonce respect together with injectivity of
$`\mathsf{iv}`$ gives pairwise distinct keyed contexts across all encryption
queries: the trunk contexts are $`(\delta,\mathsf{iv}(U,0))`$, the leaf
contexts are $`(\delta,\mathsf{iv}(U,j))`$ for $`j \ge 1`$, and no trunk keyed
context equals any leaf keyed context. Thus every trunk transcript in
$`\mathsf{TrunkWrap}^{\mathsf{IXIF}}[\mathrm{ro}_{\mathsf{tr}}]`$ and every
leaf transcript in
$`\mathsf{LeafWrap}^{\mathsf{IXIF}}[\mathrm{ro}_{\mathsf{leaf}}]`$ starts from a
fresh IXIF root.

Now follow the canonical TreeWrap schedule of Section 4.7. Each later stage is
obtained by appending deterministic transcript inputs to one of these fresh
roots. Hence every body-phase IXIF response and every squeeze response that
contributes to a visible output block is generated on a fresh IXIF path. For a
visible body block, the returned ciphertext block is obtained by XORing the
corresponding plaintext block with the leftmost visible part of a fresh uniform
$`r`$-bit IXIF response, and is therefore uniformly distributed on strings of
that visible length. Likewise, the final trunk tag is the leftmost $`\tau`$ bits
of a fresh uniform IXIF response on the final trunk squeeze path and is
therefore uniform on $`\{0,1\}^{\tau}`$.

Because the left-right query requires $`|P_0| = |P_1|`$, the chunk count
$`\chi(P_b)`$, the per-chunk visible lengths, and the resulting visible block
layout are all public and identical for $`b=0`$ and $`b=1`$. Therefore the
distribution of the returned ciphertext depends only on this public chunk
structure and visible block layout, not on the challenge bit.

The ideal leaf oracle $`\mathrm{ro}_{\mathsf{leaf}}`$ and the ideal trunk
oracle $`\mathrm{ro}_{\mathsf{tr}}`$ are sampled independently of the real
permutation $`p`$ and independently of one another. Hence the primitive
oracles remain challenge-independent in both games, while Lemma 6.3 shows that
every left-right answer has the same conditional distribution given the prior
adaptive view in world $`0`$ and in world $`1`$.
Induction over the full adaptive transcript therefore gives

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
N_{\mathsf{leaf}}^{\mathsf{ae}} = N + \sigma^{\mathsf{tr}}_e + \sigma^{\mathsf{tr}}_d
```

as the relevant primitive-query budget for the leaf distinguisher, because the
unchanged trunk transcript is still realized directly via $`p`$ in this hop.
Hence

```math
\left| \Pr[H_0(\mathcal{A}) = 1] - \Pr[H_1(\mathcal{A}) = 1] \right|
\le
\epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,Q_{\mathsf{IV,leaf}},N_{\mathsf{leaf}}^{\mathsf{ae}}).
```

For the second hop, Corollary 4.7 yields

```math
\left| \Pr[H_1(\mathcal{A}) = 1] - \Pr[H_2(\mathcal{A}) = 1] \right|
\le
\epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,Q_{\mathsf{IV,tr}},L_{\mathsf{tr}},N).
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

For each candidate, apply Lemma 7.1. In the final IXIF game, every valid fresh
candidate either forces a fresh final trunk-tag path, costing $`2^{-\tau}`$,
or else its final trunk-tag path is not fresh and therefore some earliest later
leaf transcript must collide with the unique prior hidden leaf tag on that
keyed path, costing at most $`2^{-t_{\mathsf{leaf}}}`$. Thus, for each fixed
candidate index $`d`$,

```math
\Pr[(\delta^{(d)},U^{(d)},A^{(d)},C^{(d)}) \text{ is a valid fresh forgery in } H_2]
\le
2^{-\min\{t_{\mathsf{leaf}},\tau\}}.
```

Taking a union bound over the at most $`q_f`$ final candidates gives

```math
\Pr[H_2(\mathcal{A}) = 1]
\le
\frac{q_f}{2^{\min\{t_{\mathsf{leaf}},\tau\}}}.
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

At this point no new TreeWrap-specific argument remains. The pair
$`G_0,G_1`$ is exactly the IND-CPA experiment of Section 4.1 with a dummy
decryption oracle, so the privacy side is inherited verbatim from the
canonical-schedule IND-CPA analysis of Section 6.2. Concretely, there is an
IND-CPA adversary $`\mathcal{B}_1`$ that forwards all left-right and primitive
queries of $`\mathcal{A}`$ unchanged and answers decryption queries locally
with $`\bot`$, such that

```math
\Pr[G_b(\mathcal{A}) = 1]
=
\Pr[(\mathrm{IND}\text{-}\mathrm{CPA})^{\mathsf{TreeWrap}}_b(\mathcal{B}_1) = 1]
```

for each $`b`$. This reduction preserves the entire left-right transcript and
the primitive-query transcript exactly, so it preserves $`q_e`$, $`N`$, and the
induced encryption-side lower-level resources.

To bound $`\Pr[\mathsf{Bad}_b]`, define an INT-CTXT adversary
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
forgery. This is exactly the setting handled by the canonical-schedule
INT-CTXT analysis of Section 6.3, so no separate CCA2-side freshness split is
needed. Hence

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
resource bounds gives the displayed instantiated IND-CCA2 bound. Thus the
CCA2 proof is only a BN00 wrapper around the already-established
canonical-schedule privacy and authenticity endgames.

## 7. TreeWrap Proofs

This section contains the TreeWrap-specific arguments: the authenticity
freshness split needed for the AE path and the public-permutation commitment
analysis.

### 7.1 Ideal TreeWrap Authenticity Under the Canonical Schedule

**Lemma 7.1 (Ideal TreeWrap Authenticity Under the Canonical Schedule).** Fix
any final IXIF game obtained after replacing the real trunk and leaf families by
their IXIF counterparts. Let $`(\delta,U,A,C)`$ be a valid fresh forgery
candidate, write

```math
C = Y \| T,
\qquad
Y = Y_0 \| \cdots \| Y_{n-1},
```

and let decryption under the canonical TreeWrap schedule of Section 4.7 recover

```math
X = X_0 \| \cdots \| X_{n-1},
```

together with the hidden leaf-tag vector

```math
\Sigma :=
\begin{cases}
\epsilon, & \text{if } n \le 1,\\
T_1 \| \cdots \| T_{n-1}, & \text{if } n \ge 2.
\end{cases}
```

Then every such candidate satisfies one of the following:

1. **Fresh final trunk-tag path.** The final trunk squeeze path is fresh in the
   trunk keyed context $`(\delta,\mathsf{iv}(U,0))`$. Then acceptance requires
   guessing a fresh $`\tau`$-bit trunk tag, costing $`2^{-\tau}`$.

2. **Earliest later hidden leaf-tag collision.** The final trunk squeeze path
   is not fresh. Then there exists a unique prior encryption in the same trunk
   keyed context, and because the ciphertext candidate is fresh there is a
   smallest later index $`j^\star \ge 1`$ at which the visible chunk
   $`Y_{j^\star}`$ differs from that prior encryption. At this index the
   recomputed hidden leaf tag $`T_{j^\star}`$ must collide with the unique prior
   hidden leaf tag in keyed context
   $`(\delta,\mathsf{iv}(U,j^\star))`$, costing at most
   $`2^{-t_{\mathsf{leaf}}}`$.

When $`n \le 1`$, only case 1 can arise.

Consequently each valid fresh candidate succeeds with probability at most

```math
2^{-\min\{t_{\mathsf{leaf}},\tau\}},
```

and a union bound over at most $`q_f`$ final candidates contributes the explicit
tail

```math
\frac{q_f}{2^{\min\{t_{\mathsf{leaf}},\tau\}}}.
```

**Proof.** Fix one final candidate and compare its decryption-side canonical
schedule against prior encryption schedules in the same keyed contexts. By
Lemma 4.1 and per-user nonce-respecting behavior, there is at most one prior
encryption in the trunk keyed context $`(\delta,\mathsf{iv}(U,0))`$. If no such
encryption exists, then the trunk root itself is fresh and therefore the final
trunk squeeze path is fresh, giving case 1.

Assume now that such a prior encryption exists. Compare the candidate against
this unique prior encryption along the canonical schedule.

If the schedules differ during the trunk associated-data phase or during the
trunk first-chunk body phase, then the trunk transcript diverges before the
final squeeze. Hence the final trunk-tag path is fresh and we are again in
case 1.

Otherwise the trunk prefix replays exactly. Let $`\Sigma^\star`$ denote the
hidden leaf-tag vector of the unique prior encryption in this same trunk keyed
context. If $`\Sigma \ne \Sigma^\star`$, then the two schedules first diverge in
the trunk absorb of the leaf-tag vector, so the final trunk squeeze path is
fresh and we are again in case 1.

It remains to consider the branch $`\Sigma = \Sigma^\star`$. Since the candidate
is fresh, its full ciphertext differs from the unique prior encryption. The
trunk prefix already replays exactly, and the final tag is determined by the
same nonfresh final trunk path, so there must exist a smallest later index
$`j^\star \ge 1`$ such that the visible chunk $`Y_{j^\star}`$ differs from the
corresponding visible chunk of the prior encryption. Because the keyed context
$`(\delta,\mathsf{iv}(U,j^\star))`$ is the same on both sides, this difference
forces the corresponding decryption-side leaf transcript to diverge from the
prior encryption transcript before its final squeeze phase; otherwise the same
deterministic IXIF path would reproduce the same visible chunk. Hence the leaf
tag $`T_{j^\star}`$ is uniform on a fresh IXIF squeeze path.

But we are in the branch $`\Sigma = \Sigma^\star`$, so in particular
$`T_{j^\star} = T^\star_{j^\star}`$, where $`T^\star_{j^\star}`$ is the unique
prior hidden leaf tag in keyed context
$`(\delta,\mathsf{iv}(U,j^\star))`$. By Lemma 4.1 there is at most one such
prior encryption-side tag target, and the INT-CTXT experiment exposes no
decryption-side leaf tags to the adversary. Therefore the collision target set
has size at most one, and the probability of this hidden leaf-tag collision is
at most $`2^{-t_{\mathsf{leaf}}}`$. Equality of the full vectors
$`\Sigma = \Sigma^\star`$ also forces every later divergent leaf tag to match,
but charging the earliest index $`j^\star`$ alone is sufficient because the
probability of a conjunction is at most the probability of any one conjunct.

Thus every valid fresh candidate lies either in case 1 or in case 2, and these
cases are mutually exclusive by definition of the final trunk-tag path. This
yields the stated per-candidate bound. Applying a union bound over the at most
$`q_f`$ final candidates gives the displayed tail.

### 7.2 Canonical-Schedule Injectivity for TreeWrap

Let

```math
\Theta := ((K_1,U_1,A_1,P_1),(K_2,U_2,A_2,P_2))
```

be a fixed distinct tuple pair with $`|P_1|=|P_2|`$. Write the canonical chunk
decompositions

```math
P_\nu = P_{\nu,0} \| \cdots \| P_{\nu,n-1},
\qquad
\nu \in \{1,2\},
\qquad
n := \chi(P_1) = \chi(P_2),
```

and consider the two flattened encryptions

```math
\mathsf{TW}^{\flat}[p](K_1,U_1,A_1,P_1),
\qquad
\mathsf{TW}^{\flat}[p](K_2,U_2,A_2,P_2)
```

under the canonical schedule of Sections 4.7 and 4.9. By Lemma 4.9, each
flattened transcript induces a family of absorbed $`\hat r`$-bit blocks for the
prefix-sponge view. The initialization block at trunk or leaf stage $`j`$ is

```math
I_{K,U,j}
:=
K \| \mathsf{iv}_{\mathsf{rate}}(U,j) \| 0,
```

and every later trunk or leaf absorb step contributes the $`\hat r`$-bit prefix
of the corresponding framed full-state block.

**Lemma 7.2 (Canonical-Schedule Injectivity for TreeWrap).** For any fixed
distinct tuple pair $`\Theta`$ with $`|P_1|=|P_2|`$, the two compared
flattened encryptions cannot induce exactly the same canonical-schedule input
family. Equivalently, there exists at least one canonical schedule stage at
which the two sides either present different absorbed $`\hat r`$-bit blocks to
the prefix-sponge view of Section 4.9, or one side performs an absorb step
that the other omits.

More concretely, at least one of the following cases holds.

1. **Different trunk initialization.**
   If $`(K_1,U_1) \ne (K_2,U_2)`$, then

   ```math
   I_{K_1,U_1,0} \ne I_{K_2,U_2,0}.
   ```

2. **Different trunk associated-data phase.**
   If $`(K_1,U_1)=(K_2,U_2)`$ but $`A_1 \ne A_2`$, then the padded block
   sequences of $`A_1\|\lambda_{\mathsf{ad}}`$ and
   $`A_2\|\lambda_{\mathsf{ad}}`$ either differ at some associated-data absorb
   step, or exactly one side omits the associated-data phase and the two
   schedules therefore diverge at the first post-initialization trunk stage.

3. **Different first-chunk body phase.**
   If $`(K_1,U_1,A_1)=(K_2,U_2,A_2)`$ but $`P_{1,0} \ne P_{2,0}`$, then the
   framed trunk body sequences for the first chunks differ, so the trunk
   first-chunk body phase absorbs different blocks at some stage.

4. **Different later leaf body phase.**
   If $`(K_1,U_1,A_1,P_{1,0})=(K_2,U_2,A_2,P_{2,0})`$ but
   $`P_{1,j^\star} \ne P_{2,j^\star}`$ for some smallest later index
   $`j^\star \ge 1`$, then the framed leaf body sequences at that leaf stage
   differ.

**Proof.** Because $`|P_1|=|P_2|`$, the fixed chunk size induces the same chunk
count $`n`$ and the same chunk-length profile on both sides. We now inspect the
tuple components in canonical schedule order.

If $`(K_1,U_1) \ne (K_2,U_2)`$, then injectivity of
$`\mathsf{iv}_{\mathsf{rate}}`$ gives
$`I_{K_1,U_1,0} \ne I_{K_2,U_2,0}`$, so case 1 holds.

Assume henceforth that $`(K_1,U_1)=(K_2,U_2)`$. If $`A_1 \ne A_2`$, then the
strings $`A_1\|\lambda_{\mathsf{ad}}`$ and $`A_2\|\lambda_{\mathsf{ad}}`$ are
distinct. If both associated-data phases are nonempty, then the trunk
associated-data phase absorbs the padded full-state block sequences of these
two strings, and the corresponding $`\hat r`$-bit prefixes therefore differ at
some trunk absorb step because the formatting with $`\lambda_{\mathsf{ad}}`$
is injective.

Otherwise, exactly one side omits the associated-data phase; without loss of
generality, let $`A_1 \ne \epsilon`$ and $`A_2 = \epsilon`$. On side $`1`$, the
first post-initialization trunk absorb step is the first associated-data block,
whose prefix-sponge input has the form $`W \| 0`$ because associated-data uses
$`0^c`$ framing. On side $`2`$, the associated-data phase is absent, so the
next canonical trunk stage is either the first-chunk body phase, whose
prefix-sponge input has the form $`W' \| 1`$ because body blocks use
$`1 \| 0^{c-1}`$ framing, or the final squeeze stage if $`n=0`$, whose
prefix-sponge input is $`0^{\hat r}`$. In the former subcase the absorbed
prefixes differ immediately by the framing bit; in the latter subcase the
nonzero first associated-data block on side $`1`$ differs from the zero squeeze
block on side $`2`$ because $`\mathrm{pad}10^*`$ guarantees at least one
nonzero bit in the padded associated-data block. Thus case 2 holds in all
branches.

Assume next that $`(K_1,U_1,A_1)=(K_2,U_2,A_2)`$. If
$`P_{1,0} \ne P_{2,0}`$, then the framed trunk body encodings of the first
chunks differ, so the trunk first-chunk body phase absorbs different
prefix-sponge blocks. This is case 3.

It remains to consider the branch
$`(K_1,U_1,A_1,P_{1,0})=(K_2,U_2,A_2,P_{2,0})`$. Because the tuples are
distinct, there must be some later chunk index $`j^\star \ge 1`$ with
$`P_{1,j^\star} \ne P_{2,j^\star}`$; let $`j^\star`$ be the smallest such
index. The two leaf transcripts at this stage use the same keyed context, but
they process different chunk inputs, so their framed leaf body encodings
differ. Hence the corresponding leaf stage absorbs different prefix-sponge
blocks, which is case 4.

Thus every distinct equal-length tuple pair differs in at least one
canonical-schedule input stage, proving the claim.

### 7.3 Ideal-Duplex Tag Endgame for TreeWrap

Retain the notation of Lemma 7.2 and work in the ideal sponge world furnished
by Lemma 4.10: every queried absorbed prefix receives an ideal random-oracle
answer, truncated to the requested visible length, with consistency only across
repeated identical prefixes.

**Lemma 7.3 (Ideal-Duplex Tag Endgame for TreeWrap).** Fix a distinct equal-
length tuple pair $`\Theta`$ and the corresponding idealized canonical
comparison schedule. Then the probability that the two compared encryptions
produce the same ciphertext is at most

```math
\frac{1}{2^{\min\{t_{\mathsf{leaf}}+1,\tau\}}}.
```

More precisely:

1. if the first canonical-schedule input divergence of Lemma 7.2 occurs in the
   trunk initialization, trunk associated-data phase, or trunk first-chunk body
   phase, then ciphertext collision costs at most $`2^{-\tau}`$;
2. if the first canonical-schedule input divergence occurs at a later leaf
   stage $`j^\star \ge 1`$, then ciphertext collision costs at most
   $`2^{-(t_{\mathsf{leaf}}+1)}`$ when the divergent leaf path still matches on
   a visible body bit and on the hidden leaf tag, and otherwise at most
   $`2^{-\tau}`$ through the final trunk tag.

**Proof.** By Lemma 7.2, the two compared idealized schedules differ at some
canonical input stage.

If this first divergence occurs in the trunk initialization, trunk
associated-data phase, or trunk first-chunk body phase, then the two trunk
prefixes differ before the final trunk squeeze. If any visible body block
already differs, then the ciphertexts are unequal and the collision
probability is zero. Otherwise all visible body blocks agree, so the final
trunk tag is the first remaining caller-visible output on two distinct ideal
prefixes. Matching that $`\tau`$-bit tag costs at most $`2^{-\tau}`$.

Assume now that the first divergence occurs at a later leaf stage
$`j^\star \ge 1`$. If the visible leaf body output at that stage differs, then
the ciphertexts are already unequal. So only the branch where the visible leaf
body chunk agrees can contribute to a collision.

In that branch, two possibilities remain. First, the hidden leaf tags also
agree. We are already in the branch where the visible leaf body matches, and
because this later leaf stage is nonempty, that visible agreement includes at
least one visible body bit. Requiring the hidden leaf tag to match as well
therefore costs at most $`2^{-(t_{\mathsf{leaf}}+1)}`$.

Second, the hidden leaf tags differ. Then the trunk leaf-tag absorb phase later
receives different inputs, so the trunk prefixes diverge before the final
squeeze. At that point the visible bodies are already equal by assumption, so a
full ciphertext collision can occur only if the final trunk tags also agree,
costing at most $`2^{-\tau}`$.

These two subbranches are disjoint. Therefore the later-leaf branch is bounded
by the larger of the two costs, namely

```math
2^{-\min\{t_{\mathsf{leaf}}+1,\tau\}},
```

and combining this with the trunk-divergence branch proves the stated bound.

### 7.4 Proof of Theorem 5.4

Fix a CMT-4 adversary $`\mathcal{A}`$ making at most $`N`$ primitive queries,
and compare two games.

- In the real game, after $`\mathcal{A}`$ outputs its distinct tuple pair,
  TreeWrap encryptions are computed from the real permutation.
- In the ideal post-output game, the same tuple pair is instead evaluated via
  the ideal sponge answers of Lemma 4.10 on the corresponding prefix-sponge
  query families.

Because $`\mathcal{A}`$ sees only the primitive oracles before it outputs its
pair, the prior primitive transcript and the output distribution of
$`\mathcal{A}`$ are identical in these two games. By Lemma 4.8 and Lemma 4.9,
the post-output encryption computation in the real game is exactly the
flattened prefix-sponge computation associated with the two compared
encryptions. Lemma 4.10 therefore bounds the change in success probability
between the two games by
$`\epsilon_{\mathsf{ideal}}(M_{\mathsf{tw}}^{\max}(\mathcal{A},N))`$.

It remains to bound success in the ideal post-output game. Condition on the
realized tuple pair

```math
\Theta := ((K_1,U_1,A_1,P_1),(K_2,U_2,A_2,P_2)).
```

If $`|P_1| \ne |P_2|`$, then TreeWrap is length preserving and ciphertext
collision is impossible. Otherwise the pair is a distinct equal-length tuple
pair, so Lemma 7.2 guarantees a canonical-schedule input divergence and Lemma
7.3 bounds the resulting ideal-world collision probability by
$`2^{-\min\{t_{\mathsf{leaf}}+1,\tau\}}`$. This bound is uniform over all
realized equal-length output pairs, so it also bounds the unconditional success
probability of the ideal post-output game.

Combining the imported experiment-level replacement step with this ideal-world
tail yields Theorem 5.4:

```math
\mathrm{Adv}^{\mathsf{cmt}\text{-}4}_{\mathsf{TreeWrap}}(\mathcal{A})
\le
\epsilon_{\mathsf{ideal}}(M_{\mathsf{tw}}^{\max}(\mathcal{A},N))
+
\frac{1}{2^{\min\{t_{\mathsf{leaf}}+1,\tau\}}}.
```

## 8. TW128 Instantiation

We instantiate TreeWrap as a concrete octet-oriented scheme $`\mathsf{TW128}`$
based on the twelve-round Keccak permutation from [FIPS202]. The goal of this
instantiation is a 128-bit security target with a 256-bit final tag, a 256-bit
leaf tag, and an empirically tuned chunk size of 8128 bytes. The choice of
$`\mathrm{Keccak\text{-}p}[1600,12]`$ is not novel to TreeWrap: it follows the
software-oriented KangarooTwelve and TurboSHAKE precedent of [BDPVAVKV18, RFC9861],
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
- rate-side IV payload space:
  $`\mathcal{IV}_{\mathsf{rate}} = \{0,1\}^{1088}`$;
- admissible keyed-duplex IV image:
  $`\mathcal{IV} = \{ V \| 0^{256} : V \in \mathcal{IV}_{\mathsf{rate}} \}`$;
- nonce space: $`\mathcal{U} = \{0,1\}^{128}`$;
- chunk size: $`B = 65024`$ bits $`= 8128`$ bytes;
- leaf tag size: $`t_{\mathsf{leaf}} = 256`$;
- final tag size: $`\tau = 256`$;
- associated-data phase trailer: $`\lambda_{\mathsf{ad}} = \mathtt{00}`$;
- leaf-tag phase trailer: $`\lambda_{\mathsf{tc}} = \mathtt{01}`$;
- IV-suffix encoding: $`\nu = \mathrm{right\_encode}`$ from [SP800185].

Here $`\chi(P) := \lceil |P| / B \rceil`$ denotes the canonical chunk count of
the plaintext under the concrete chunk size $`B = 65024`$. Also,
$`\mathrm{right\_encode}`$ in [SP800185] is the integer encoder applied here to
the suffix value $`j`$. The concrete `TW128` interface itself operates on octet
strings throughout. Concretely,
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
nonce and suffix value into the $`r-k = 1088`$-bit rate-side IV payload used by
the generic model. Define the concrete rate-side IV-derivation map

```math
\mathsf{iv}_{\mathsf{rate}}^{\mathsf{TW128}}
: \mathcal{U} \times \{0,\ldots,2^{952}-1\}
\to
\mathcal{IV}_{\mathsf{rate}}
```

by

```math
\mathsf{iv}_{\mathsf{rate}}^{\mathsf{TW128}}(U,j)
:=
0^{1088 - 128 - |\nu(j)|} \| U \| \nu(j),
```

which is well defined exactly for suffix values $`0 \le j \le 2^{952}-1`$. The
actual keyed-duplex IV is then

```math
\mathsf{iv}^{\mathsf{TW128}}(U,j)
:=
\mathsf{iv}_{\mathsf{rate}}^{\mathsf{TW128}}(U,j) \| 0^{256}.
```

In the present design the trunk always uses $`j = 0`$, while leaf calls on
chunks $`i \ge 1`$ use $`j = i`$. Thus

```math
V_{\mathsf{tr}}(U) := \mathsf{iv}^{\mathsf{TW128}}(U,0),
\qquad
V_i(U) := \mathsf{iv}^{\mathsf{TW128}}(U,i)
\quad\text{for } i \ge 1.
```

Because the nonce length is fixed and $`\nu = \mathrm{right\_encode}`$ is
injective, this yields an injective embedding of the trunk and leaf IV
namespaces into the 1088-bit rate-side IV payload, and hence into the
admissible keyed-duplex IV image by appending $`0^{256}`$. The resulting size
bound is not restrictive in practice: it allows up to $`2^{952}`$ distinct suffix values,
far beyond any realistic number of chunks. Outside this range the concrete IV
embedding is undefined, so $`\mathsf{TW128.ENC}`$ and $`\mathsf{TW128.DEC}`$
are defined only on inputs whose canonical chunk count satisfies $`\chi(P) \le
2^{952}`$. More generally, the same 1088-bit rate-side IV payload budget would easily
accommodate a 256-bit nonce variant with the same rate, capacity, and
duplex-call counts; only the concrete IV-embedding map would change.

For $`\mathsf{TW128}`$, both the leaf tag and the final trunk tag fit within a
single $`r = 1344`$-bit squeeze block, so

```math
s_{\mathsf{leaf}} = s_{\mathsf{tr}} = 1.
```

Thus raising the leaf tag from 128 to 256 bits does not change the local leaf
transcript length: each remaining chunk still performs one blank squeeze for
its hidden tag. The concrete cost appears only in the trunk leaf-tag phase,
which absorbs an additional $`128 \max(\chi(P)-1,0)`$ bits across the leaf tag
vector. This tradeoff is favorable for $`\mathsf{TW128}`$, because it
materially strengthens the INT-CTXT guessing term while increasing the global
commitment schedule cost only through that trunk absorb.

For the leaf resource accounting of Section 4.5, a full remaining chunk has
length $`65024`$ bits, so

```math
\omega_r(65024) = \left\lceil \frac{65024+1}{1344} \right\rceil = 49,
\qquad
\omega_r(65024) + s_{\mathsf{leaf}} = 50.
```

Hence each full remaining chunk contributes $`50`$ transcript-extension calls
to $`\sigma_{\mathsf{leaf}}(P)`$. More generally, if the final remaining chunk
has length $`\lambda`$ bits, where $`0 < \lambda \le 65024`$ and $`\lambda`$ is
a multiple of $`8`$, then its leaf contribution is

```math
\left\lceil \frac{\lambda+1}{1344} \right\rceil + 1.
```

For the concrete commitment accounting, however, it is more informative not to
collapse these local transcripts into the total schedule length. A later leaf
transcript on a nonempty chunk of length $`\lambda`$ bits makes one visible-body
query to the prefix-sponge view at each prefix length
$`1,\ldots,\omega_r(\lambda)`$, and one hidden-tag query at the final prefix
length $`\omega_r(\lambda)+1`$. Hence its exact local prefix-sponge cost is

```math
\Phi_{\mathsf{leaf}}(\lambda)
:=
\sum_{h=1}^{\omega_r(\lambda)} (h+1)
+
(\omega_r(\lambda)+2)
=
\frac{\omega_r(\lambda)^2 + 5\omega_r(\lambda) + 4}{2}.
```

For a full remaining chunk this gives

```math
\Phi_{\mathsf{leaf}}(65024) = \frac{49^2 + 5 \cdot 49 + 4}{2} = 1325.
```

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

For commitment, Theorem 5.4 is evaluated at the effective prefix-sponge
parameters

```math
\hat r = r+1 = 1345,
\qquad
\hat c = c-1 = 255.
```

Only the first-chunk body phase and the final trunk tag contribute
output-bearing prefix-sponge queries in the trunk. Hence the exact local trunk
prefix-sponge cost is

```math
\Phi_{\mathsf{tr}}(A,P)
:=
\sum_{h=\alpha_r(A)+1}^{\alpha_r(A)+\beta_r(P)} (h+1)
+
(\alpha_r(A)+\beta_r(P)+\gamma_r(P)+2)
```

```math
=
\alpha_r(A)(\beta_r(P)+1)
+
\frac{\beta_r(P)(\beta_r(P)+5)}{2}
+
\gamma_r(P)
+
2.
```

Thus:

- the empty-message path contributes

  ```math
  \Phi_{\mathsf{tr}}(A,\epsilon) = \alpha_r(A) + 2;
  ```

- a one-chunk full-block message with empty associated data contributes

  ```math
  \Phi_{\mathsf{tr}}(\epsilon,P) = \frac{49 \cdot 54}{2} + 2 = 1325;
  ```

- a message of $`n`$ full chunks with empty associated data contributes

  ```math
  \Phi_{\mathsf{tr}}(\epsilon,P)
  =
  1325
  +
  \left\lceil \frac{(n-1)256+9}{1344} \right\rceil.
  ```

For any fixed distinct equal-length tuple pair
$`\Theta=((K_1,U_1,A_1,P_1),(K_2,U_2,A_2,P_2))`$ and prior primitive-query
budget $`N`$, the exact local prefix-sponge cost of the compared pair is

```math
M_{\Theta}^{\mathsf{loc}}
:=
N
+
\Phi_{\mathsf{tr}}(A_1,P_1)
+
\Phi_{\mathsf{tr}}(A_2,P_2)
+
\sum_{j=1}^{\chi(P_1)-1} \Phi_{\mathsf{leaf}}(|P_{1,j}|)
+
\sum_{j=1}^{\chi(P_2)-1} \Phi_{\mathsf{leaf}}(|P_{2,j}|).
```

This is the exact [BDPVA08] cost of the output-bearing query family induced by
Lemma 4.9 for the concrete $`\mathsf{TW128}`$ wrapper. Unlike the generic
schedule-collapse upper bound of Section 4.9, it grows linearly with the
number of later chunks at fixed chunk size. In particular, for empty
associated data and equal-length messages of $`n`$ full chunks on both sides,
it simplifies to

```math
M_{\Theta}^{\mathsf{loc}}
=
N
+
2 \left(
1325 n
+
\left\lceil \frac{(n-1)256+9}{1344} \right\rceil
\right).
```

Thus Section 4.9 continues to provide the generic theorem-level upper bound in
terms of $`M_{\mathsf{tw}}^{\max}(\mathcal{A},N)`$, while the present
$`\mathsf{TW128}`$ specialization replaces that coarse schedule-collapse bound
by the tighter exact local cost $`M_{\Theta}^{\mathsf{loc}}`$ on each realized
output pair.

Evaluated at this exact local cost, the imported TW128 ideality term satisfies

```math
\epsilon_{\mathsf{ideal}}(M_{\Theta}^{\mathsf{loc}})
\lesssim
\frac{
(1-2^{-1345})(M_{\Theta}^{\mathsf{loc}})^2
+
(1+2^{-1345})M_{\Theta}^{\mathsf{loc}}
}{2^{256}},
```

which is extremely close to $`(M_{\Theta}^{\mathsf{loc}})^2 / 2^{256}`$ at all
practical scales. Thus the imported commitment term remains capacity-limited at
the intended 128-bit generic target. For the full-chunk empty-AD family above
with $`N = 0`$, this leading imported term does not reach the $`2^{-128}`$
scale until $`n`$ is about $`6.96 \times 10^{15}`$ chunks, i.e. about
$`49`$ EiB per message.

The remaining TreeWrap-specific tail of Theorem 5.4 specializes to

```math
\frac{1}{2^{\min\{t_{\mathsf{leaf}}+1,\tau\}}}
=
\frac{1}{2^{256}}.
```

This is exactly the 256-bit final-tag scale. In the concrete octet-oriented
format one could sharpen the leaf branch further, because any nonempty later
chunk contributes at least one visible octet before its hidden leaf tag, but
the generic expression above already specializes cleanly for $`\mathsf{TW128}`$.
Likewise, although the commitment wrapper uses the effective hidden suffix
$`\hat c = 255`$, the imported sponge denominator is $`2^{\hat c+1}=2^{256}`$,
so the leading $`\mathsf{TW128}`$ commitment term still lands at the intended
128-bit birthday scale.

Substituting these parameters into Theorems 5.1, 5.2, and 5.4 yields the
concrete parameterized security statements for $`\mathsf{TW128}`$. On the AE
side, these remain explicit $`\mu`$-user formulas: the imported trunk terms are
evaluated at the adversary's primitive-query budget $`N`$, while the imported
leaf terms are evaluated at the enlarged leaf-hop budgets
$`N_{\mathsf{leaf}}^{\mathsf{enc}}`$ and $`N_{\mathsf{leaf}}^{\mathsf{ae}}`$.
Thus a fully numeric deployment claim must fix concrete caps for $`\mu`$,
$`N`$, and the induced trunk and leaf transcript resources, and then evaluate
the imported [Men23] expressions. The present section therefore fixes the
algorithmic parameters and the exact terms to be evaluated, but does not bake
in deployment-specific resource caps. Under any such concrete caps satisfying
the low-complexity side conditions of Section 4.6, the dominant generic terms
remain capacity-limited and target the intended 128-bit level, while the
commitment bound becomes the sum of one imported capacity-limited sponge term
and one short explicit tag-dominated tail.
In particular, the pairwise-user term $`\binom{\mu}{2}/2^{256}`$ remains below
the $`2^{-128}`$ scale until $`\mu`$ is on the order of $`2^{64}`$ users, so
it is negligible throughout any realistic deployment regime.

**Corollary 8.1 (TW128 Security).** Let $`\mathcal{A}`$ be an adversary against
$`\mathsf{TW128}`$ in the corresponding $`\mu`$-user experiment, and let the
induced lower-level resources be as in Sections 4.5 and 4.6. Throughout this
corollary, all wrapper inputs are assumed to lie in the defined domain of
$`\mathsf{TW128}`$; equivalently, every queried or extracted message has
canonical chunk count at most $`2^{952}`$. As in Section 5, write

```math
N_{\mathsf{leaf}}^{\mathsf{enc}} := N + \sigma^{\mathsf{tr}}_e,
\qquad
N_{\mathsf{leaf}}^{\mathsf{ae}} := N + \sigma^{\mathsf{tr}}_e + \sigma^{\mathsf{tr}}_d.
```

- If $`\sigma^{\mathsf{tr}}_e + N \le 0.1 \cdot 2^{256}`$ and
  $`\sigma^{\mathsf{leaf}}_e + N_{\mathsf{leaf}}^{\mathsf{enc}} \le
  0.1 \cdot 2^{256}`$, then

  ```math
  \mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cpa}}_{\mathsf{TW128}}(\mathcal{A})
  \le
  \epsilon_{\mathsf{tr}}^{\mathsf{enc}}(\mu,q^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_e,N)
  +
  \epsilon_{\mathsf{leaf}}^{\mathsf{enc}}(\mu,\chi_{\mathsf{leaf},e},\sigma^{\mathsf{leaf}}_e,N_{\mathsf{leaf}}^{\mathsf{enc}}),
  ```

  where the imported [Men23] terms are evaluated with
  $`(b,r,c,k) = (1600,1344,256,256)`$ and the concrete rate-side IV embedding
  defined above.

- If $`\sigma^{\mathsf{tr}}_e + \sigma^{\mathsf{tr}}_d + N \le 0.1 \cdot 2^{256}`$
  and
  $`\sigma^{\mathsf{leaf}}_e + \sigma^{\mathsf{leaf}}_d +
  N_{\mathsf{leaf}}^{\mathsf{ae}} \le 0.1 \cdot 2^{256}`$, then

  ```math
  \mathrm{Adv}^{\mathsf{int}\text{-}\mathsf{ctxt}}_{\mathsf{TW128}}(\mathcal{A})
  \le
  \epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,\mu+q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_d,N)
  +
  \epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,\mu+q_f,N_{\mathsf{leaf}}^{\mathsf{ae}})
  +
  \frac{q_f}{2^{256}}.
  ```

- Consequently, under the same side conditions, IND-CCA2 specializes to

  ```math
  \mathrm{Adv}^{\mathsf{ind}\text{-}\mathsf{cca2}}_{\mathsf{TW128}}(\mathcal{A})
  \le
  \epsilon_{\mathsf{tr}}^{\mathsf{enc}}(\mu,q^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_e,N)
  +
  \epsilon_{\mathsf{leaf}}^{\mathsf{enc}}(\mu,\chi_{\mathsf{leaf},e},\sigma^{\mathsf{leaf}}_e,N_{\mathsf{leaf}}^{\mathsf{enc}})
  +
  2 \cdot \epsilon_{\mathsf{tr}}^{\mathsf{ae}}(\mu,q^{\mathsf{tr}}_e,q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_e,\sigma^{\mathsf{tr}}_d,\mu+q^{\mathsf{tr}}_d,\sigma^{\mathsf{tr}}_d,N)
  +
  2 \cdot \epsilon_{\mathsf{leaf}}^{\mathsf{ae}}(\mu,\chi_{\mathsf{leaf},e},\chi_{\mathsf{leaf},d},\sigma^{\mathsf{leaf}}_e,\sigma^{\mathsf{leaf}}_d,\mu+q_d,N_{\mathsf{leaf}}^{\mathsf{ae}})
  +
  \frac{2 q_d}{2^{256}}.
  ```

- For any CMT-4 adversary $`\mathcal{A}`$ against $`\mathsf{TW128}`$ making at
  most $`N`$ primitive queries, write for each realized equal-length output
  pair
  $`\Theta=((K_1,U_1,A_1,P_1),(K_2,U_2,A_2,P_2))`$

  one has

  ```math
  M_{\Theta}^{\mathsf{loc}}
  :=
  N
  +
  \Phi_{\mathsf{tr}}(A_1,P_1)
  +
  \Phi_{\mathsf{tr}}(A_2,P_2)
  +
  \sum_{j=1}^{\chi(P_1)-1} \Phi_{\mathsf{leaf}}(|P_{1,j}|)
  +
  \sum_{j=1}^{\chi(P_2)-1} \Phi_{\mathsf{leaf}}(|P_{2,j}|),
  ```

  and let

  ```math
  M_{\mathsf{loc}}^{\max}(\mathcal{A},N)
  :=
  \max_{\substack{\Theta \in \mathrm{Supp}(\mathcal{A})\\|P_1|=|P_2|}} M_{\Theta}^{\mathsf{loc}}.
  ```

  ```math
  \mathrm{Adv}^{\mathsf{cmt}\text{-}4}_{\mathsf{TW128}}(\mathcal{A})
  \le
  \epsilon_{\mathsf{ideal}}(M_{\mathsf{loc}}^{\max}(\mathcal{A},N))
  +
  \frac{1}{2^{256}}.
  ```

  In particular, the imported TW128 sponge term may be approximated in the
  low-complexity regime by

  ```math
  \epsilon_{\mathsf{ideal}}(M_{\mathsf{loc}}^{\max}(\mathcal{A},N))
  \lesssim
  \frac{
  (1-2^{-1345})(M_{\mathsf{loc}}^{\max}(\mathcal{A},N))^2
  +
  (1+2^{-1345})M_{\mathsf{loc}}^{\max}(\mathcal{A},N)
  }{2^{256}},
  ```

  which is essentially
  $`(M_{\mathsf{loc}}^{\max}(\mathcal{A},N))^2 / 2^{256}`$ at practical
  scales, while the explicit TreeWrap-specific tail is already dominated by
  $`2^{-256}`$.

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
\frac{q_f}{2^{256}} = 2^{-224}.
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
\frac{q_f}{2^{256}} \approx 2^{-128},
```

that is, when $`q_f`$ approaches $`2^{128}`$. In other words, for
$`\mathsf{TW128}`$ the practical AE margin is not volume-limited at realistic
scales; the visible edge of the bound appears only under astronomically large
primitive-query or forgery budgets.

The commitment side has a different concrete profile. Consider
two distinct equal-length $`1`$ GiB messages with empty associated data and no
prior primitive queries ($`N=0`$). Each message decomposes into
$`132{,}105`$ chunks: the first chunk is full, the next $`132{,}103`$ later
chunks are full, and the final later chunk has length $`512`$ bytes. Hence

```math
\Phi_{\mathsf{tr}}(\epsilon,P)
=
1325
+
\left\lceil \frac{132{,}104 \cdot 256 + 9}{1344} \right\rceil
=
1325 + 25{,}163
=
26{,}488,
```

while the later-leaf family contributes

```math
132{,}103 \cdot \Phi_{\mathsf{leaf}}(65024)
+
\Phi_{\mathsf{leaf}}(4096)
=
132{,}103 \cdot 1325 + 20
=
175{,}036{,}495.
```

Thus one encryption induces the exact local prefix-sponge cost

```math
26{,}488 + 175{,}036{,}495 = 175{,}062{,}983,
```

and the compared pair induces

```math
M_{\Theta}^{\mathsf{loc}} = 350{,}125{,}966.
```

The imported TW128 sponge term is therefore approximately

```math
\epsilon_{\mathsf{ideal}}(M_{\Theta}^{\mathsf{loc}})
\approx
\frac{(350{,}125{,}966)^2}{2^{256}}
\approx
2^{-199.2},
```

while the explicit TreeWrap-specific tail remains exactly $`2^{-256}`$. So even
at the gigabyte-per-ciphertext scale, the concrete commitment bound is still
dominated by an imported term that sits roughly seventy bits below the
$`2^{-128}`$ threshold.

### 8.3 Prototype Performance

To complement the concrete bound calculations above, we also measured
$`\mathsf{TW128}`$ in optimized prototype implementations on two representative
software targets: Apple M4 Pro (`darwin/arm64`) and Intel Emerald Rapids
(`linux/amd64`). The measurements below are end-to-end Go benchmark results
for the optimized $`\mathsf{TW128}`$ prototype and, for context, Go's
standard-library AES-128-GCM implementation on the same platforms.

Table 1 reports short-message latency.

| Platform | Operation | 1 B (ns/op) | 64 B (ns/op) |
| --- | --- | ---: | ---: |
| M4 Pro | TW128 encrypt | 153.8 | 153.9 |
| M4 Pro | AES-128-GCM seal | 207.2 | 219.8 |
| Emerald Rapids | TW128 encrypt | 340.4 | 344.3 |
| Emerald Rapids | AES-128-GCM seal | 351.1 | 403.1 |

Table 2 reports representative throughput points.

| Platform | Operation | 8 KiB (MB/s) | 64 KiB (MB/s) | 1 MiB (MB/s) | 16 MiB (MB/s) |
| --- | --- | ---: | ---: | ---: | ---: |
| M4 Pro | TW128 encrypt | 2326.91 | 3410.14 | 5360.60 | 5380.68 |
| M4 Pro | AES-128-GCM seal | 7234.61 | 8754.33 | 8917.25 | 8921.59 |
| Emerald Rapids | TW128 encrypt | 1028.95 | 2421.03 | 4838.75 | 4934.75 |
| Emerald Rapids | AES-128-GCM seal | 4100.75 | 4918.17 | 5045.80 | 5040.00 |

These figures show the expected profile of the design. Short messages are
dominated by the fixed trunk work, and in this benchmark setup
$`\mathsf{TW128}`$ has lower end-to-end latency than the AES-128-GCM baseline
on both tested platforms. Once several remaining chunks are available, the
throughput improves sharply and then plateaus.

At larger message sizes AES-GCM reaches higher throughput, especially on ARM64,
but the AMD64 results are still encouraging: on Emerald Rapids,
$`\mathsf{TW128}`$ reaches about $`4.9`$ GB/s at $`16`$ MiB versus about
$`5.0`$ GB/s for the AES-128-GCM baseline. That is a useful point of reference
because the `TW128` prototype relies on software Keccak on `amd64`, without any
dedicated Keccak instruction set.

These measurements also help explain the choice of $`B = 8128`$ bytes for
$`\mathsf{TW128}`$. That value was selected empirically across the optimized
ARM64 and AVX-512 backends rather than from permutation-count arithmetic alone:
the best practical chunk size is shaped not only by the number of duplex calls
per chunk, but also by backend-specific vectorization and tail-handling costs.

## 9. Conclusion

TreeWrap shows that a chunk-parallel permutation-based AEAD can be analyzed
cleanly by organizing the proof around a trunk transcript, a family of leaf
transcripts, and one canonical TreeWrap schedule shared across the AE and
commitment arguments. On the AE side, this decomposition lets the proof reuse
the keyed-duplex/IXIF machinery of [Men23] for both `TrunkWrap` and the leaf
family while isolating the genuinely TreeWrap-specific endgames: a
schedule-based privacy lemma, a schedule-based authenticity lemma, and a BN00
dead-decryption composition for IND-CCA2. On the commitment side, the same
schedule supports a global public-permutation analysis in which whole
encryptions are flattened once, mapped to prefix-sponge queries, and then
handed to an imported sponge-ideality step before a short TreeWrap-specific
injectivity and tag-endgame argument.

The concrete $`\mathsf{TW128}`$ instantiation shows that this proof strategy
leads to a practically parameterized scheme based on twelve-round Keccak,
8128-byte chunks, 256-bit leaf tags, and a 256-bit final tag. Its AE guarantees
remain explicitly multi-user and parameterized by the imported keyed-duplex
bounds, while its commitment guarantee specializes to an explicit
collision bound given by one imported capacity-limited sponge term plus a short
tag-dominated explicit tail. Together, these results give TreeWrap a much
cleaner proof architecture and a concrete target instantiation for further
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

[BDPVAVK16] Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche, and
Ronny Van Keer. *CAESAR Submission: Keyak v2*. Document version 2.2, September
15, 2016. <https://keccak.team/files/Keyakv2-doc2.2.pdf>

[BDPVAVKV18] Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche, Ronny Van
Keer, and Benoît Viguier. *KangarooTwelve: Fast Hashing Based on Keccak-p*. In
Pooya Farshim and Steven Guilley, editors, *Applied Cryptography and Network
Security*, volume 10892 of *Lecture Notes in Computer Science*, pages 400-418.
Springer, 2018. <https://doi.org/10.1007/978-3-319-93387-0_21>

[BH22] Mihir Bellare and Viet Tung Hoang. *Efficient Schemes for Committing
Authenticated Encryption*. In Orr Dunkelman and Stefan Dziembowski, editors,
*Advances in Cryptology -- EUROCRYPT 2022, Part II*, volume 13276 of *Lecture
Notes in Computer Science*, pages 845-875. Springer, 2022.

[BN00] Mihir Bellare and Chanathip Namprempre. *Authenticated Encryption:
Relations among Notions and Analysis of the Generic Composition Paradigm*. In
Tatsuaki Okamoto, editor, *Advances in Cryptology -- ASIACRYPT 2000*, volume
1976 of *Lecture Notes in Computer Science*, pages 531-545. Springer, 2000.

[DEMS21] Christoph Dobraunig, Maria Eichlseder, Florian Mendel, and Martin
Schläffer. *Ascon v1.2: Lightweight Authenticated Encryption and Hashing*.
*Journal of Cryptology*, 34(3): Article 33, 2021.
<https://doi.org/10.1007/s00145-021-09398-9>

[DHPVAVK20] Joan Daemen, Seth Hoffert, Michaël Peeters, Gilles Van Assche, and
Ronny Van Keer. *Xoodyak, a Lightweight Cryptographic Scheme*. *IACR
Transactions on Symmetric Cryptology*, 2020(S1): 60-87, 2020.
<https://doi.org/10.13154/tosc.v2020.is1.60-87>

[FIPS202] National Institute of Standards and Technology. *SHA-3 Standard:
Permutation-Based Hash and Extendable-Output Functions*. Federal Information
Processing Standards Publication 202, 2015.
<https://doi.org/10.6028/NIST.FIPS.202>

[IR23] Takanori Isobe and Mostafizar Rahman. *Key Committing Security
Analysis of AEGIS*. *IACR Cryptology ePrint Archive*, Paper 2023/1495, 2023.
<https://eprint.iacr.org/2023/1495>

[Men23] Bart Mennink. *Understanding the Duplex and Its Security*. *IACR
Transactions on Symmetric Cryptology*, 2023(2): 1-46, 2023.

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

[WP13] Hongjun Wu and Bart Preneel. *AEGIS: A Fast Authenticated Encryption
Algorithm*. *IACR Cryptology ePrint Archive*, Paper 2013/695, 2013.
<https://eprint.iacr.org/2013/695>
