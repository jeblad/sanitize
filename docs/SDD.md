# Software Design Description (SDD): sanitize

Prepared per MIL-STD-498 DID DI-IPSC-81435.

The project's `README.md` is a synopsis of what sanitize is and how to use
it; this document is the full picture — the design decisions behind that
surface, and why each part of the implementation is shaped the way it is.
`README.md`'s Architecture section links here.

## 1. Scope

### 1.1 Identification

- System/software name: **sanitize**
- Abbreviation: none beyond the project name itself
- Version at time of writing: 2.1.0 (see `sanitize::Version` /
  `sanitize::VersionMajor`/`VersionMinor`/`VersionPatch`, or the
  `SANITIZE_VERSION*` preprocessor macros, for the authoritative
  compile-time value; see `CHANGELOG.md` and git tags for release history)
- Repository: `https://github.com/jeblad/sanitize`

### 1.2 System overview

Sanitize is a header-only C++20 library for filtering character streams —
filenames, shell arguments, or anything else that might reach a command
line or a user-facing view — against a compile-time-defined
forbidden-character set, with UTF-8-aware security checks built in. It
decides which characters are forbidden, then replaces, drops, or escapes
them, always against the *decoded* UTF-8 codepoint rather than the raw
bytes, so that an overlong-encoded forbidden character (a known
filter-bypass technique) is caught regardless of policy.

Development history, per `CHANGELOG.md`:

- **1.0.1** — an earlier, now-superseded runtime bool-flag API
  (`rewrite`/`escape`/`validate`/`untaint`/`set_forbidden_characters`,
  backed by a mutable global `Config` singleton).
- **2.0.0** — a complete breaking rewrite to the current compile-time,
  template-based design (`FixedString`, `Config<Chars>`, `map` and its
  wrappers, `Overlong` policy, `find_substrings`), and a switch to
  header-only distribution (`sanitize.cpp` removed).
  compiled from `sanitize.hpp.in` via CMake.
- **2.1.0** — a naming-consistency pass (`isValid`→`is_valid`,
  `findSubstrings`→`find_substrings`) plus internal hardening: `std::span`
  instead of raw pointer+length in the UTF-8 decoder, bounds-checked
  bit-vector access, and deduplicated forbidden-codepoint checking.

This is a standing adaptation of this paragraph's literal wording: the DID
assumes a DoD acquisition context (sponsor, acquirer, contract-driven
delivery) that doesn't hold here. There is no acquirer or sponsor; the
sole developer is John Erling Blad; support is handled through the
project's GitHub issue tracker
(`https://github.com/jeblad/sanitize/issues`) rather than a formal support
agency. The library has no "operating sites" in the DID's sense — it is
consumed by whatever C++ project includes its header, not deployed to a
fixed set of locations.

### 1.3 Document overview

This document describes sanitize's CSCI-wide design decisions (§3),
architectural design (§4), and detailed per-unit design (§5). It is the
depth companion to `README.md`'s synopsis (see the note at the top of this
document).

Security considerations: this library's core purpose is security-relevant
— it implements UTF-8 decoding hardened specifically against overlong-
encoding filter-bypass attacks (see §3.d and §5.5). This document
describes that design explicitly, since understanding *why* the decoder
is shaped the way it is matters for anyone auditing or extending it.
There are no privacy considerations beyond this: the library processes
only whatever string data its caller passes in, in-process, with no
logging, storage, or transmission of its own.

## 2. Referenced documents

| Document | Location |
|---|---|
| README.md (user-facing synopsis) | `README.md` |
| AGENTS.md (code-review standards, project-specific rule exceptions, comment conventions) | `AGENTS.md` |
| TODO.md (open design questions) | `TODO.md` |
| CHANGELOG.md (release history) | `CHANGELOG.md` |
| LICENSE (GNU GPL v3.0) | `LICENSE` |
| Test suite (executable specification of expected behavior) | `tests/test_sanitize.cpp` |
| Build configuration | `CMakeLists.txt`, `package.json` |
| This DID | MIL-STD-498, DI-IPSC-81435 (Software Design Description) |

## 3. CSCI-wide design decisions

If all such decisions were either explicit in a formal CSCI requirements
document or deferred entirely to unit-level design, this section would so
state — but sanitize has no formal Software Requirements Specification
(see §6), so the CSCI-wide decisions below are the primary record of *why*
the library behaves as it does, not a restatement of separately-documented
requirements.

a. **Inputs and outputs.** Sanitize has no interfaces with other systems,
   HWCIs, or CSCIs — it is a pure, in-process C++ library. Its only
   interfacing entity is calling C++ code, through the public function
   templates described in §4.3 (IF-1) and, at build time, the CMake build
   system that generates its header (§4.3, IF-2).

b. **Behavior in response to input.** Every entry point (`map`,
   `replace`, `filter`, `escape`, `strict`, `is_valid`) decodes input one
   UTF-8 sequence at a time, classifies the decoded codepoint (forbidden,
   overlong, invalid, or ordinary), and acts accordingly — transforming
   forbidden characters, passing everything else through unchanged, and
   signaling problems via `std::invalid_argument` (never a crash — see
   item d). This decode-classify-act loop is the single behavioral
   pattern underlying every public function; see §4.2 for its control
   flow and §5.5–§5.13 for the specific units that implement it.

c. **Database appearance.** Not applicable. Sanitize has no databases or
   persistent storage of any kind; it operates entirely on in-memory
   `std::string`/`std::string_view` data supplied by its caller.

d. **Safety, security, and privacy approach.** Two decisions dominate
   here, both recorded as standing project rules in `AGENTS.md`:

   - *Detection always runs against the decoded codepoint, never the raw
     bytes* (see §5.5, §5.7). This is what makes an overlong-encoded
     forbidden character unable to bypass filtering regardless of the
     caller's chosen `Overlong` policy — the policy only ever governs what
     happens to a sequence *after* it's confirmed harmless.
   - *No `assert`/abort-based checks anywhere in the library* — a
     departure from Power of Ten Rule 5 (`AGENTS.md`'s Code-review
     standards), justified because sanitize is meant to embed in
     continuously-running programs, where an aborted process is itself an
     unacceptable failure, not a safe fallback. Every error condition is
     either reported (a return status or a `std::invalid_argument`,
     matching whatever the surrounding function already uses) or made
     structurally unreachable — see `Bits128::set`/`test` (§5.3) and
     `decode_utf8`'s empty-span handling (§5.5) for concrete instances.

e. **Other CSCI-wide decisions.**

   - *Forbidden-character sets are restricted to 7-bit ASCII*, enforced at
     compile time by the `AsciiOnly` concept (§5.2). This is what makes
     `O(1)` forbidden-character lookup possible via a 128-bit bit-vector
     (§5.3) instead of a general-purpose (and slower) lookup structure. A
     SIMD-based path for non-ASCII forbidden sets is documented as future
     work, not yet implemented.
   - *Compile-time-first design.* `FixedString`, `AsciiOnly`, and
     `Config<Chars>` are all `constexpr`-constructible, so a forbidden-
     character set and its lookup structure can be fully built at compile
     time with no runtime cost and no dynamic allocation. This is a
     deliberate flexibility/performance trade-off in the sense the DID
     template names: it trades runtime reconfigurability (no singleton, no
     "change the forbidden set later") for speed and the ability to prove
     correctness (e.g. `AsciiOnly`) at compile time rather than needing a
     runtime check.
   - *Header-only distribution.* The library ships as a single generated
     header (`include/sanitize/sanitize.hpp`), produced by CMake from
     `sanitize.hpp.in` via `configure_file`. `sanitize.hpp.in` is the
     source of truth; the generated header is regenerated on every CMake
     configure and must never be hand-edited (see §5.14 and the
     Limitations section of `README.md`).

## 4. CSCI architectural design

### 4.1 CSCI components

The table below identifies each software unit making up the CSCI, its
purpose, and its static ("consists of"/"uses") relationships. Development
status is uniform across all units: new development, as part of the 2.0.0
template-based rewrite (see §1.2); none are reused, reengineered, or
planned for a future build. Requirement allocation is informal, per §6 —
each unit's purpose below stands in for a formal requirements trace.

| Unit | Purpose | Uses |
|---|---|---|
| `FixedString<Capacity>` (+ `operator+`/`operator-`) | Compile-time character set, usable as a non-type template parameter | — |
| `AsciiOnly` | Concept constraining a `FixedString` to 7-bit ASCII | `FixedString` |
| `detail::Bits128` | Hand-rolled 128-bit bit-vector (constexpr-compatible, unlike `std::bitset` pre-C++23) | — |
| `Config<Chars>` | Immutable, O(1) forbidden-character lookup | `FixedString`, `AsciiOnly`, `detail::Bits128` |
| `detail::Utf8Status`/`Utf8Decoded`/`decode_utf8`/`encode_utf8` | UTF-8 codec: decode one sequence with structural/overlong/surrogate/range validation, and canonical re-encoding | `std::span` |
| `detail::escape_one` | Renders one already-forbidden character as its backslash-escape form | — |
| `detail::is_forbidden_codepoint` | Shared "is this decoded codepoint forbidden" check | `Config`, `detail::Utf8Decoded` |
| `FragmentType`/`Fragment`/`detail::ClassifiedChar`/`detail::classify_one` | Classifies one character as Valid/Forbidden/Invalid | `detail::decode_utf8`, `detail::is_forbidden_codepoint` |
| `SubstringRange<Chars>` (+ nested `iterator`/`sentinel`) | Lazy, forward-only partitioning of a string into typed, run-length-grouped fragments | `detail::classify_one`, `Config` |
| `Overlong` | Enum policy governing what happens to a harmless overlong sequence | — |
| `CharTransform` | Concept constraining a callable usable with `map` | — |
| `map`/`replace`/`filter`/`escape` | The transform family: apply a callable (or one of three built-in transforms) to every forbidden character | `Config`, `detail::decode_utf8`, `detail::is_forbidden_codepoint`, `detail::encode_utf8`, `detail::escape_one`, `Overlong`, `CharTransform` |
| `strict`/`is_valid` | The validation family: throw (or return bool) on the first forbidden character or encoding problem | `Config`, `detail::decode_utf8`, `detail::is_forbidden_codepoint`, `Overlong` |
| `find_substrings` | Entry point constructing a `SubstringRange` | `SubstringRange` |
| `VersionMajor`/`VersionMinor`/`VersionPatch`/`Version` | Compile-time version constants | — |

Program library: all units are implemented in `sanitize.hpp.in` (the
source of truth) and distributed via the generated
`include/sanitize/sanitize.hpp`, exposed to consumers as the CMake
`sanitize` `INTERFACE` target (see `README.md`'s Installation section).

Computer hardware resource utilization: this paragraph has been tailored
out in its literal (processor/memory/I-O capacity budget) sense — no
formal resource-utilization budget exists for this library, and none of
the DID's listed resource categories (processor capacity, auxiliary
storage, communications/network equipment) apply to a header-only
template library with no persistent state. The one relevant design
consequence is noted instead: forbidden-character lookup is deliberately
`O(1)` (§3.e, §5.3) rather than budgeted against a specific hardware
target.

### 4.2 Concept of execution

Sanitize has two distinct execution phases, neither involving
concurrency, interrupts, or dynamic dispatch:

**Compile time.** A caller defines a `FixedString` character set (e.g.
`constexpr auto TightChars = sanitize::FixedString("...")`) and,
implicitly, a `Config<TightChars>`. `FixedString`'s constructor
deduplicates its input; `AsciiOnly` is checked as a template constraint;
`Config::build()` sets one bit per forbidden character into a
`Bits128`. All of this can happen entirely at compile time since every
type and function involved is `constexpr`.

**Runtime, per call.** Every public entry point (`map` and its wrappers
`replace`/`filter`/`escape`; `strict` and its wrapper `is_valid`;
`find_substrings`) walks its input left to right in a single pass:

1. Decode one UTF-8 sequence at the current byte offset
   (`detail::decode_utf8`, taking a `std::span` over the remaining bytes).
2. Classify the result: `Invalid` (malformed, empty span, UTF-16
   surrogate, or beyond U+10FFFF) always signals an error; `Overlong`
   checks the *decoded* codepoint against `Config` regardless of the
   caller's `Overlong` policy, and only consults that policy once the
   codepoint is confirmed not forbidden; anything else checks the decoded
   codepoint against `Config` directly.
3. Act on the classification — append the original bytes unchanged, apply
   the caller's transform, throw `std::invalid_argument`, or (for
   `find_substrings`) extend the current `Fragment` — then advance by the
   sequence's byte length and repeat.

`find_substrings` differs from the transform/validation families in one
respect: it doesn't act immediately per character. `SubstringRange`'s
`iterator::advance()` instead keeps classifying consecutive characters
into the *same* fragment for as long as their `FragmentType` doesn't
change, only stopping (and yielding a `Fragment`) at a type boundary —
lazy, one run at a time, on each `operator++`.

Error signaling throughout is via `std::invalid_argument` exceptions
(never process termination — see §3.d); `is_valid` is the sole function
that converts this into a `bool`, via a `try`/`catch` documented as
`noexcept` (any exception type other than `std::invalid_argument`
escaping `strict` — e.g. `std::bad_alloc` — is left to propagate rather
than folded into "input is invalid").

### 4.3 Interface design

#### 4.3.1 Interface identification and diagrams

Sanitize has exactly two interfaces, both with fixed characteristics
imposed by sanitize on whatever interacts with it — there are no
interfaces under active co-development with an external system.

| ID | Interfacing entities |
|---|---|
| IF-1 | sanitize ⇄ calling C++ code (the public API) |
| IF-2 | `sanitize.hpp.in` ⇄ CMake build system ⇄ `include/sanitize/sanitize.hpp` (header generation) |

No interface diagram beyond the table above is warranted: both interfaces
are direct, single-hop, in-process/in-build-tree relationships with no
intermediate routing, network hop, or third interfacing entity involved.

#### 4.3.2 IF-1: Public API

- **Priority:** primary — this is the interface sanitize exists to
  provide.
- **Type:** synchronous, in-process C++ function-call interface (template
  functions and types), not a data-transfer or storage-and-retrieval
  interface in the DID's network/messaging sense.
- **Data elements provided by sanitize:**

  | Element | Technical name | Type | Notes |
  |---|---|---|---|
  | Compile-time character set | `FixedString<Capacity>` | Class template, usable as an NTTP | Deduplicating; composable with `+`/`-` |
  | ASCII constraint | `AsciiOnly<Chars>` | Concept | Compile error if violated |
  | Forbidden-set lookup | `Config<Chars>` | Class template | Immutable, O(1) `is_forbidden(char)` |
  | Transform | `map`/`replace`/`filter`/`escape` | Function templates | Return `std::string`; throw `std::invalid_argument` per §4.2 |
  | Validation | `strict`/`is_valid` | Function templates | `strict` throws; `is_valid` returns `bool`, `noexcept` |
  | Partitioning | `find_substrings` → `SubstringRange<Chars>` | Function template / range type | Lazy; yields `Fragment{FragmentType, std::string_view}` |
  | Overlong policy | `Overlong` | Enum (`Throw`/`Remove`/`Replace`/`AsIs`/`Compact`) | Template parameter, defaults to `Throw` |
  | Version | `Version`/`VersionMajor`/`VersionMinor`/`VersionPatch`, `SANITIZE_VERSION*` | `constexpr` values / macros | Macros exist specifically for `#if`-based gating |

  Accuracy and precision, units of measurement, and priority/timing
  constraints (DID sub-items c.6, c.4, c.7) are not applicable — these
  are plain value types and function calls with no numeric-measurement or
  real-time-scheduling dimension.

- **Characteristics of communication methods and protocols (DID
  sub-items e, f):** this paragraph has been tailored out. IF-1 is an
  in-process function-call interface; there are no communication
  links, message formats, transmission protocols, or network addressing
  involved for a caller linking against a C++ header.

- **Other characteristics:** IF-1 requires a C++20-capable compiler (see
  `README.md`'s Requirements); no other physical-compatibility
  constraints apply.

#### 4.3.3 IF-2: Build-time header generation

- **Priority:** secondary — required to produce IF-1's actual header, but
  invisible to a consumer who only links against the `sanitize`
  `INTERFACE` target.
- **Type:** file generation (CMake `configure_file`, `@ONLY` mode), not a
  runtime interface.
- **Data elements:** `sanitize.hpp.in` (source, containing `@VAR@`
  placeholders) is substituted into `include/sanitize/sanitize.hpp`
  (generated output, tracked in git as the distribution copy). Recognized
  placeholders: `@SANITIZE_GENERATED_WARNING@`, `@SANITIZE_FULL_VERSION@`,
  `@SANITIZE_VERSION_MAJOR@`, `@SANITIZE_VERSION_MINOR@`,
  `@SANITIZE_VERSION_PATCH@` — all sourced from `package.json`'s
  `version` field via `CMakeLists.txt`.
- **Characteristics of communication methods and protocols:** not
  applicable, same reasoning as IF-1.
- **Other characteristics:** the generated file is excluded from direct
  AI editing (`.aiexclude`) and is silently overwritten on every CMake
  configure — see `README.md`'s Limitations and `AGENTS.md`.

## 5. CSCI detailed design

Design conventions applying throughout, stated once here rather than
repeated per unit: every unit is C++20; every doc comment follows the
Doxygen `@`-tag convention recorded in `AGENTS.md`; unit-level code style
follows *The Art of Readable Code* as a base, narrowed by *The Power of
Ten* (`AGENTS.md`'s Code-review standards), with the two project-specific
exceptions recorded there (no `assert`/abort; `decode_utf8` deliberately
left over the complexity guideline). Interface characteristics for every
unit are covered by §4.3's IF-1 rather than repeated per unit.

### 5.1 `FixedString<Capacity>` (and `operator+`/`operator-`)

- **Design decisions:** modeled as a *set*, not a sequence — the
  constructor deduplicates on construction, and `operator+`/`operator-`
  give union/difference rather than concatenation. `Capacity` is an upper
  bound deduced from the source literal's array size; `len` is the actual
  post-deduplication/composition count.
- **Constraints:** `Capacity` must be deduced from a NUL-terminated
  string literal; passing a non-literal `char` array of exact length
  silently drops its last character (documented, not defended against
  — a `FixedString` is always constructed from a literal in practice).
- **Language:** C++20 (relies on class-type non-type template parameters).
- **Data:** `data[Capacity]` (the character storage) and `len` (actual
  count) — both public; no data local vs. input/output split applies to
  a value type like this.
- **Logic:** the constructor's dedup loop and `contains()`'s linear scan
  are both `O(Capacity)`/`O(len)` — acceptable given forbidden-character
  sets are small (tens of characters, not thousands).

### 5.2 `AsciiOnly` concept

- **Design decisions:** implemented as an immediately-invoked `consteval`-
  style lambda over a `FixedString`'s characters, checking each against
  `< 128`. `Config<Chars>` is only ever defined for `Chars` satisfying
  this concept (via a `requires` clause), turning "forbidden set contains
  a non-ASCII character" into a compile error rather than a runtime
  concern.
- **Constraints:** this is the specific mechanism behind the "ASCII only,
  for now" limitation recorded in `README.md` — non-ASCII forbidden
  characters are not yet supported (a SIMD-based path is future work).
- **Language:** C++20 (concepts).

### 5.3 `detail::Bits128`

- **Design decisions:** a hand-rolled 128-bit vector (two `uint64_t`
  words), used instead of `std::bitset<128>` specifically because
  `std::bitset::set()`/`test()` are not `constexpr` until C++23, and
  `Config` needs compile-time construction (§3.e).
- **Constraints:** `set(pos)`/`test(pos)` both guard `pos >= 128`
  explicitly, returning `false` rather than performing an out-of-range
  bit shift — a direct instance of the no-`assert`/abort rule (§3.d):
  the out-of-range case is reported via return value instead of being
  treated as an invariant violation. `Config::build()` deliberately
  discards this return value (`[[maybe_unused]]`) since `AsciiOnly`
  already guarantees every character passed to `set()` is in range; the
  guard exists as defense-in-depth for `Bits128` used outside that
  guarantee, not because `build()` expects it to ever fire.
- **Language:** C++20; both methods are `constexpr`.
- **Logic:** `pos < 64` selects the low word (`lo`), otherwise the high
  word (`hi`) at `pos - 64`.

### 5.4 `Config<Chars>`

- **Design decisions:** immutable by design — no singleton, no runtime
  reconfiguration; a different forbidden set means constructing a
  different `Config<Chars>` (a different type, since `Chars` is a
  template parameter). `is_forbidden(c)` is `O(1)`: a range check
  (`c < 128`) short-circuiting a single `Bits128::test` call.
- **Constraints:** only defined for `Chars` satisfying `AsciiOnly` (§5.2).
- **Language:** C++20.
- **Data:** a single private `detail::Bits128 bits_` member, built once
  at construction via the private `build()` method.

### 5.5 UTF-8 codec: `detail::decode_utf8`/`encode_utf8`, `Utf8Status`,
    `Utf8Decoded`

- **Unit design decisions:** `decode_utf8` decodes exactly one sequence
  starting at `bytes[0]`, taking a `std::span<const std::uint8_t>` (not a
  raw pointer + length — see the constraints note below) and returning a
  `Utf8Decoded{status, length, codepoint}`. Three statuses: `Valid`
  (well-formed, not overlong), `Invalid` (empty span, malformed, a UTF-16
  surrogate half U+D800–U+DFFF, or beyond U+10FFFF), `Overlong`
  (well-formed but encoded with more bytes than the codepoint needs).
  `Overlong` is reported with the *true* decoded codepoint and correct
  structural length, not just a failure code, so callers can re-encode
  canonically without redoing the decode. Every `Invalid` result reports
  `length = 1, codepoint = 0` uniformly (including the empty-span case),
  so a caller can always safely skip forward exactly one byte and retry
  — this specific invariant is load-bearing: `SubstringRange`'s run
  accumulation (§5.9) depends on `Invalid` always advancing by exactly
  one byte.

  `encode_utf8` is the inverse: canonical (minimal-length) re-encoding of
  a codepoint, used by `Overlong::Compact` (§5.10).

- **Constraints/rationale for design that might look unusual:** this
  function carries a `NOLINTNEXTLINE(readability-function-cognitive-
  complexity)` suppression and is left deliberately over both Power of
  Ten Rule 4's ~60-line guideline and `.clang-tidy`'s cognitive-
  complexity threshold (76 lines, complexity 28 against a default
  threshold of 25 — `.clang-tidy` itself is left at that default, not
  raised to accommodate this function). This is a considered exception,
  recorded in `AGENTS.md`: splitting the function's four lead-byte
  branches into shared helpers was tried and rejected, because each
  branch is currently obviously correct *by structural omission* — the
  2-byte branch has no surrogate/max-range check because there's no line
  there to have one. Extracting that check into a shared helper would
  make it run unconditionally for every branch, correct only because of
  a numeric fact (2-byte codepoints top out at U+07FF, 3-byte at U+FFFF,
  both below the surrogate/max-range danger zones) that a reader would
  then have to verify by arithmetic instead of seeing structurally. For a
  function whose whole purpose is rejecting encoding-based security
  bypasses (§3.d) — and which already had one real overlong-surrogate-
  bypass defect during development — trading "obviously correct" for
  "correct if you check the math" was judged a worse deal than the line
  count implies.

  Taking a `std::span` instead of a raw pointer and a separate length
  parameter (as an earlier version of this unit did) is itself a design
  decision worth recording: it bundles the pointer and its bound into one
  value that can't drift out of sync as the code evolves, directly
  addressing Power of Ten Rule 2's concern about a bounds check living
  apart from the access it protects.

- **Language:** C++20 (`decode_utf8` is `constexpr`; `encode_utf8` is
  `inline`, not `constexpr`, since it heap-allocates a `std::string`).
- **Logic:** lead-byte bit-pattern matching (`110xxxxx`/`1110xxxx`/
  `11110xxx`) selects a 2/3/4-byte branch; each branch validates
  continuation-byte structure (`10xxxxxx` pattern, via
  `(byte & 0xC0) != 0x80`) before assembling the codepoint from the lead
  byte's low bits and each continuation byte's low 6 bits.

### 5.6 `detail::escape_one`

- **Design decisions:** a `switch` over the eight control characters with
  a named C escape (`\0`, `\n`, `\r`, `\t`, `\v`, `\f`, `\b`, `\a`);
  `\xHH` for any other control/DEL byte; a plain backslash prefix for
  anything else. Only ever called for a character already confirmed
  forbidden by `Config` — escaping is never applied unconditionally.
- **Constraints:** the output is only safely un-escapable (a reader can
  tell an escape sequence apart from a literal backslash) if `\` itself
  is a member of the caller's `Chars` — otherwise a literal backslash in
  the input passes through unescaped. Documented as a caller-facing
  caution in `escape`'s own doc comment and in `README.md`, not defended
  against here (the caller controls `Chars`).
- **Language:** C++20 (`std::format` for the `\xHH` case).

### 5.7 `detail::is_forbidden_codepoint`

- **Design decisions:** the single shared "is this decoded codepoint
  forbidden" check, used identically by `classify_one` (§5.8), `map`, and
  `strict` (§5.12) — previously duplicated three times with slight
  variations before being deduplicated. Its logic
  (`decoded.codepoint < 128 && config.is_forbidden(...)`) generalizes
  correctly to *any* decode result, not just `Overlong` ones: for a
  `Valid` single-byte result, `codepoint < 128` holds exactly when
  `length == 1`, so the same check doubles as the plain-ASCII forbidden
  check without needing a separate `length == 1` guard at each call site.
- **Language:** C++20, `constexpr`.

### 5.8 Classification: `FragmentType`, `Fragment`, `detail::ClassifiedChar`,
    `detail::classify_one`

- **Design decisions:** `classify_one` decodes and classifies the
  character at a given byte offset into one of three `FragmentType`
  values: `Valid`, `Forbidden`, or `Invalid`. An overlong sequence is
  classified `Forbidden` if its decoded codepoint is itself forbidden,
  and `Invalid` otherwise — never `Valid`, since an overlong encoding is
  always structurally suspect regardless of what it decodes to.
- **Data:** `Fragment{FragmentType type, std::string_view text}` — `text`
  is a view into the caller's original input, not a copy; valid only as
  long as that input stays alive and unmodified.
- **Language:** C++20.

### 5.9 `SubstringRange<Chars>` and its `iterator`/`sentinel`

- **Design decisions:** a lazy, forward-only range partitioning a string
  into consecutive runs of same-`FragmentType` characters — every byte of
  input is covered by exactly one yielded `Fragment`, not just the
  anomalous parts. `iterator::advance()` repeatedly calls `classify_one`
  starting at the current position, extending the current run for as
  long as consecutive characters share a `FragmentType`, stopping at the
  first type change (or end of input). There is no write-back mechanism
  by design — a caller that wants to fix `Forbidden`/`Invalid` runs
  builds a new string from the fragments rather than editing the
  original in place, keeping `Fragment::text`'s view-into-input contract
  simple.
- **Constraints:** relies on `decode_utf8`'s "`Invalid` always reports
  `length = 1`" invariant (§5.5) to guarantee forward progress — the
  accumulation loop has no separate bound of its own besides "byte offset
  strictly increases," and correctness of that bound is inherited from
  the decoder, not independently enforced here.
- **Language:** C++20; `iterator::operator!=` compares against an empty
  `sentinel` marker type (C++20 range machinery) rather than a second
  `iterator` instance.

### 5.10 `Overlong` policy enum

- **Design decisions:** governs only what happens to an overlong sequence
  whose decoded codepoint is *not* itself forbidden — a forbidden
  character is always caught the same way regardless of this policy,
  since detection runs against the decoded codepoint (§3.d), never the
  raw overlong bytes. Five values: `Throw` (reject outright, the
  default), `Remove` (drop the sequence), `Replace` (substitute U+FFFD),
  `AsIs` (keep the original overlong bytes unchanged), `Compact`
  (re-encode canonically via `encode_utf8`).
- **Language:** C++20 `enum class`; consumed as a non-type template
  parameter, so the choice is resolved entirely at compile time
  (`if constexpr` branches in `map`/`strict`).

### 5.11 `map`/`replace`/`filter`/`escape` (transform family)

- **Design decisions:** `map` is the general primitive — it applies any
  `CharTransform`-constrained callable to every forbidden character,
  leaving everything else (including well-formed multibyte UTF-8)
  untouched, and returns the transformed copy as a new `std::string`.
  `replace`, `filter`, and `escape` are thin wrappers supplying a fixed
  transform lambda (substitute a character, drop it, or call
  `escape_one`) — no logic of their own beyond that.
- **Constraints:** none beyond `CharTransform`'s own constraint (a
  callable accepting `char` and returning something convertible to
  `std::string`).
- **Language:** C++20 (concepts for `CharTransform`, `if constexpr` for
  `Overlong` branching).
- **Logic:** per §4.2's decode-classify-act loop; see §5.5 for the
  decode step's own logic.
- **Exception/error handling:** throws `std::invalid_argument` on
  `Invalid` UTF-8 unconditionally, and on `Overlong` specifically when
  `OverlongPolicy == Overlong::Throw` and the codepoint isn't itself
  forbidden.

### 5.12 `strict`/`is_valid` (validation family)

- **Design decisions:** `strict` inspects input character by character
  and throws on the first forbidden character or encoding problem,
  without copying or transforming anything — the validation-only
  counterpart to `map`. `is_valid` wraps `strict` in a `try`/`catch`,
  catching only `std::invalid_argument` (the one type `strict` documents
  throwing) and returning `bool`; any other exception type (e.g.
  `std::bad_alloc`) is left to propagate rather than folded into "input
  is invalid," since `is_valid` is declared `noexcept` and such a failure
  is an unexpected one, not an ordinary validation result.
- **Language:** C++20.
- **Logic:** same decode-classify loop as `map` (§4.2), stopping at the
  first problem instead of accumulating output.

### 5.13 `find_substrings`

- **Design decisions:** a thin entry point constructing a
  `SubstringRange<Chars>` (§5.9) over the given input — all the actual
  logic lives in `SubstringRange`/`iterator`; this function exists purely
  to give that construction a discoverable, conventionally-named call
  site (`sanitize::find_substrings<Chars>(input)`), usable directly in a
  range-based `for` loop.
- **Language:** C++20.

### 5.14 Version constants: `VersionMajor`/`VersionMinor`/`VersionPatch`/
    `Version`

- **Design decisions:** `inline constexpr` mirrors of the
  `SANITIZE_VERSION_MAJOR`/`MINOR`/`PATCH`/`SANITIZE_VERSION` macros
  (§4.3, IF-2), added so ordinary C++ code (template arguments,
  `static_assert`, runtime comparisons) has a typed, macro-free way to
  read the library's version, without needing the macros' `#if`-only
  capability. The macros themselves stay defined for the one thing
  `constexpr` genuinely can't do: preprocessor-time (`#if`) version
  gating — a case recorded as a general pattern (not just a one-off) in
  this project's documentation-skill notes: when a macro's actual job is
  a preprocessor-only capability, the fix for "prefer constexpr" is
  adding a `constexpr` mirror alongside it, not replacing it.
- **Constraints:** all four values are generated from `package.json`'s
  `version` field via `CMakeLists.txt` and `configure_file` (§4.3, IF-2)
  — they are not independently maintained.
- **Language:** C++20 (`inline constexpr`).

## 6. Requirements traceability

This section has been tailored out. Sanitize has no formal Software
Requirements Specification (SRS) or numbered-requirement scheme to trace
design decisions against — behavioral expectations are captured
informally in `README.md`'s Features/Limitations sections and, more
concretely, in `tests/test_sanitize.cpp`'s test suite, which functions as
an executable specification of expected behavior. Establishing formal
traceability would mean first producing a numbered requirements document
(effectively a retroactive SRS) — a separate undertaking, not something
to improvise inside this SDD.

## 7. Notes

### Acronyms and abbreviations

| Term | Meaning |
|---|---|
| ASCII | American Standard Code for Information Interchange (7-bit character encoding) |
| CSCI | Computer Software Configuration Item |
| DID | Data Item Description |
| DoD | Department of Defense |
| HWCI | Hardware Configuration Item |
| NFC/NFD | Unicode Normalization Form C/D |
| NTTP | Non-Type Template Parameter (a C++ template parameter that is a value, not a type) |
| SDD | Software Design Description |
| SIMD | Single Instruction, Multiple Data |
| SRS | Software Requirements Specification |
| UTF-8 | Unicode Transformation Format, 8-bit |

### Glossary

- **Codepoint** — a single Unicode character's numeric identifier (e.g.
  U+0041 for `A`), as distinct from its UTF-8 byte encoding, which may be
  1 to 4 bytes long.
- **Overlong encoding** — a UTF-8 sequence that encodes a codepoint using
  more bytes than the minimum required (e.g. encoding `A` U+0041, which
  needs only 1 byte, as a 2-byte sequence). Well-formed but structurally
  suspect; a known technique for smuggling a forbidden character past a
  filter that checks raw bytes instead of the decoded codepoint.
- **Surrogate half** — one of the codepoints in the range U+D800–U+DFFF,
  reserved by the Unicode standard for UTF-16 surrogate pairs and never a
  real, standalone character. A well-formed UTF-8 sequence that decodes
  into this range is not a valid codepoint.

## A. Appendixes

None.
