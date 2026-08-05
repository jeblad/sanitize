# Sanitize

![status](https://img.shields.io/badge/status-stable-brightgreen)
![license](https://img.shields.io/github/license/jeblad/sanitize)
![C++](https://img.shields.io/badge/C%2B%2B-20-blue)
![issues](https://img.shields.io/github/issues-raw/jeblad/sanitize)
![pull requests](https://img.shields.io/github/issues-pr-raw/jeblad/sanitize)

A header-only C++20 library for filtering character streams — filenames,
shell arguments, or anything else that might reach a command line or a
user-facing view — against a compile-time-defined forbidden-character set,
with UTF-8-aware security checks built in.

Sanitize isn't a general-purpose text validator, and doesn't attempt full
Unicode conformance — that has too many edge cases to do safely. Its scope
is narrower: decide which characters are forbidden, then replace, drop, or
escape them. Every decision is made against the *decoded* UTF-8 codepoint,
never the raw bytes, so an overlong-encoded forbidden character — a
well-known filter-bypass technique — is caught the same way regardless of
policy.

Forbidden-character sets are `FixedString` values, fixed at compile time
and composable with `+`/`-`, so a new set can build on an existing one
instead of repeating it. `Config<Chars>` turns a set into an immutable,
O(1) lookup; `replace`, `filter`, and `escape` are the three built-in
transforms, all thin wrappers over the more general `map`.

## Quick start

```cpp
#include "sanitize/sanitize.hpp"

constexpr auto TightChars = sanitize::FixedString("\\/:;!?\"'`<>|*$&()[]{}@~# ");

std::string name = "My/File:Name?with*illegal\"chars.txt";
std::string clean = sanitize::replace<TightChars, '_'>(name);
// "My_File_Name_with_illegal_chars.txt"
```

## Usage

### Defining a character set

```cpp
#include "sanitize/sanitize.hpp"

constexpr auto TightChars = sanitize::FixedString("\\/:;!?\"'`<>|*$&()[]{}@~# ");
constexpr auto LooseChars = sanitize::FixedString("\\/:?\"<>|*");

// Compose new sets from existing ones — no need to repeat the base set.
constexpr auto ExtraChars = TightChars + sanitize::FixedString("%");
```

### Replacing forbidden characters

```cpp
std::string name = "My/File:Name?with*illegal\"chars.txt";
std::string clean = sanitize::replace<TightChars, '_'>(name);
// "My_File_Name_with_illegal_chars.txt"
```

### Filtering (dropping) forbidden characters

```cpp
std::string clean = sanitize::filter<TightChars>("file name.txt");
// "filename.txt"
```

### Escaping for display or shell use

```cpp
std::string untrusted = "Hello World; rm -rf /";
std::string escaped = sanitize::escape<TightChars>(untrusted);
// "Hello\ World\;\ rm\ -rf\ \/"
```

`escape` only produces output that can be safely unescaped (one where a
reader can tell an escape sequence apart from a literal backslash) if `\` is
itself a member of the character set — `TightChars` above includes it.
If your set omits `\`, a literal backslash in the input passes through
unescaped, which can make the output ambiguous to a downstream parser.

### Validating

```cpp
sanitize::is_valid<TightChars>("safe_filename.txt");   // true
sanitize::is_valid<TightChars>("bad;name.txt");        // false
sanitize::is_valid<LooseChars>("bad;name.txt");        // true — ';' isn't in LooseChars

// strict throws std::invalid_argument instead of returning false.
sanitize::strict<TightChars>("bad;name.txt");
```

### A custom transform

`replace`/`filter`/`escape` are just `map` with a particular transform.
Anything invocable on a `char` and returning something string-convertible
works:

```cpp
std::string result = sanitize::map<TightChars>("a/b", [](char c) {
    return std::string("[") + c + "]";
});
// "a[/]b"
```

### Controlling overlong-encoding handling

```cpp
// Default: any overlong sequence is rejected, even a harmless one.
sanitize::is_valid<TightChars>(input);

// Re-encode a harmless overlong sequence to its canonical minimal form
// instead of rejecting it. A forbidden character is still always caught,
// regardless of this policy.
sanitize::is_valid<TightChars, sanitize::Overlong::Compact>(input);
```

### Partitioning a string by type

`find_substrings` splits input into a lazy sequence of `Fragment`s, each one
a run of consecutive characters sharing the same `FragmentType` (`Valid`,
`Forbidden`, or `Invalid`). Every byte of input is covered by exactly one
fragment — this isn't limited to the "bad" parts, it's the whole string,
typed. `Fragment::text` is a `std::string_view` into `input`: valid as
long as `input` stays alive and unmodified. There's no write-back —
build a new string from the fragments instead of editing `input` in place.

```cpp
for (auto frag : sanitize::find_substrings<TightChars>("file/name.txt")) {
    // Valid: "file"
    // Forbidden: "/"
    // Valid: "name.txt"
}
```

This is the primitive `replace`/`filter`/`escape` are effectively built
on top of; use it directly when you need custom per-fragment handling
(e.g. logging what was found, or a transform that depends on surrounding
context) that a per-character `map` transform can't express.

## Requirements

- C++20 (concepts and non-type template string parameters are used throughout)
- Header-only: `#include "sanitize/sanitize.hpp"`, no library to link

**Development:** CMake 3.19 or later, to build and run the test suite.

## Installation

Sanitize is header-only, so the simplest path is copying
`include/sanitize/sanitize.hpp` directly into a project — no build step,
nothing to link.

To pull it in via CMake instead:

```cmake
include(FetchContent)
FetchContent_Declare(sanitize
    GIT_REPOSITORY https://github.com/jeblad/sanitize.git
    GIT_TAG v2.1.0)
FetchContent_MakeAvailable(sanitize)

target_link_libraries(your_target PRIVATE sanitize)
```

`CMakeLists.txt` doesn't currently guard its own test target behind a
top-level-project check, so `FetchContent`/`add_subdirectory` also builds
`sanitize_test` inside the consuming project's tree — a known wrinkle,
not a hidden one.

## Development

This project uses CMake. Since the library itself is header-only, building
only produces the test executable.

```bash
cmake -B build
cmake --build build
```

To run the included unit tests, use CTest after building:

```bash
(cd build && ctest --verbose)
```

## Limitations

- **ASCII only, for now**: forbidden-character sets are restricted to 7-bit
  ASCII (enforced at compile time). A set containing a character above
  U+007F fails to compile — that's a placeholder for a future SIMD-based
  path, not yet implemented.
- **No Unicode normalization**: the library checks UTF-8 structural
  validity and rejects overlong encodings, but doesn't normalize (NFC/NFD).
  A visually similar character — e.g. Full-width Solidus (`／` U+FF0F) —
  can pass through unfiltered and later be normalized by the OS or a
  downstream library into an ordinary `/`. Normalize first, then sanitize.
- **No path semantics**: the library filters characters, not path
  structure. It has no opinion on `.`/`..` path-traversal components; if a
  path separator like `/` matters for your use case, put it in your
  forbidden set like any other character.
- **No reserved-name or filesystem-limit checks**: it doesn't check
  OS-reserved names (`NUL`, `CON`, `PRN`, ...) or filesystem limits like
  path length, since those aren't character-level concerns.
- **Editing the generated header directly**: `include/sanitize/sanitize.hpp`
  is generated from `sanitize.hpp.in` by CMake on every configure; edits
  made straight to the generated file are silently overwritten. Edit
  `sanitize.hpp.in` instead.
- **No way to reject non-ASCII outright**: every function decodes input as
  UTF-8 unconditionally, and well-formed multibyte UTF-8 that isn't on the
  forbidden list always passes through — there's currently no way to say
  "this string should never contain non-ASCII at all," even for a field
  where that would itself be a red flag. Tracked in `TODO.md`.

## Architecture

Sanitize decodes UTF-8 one sequence at a time and checks the *decoded*
codepoint against the forbidden-character set — never the raw bytes — so
an overlong-encoded forbidden character can't bypass filtering regardless
of policy. Character sets and their lookup structures are built entirely
at compile time (`FixedString`, `Config<Chars>`), with no runtime
reconfiguration.

This is a synopsis; see [docs/SDD.md](docs/SDD.md) for the full Software
Design Description (prepared per MIL-STD-498), covering every software
unit's design decisions in detail.

## Code Style

Source code follows *The Art of Readable Code* (Boswell & Foucher), with
a stricter *The Power of Ten* (Holzmann) overlay on the UTF-8 parsing
code. See `AGENTS.md` for the full record.

## Internationalization / localization

Not applicable: Sanitize is a low-level character-filtering library with no
user-facing strings of its own to translate. Its ASCII-only restriction on
forbidden-character sets (see Limitations) is a related but separate
technical constraint, not a localization concern.

## Versioning, License, and Terms

Sanitize follows [Semantic Versioning](https://semver.org/); released
versions are tracked as git tags and in `CHANGELOG.md`. The current
version is also available at compile time as `sanitize::Version` (and
`VersionMajor`/`VersionMinor`/`VersionPatch`), alongside the
`SANITIZE_VERSION*` preprocessor macros for `#if`-based checks.

This project is licensed under the GNU General Public License v3.0 — see
the LICENSE file for details.

## Acknowledgements

*Created with assistance from AI tools (Gemini and Claude Sonnet) across all parts of this work.*

This project was developed independently, with no external financial or institutional support other than the AI tools mentioned. The views and conclusions contained herein are those of the author(s) and should not be interpreted as representing the official policies or endorsements, either expressed or implied, of any external agency or entity.
