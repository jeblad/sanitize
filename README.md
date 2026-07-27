# Sanitize

A header-only C++20 library for filtering character streams against a
compile-time-defined forbidden-character set, with UTF-8 security checks.

## Overview

Sanitize is not a general-purpose text validation library, and it does not
validate Unicode character sets in general — that has too many edge cases
and gaps to do safely. Its scope is narrower and more concrete: characters
that might end up on a command line, in a shell argument, or in some other
user-facing view. Filenames are one example of that, but the library isn't
filename-specific; it's built for filtering character streams in general,
against whatever forbidden-character set the caller defines.

## Requirements

- C++20 (concepts and non-type template string parameters are used throughout)
- Header-only: `#include "sanitize/sanitize.hpp"`, no library to link

## Features

- **Compile-time character sets**: `FixedString` is a set of characters
  fixed at compile time, with `+` (union) and `-` (difference) to compose
  new sets from existing ones without repeating yourself.
- **`Config<Chars>`**: an immutable, O(1) forbidden-character lookup built
  from a `FixedString`. No singleton, no runtime reconfiguration — if you
  want a different set, you construct a different `Config`.
- **`map` / `replace` / `filter` / `escape`**: `map` applies any callable of
  your choosing to every forbidden character, leaving everything else
  (including well-formed multibyte UTF-8) untouched. `replace`, `filter`,
  and `escape` are the three built-in transforms — substitute a fixed
  character, drop the character, or backslash-escape it — all just `map`
  under the hood.
- **`strict` / `isValid`**: `strict` inspects a string and throws on the
  first forbidden character or encoding problem, without copying anything.
  `isValid` is `strict` wrapped in a try/catch for callers who want a bool.
- **`findSubstrings`**: partitions a string into a lazy sequence of typed
  `Fragment`s (`Valid`/`Forbidden`/`Invalid`), run-length-grouped, covering
  every byte of input — not just the anomalies. No write-back; build a new
  string from the fragments.
- **Overlong UTF-8 handling**: every function decodes UTF-8 and checks
  whether the *decoded* codepoint is forbidden, never the raw bytes, so
  an overlong-encoded forbidden character (a known filter-bypass technique)
  is always caught regardless of policy. The `Overlong` enum
  (`Throw`/`Remove`/`Replace`/`AsIs`/`Compact`) only governs what happens to
  an overlong sequence whose decoded codepoint turns out to be harmless.

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
sanitize::isValid<TightChars>("safe_filename.txt");   // true
sanitize::isValid<TightChars>("bad;name.txt");        // false
sanitize::isValid<LooseChars>("bad;name.txt");        // true — ';' isn't in LooseChars

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
sanitize::isValid<TightChars>(input);

// Re-encode a harmless overlong sequence to its canonical minimal form
// instead of rejecting it. A forbidden character is still always caught,
// regardless of this policy.
sanitize::isValid<TightChars, sanitize::Overlong::Compact>(input);
```

### Partitioning a string by type

`findSubstrings` splits input into a lazy sequence of `Fragment`s, each one
a run of consecutive characters sharing the same `FragmentType` (`Valid`,
`Forbidden`, or `Invalid`). Every byte of input is covered by exactly one
fragment — this isn't limited to the "bad" parts, it's the whole string,
typed. `Fragment::text` is a `std::string_view` into `input`: valid as
long as `input` stays alive and unmodified. There's no write-back —
build a new string from the fragments instead of editing `input` in place.

```cpp
for (auto frag : sanitize::findSubstrings<TightChars>("file/name.txt")) {
    // Valid: "file"
    // Forbidden: "/"
    // Valid: "name.txt"
}
```

This is the primitive `replace`/`filter`/`escape` are effectively built
on top of; use it directly when you need custom per-fragment handling
(e.g. logging what was found, or a transform that depends on surrounding
context) that a per-character `map` transform can't express.

## Building and Testing

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

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.

## Acknowledgements

*Created with assistance from AI tools (Gemini 2.5, 3.0, and 3.1, in both Flash and Pro versions; Claude 4.6, 4.8, and 5.0) across all parts of this work.*

This project was developed independently, with no external financial or institutional support other than the AI tools mentioned. The views and conclusions contained herein are those of the author(s) and should not be interpreted as representing the official policies or endorsements, either expressed or implied, of any external agency or entity.
