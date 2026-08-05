# TODO

## Encoding assumptions

- Every entry point (`map`/`replace`/`filter`/`escape`/`strict`/`is_valid`)
  decodes input as UTF-8 unconditionally — there's no way for a caller to
  say "this should never contain non-ASCII at all, valid UTF-8 or not."
  `std::string_view` carries no encoding information, so "assume UTF-8" is
  always an assumption imposed by the library, never a fact about the
  bytes; for a field that's supposed to be plain ASCII (an internal
  identifier, say), the mere presence of well-formed multi-byte UTF-8 can
  itself be the signal something's wrong, but nothing today can catch
  that — it just passes through as valid text.
- Candidate fix discussed: a `MaybeUnicode` wrapper type around
  `std::string_view` that every entry point takes instead of a bare
  `std::string_view`, with no default construction and no implicit
  conversion — a call site has to explicitly pick `assume_utf8(text)` or
  `ascii_only(text)` before anything compiles, so the assumption is stated
  rather than silently defaulted. A template-parameter policy (mirroring
  `Overlong`) was also considered and rejected: it still ships with a
  default, so it just relocates the same implicit assumption one level
  down instead of removing it.
- Open questions before implementing: what `map`/`replace`/`filter`/
  `escape` should do with a rejected non-ASCII byte under `ascii_only`
  (throw like `strict`, or something `Overlong`-policy-like instead), and
  whether `ascii_only` should still run the existing `Config`
  forbidden-character check afterward or treat "not ASCII-clean" as
  sufficient on its own.
