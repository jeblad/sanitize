# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## [2.1.0](https://github.com/jeblad/sanitize/compare/v2.0.0...v2.1.0) (2026-08-05)

### ⚠ BREAKING CHANGES

* isValid and findSubstrings are renamed to is_valid and
  find_substrings for naming consistency with the rest of the public API.

* rename isValid/findSubstrings to is_valid/find_substrings; harden internals ([93785b2](https://github.com/jeblad/sanitize/commit/93785b232dd052a64218da8a2ffac8f8137f9539))

### Bug Fixes

* **release:** amend postbump-generated files into the release commit ([b9501da](https://github.com/jeblad/sanitize/commit/b9501daf730d15538ce7b3ed67a1ec236d49b8d6))
## [2.0.0](https://github.com/jeblad/sanitize/compare/v1.0.1...v2.0.0) (2026-07-27)


### ⚠ BREAKING CHANGES

* the entire public API is replaced. rewrite(), escape(),
validate(), untaint(), and set_forbidden_characters() are gone.
sanitize.cpp no longer exists; the library is header-only, generated
from sanitize.hpp.in via CMake.

* rewrite as a template-based header-only library ([bf883b9](https://github.com/jeblad/sanitize/commit/bf883b97f32dff6827e42c3d33116bf909e878ce))

## 1.0.1 (2026-07-25)
