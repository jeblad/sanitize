# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## [2.0.0](https://github.com/jeblad/sanitize/compare/v1.0.1...v2.0.0) (2026-07-27)


### ⚠ BREAKING CHANGES

* the entire public API is replaced. rewrite(), escape(),
validate(), untaint(), and set_forbidden_characters() are gone.
sanitize.cpp no longer exists; the library is header-only, generated
from sanitize.hpp.in via CMake.

* rewrite as a template-based header-only library ([bf883b9](https://github.com/jeblad/sanitize/commit/bf883b97f32dff6827e42c3d33116bf909e878ce))

## 1.0.1 (2026-07-25)
