# Sanitize

A portable C++ library for filename and path sanitization, incorporating UTF-8 security checks to prevent common vulnerabilities.

## Overview
Sanitize is a portable C++ library designed to secure file operations by validating and cleaning untrusted input. It features robust UTF-8 inspection to detect overlong encodings and path traversal attempts, ensuring filenames are safe for use across different operating systems and shells.

## Features

-   **Filename Rewriting**: Replaces illegal or problematic characters in filenames with a safe alternative (e.g., underscore `_`).
-   **Character Escaping**: Instead of replacing characters, this prefixes illegal characters with a backslash or hex-encodes control characters, making strings safe for display or shell use.
-   **Validation and Untainting**: Offers `validate` for lightweight boolean checks and `untaint` for secure, exception-throwing data copying.
-   **Configurable Strictness**: Supports both a "tight" mode for very strict character filtering (e.g., for Windows/Linux filesystem compatibility) and a "loose" mode that also filters common shell metacharacters.
-   **UTF-8 Aware**: Correctly handles multi-byte UTF-8 characters, ensuring they are preserved unless they are part of an invalid sequence or overlong encoding.


## Heuristic Parsing Logic

The library employs a deterministic byte-stream inspection to validate input integrity. It recognizes:
*   **Overlong UTF-8 Encodings**: It calculates the codepoint for every multi-byte sequence to ensure it uses the minimum necessary bytes, preventing attacks that use obfuscated characters (like `/` or `.`) to bypass filters.
*   **Path Traversal Tokens**: It explicitly identifies and blocks directory navigation segments (`.` and `..`) that could lead to unauthorized filesystem access.
*   **Context-Aware Forbidden Characters**: Based on the selected strictness, it identifies shell metacharacters (e.g., `$`, `;`, `&`) or OS-specific restricted characters (e.g., `:`, `*`, `?`) to ensure compatibility and safety.

## Limitations

*   **Specialized Scope**: This library is strictly intended for sanitizing strings for use as filenames and within shell environments. It is **not** a general-purpose validation library; for example, it cannot validate natural language data like proper names, addresses, or emails.
*   **Unicode Normalization**: The library validates UTF-8 structural integrity and prevents overlong encodings but does not perform Unicode normalization (e.g., NFC/NFD). 
    *   **Security Risk**: Certain characters like "Full-width Solidus" (`／` U+FF0F) may pass filters but later be normalized by the OS or downstream libraries into a standard slash (`/`).
    *   **Best Practice**: Always **Normalize first, then Sanitize**. This ensures that any "hidden" characters are expanded to their canonical forms before the security checks are applied.
*   **Reserved Names**: While it filters illegal characters, it does not currently check against a blacklist of OS-reserved filenames that contain only legal characters (such as `NUL`, `CON`, or `PRN` on Windows).
*   **Filesystem Specifics**: It does not account for specific filesystem limits like maximum path length (usually 4096 bytes) or maximum filename length (usually 255 bytes).

## Building and Testing

This project uses CMake for its build system.

```bash
cmake -B build
cmake --build build
```

To run the included unit tests, use CTest after building:

```bash
( build ; ctest --verbose )
```

## Usage

### Rewriting Filenames

The `rewrite` function takes a `std::string_view` and returns a new `std::string` with illegal characters replaced.

```cpp
#include <iostream>
#include "sanitize/sanitize.hpp"

int main() {
    std::string original_name = "My/File:Name?with*illegal\"chars.txt";
    std::string sanitized_name = sanitize::rewrite(original_name);
    std::cout << "Original: " << original_name << std::endl;
    std::cout << "Sanitized (default): " << sanitized_name << std::endl;

    std::string tight_name = "Another File with spaces & special chars.txt";
    std::string sanitized_tight = sanitize::rewrite(tight_name, true); // Use tight mode
    std::cout << "Original (tight): " << tight_name << std::endl;
    std::cout << "Sanitized (tight): " << sanitized_tight << std::endl;

    return 0;
}
```

### Escaping for Display or Shell

Use `escape` when you want to see the original "bad" characters in a safe format, or when passing arguments to a shell.

```cpp
#include <iostream>
#include "sanitize/sanitize.hpp"

int main() {
    std::string untrusted = "Hello\nWorld; rm -rf /";
    // Result: Hello\nWorld\; rm -rf /
    std::cout << "Escaped: " << sanitize::escape(untrusted, false) << std::endl;
    return 0;
}
```

### Validating Filenames

The `validate` function returns `false` if the input string contains any forbidden elements.

```cpp
#include <iostream>
#include "sanitize/sanitize.hpp"

int main() {
    if (sanitize::validate("safe_filename.txt")) {
        std::cout << "safe_filename.txt is valid." << std::endl;
    }
    
    if (!sanitize::validate("../path/traversal.txt")) {
        std::cout << "Traversal detected!" << std::endl;
    }
    return 0;
}
```

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.

## Acknowledgements

*Created with assistance from AI tools (Gemini 2.5, 3.0, and 3.1, in both Flash and Pro versions) across all parts of this work.*

This project was developed independently, with no external financial or institutional support other than the AI tools mentioned. The views and conclusions contained herein are those of the author(s) and should not be interpreted as representing the official policies or endorsements, either expressed or implied, of any external agency or entity.
