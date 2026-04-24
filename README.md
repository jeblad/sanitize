# Sanitize

A C++ library designed for robust filename and path sanitization, incorporating UTF-8 security checks to prevent common vulnerabilities and ensure cross-platform compatibility.

## Features

-   **Filename Rewriting**: Replaces illegal or problematic characters in filenames with a safe alternative (e.g., underscore `_`).
-   **Path Validation**: Throws exceptions for invalid UTF-8 sequences, overlong encodings, control characters, and path traversal attempts (`.` or `..`).
-   **Configurable Strictness**: Supports both a "tight" mode for very strict character filtering (e.g., for Windows/Linux filesystem compatibility) and a "loose" mode that also filters common shell metacharacters.
-   **UTF-8 Aware**: Correctly handles multi-byte UTF-8 characters, ensuring they are preserved unless they are part of an invalid sequence or overlong encoding.

## Building

This project uses CMake for its build system.

```bash
mkdir build
cd build
cmake ..
make
# Optional: make install
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

### Validating Filenames

The `validate` function throws a `std::invalid_argument` exception if the input string contains any forbidden elements.

```cpp
#include <iostream>
#include "sanitize/sanitize.hpp"

int main() {
    try {
        sanitize::validate("safe_filename.txt");
        std::cout << "safe_filename.txt is valid." << std::endl;

        sanitize::validate("../path/traversal.txt"); // This will throw
        std::cout << "This line will not be reached." << std::endl;
    } catch (const std::invalid_argument& e) {
        std::cerr << "Validation error: " << e.what() << std::endl;
    }
    return 0;
}
```

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.
