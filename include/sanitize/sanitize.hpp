/**
 * sanitize – filename and path sanitization with UTF-8 security checks
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 * 
 * See accompanying file LICENSE or the page at https://www.gnu.org/licenses/
 * Copyright 2026 John Erling Blad
 **/

#pragma once

#include <stdexcept>
#include <string>
#include <string_view>

namespace sanitize {

/**
 * @brief Rewrites a filename by replacing illegal characters with underscores.
 * 
 * @param name The input filename to sanitize.
 * @param tight If true, applies strict rules (standard Windows/Linux forbidden chars).
 *              If false, applies a broader filter including shell metacharacters.
 * @return A sanitized copy of the input string.
 */
std::string rewrite(std::string_view name, bool tight = false);

/**
 * @brief Validates a filename and throws an exception if illegal characters are found.
 * 
 * Checks for illegal ASCII, control characters, invalid UTF-8 (including overlong encodings),
 * and path traversal components like "." or "..".
 * 
 * @param name The input string to validate.
 * @param tight If true, applies strict rules. If false, applies broader shell filter.
 * @throws std::invalid_argument if the input is dangerous or malformed.
 */
void validate(std::string_view name, bool tight = false);

}  // namespace sanitize
