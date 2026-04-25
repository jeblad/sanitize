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
 * @brief Configures the character sets used by the library.
 * 
 * If not called, the library uses default Windows/Linux and Shell-safe sets.
 * 
 * @param tight_set Characters forbidden in 'tight' mode.
 * @param loose_set Characters forbidden in 'loose' (default) mode.
 */
void set_forbidden_characters(std::string_view tight_set, std::string_view loose_set);

/**
 * @brief Rewrites a filename by replacing illegal characters with underscores.
 * 
 * @param name The input filename to sanitize.
 * @param tight If true, applies strict rules (standard Windows/Linux forbidden chars).
 *              If false, applies a broader filter including shell metacharacters.
 * @param replacement The character used to replace illegal characters (default: '_').
 * @return A sanitized copy of the input string.
 */
std::string rewrite(std::string_view name, bool tight = true, char replacement = '_');

/**
 * @brief Escapes illegal characters instead of replacing them.
 * 
 * Uses backslash prefixes for metacharacters and hex-encoding (\xHH) for 
 * control characters or invalid UTF-8.
 * 
 * @param name The input string to escape.
 * @param tight If true, applies strict rules.
 * @return An escaped version of the input string.
 */
std::string escape(std::string_view name, bool tight = true);

/**
 * @brief Validates a filename and returns a status.
 * 
 * Checks for illegal ASCII, control characters, invalid UTF-8,
 * and path traversal components.
 * 
 * @param name The input string to validate.
 * @param tight If true, applies strict rules. If false, applies broader shell filter.
 * @return true if the string is valid, false otherwise.
 */
bool validate(std::string_view name, bool tight = true);

/**
 * @brief Validates a string and returns a copy if it is clean.
 * 
 * This follows the untainting principle by checking every character and
 * only returning a copy if the input passes all validation checks.
 * 
 * @param name The untrusted input string.
 * @param tight If true, applies strict rules.
 * @return A trusted copy of the input string.
 * @throws std::invalid_argument if validation fails.
 */
std::string untaint(std::string_view name, bool tight = true);

}  // namespace sanitize
