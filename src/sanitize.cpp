/**
 * sanitize – filename and path sanitization with UTF-8 security checks
 * 
 * Copyright © 2026 John Erling Blad
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 * 
 * See accompanying file LICENSE or the page at https://www.gnu.org/licenses/
 * Copyright 2026 John Erling Blad
 
 **/

#include "sanitize/sanitize.hpp"
#include <string>
#include <string_view>
#include <algorithm>
#include <stdexcept>
#include <cstdint>

namespace sanitize {

namespace {
    // Helper to determine UTF-8 sequence length and check for overlong encodings
    int get_utf8_info(const uint8_t* p, size_t remaining, uint32_t& codepoint) {
        uint8_t c = p[0];
        if (c < 0x80) {
            codepoint = c;
            return 1;
        }
        if ((c & 0xE0) == 0xC0) {
            if (remaining < 2 || (p[1] & 0xC0) != 0x80) return -1;
            codepoint = ((c & 0x1F) << 6) | (p[1] & 0x3F);
            if (codepoint < 0x80) return -2; // Overlong
            return 2;
        }
        if ((c & 0xF0) == 0xE0) {
            if (remaining < 3 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80) return -1;
            codepoint = ((c & 0x0F) << 12) | ((p[1] & 0x3F) << 6) | (p[2] & 0x3F);
            if (codepoint < 0x800) return -2; // Overlong
            return 3;
        }
        if ((c & 0xF8) == 0xF0) {
            if (remaining < 4 || (p[1] & 0xC0) != 0x80 || (p[2] & 0xC0) != 0x80 || (p[3] & 0xC0) != 0x80) return -1;
            codepoint = ((c & 0x07) << 18) | ((p[1] & 0x3F) << 12) | ((p[2] & 0x3F) << 6) | (p[3] & 0x3F);
            if (codepoint < 0x10000) return -2; // Overlong
            return 4;
        }
        return -1; // Invalid start byte
    }
}

std::string rewrite(std::string_view name, bool tight) {
    if (name == "." || name == "..") return "_";
    
    std::string result;
    result.reserve(name.size());

    const std::string_view illegal = tight ? "\\/:?\"<>|*" : "\\/:;!?\"'`<>|*$&()[]{}@~# ";
    const uint8_t* p = reinterpret_cast<const uint8_t*>(name.data());
    size_t len = name.size();

    for (size_t i = 0; i < len; ) {
        uint32_t cp = 0;
        int consumed = get_utf8_info(p + i, len - i, cp);

        if (consumed < 0) {
            result += '_';
            i++;
            continue;
        }

        if (consumed == 1) {
            if (cp < 32 || cp == 127 || illegal.find(static_cast<char>(cp)) != std::string::npos) {
                result += '_';
            } else {
                result += static_cast<char>(cp);
            }
        } else {
            // Multi-byte UTF-8 is kept unless it was overlong (handled by consumed < 0)
            result.append(name.substr(i, consumed));
        }
        i += consumed;
    }
    return result;
}

void validate(std::string_view name, bool tight) {
    if (name.empty()) return;
    if (name == "." || name == "..") {
        throw std::invalid_argument("Path traversal component detected");
    }

    const std::string_view illegal = tight ? "\\/:?\"<>|*" : "\\/:;!?\"'`<>|*$&()[]{}@~# ";
    const uint8_t* p = reinterpret_cast<const uint8_t*>(name.data());
    size_t len = name.size();

    for (size_t i = 0; i < len; ) {
        uint32_t cp = 0;
        int consumed = get_utf8_info(p + i, len - i, cp);

        if (consumed == -1) {
            throw std::invalid_argument("Invalid UTF-8 sequence");
        }
        if (consumed == -2) {
            throw std::invalid_argument("Overlong UTF-8 encoding detected (security bypass attempt)");
        }

        if (consumed == 1) {
            if (cp < 32 || cp == 127) {
                throw std::invalid_argument("Control characters not allowed in name");
            }
            if (illegal.find(static_cast<char>(cp)) != std::string::npos) {
                throw std::invalid_argument("Forbidden character detected in name");
            }
        }
        i += consumed;
    }
}

}  // namespace sanitize
