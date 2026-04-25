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

#include "sanitize/sanitize.hpp"
#include <string>
#include <string_view>
#include <algorithm>
#include <stdexcept>
#include <cstdint>


namespace sanitize {

namespace {
    struct Config {
        std::string tight = "\\/:;!?\"'`<>|*$&()[]{}@~# ";
        std::string loose = "\\/:?\"<>|*";
    };

    Config& get_config() {
        static Config instance;
        return instance;
    }

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

    void append_hex(std::string& s, uint8_t b) {
        static const char hex[] = "0123456789ABCDEF";
        s += "\\x"; s += hex[b >> 4]; s += hex[b & 0x0F];
    }
}

void set_forbidden_characters(std::string_view tight_set, std::string_view loose_set) {
    get_config().tight = std::string(tight_set);
    get_config().loose = std::string(loose_set);
}

std::string rewrite(std::string_view name, bool tight, char replacement) {
    if (name == "." || name == "..") return std::string(1, replacement);
    
    std::string result;
    result.reserve(name.size());

    const std::string_view illegal = tight ? get_config().tight : get_config().loose;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(name.data());
    size_t len = name.size();

    for (size_t i = 0; i < len; ) {
        uint32_t cp = 0;
        int consumed = get_utf8_info(p + i, len - i, cp);

        if (consumed < 0) {
            result += replacement;
            i++;
            continue;
        }

        if (consumed == 1) {
            if (cp < 32 || cp == 127 || illegal.find(static_cast<char>(cp)) != std::string::npos) {
                result += replacement;
            } else {
                result += static_cast<char>(cp);
            }
        } else {
            // Multi-byte UTF-8 is kept unless it was overlong (handled by consumed < 0)
            result.append(name.substr(i, consumed));
        }
        i += static_cast<size_t>(consumed);
    }
    return result;
}

std::string escape(std::string_view name, bool tight) {
    std::string result;
    result.reserve(name.size());

    const std::string_view illegal = tight ? get_config().tight : get_config().loose;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(name.data());
    size_t len = name.size();

    for (size_t i = 0; i < len; ) {
        uint32_t cp = 0;
        int consumed = get_utf8_info(p + i, len - i, cp);

        if (consumed < 0) {
            append_hex(result, p[i]);
            i++;
            continue;
        }

        if (consumed == 1) {
            char c = static_cast<char>(cp);
            if (cp < 32 || cp == 127) {
                switch (c) {
                    case '\0': result += "\\0"; break;
                    case '\n': result += "\\n"; break;
                    case '\r': result += "\\r"; break;
                    case '\t': result += "\\t"; break;
                    case '\v': result += "\\v"; break;
                    case '\f': result += "\\f"; break;
                    case '\b': result += "\\b"; break;
                    default: append_hex(result, static_cast<uint8_t>(c));
                }
            } else if (illegal.find(c) != std::string::npos || c == '\\') {
                result += '\\';
                result += c;
            } else {
                result += c;
            }
        } else {
            result.append(name.substr(i, static_cast<size_t>(consumed)));
        }
        i += static_cast<size_t>(consumed);
    }
    return result;
}

bool validate(std::string_view name, bool tight) {
    if (name.empty()) return true;
    if (name == "." || name == "..") return false;

    const std::string_view illegal = tight ? get_config().tight : get_config().loose;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(name.data());
    size_t len = name.size();

    for (size_t i = 0; i < len; ) {
        uint32_t cp = 0;
        int consumed = get_utf8_info(p + i, len - i, cp);

        if (consumed < 0) return false;

        if (consumed == 1) {
            if (cp < 32 || cp == 127 || illegal.find(static_cast<char>(cp)) != std::string::npos)
                return false;
        }
        i += static_cast<size_t>(consumed);
    }
    return true;
}

std::string untaint(std::string_view name, bool tight) {
    if (name.empty()) return {};
    if (name == "." || name == "..") {
        throw std::invalid_argument("Path traversal component detected");
    }

    const std::string_view illegal = tight ? get_config().tight : get_config().loose;
    const uint8_t* p = reinterpret_cast<const uint8_t*>(name.data());
    size_t len = name.size();

    std::string result;
    result.reserve(len);

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
            result += static_cast<char>(cp);
        } else {
            // Multi-byte UTF-8 is kept. get_utf8_info already validated structure and overlong.
            result.append(name.substr(i, static_cast<size_t>(consumed)));
        }
        i += static_cast<size_t>(consumed);
    }
    return result;
}

}  // namespace sanitize
