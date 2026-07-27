#include "sanitize/sanitize.hpp"
#include <cassert>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace sanitize;

constexpr auto TightChars = FixedString("\\/:;!?\"'`<>|*$&()[]{}@~# ");
constexpr auto LooseChars = FixedString("\\/:?\"<>|*");
constexpr auto ControlChars = FixedString(
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
    "\x7F");

void test_fixed_string() {
    std::cout << "Running FixedString tests..." << std::endl;

    static_assert(FixedString("aab").len == 2, "duplicate characters must collapse");

    constexpr auto extra = TightChars + FixedString("%");
    static_assert(extra.len == TightChars.len + 1);
    static_assert(extra.contains('%'));

    constexpr auto fewer = TightChars - FixedString("@");
    static_assert(fewer.len == TightChars.len - 1);
    static_assert(!fewer.contains('@'));

    std::cout << "FixedString tests passed!\n" << std::endl;
}

void test_replace() {
    std::cout << "Running replace tests..." << std::endl;

    assert((replace<TightChars, '_'>("simple.txt") == "simple.txt"));
    assert((replace<TightChars, '_'>("file/name.txt") == "file_name.txt"));
    assert((replace<TightChars, '_'>("file name.txt") == "file_name.txt"));
    assert((replace<TightChars, '_'>("file$name.txt") == "file_name.txt"));
    assert((replace<TightChars, '_'>("file(1).txt") == "file_1_.txt"));

    // Loose set allows spaces, but still blocks its own forbidden chars.
    assert((replace<LooseChars, '_'>("file name.txt") == "file name.txt"));
    assert((replace<LooseChars, '_'>("file:name.txt") == "file_name.txt"));

    // Custom replacement character.
    assert((replace<LooseChars, '+'>("file/name.txt") == "file+name.txt"));

    // UTF-8 is preserved as long as it isn't forbidden data.
    assert((replace<TightChars, '_'>("bl\xC3\xA5" "b\xC3\xA6" "r.txt") == "bl\xC3\xA5" "b\xC3\xA6" "r.txt"));
    assert((replace<TightChars, '_'>("\xF0\x9F\x98\x8A.txt") == "\xF0\x9F\x98\x8A.txt"));

    std::cout << "Replace tests passed!\n" << std::endl;
}

void test_filter() {
    std::cout << "Running filter tests..." << std::endl;

    assert((filter<TightChars>("file/name.txt") == "filename.txt"));
    assert((filter<TightChars>("file name.txt") == "filename.txt"));

    std::cout << "Filter tests passed!\n" << std::endl;
}

void test_escape() {
    std::cout << "Running escape tests..." << std::endl;

    assert((escape<TightChars>("file name.txt") == "file\\ name.txt"));
    assert((escape<TightChars>("dangerous; shell") == "dangerous\\;\\ shell"));
    assert((escape<TightChars>("tight/path") == "tight\\/path"));

    // Control characters are only escaped if actually in the configured set —
    // no hardcoded control-character handling.
    assert((escape<TightChars>("line\nbreak") == "line\nbreak"));
    assert((escape<ControlChars>("line\nbreak") == "line\\nbreak"));
    assert((escape<ControlChars>("a\x01" "b") == "a\\x01" "b"));

    // Documented caveat: a literal backslash only gets escaped if '\' is
    // itself in Chars. TightChars includes it, so this round-trips safely...
    assert((escape<TightChars>("a\\b") == "a\\\\b"));
    // ...but a set without it lets a literal backslash through unescaped.
    constexpr auto NoBackslashChars = FixedString(";");
    assert((escape<NoBackslashChars>("a\\;b") == "a\\\\;b"));

    std::cout << "Escape tests passed!\n" << std::endl;
}

void test_strict_and_isvalid() {
    std::cout << "Running strict/isValid tests..." << std::endl;

    assert((isValid<TightChars>("valid_filename.txt") == true));
    assert((isValid<TightChars>("filename with spaces.txt") == false));
    assert((isValid<LooseChars>("filename with spaces.txt") == true));

    assert((isValid<TightChars>("bad;char.txt") == false));
    assert((isValid<LooseChars>("bad;char.txt") == true));

    // Overlong UTF-8 (security bypass attempt) is rejected by default.
    assert((isValid<TightChars>("\xC0\xAF") == false));

    bool threw = false;
    try {
        strict<TightChars>("bad;char.txt");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    assert(threw);

    std::cout << "Strict/isValid tests passed!\n" << std::endl;
}

void test_utf8_range_validation() {
    std::cout << "Running UTF-8 range validation tests..." << std::endl;

    // A UTF-16 surrogate half (U+D800) encoded as well-formed 3-byte UTF-8
    // is not a real codepoint and must be rejected, not passed through.
    assert((isValid<TightChars>("\xED\xA0\x80") == false));

    // A well-formed 4-byte sequence decoding past U+10FFFF (here 0x1FFFFF)
    // is not a real codepoint either.
    assert((isValid<TightChars>("\xF7\xBF\xBF\xBF") == false));

    // U+10FFFF itself is the maximum valid codepoint and must still pass.
    assert((isValid<TightChars>("\xF4\x8F\xBF\xBF") == true));

    // A UTF-16 surrogate half (U+D800) overlong-encoded as 4 bytes must
    // also be rejected — not classified as merely Overlong — regardless
    // of the Overlong policy, since it's never a real codepoint.
    const std::string overlong_surrogate = "\xF0\x8D\xA0\x80";
    assert((isValid<TightChars>(overlong_surrogate) == false));
    assert((isValid<TightChars, Overlong::Compact>(overlong_surrogate) == false));
    assert((isValid<TightChars, Overlong::AsIs>(overlong_surrogate) == false));

    std::cout << "UTF-8 range validation tests passed!\n" << std::endl;
}

void test_overlong_policies() {
    std::cout << "Running Overlong policy tests..." << std::endl;

    // Overlong-encoded 'A' (0x41) as a 2-byte sequence: harmless once decoded.
    const std::string overlong_a = "\xC1\x81";
    assert((isValid<TightChars, Overlong::Throw>(overlong_a) == false));
    assert((isValid<TightChars, Overlong::Compact>(overlong_a) == true));
    assert((replace<TightChars, '_', Overlong::Compact>(overlong_a) == "A"));
    assert((replace<TightChars, '_', Overlong::AsIs>(overlong_a) == overlong_a));
    assert((replace<TightChars, '_', Overlong::Remove>(overlong_a) == ""));
    assert((replace<TightChars, '_', Overlong::Replace>(overlong_a) == "\xEF\xBF\xBD"));

    // Overlong-encoded '/' (forbidden in TightChars): caught regardless of
    // policy, since detection always runs against the decoded codepoint.
    const std::string overlong_slash = "\xC0\xAF";
    assert((isValid<TightChars, Overlong::AsIs>(overlong_slash) == false));
    assert((replace<TightChars, '_', Overlong::AsIs>(overlong_slash) == "_"));

    std::cout << "Overlong policy tests passed!\n" << std::endl;
}

void test_find_substrings() {
    std::cout << "Running findSubstrings tests..." << std::endl;

    // Run-length grouping: valid, forbidden, valid.
    {
        std::vector<std::pair<FragmentType, std::string>> got;
        for (auto frag : findSubstrings<TightChars>("abc/def")) {
            got.emplace_back(frag.type, std::string(frag.text));
        }
        assert(got.size() == 3);
        assert((got[0] == std::pair{FragmentType::Valid, std::string("abc")}));
        assert((got[1] == std::pair{FragmentType::Forbidden, std::string("/")}));
        assert((got[2] == std::pair{FragmentType::Valid, std::string("def")}));
    }

    // Consecutive forbidden characters merge into one fragment.
    {
        std::vector<FragmentType> types;
        std::vector<std::string> texts;
        for (auto frag : findSubstrings<TightChars>("a//b")) {
            types.push_back(frag.type);
            texts.emplace_back(frag.text);
        }
        assert(types.size() == 3);
        assert(types[1] == FragmentType::Forbidden);
        assert(texts[1] == "//");
    }

    // Well-formed multi-byte UTF-8 that isn't forbidden is Valid, and
    // merges with adjacent valid ASCII into one fragment.
    {
        int count = 0;
        FragmentType only_type{};
        for (auto frag : findSubstrings<TightChars>("bl\xC3\xA5" "b\xC3\xA6" "r")) {
            only_type = frag.type;
            ++count;
        }
        assert(count == 1);
        assert(only_type == FragmentType::Valid);
    }

    // A byte that starts no valid UTF-8 sequence is Invalid, length 1, and
    // adjacent invalid bytes merge into one fragment.
    {
        std::vector<FragmentType> types;
        std::vector<std::string> texts;
        for (auto frag : findSubstrings<TightChars>("a\xFF" "\xFF" "b")) {
            types.push_back(frag.type);
            texts.emplace_back(frag.text);
        }
        assert(types.size() == 3);
        assert(types[1] == FragmentType::Invalid);
        assert(texts[1].size() == 2);
    }

    // Overlong-encoded '/' (forbidden) classifies as Forbidden, not Invalid.
    {
        int count = 0;
        FragmentType only_type{};
        for (auto frag : findSubstrings<TightChars>("\xC0\xAF")) {
            only_type = frag.type;
            ++count;
        }
        assert(count == 1);
        assert(only_type == FragmentType::Forbidden);
    }

    // Overlong-encoded 'A' (not forbidden) classifies as Invalid, not Valid
    // — an overlong encoding is always structurally suspect.
    {
        int count = 0;
        FragmentType only_type{};
        for (auto frag : findSubstrings<TightChars>("\xC1\x81")) {
            only_type = frag.type;
            ++count;
        }
        assert(count == 1);
        assert(only_type == FragmentType::Invalid);
    }

    // Overlong-encoded surrogate classifies as Invalid too.
    {
        int count = 0;
        FragmentType only_type{};
        for (auto frag : findSubstrings<TightChars>("\xF0\x8D\xA0\x80")) {
            only_type = frag.type;
            ++count;
        }
        assert(count == 1);
        assert(only_type == FragmentType::Invalid);
    }

    // Empty input yields zero fragments.
    {
        int count = 0;
        for (auto frag : findSubstrings<TightChars>("")) {
            (void)frag;
            ++count;
        }
        assert(count == 0);
    }

    // Fragments can be used to rebuild a replace()-equivalent string.
    {
        std::string rebuilt;
        for (auto frag : findSubstrings<TightChars>("file/name.txt")) {
            if (frag.type == FragmentType::Valid) {
                rebuilt += frag.text;
            } else {
                rebuilt += std::string(frag.text.size(), '_');
            }
        }
        assert(rebuilt == "file_name.txt");
    }

    std::cout << "findSubstrings tests passed!\n" << std::endl;
}

int main() {
    try {
        test_fixed_string();
        test_replace();
        test_filter();
        test_escape();
        test_strict_and_isvalid();
        test_utf8_range_validation();
        test_overlong_policies();
        test_find_substrings();
        std::cout << "All tests passed successfully!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected test failure: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
