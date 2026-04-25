#include "sanitize/sanitize.hpp"
#include <iostream>
#include <cassert>
#include <string>
#include <stdexcept>

void test_rewrite() {
    std::cout << "Running rewrite tests..." << std::endl;

    // Test basic replacements
    assert(sanitize::rewrite("simple.txt") == "simple.txt");
    assert(sanitize::rewrite("file/name.txt") == "file_name.txt");

    // Test tight mode (default) - spaces and shell metachars are replaced
    assert(sanitize::rewrite("file name.txt") == "file_name.txt");
    assert(sanitize::rewrite("file$name.txt") == "file_name.txt");
    assert(sanitize::rewrite("file(1).txt") == "file_1_.txt");

    // Test loose mode (false) - spaces allowed, but specific OS forbidden chars blocked
    assert(sanitize::rewrite("file name.txt", false) == "file name.txt");
    assert(sanitize::rewrite("file:name.txt", false) == "file_name.txt");

    // Test custom replacement character
    assert(sanitize::rewrite("file/name.txt", false, '+') == "file+name.txt");
    assert(sanitize::rewrite("..", false, '-') == "-");

    // Test path components
    assert(sanitize::rewrite(".") == "_");
    assert(sanitize::rewrite("..") == "_");

    // Test UTF-8 preservation
    assert(sanitize::rewrite("blåbær.txt") == "blåbær.txt");
    assert(sanitize::rewrite("π.txt") == "π.txt");
    assert(sanitize::rewrite("😊.txt") == "😊.txt");

    // Test invalid UTF-8 (0xFF is an invalid start byte)
    assert(sanitize::rewrite("\xFF.txt") == "_.txt");

    std::cout << "Rewrite tests passed!\n" << std::endl;
}

void test_escape() {
    std::cout << "Running escape tests..." << std::endl;
    assert(sanitize::escape("file name.txt", true) == "file\\ name.txt");
    assert(sanitize::escape("line\nbreak") == "line\\nbreak");
    assert(sanitize::escape("dangerous; shell", true) == "dangerous\\;\\ shell");
    assert(sanitize::escape("safe_filename.txt", false) == "safe_filename.txt");
    assert(sanitize::escape("tight/path", true) == "tight\\/path");
    assert(sanitize::escape("\xFF", true) == "\\xFF");
    std::cout << "Escape tests passed!\n" << std::endl;
}

void test_validate() {
    std::cout << "Running validate tests..." << std::endl;

    // Should not throw for valid filenames
    assert(sanitize::validate("valid_filename.txt") == true);
    assert(sanitize::validate("filename with spaces.txt", false) == true);

    // Path traversal components should throw
    assert(sanitize::validate("..") == false);

    // Semicolon is forbidden in tight mode (default) but allowed in loose mode
    assert(sanitize::validate("bad;char.txt") == false);
    assert(sanitize::validate("bad;char.txt", false) == true);

    // Overlong UTF-8 (Security bypass attempt)
    assert(sanitize::validate("\xC0\xAF") == false);

    std::cout << "Validate tests passed!\n" << std::endl;
}

int main() {
    try {
        test_rewrite();
        test_escape();
        test_validate();
        std::cout << "All tests passed successfully!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected test failure: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
