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
    
    // Test loose mode (default) - spaces and shell metachars are replaced
    assert(sanitize::rewrite("file name.txt") == "file_name.txt");
    assert(sanitize::rewrite("file$name.txt") == "file_name.txt");
    assert(sanitize::rewrite("file(1).txt") == "file_1_.txt");

    // Test tight mode - spaces allowed, but specific OS forbidden chars blocked
    assert(sanitize::rewrite("file name.txt", true) == "file name.txt");
    assert(sanitize::rewrite("file:name.txt", true) == "file_name.txt");

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

void test_validate() {
    std::cout << "Running validate tests..." << std::endl;

    // Should not throw for valid filenames
    sanitize::validate("valid_filename.txt");
    sanitize::validate("filename with spaces.txt", true);

    // Path traversal components should throw
    try {
        sanitize::validate("..");
        assert(false && "Validation should have failed for '..'");
    } catch (const std::invalid_argument& e) {
        std::cout << "Caught expected error: " << e.what() << std::endl;
    }

    // Illegal characters in loose mode
    try {
        sanitize::validate("bad;char.txt");
        assert(false && "Validation should have failed for ';'");
    } catch (const std::invalid_argument& e) {
        std::cout << "Caught expected error: " << e.what() << std::endl;
    }

    // Overlong UTF-8 (Security bypass attempt)
    // A 2-byte encoding of '/' (0x2F) is 0xC0 0xAF
    try {
        sanitize::validate("\xC0\xAF");
        assert(false && "Validation should have failed for overlong UTF-8");
    } catch (const std::invalid_argument& e) {
        std::cout << "Caught expected error: " << e.what() << std::endl;
    }

    std::cout << "Validate tests passed!\n" << std::endl;
}

int main() {
    try {
        test_rewrite();
        test_validate();
        std::cout << "All tests passed successfully!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected test failure: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
