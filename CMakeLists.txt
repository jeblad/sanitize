cmake_minimum_required(VERSION 3.10)
project(sanitize VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

configure_file(version.h.in include/sanitize/version.h)
configure_file(version.md.in ${CMAKE_CURRENT_SOURCE_DIR}/VERSION.md @ONLY)

add_library(sanitize src/sanitize.cpp)
set_target_properties(sanitize PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(sanitize PUBLIC 
    include
    ${CMAKE_CURRENT_BINARY_DIR}/include
)
target_compile_features(sanitize PUBLIC cxx_std_17) # Explicitly set C++17 features

# Enkel test-executable
add_executable(sanitize_test tests/test_sanitize.cpp)
target_include_directories(sanitize_test PRIVATE include) # Explicitly add include for test
target_link_libraries(sanitize_test sanitize)
