# An LLVM pass plugin that obfuscates a function, by flattening its control
# flow, adding bogus flow or substituting its arithmetic, so a test can check
# that `hereticus` still pairs the functions of a binary a mutation engine
# rewrote. Built by `fixtures/pe.sh` where the LLVM development files are
# there. See `Obfuscate.cpp`.
cmake_minimum_required(VERSION 3.20)
project(hereticus_obfuscate LANGUAGES CXX)

find_package(LLVM REQUIRED CONFIG)
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

add_llvm_pass_plugin(HereticusObfuscate Obfuscate.cpp)
set_target_properties(HereticusObfuscate PROPERTIES CXX_STANDARD 17)
target_compile_definitions(HereticusObfuscate PRIVATE ${LLVM_DEFINITIONS})
target_include_directories(HereticusObfuscate PRIVATE ${LLVM_INCLUDE_DIRS})
