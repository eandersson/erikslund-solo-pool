cmake_minimum_required(VERSION 3.22)
project(erikslund_pool_cpp LANGUAGES CXX)

# ---- language / warnings -----------------------------------------------------
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wshadow)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---- aggressive optimization for Release (the production profile) -------------
# Release already implies -O3 -DNDEBUG; this adds LTO, loop/alignment tuning,
# dead-section GC, and full RELRO. NOTE: -march=native tunes for the BUILDING
# machine's CPU (fastest when you build on the deployment host). For a portable
# image built on a different CPU than it runs on, configure -DNATIVE_ARCH=OFF to
# avoid an illegal-instruction crash at runtime.
option(NATIVE_ARCH "Tune for the build machine's CPU (-march=native -mtune=native)" ON)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(
        -O3 -flto -fno-plt -fno-semantic-interposition
        -fno-trapping-math -fno-math-errno -funroll-loops -fomit-frame-pointer
        -falign-functions=32 -falign-loops=32 -ffunction-sections -fdata-sections -pipe)
    add_link_options(
        -flto=auto -Wl,-O3 -Wl,--as-needed -Wl,--gc-sections
        -Wl,-z,relro -Wl,-z,now)
    if(NATIVE_ARCH)
        add_compile_options(-march=native -mtune=native)
    endif()
endif()

# ---- dependencies ------------------------------------------------------------
# nlohmann/json and doctest are header-only and installed on the default include
# path by their -dev packages, so they need no find_package(). libcurl needs a
# link target.
find_package(Threads REQUIRED)
find_package(CURL REQUIRED)
find_package(simdjson CONFIG REQUIRED)  # fast Stratum JSON parsing (hot path)
find_library(ZMQ_LIBRARY zmq REQUIRED)
# yaml-cpp: config files + on-disk stats (pool.status / users/) are YAML. The
# HTTP API stays JSON. Prefer the package's CMake config; fall back to a plain
# library search if the -dev package ships no config (older distros).
find_package(yaml-cpp QUIET)
if(NOT yaml-cpp_FOUND)
    find_library(YAML_CPP_LIBRARY yaml-cpp REQUIRED)
endif()
# Optional mimalloc: a faster allocator for the many small concurrent
# allocations the share path makes. Linked into the executable with
# --no-as-needed so it interposes malloc process-wide (covering operator new).
find_library(MIMALLOC_LIBRARY mimalloc)

# ---- vendored Bitcoin Core SHA-256 (MIT, third_party/bitcoin) ----------------
# Verbatim from bitcoin/bitcoin v31.0; the fastest SHA-256 path is chosen at
# runtime. Each transform is compiled with the SIMD flags + ENABLE_* defines its
# build expects; warnings are silenced (-w) as it is upstream code we don't edit.
set(BTC_DIR ${CMAKE_SOURCE_DIR}/third_party/bitcoin)
set(BTC_CRYPTO_SOURCES ${BTC_DIR}/crypto/sha256.cpp)
set_source_files_properties(${BTC_DIR}/crypto/sha256.cpp PROPERTIES COMPILE_OPTIONS "-w")
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64|i[3-6]86")
    list(APPEND BTC_CRYPTO_SOURCES
        ${BTC_DIR}/crypto/sha256_sse4.cpp ${BTC_DIR}/crypto/sha256_sse41.cpp
        ${BTC_DIR}/crypto/sha256_avx2.cpp ${BTC_DIR}/crypto/sha256_x86_shani.cpp)
    set_source_files_properties(${BTC_DIR}/crypto/sha256_sse4.cpp PROPERTIES COMPILE_OPTIONS "-w")
    set_source_files_properties(${BTC_DIR}/crypto/sha256_sse41.cpp PROPERTIES COMPILE_OPTIONS "-w;-msse4.1")
    set_source_files_properties(${BTC_DIR}/crypto/sha256_avx2.cpp PROPERTIES COMPILE_OPTIONS "-w;-mavx;-mavx2")
    set_source_files_properties(${BTC_DIR}/crypto/sha256_x86_shani.cpp PROPERTIES COMPILE_OPTIONS "-w;-msse4.1;-msha")
    set_source_files_properties(${BTC_CRYPTO_SOURCES} PROPERTIES COMPILE_DEFINITIONS "ENABLE_SSE41;ENABLE_AVX2;ENABLE_X86_SHANI")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|armv8")
    list(APPEND BTC_CRYPTO_SOURCES ${BTC_DIR}/crypto/sha256_arm_shani.cpp)
    set_source_files_properties(${BTC_DIR}/crypto/sha256_arm_shani.cpp PROPERTIES COMPILE_OPTIONS "-w;-march=armv8-a+crypto")
    set_source_files_properties(${BTC_CRYPTO_SOURCES} PROPERTIES COMPILE_DEFINITIONS "ENABLE_ARM_SHANI")
endif()

# ---- core library ------------------------------------------------------------
# Every .cpp under src/ except main.cpp becomes the testable core library.
file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.cpp)
list(FILTER CORE_SOURCES EXCLUDE REGEX ".*/main\\.cpp$")

add_library(erikslund_core STATIC ${CORE_SOURCES} ${BTC_CRYPTO_SOURCES})
target_include_directories(erikslund_core PUBLIC ${CMAKE_SOURCE_DIR}/src ${BTC_DIR})
target_link_libraries(erikslund_core PUBLIC Threads::Threads CURL::libcurl ${ZMQ_LIBRARY} simdjson::simdjson)
# yaml-cpp: prefer the imported target from find_package; else the raw library.
if(yaml-cpp_FOUND)
    target_link_libraries(erikslund_core PUBLIC yaml-cpp)
else()
    target_link_libraries(erikslund_core PUBLIC ${YAML_CPP_LIBRARY})
endif()

# ---- main executable ---------------------------------------------------------
add_executable(erikslund-pool ${CMAKE_SOURCE_DIR}/src/main.cpp)
target_link_libraries(erikslund-pool PRIVATE erikslund_core)
# Export the dynamic symbol table so the crash handler's backtrace shows function
# names rather than bare addresses (negligible cost; just a larger symtab).
target_link_options(erikslund-pool PRIVATE -rdynamic)
if(MIMALLOC_LIBRARY)
    target_link_libraries(erikslund-pool PRIVATE
        -Wl,--no-as-needed ${MIMALLOC_LIBRARY} -Wl,--as-needed)
    target_compile_definitions(erikslund-pool PRIVATE HAVE_MIMALLOC)
    message(STATUS "mimalloc: ${MIMALLOC_LIBRARY}")
else()
    message(STATUS "mimalloc: not found -- using the system allocator")
endif()

# ---- tests -------------------------------------------------------------------
enable_testing()
file(GLOB_RECURSE TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/tests/*.cpp)
add_executable(erikslund_tests ${TEST_SOURCES})
target_link_libraries(erikslund_tests PRIVATE erikslund_core)
# doctest's SUBCASE/CHECK macros legitimately shadow, so quiet that on tests.
target_compile_options(erikslund_tests PRIVATE -Wno-shadow)
add_test(NAME unit COMMAND erikslund_tests)
