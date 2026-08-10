cmake_minimum_required(VERSION 3.22)
project(sv2_noise VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(
    SV2_NOISE_BUILD_CREDENTIAL_TOOL
    "Build the offline credential provisioning tool"
    ${PROJECT_IS_TOP_LEVEL})
option(
    SV2_NOISE_BUILD_TESTS
    "Build the native responder test suite"
    ${PROJECT_IS_TOP_LEVEL})

if(SV2_NOISE_BUILD_TESTS)
    include(CTest)
endif()

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

# libsecp256k1 is supplied by the build environment (see the repository Dockerfiles),
# which builds the pinned upstream commit as a PIC static library with hidden visibility and only
# the extrakeys/schnorrsig/ellswift modules -- exactly the configuration this responder needs. It is
# an implementation detail: it links PRIVATE everywhere and stays behind this library's C interface.
find_package(libsecp256k1 CONFIG REQUIRED)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

function(configure_sv2_noise_target target)
    target_sources(${target} PRIVATE src/sv2_noise.c)
    target_include_directories(
        ${target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(${target} PRIVATE OpenSSL::Crypto libsecp256k1::secp256k1)
    target_compile_options(
        ${target}
        PRIVATE
            $<$<C_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wshadow;-Wconversion>)
endfunction()

function(configure_sv2_credentials_target target)
    target_include_directories(
        ${target}
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    target_link_libraries(${target} PRIVATE OpenSSL::Crypto libsecp256k1::secp256k1)
    target_compile_options(
        ${target}
        PRIVATE
            $<$<C_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wshadow;-Wconversion>)
    set_target_properties(
        ${target}
        PROPERTIES
            C_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN YES)
endfunction()

add_library(sv2_noise_static STATIC)
configure_sv2_noise_target(sv2_noise_static)
set_target_properties(
    sv2_noise_static
    PROPERTIES
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES
        OUTPUT_NAME sv2_noise_static)
add_library(sv2_noise::static ALIAS sv2_noise_static)

if(SV2_NOISE_BUILD_CREDENTIAL_TOOL OR SV2_NOISE_BUILD_TESTS)
    add_library(sv2_noise_credentials_core STATIC tools/credentials.c)
    configure_sv2_credentials_target(sv2_noise_credentials_core)
endif()

if(SV2_NOISE_BUILD_CREDENTIAL_TOOL)
    add_executable(
        sv2_noise_credentials
        tools/sv2_noise_credentials.c)
    configure_sv2_credentials_target(sv2_noise_credentials)
    target_link_libraries(
        sv2_noise_credentials
        PRIVATE sv2_noise_credentials_core)
    set_target_properties(
        sv2_noise_credentials
        PROPERTIES OUTPUT_NAME sv2-noise-credentials)
endif()

if(SV2_NOISE_BUILD_TESTS)
    add_library(sv2_noise_test_static STATIC)
    configure_sv2_noise_target(sv2_noise_test_static)
    target_compile_definitions(sv2_noise_test_static PRIVATE SV2_NOISE_TESTING)
    set_target_properties(
        sv2_noise_test_static
        PROPERTIES
            C_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN YES)

    add_executable(sv2_noise_tests tests/test_sv2_noise.cpp)
    target_compile_definitions(sv2_noise_tests PRIVATE SV2_NOISE_TESTING)
    target_include_directories(
        sv2_noise_tests
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(
        sv2_noise_tests
        PRIVATE sv2_noise_test_static OpenSSL::Crypto libsecp256k1::secp256k1)
    target_compile_options(
        sv2_noise_tests
        PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wshadow>)
    add_test(NAME sv2_noise_unit COMMAND sv2_noise_tests)

    add_executable(
        sv2_noise_credentials_tests
        tests/test_sv2_noise_credentials.cpp)
    target_compile_definitions(
        sv2_noise_credentials_tests
        PRIVATE _POSIX_C_SOURCE=200809L)
    target_include_directories(
        sv2_noise_credentials_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/tools)
    target_link_libraries(
        sv2_noise_credentials_tests
        PRIVATE sv2_noise_credentials_core sv2_noise_test_static)
    target_compile_options(
        sv2_noise_credentials_tests
        PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wshadow>)
    add_test(
        NAME sv2_noise_credentials_unit
        COMMAND sv2_noise_credentials_tests)

    if(SV2_NOISE_BUILD_CREDENTIAL_TOOL)
        add_test(
            NAME sv2_noise_credentials_cli
            COMMAND
                bash
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_sv2_noise_credentials_cli.sh
                $<TARGET_FILE:sv2_noise_credentials>)
    endif()
endif()
