#
# CertParser library
#

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)

# We need to build 3rdparty/mbedtls for this and would like to avoid
# all users of OS_CERT to include this as well, so we do it here
seos_use_libs(
    3RDPARTY_MBEDTLS_FOR_CERT
)

if (ENABLE_LINT)
    set(CMAKE_C_CPPCHECK "cppcheck;--enable=warning;--inline-suppr")
    set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*")
endif()

#------------------------------------------------------------------------------

project(seos_cert C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/CertParser.c"
)

target_compile_options(${PROJECT_NAME}
    INTERFACE
       -Wall
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "include"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_cert
        seos_core_api
        seos_libs
)