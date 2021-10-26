#
# OS CertParser
#
# Copyright (C) 2020, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)


#------------------------------------------------------------------------------
project(os_cert C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/OS_CertParser.c"
        "src/OS_CertParserCert.c"
        "src/OS_CertParserChain.c"
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "include"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        3rdparty_mbedtls_for_cert
        os_core_api
        lib_debug
        os_crypto
)
