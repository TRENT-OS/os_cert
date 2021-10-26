/**
 * Copyright (C) 2020, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_CertParser.h"

#include "lib_debug/Debug.h"

#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/trentos_x509_crt.h"

struct OS_CertParser
{
    OS_CertParser_Config_t config;
    OS_CertParserChain_t const** trusted;
    size_t chains;
};

struct OS_CertParserCert
{
    uint8_t* data;
    size_t len;
    OS_CertParserCert_Encoding_t encoding;
    struct
    {
        mbedtls_x509_crt cert;
    } mbedtls;
};

struct OS_CertParserChain
{
    size_t certs;
    OS_CertParserCert_t** chain;
};

/*
 * This profile is used to enforce specific signature and hash algorithms for
 * certificates as well as minimum key lengths. We need to make sure that what
 * we support here is also what the TRENTOS crypto API supports.
 */
static const mbedtls_x509_crt_profile certProfile =
{
    // We currently have only SHA256
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ),
    // Only signature algorithm we have is RSA
    MBEDTLS_X509_ID_FLAG( MBEDTLS_PK_RSA ),
    // We do not support ECC
    0x0,
    // Minimum bit length we accept for RSA moduli
    2048,
};

#define Debug_LOG_RET(fn, rc)                           \
{                                                       \
    Debug_LOG_ERROR("%s() failed with %d", fn, rc);     \
}
#define Debug_LOG_RET_MBEDTLS(fn, rc)                               \
{                                                                   \
    char errstr[256];                                               \
    mbedtls_strerror(rc, errstr, sizeof(errstr));                   \
    Debug_LOG_ERROR("%s() failed with %d [%s]", fn, rc, errstr);    \
}
