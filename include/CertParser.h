/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 *
 * @addtogroup Cert
 * @{
 *
 * @file CertParser.h
 *
 * @brief Cert parser library module
 *
 */

#pragma once

#include "OS_Crypto.h"

typedef enum
{
    CertParser_Cert_Encoding_NONE = 0x00,
    CertParser_Cert_Encoding_DER,
    CertParser_Cert_Encoding_PEM
} CertParser_Cert_Encoding_t;

typedef enum
{
    CertParser_VerifyFlags_NONE                 = 0x00,
    CertParser_VerifyFlags_INVALID_SIG_ALG      = (1u << 0),
    CertParser_VerifyFlags_INVALID_HASH_ALG     = (1u << 1),
    CertParser_VerifyFlags_INVALID_KEY          = (1u << 2),
    CertParser_VerifyFlags_INVALID_SIG          = (1u << 3),
    CertParser_VerifyFlags_CN_MISMATCH          = (1u << 4),
    CertParser_VerifyFlags_EXTENSION_MISMATCH   = (1u << 5),
    CertParser_VerifyFlags_OTHER_ERROR          = (1u << 6),
} CertParser_VerifyFlags_t;

typedef enum
{
    CertParser_Cert_Attrib_Type_NONE = 0x00,
    CertParser_Cert_Attrib_Type_PUBLICKEY,
    CertParser_Cert_Attrib_Type_SUBJECT,
    CertParser_Cert_Attrib_Type_ISSUER
} CertParser_Cert_Attrib_Type_t;

// Maximum length of these attributes in X509
#define CertParser_Cert_Attrib_Subject_MAX_LEN 256
#define CertParser_Cert_Attrib_Issuer_MAX_LEN 256

typedef struct
{
    CertParser_Cert_Attrib_Type_t type;
    union
    {
        OS_CryptoKey_Data_t publicKey;
        char subject[CertParser_Cert_Attrib_Subject_MAX_LEN];
        char issuer[CertParser_Cert_Attrib_Issuer_MAX_LEN];
    } data;
} CertParser_Cert_Attrib_t;

typedef struct
{
    OS_Crypto_Handle_t hCrypto;
} CertParser_Config_t;

typedef struct CertParser_Cert CertParser_Cert_t;
typedef struct CertParser_Chain CertParser_Chain_t;
typedef struct CertParser CertParser_t;

// ---------------------------------- Lib --------------------------------------

// Setup API object.
seos_err_t
CertParser_init(
    CertParser_t**             parser,
    const CertParser_Config_t* config);

// Free API and any memory associated internally.
seos_err_t
CertParser_free(
    CertParser_t* parser,
    const bool    freeChains);

// Add a trusted certificate chain to the internal "trust store".
seos_err_t
CertParser_addTrustedChain(
    CertParser_t*             parser,
    const CertParser_Chain_t* chain);

// In case user is not interested in the actual verification chain, simply
// check if a chain can be found.
seos_err_t
CertParser_verifyChain(
    const CertParser_t*       parser,
    const size_t              index,
    const CertParser_Chain_t* chain,
    CertParser_VerifyFlags_t* result);

// --------------------------------- Cert --------------------------------------

// Allocate and fill in a certificate from raw data.
seos_err_t
CertParser_Cert_init(
    CertParser_Cert_t**              cert,
    const CertParser_t*              parser,
    const CertParser_Cert_Encoding_t encoding,
    const uint8_t*                   data,
    const size_t                     len);

// Free up memory associated with cert.
seos_err_t
CertParser_Cert_free(
    CertParser_Cert_t* cert);

// Extract attributes from a certificate.
seos_err_t
CertParser_Cert_getAttrib(
    const CertParser_Cert_t*            cert,
    const CertParser_Cert_Attrib_Type_t type,
    CertParser_Cert_Attrib_t*           attrib);

// --------------------------------- Chain -------------------------------------

// Allocate cert chain with a max. amount of certs it can hold.
seos_err_t
CertParser_Chain_init(
    CertParser_Chain_t** chain,
    const CertParser_t*  parser);

// Free up memory associated with a chain (certs need to be freed individually).
seos_err_t
CertParser_Chain_free(
    CertParser_Chain_t* chain,
    const bool          freeCerts);

// Add certificate to end of existing cert chain; certificate should not be
// freed while chain is in use.
seos_err_t
CertParser_Chain_addCert(
    CertParser_Chain_t*      chain,
    const CertParser_Cert_t* cert);

// Get pointer to a cert in the cert chain (indexed starting at 0).
seos_err_t
CertParser_Chain_getCert(
    const CertParser_Chain_t* chain,
    const size_t              index,
    CertParser_Cert_t const** cert);

// Get length of a chain
seos_err_t
CertParser_Chain_getLength(
    const CertParser_Chain_t* chain,
    size_t*                   len);

/** @} */