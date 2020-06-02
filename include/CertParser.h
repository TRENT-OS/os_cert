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

/**
 * Supported certificate encodings
 */
typedef enum
{
    CertParser_Cert_Encoding_NONE = 0x00,
    CertParser_Cert_Encoding_DER,
    CertParser_Cert_Encoding_PEM
} CertParser_Cert_Encoding_t;

/**
 * Flags indicating reasons for verification failures
 */
typedef enum
{
    CertParser_VerifyFlags_NONE           = 0x00,

    /**
     * The key involved in verifying a signature is too small (e.g., for RSA
     * less than 2048 bits)
     */
    CertParser_VerifyFlags_INVALID_KEY    = (1u << 0),

    /**
     * The signature is invalid
     */
    CertParser_VerifyFlags_INVALID_SIG    = (1u << 1),

    /**
     * There is a mismatch in the common names of the certificates in a chain
     */
    CertParser_VerifyFlags_CN_MISMATCH    = (1u << 2),

    /**
     * The way a certificate's extension fields are used is incorrect
     */
    CertParser_VerifyFlags_EXT_MISMATCH   = (1u << 3),

    /**
     * Any other error
     */
    CertParser_VerifyFlags_OTHER_ERROR    = (1u << 4),
} CertParser_VerifyFlags_t;

/**
 * Attribute types which can be read from a x509 certificate
 */
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

/**
 * x509 cert attribute data
 */
typedef struct
{
    CertParser_Cert_Attrib_Type_t type;
    union
    {
        /**
         * Certificate's public key
         */
        OS_CryptoKey_Data_t publicKey;

        /**
         * Subject field of x509 cert
         */
        char subject[CertParser_Cert_Attrib_Subject_MAX_LEN];

        /**
         * Issuer field of x509 cert
         */
        char issuer[CertParser_Cert_Attrib_Issuer_MAX_LEN];
    } data;
} CertParser_Cert_Attrib_t;

/**
 * Configuration of certificate parser
 */
typedef struct
{
    /**
     * Handle to an initialized Crypto API instance
     */
    OS_Crypto_Handle_t hCrypto;
} CertParser_Config_t;

typedef struct CertParser_Cert CertParser_Cert_t;
typedef struct CertParser_Chain CertParser_Chain_t;
typedef struct CertParser CertParser_t;

/**
 * @brief Initialize parser context
 *
 * @param parser pointer to parser context
 * @param config configuration of parser
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_ABORTED if the internal state could not be initialized
 * @retval OS_ERROR_NOT_SUPPORTED if \p config is not supported
 * @retval OS_ERROR_INSUFFICIENT_SPACE if allocation of \p parser failed
 */
OS_Error_t
CertParser_init(
    CertParser_t**             parser,
    const CertParser_Config_t* config);

/**
 * @brief Free parser context
 *
 * NOTE: This function can also free all associated chains and certs, just
 *       be careful that you are not having other references which might
 *       still be in use!
 *
 * @param parser parser context to free
 * @param freeChains set to true if all CA chains and the certificates associated
 *  with them shall be freed as well
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 */
OS_Error_t
CertParser_free(
    CertParser_t* parser,
    const bool    freeChains);

/**
 * @brief Add trusted CA chain to parser
 *
 * Add reference to a chain to the parser; the parser can hold references
 * to many chains, which can then be addressed with their respective index
 * during certificate verification.
 *
 * NOTE: Just the reference to a chain is added; the chain (and its respective
 *       certs) SHOULD NOT be free'd while it is associated to the parser.
 *
 * @param parser parser context to add chain to
 * @param chain chain containig at least one CA certificate
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_INSUFFICIENT_SPACE if enlarging internal buffer of
 *  \p parser failed
 */
OS_Error_t
CertParser_addTrustedChain(
    CertParser_t*             parser,
    const CertParser_Chain_t* chain);

/**
 * @brief Verify a certificate chain with a trusted CA chain
 *
 * This function takes a chain and verifies it against one of the trusted
 * CA chains added to the parser. Which chain to use is indicated by the
 * \p index parameter. If verifcation succeeds, this function returns no
 * error and \p result is set to 0. If there is a specific verification
 * error, this function returns OS_ERROR_GENERIC and \p result will
 * have the respective error flags set.
 *
 * @param parser parser context
 * @param index index of CA chain to use
 * @param chain chain to verify against CA chain
 * @param result flags indicating verification result
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_ABORTED if the underlying x509 parser returned an error
 * @retval OS_ERROR_NOT_FOUND if \p index is out of range
 * @retval OS_ERROR_GENERIC if \p chain could not be verified
 */OS_Error_t
CertParser_verifyChain(
    const CertParser_t*       parser,
    const size_t              index,
    const CertParser_Chain_t* chain,
    CertParser_VerifyFlags_t* result);

/**
 * @brief Initialize a cert context
 *
 * Create a cert context by parsing a blob of cert data in different encodings
 * into its internal structure. This function will make sure the certificate
 * algorithms are supported.
 *
 * @param cert pointer to cert context to be initialized
 * @param parser parser context
 * @param encoding encoding type of cert
 * @param data raw cert data
 * @param len length of cert data in bytes
  *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_ABORTED if the underlying x509 parser returned an error
 * @retval OS_ERROR_NOT_SUPPORTED if hash or pk algo of certificate are not
 *  supported by the parser
 * @retval OS_ERROR_INSUFFICIENT_SPACE if allocation of \p cert failed
 */
OS_Error_t
CertParser_Cert_init(
    CertParser_Cert_t**              cert,
    const CertParser_t*              parser,
    const CertParser_Cert_Encoding_t encoding,
    const uint8_t*                   data,
    const size_t                     len);

/**
 * @brief Free a cert context
 *
 * @param cert certificate context to free
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 */
OS_Error_t
CertParser_Cert_free(
    CertParser_Cert_t* cert);

/**
 * @brief Extract an attribute from a cert
 *
 * x509 certificates have many different fields such as ISSUER, SUBJECT,
 * etc. This function allows to extract some of those fields into a usable
 * form.
 *
 * @param cert certificate context
 * @param type type of attribute to extract
 * @param attrib buffer to attribute data
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_ABORTED if the underlying x509 parser returned an error
 */
OS_Error_t
CertParser_Cert_getAttrib(
    const CertParser_Cert_t*            cert,
    const CertParser_Cert_Attrib_Type_t type,
    CertParser_Cert_Attrib_t*           attrib);

/**
 * @brief Initialize a certificate chain context
 *
 * @param chain chain context to initialize
 * @param parser parser context
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_INSUFFICIENT_SPACE if allocation of \p chain failed
 */
OS_Error_t
CertParser_Chain_init(
    CertParser_Chain_t** chain,
    const CertParser_t*  parser);

/**
 * @brief Free certificate chain context
 *
 * NOTE: This function can free all associated certs; just make sure there are
 *       no other references to those certs in use when they are freed.
 *
 * @param chain chain context to free
 * @param freeCerts set to true if all associated certs should be free'd
 *  as well
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 */
OS_Error_t
CertParser_Chain_free(
    CertParser_Chain_t* chain,
    const bool          freeCerts);

/**
 * @brief Add certificate to certificate chain
 *
 * Add a certificate to a certificate chain. To access the certificate later,
 * its position in the chain can be used as index. This function will also
 * check if \p cert actually belongs to \p chain by ensuring that the issuer
 * of \p cert matches the last certificate in \p chain.
 *
 * NOTE: Just the reference to \p cert is added; the certificte SHOULD NOT
 *       be free'd  while it is associated with a chain that is in use (or
 *       associated with a parser context).
 *
 * @param chain chain context to add cert to
 * @param cert certificate to add to the chain
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_ABORTED if subject of the last element in the chain and the #
 *  subject of the new cert do not match (i.e., cert is not part of the chain)
 * @retval OS_ERROR_INSUFFICIENT_SPACE if enlarging internal buffers of
 *  \p chain failed
 */
OS_Error_t
CertParser_Chain_addCert(
    CertParser_Chain_t*      chain,
    const CertParser_Cert_t* cert);

/**
 * @brief Get reference to certificate in chain
 *
 * Get pointer to a certificate in \p chain. The certificate is selected by
 * giving its \p index, i.e., its position in \p chain.
 *
 * @param chain chain context
 * @param index index of certificate in chain
 * @param cert pointer to cert context
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 * @retval OS_ERROR_NOT_FOUND if \p index is out of range
 */
OS_Error_t
CertParser_Chain_getCert(
    const CertParser_Chain_t* chain,
    const size_t              index,
    CertParser_Cert_t const** cert);

/**
 * @brief Get number of certs in chain
 *
 * @param chain chain context
 * @param len pointer to length
 *
 * @return an error code
 * @retval OS_SUCCESS if operation succeeded
 * @retval OS_ERROR_INVALID_PARAMETER if a parameter was missing or invalid
 */
OS_Error_t
CertParser_Chain_getLength(
    const CertParser_Chain_t* chain,
    size_t*                   len);

/** @} */