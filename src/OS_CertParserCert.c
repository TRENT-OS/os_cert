/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "OS_CertParser.h"
#include "OS_CertParser.int.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Private functions -----------------------------------------------------------
static inline OS_Error_t
initImpl(
    OS_CertParserCert_t* cert,
    const OS_CertParserCert_Encoding_t encoding)
{
    OS_Error_t retval = OS_ERROR_GENERIC;
    // Also, we parse the cert data into an mbedTLS structure so we can check if
    // the provided format is valid and to make extraction of attribues easy.
    mbedtls_x509_crt_init(&cert->mbedtls.cert);

    // Translate parsing errors due to unkown algos into NOT_SUPPORTED, so it
    // aligns with the follow-up check. UNKNOWN_SIG_ALG will be returned in cases
    // where mbedTLS has not been compiled for a certain algorithm. In our case,
    // mbedTLS may actually provide more algorithms than we want to have as per
    // the certProfile, so that is why we add a second check below.
    switch (encoding)
    {
        int rc;

    case OS_CertParserCert_Encoding_DER:
        if ((rc = mbedtls_x509_crt_parse_der(&cert->mbedtls.cert,
                                             cert->data,
                                             cert->len)) != 0)
        {
            Debug_LOG_RET_MBEDTLS("mbedtls_x509_crt_parse_der", rc);
            retval = (rc & MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG) ?
                     OS_ERROR_NOT_SUPPORTED : OS_ERROR_ABORTED;
            goto err;
        }
        break;
    case OS_CertParserCert_Encoding_PEM:
        if ((rc = mbedtls_x509_crt_parse(&cert->mbedtls.cert,
                                         cert->data,
                                         cert->len)) != 0)
        {
            Debug_LOG_RET_MBEDTLS("mbedtls_x509_crt_parse", rc);
            retval = (rc & MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG) ?
                     OS_ERROR_NOT_SUPPORTED : OS_ERROR_ABORTED;
            goto err;
        }
        break;
    default:
        retval = OS_ERROR_INVALID_PARAMETER;
        goto err;
    }

    // The certificate verification checks if a cert has uses only allowed
    // algorithms for hash and PK. However, to make user experience more
    // consistent, we do these checks here already so a user cannot even create
    // a cert that will later fail.
    if ( !(certProfile.allowed_mds & MBEDTLS_X509_ID_FLAG(
               cert->mbedtls.cert.sig_md))
         || !(certProfile.allowed_pks & MBEDTLS_X509_ID_FLAG(
                  cert->mbedtls.cert.sig_pk)) )
    {
        Debug_LOG_ERROR("Certificate PK or HASH algorithm are not supported");
        retval = OS_ERROR_NOT_SUPPORTED;
        goto err;
    }
    return OS_SUCCESS;
err:
    mbedtls_x509_crt_free(&cert->mbedtls.cert);
    return retval;
}

// Public functions ------------------------------------------------------------

OS_Error_t
OS_CertParserCert_init(
    OS_CertParserCert_Handle_t*        self,
    const OS_CertParser_Handle_t       parser,
    const OS_CertParserCert_Encoding_t encoding,
    const uint8_t*                     data,
    const size_t                       len)
{
    OS_Error_t err;
    OS_CertParserCert_t* cert;

    if (NULL == parser || NULL == self || NULL == data || 0 == len)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((cert = calloc(1, sizeof(OS_CertParserCert_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    // So here is the thing with mbedTLS: For PEM certificates it expects a
    // terminating \0 at the end. We add this ourselves, so we don't need to
    // trouble the user with it.
    cert->len = (data[len - 1] == 0x00) ? len : len + 1;
    if ((cert->data = calloc(cert->len, sizeof(uint8_t))) == NULL)
    {
        err  = OS_ERROR_INSUFFICIENT_SPACE;
        goto err0;
    }

    // We keep the raw data for later so we can re-create the mbedTLS data
    // structure at any time we want.
    memcpy(cert->data, data, len);
    cert->encoding = encoding;

    err = initImpl(cert, encoding);
    if (OS_SUCCESS != err)
    {
        goto err1;
    }
    else
    {
        *self = cert;
    }
    return OS_SUCCESS;

err1:
    free(cert->data);
err0:
    free(cert);
    return err;
}

OS_Error_t
OS_CertParserCert_free(
    OS_CertParserCert_Handle_t self)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if (self->data != NULL)
    {
        mbedtls_x509_crt_free(&self->mbedtls.cert);
        free(self->data);
    }
    free(self);

    return OS_SUCCESS;
}

OS_Error_t
OS_CertParserCert_getAttrib(
    const OS_CertParserCert_Handle_t     self,
    const OS_CertParserCert_AttribType_t type,
    OS_CertParserCert_Attrib_t*          attrib)
{
    int rc;

    if (NULL == self || NULL == attrib)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    attrib->type = OS_CertParserCert_AttribType_NONE;

    switch (type)
    {
    case OS_CertParserCert_AttribType_PUBLICKEY:
        if ((rc = trentos_ssl_cli_export_cert_key(self->mbedtls.cert.sig_pk,
                                                  self->mbedtls.cert.pk.pk_ctx,
                                                  &attrib->data.publicKey)) != 0)
        {
            Debug_LOG_RET_MBEDTLS("trentos_ssl_cli_export_cert_key", rc);
            return OS_ERROR_ABORTED;
        }
        break;
    case OS_CertParserCert_AttribType_SUBJECT:
        if ((rc = mbedtls_x509_dn_gets(attrib->data.subject,
                                       OS_CertParserCert_Subject_MAX_LEN,
                                       &self->mbedtls.cert.subject)) < 0)
        {
            Debug_LOG_RET_MBEDTLS("mbedtls_x509_dn_gets", rc);
            return OS_ERROR_ABORTED;
        }
        break;
    case OS_CertParserCert_AttribType_ISSUER:
        if ((rc = mbedtls_x509_dn_gets(attrib->data.issuer,
                                       OS_CertParserCert_Issuer_MAX_LEN,
                                       &self->mbedtls.cert.issuer)) < 0)
        {
            Debug_LOG_RET_MBEDTLS("mbedtls_x509_dn_gets", rc);
            return OS_ERROR_ABORTED;
        }
        break;
    default:
        return OS_ERROR_INVALID_PARAMETER;
    }

    // Only in case of success we assign the type
    attrib->type = type;

    return OS_SUCCESS;
}