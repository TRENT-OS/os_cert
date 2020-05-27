/**
 * Copyright (C) 2019-2020, Hensoldt Cyber GmbH
 */

#include "CertParser.h"

#include "LibDebug/Debug.h"

#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/trentos_x509_crt.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct CertParser
{
    CertParser_Config_t config;
    CertParser_Chain_t const** trusted;
    size_t chains;
};

struct CertParser_Cert
{
    uint8_t* data;
    size_t len;
    CertParser_Cert_Encoding_t encoding;
    struct
    {
        mbedtls_x509_crt cert;
    } mbedtls;
};

struct CertParser_Chain
{
    size_t certs;
    CertParser_Cert_t const** chain;
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

// Private static functions ----------------------------------------------------

OS_Error_t
convertChain(
    const CertParser_Chain_t* chain,
    mbedtls_x509_crt*         mbedtls_chain)
{
    int rc;

    mbedtls_x509_crt_init(mbedtls_chain);

    /*
     * Parse all certs from a chain into mbedTLS. Since parsing is done already
     * when a cert is created, these functions *should not* fail. However, we do
     * check it anyways but we are not very verbose about failures...
     */
    for (size_t i = 0; i < chain->certs; i++)
    {
        switch (chain->chain[i]->encoding)
        {
        case CertParser_Cert_Encoding_DER:
            rc = mbedtls_x509_crt_parse_der(mbedtls_chain,
                                            chain->chain[i]->data,
                                            chain->chain[i]->len);
            break;
        case CertParser_Cert_Encoding_PEM:
            rc = mbedtls_x509_crt_parse(mbedtls_chain,
                                        chain->chain[i]->data,
                                        chain->chain[i]->len);
            break;
        default:
            rc = 1;
        }
        if (rc != 0)
        {
            goto out;
        }
    }

    return OS_SUCCESS;

out:
    mbedtls_x509_crt_free(mbedtls_chain);

    return OS_ERROR_ABORTED;
}

// Public functions ------------------------------------------------------------

OS_Error_t
CertParser_init(
    CertParser_t**             self,
    const CertParser_Config_t* config)
{
    CertParser_t* parser;

    if (NULL == self || NULL == config)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((parser = calloc(1, sizeof(CertParser_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    parser->config  = *config;
    parser->trusted = NULL;
    parser->chains  = 0;

    *self = parser;

    return OS_SUCCESS;
}

OS_Error_t
CertParser_free(
    CertParser_t* self,
    const bool    freeChains)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    // Free all chains associated with this parser context, and also free the
    // certs associated with each chain
    if (freeChains)
    {
        for (size_t i = 0; i < self->chains; i++)
        {
            CertParser_Chain_free((CertParser_Chain_t*) self->trusted[i], true);
        }
    }

    if (self->trusted != NULL)
    {
        free(self->trusted);
    }
    free(self);

    return OS_SUCCESS;
}

OS_Error_t
CertParser_addTrustedChain(
    CertParser_t*             self,
    const CertParser_Chain_t* chain)
{
    size_t sz;
    void* ptr;

    if (NULL == self || NULL == chain)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    sz  = (self->chains + 1) * sizeof(CertParser_Chain_t*);
    ptr = (self->trusted == NULL) ? malloc(sz) : realloc(self->trusted, sz);
    if (ptr == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    self->trusted = ptr;
    self->trusted[self->chains] = chain;
    self->chains++;

    return OS_SUCCESS;
}

OS_Error_t
CertParser_verifyChain(
    const CertParser_t*       self,
    const size_t              index,
    const CertParser_Chain_t* chain,
    CertParser_VerifyFlags_t* flags)
{
    int rc;
    OS_Error_t err;
    mbedtls_x509_crt ca_chain, cert_chain;
    uint32_t mbedtls_flags;

    if (NULL == self || NULL == chain || NULL == flags)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (index >= self->chains)
    {
        return OS_ERROR_NOT_FOUND;
    }

    // Since mbedTLS modifies the certificate data structure, we have to
    // re-create it every time we call mbedtls_x509_crt_verify_with_profile()
    if ((err = convertChain(chain, &cert_chain)) != OS_SUCCESS)
    {
        return err;
    }
    if ((err = convertChain(self->trusted[index], &ca_chain)) == OS_SUCCESS)
    {
        rc = mbedtls_x509_crt_verify_with_profile(
                 self->config.hCrypto,
                 &cert_chain,
                 &ca_chain,
                 NULL,
                 &certProfile,
                 NULL,
                 &mbedtls_flags,
                 NULL,
                 NULL);
        mbedtls_x509_crt_free(&cert_chain);

        /*
         * We consider three error conditions:
         * 1. rc = 0
         *      cert verification is OK, so we return OS_SUCCESS
         * 2. rc = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED
         *      cert verification failed due to problem with a cert in the chain,
         *      we return OS_ERROR_GENERIC and also a flags value indicating
         *      what exactly is the problem
         * 3. rc = anything else
         *      some other problem occured, we return OS_ERROR_ABORTED
         */
        err = (0 == rc) ? OS_SUCCESS :
              (MBEDTLS_ERR_X509_CERT_VERIFY_FAILED == rc) ? OS_ERROR_GENERIC :
              OS_ERROR_ABORTED;

        // Parse the flag value which contains the aggregate of all problems
        // that were encountered during verification
        *flags = CertParser_VerifyFlags_NONE;
        if (mbedtls_flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)
        {
            *flags |= CertParser_VerifyFlags_CN_MISMATCH;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_CN_MISMATCH;
        }
        if (mbedtls_flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
        {
            *flags |= CertParser_VerifyFlags_INVALID_SIG;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        }
        if (mbedtls_flags & MBEDTLS_X509_BADCERT_BAD_MD)
        {
            *flags |= CertParser_VerifyFlags_INVALID_HASH_ALG;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_BAD_MD;
        }
        if (mbedtls_flags & MBEDTLS_X509_BADCERT_BAD_PK)
        {
            *flags |= CertParser_VerifyFlags_INVALID_SIG_ALG;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_BAD_PK;
        }
        if (mbedtls_flags & MBEDTLS_X509_BADCERT_BAD_KEY)
        {
            *flags |= CertParser_VerifyFlags_INVALID_KEY;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_BAD_KEY;
        }
        if (mbedtls_flags & MBEDTLS_X509_BADCERT_KEY_USAGE ||
            mbedtls_flags & MBEDTLS_X509_BADCERT_EXT_KEY_USAGE ||
            mbedtls_flags & MBEDTLS_X509_BADCERT_NS_CERT_TYPE)
        {
            *flags |= CertParser_VerifyFlags_EXTENSION_MISMATCH;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_KEY_USAGE;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_EXT_KEY_USAGE;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_NS_CERT_TYPE;
        }

        // If there are still bits set, we do not bother further and just return
        // a generic error (remaining bits may be due to CRL problems or time
        /// issues, both are currently not supported)
        if (mbedtls_flags)
        {
            *flags |= CertParser_VerifyFlags_OTHER_ERROR;
        }
    }

    mbedtls_x509_crt_free(&ca_chain);

    return err;
}

// --------------------------------- Cert --------------------------------------

OS_Error_t
CertParser_Cert_init(
    CertParser_Cert_t**              self,
    const CertParser_t*              parser,
    const CertParser_Cert_Encoding_t encoding,
    const uint8_t*                   data,
    const size_t                     len)
{
    int rc;
    OS_Error_t err;
    CertParser_Cert_t* cert;

    if (NULL == parser || NULL == self || NULL == data)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((cert = calloc(1, sizeof(CertParser_Cert_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    // So here is the thing with mbedTLS: For PEM certificates it expects a
    // terminating \0 at the end. We add this ourselves, so we don't need to
    // trouble the user with it.
    cert->len = (data[len - 1] == 0x00) ? len : len + 1;
    if ((cert->data = calloc(cert->len, sizeof(uint8_t))) == NULL)
    {
        rc = OS_ERROR_INSUFFICIENT_SPACE;
        goto err0;
    }

    // We keep the raw data for later so we can re-create the mbedTLS data
    // structure at any time we want.
    memcpy(cert->data, data, len);
    cert->encoding = encoding;

    // Also, we parse the cert data into an mbedTLS structure so we can check if
    // the provided format is valid and to make extraction of attribues easy.
    mbedtls_x509_crt_init(&cert->mbedtls.cert);
    err = OS_ERROR_ABORTED;
    switch (encoding)
    {
    case CertParser_Cert_Encoding_DER:
        if ((rc = mbedtls_x509_crt_parse_der(&cert->mbedtls.cert,
                                             cert->data,
                                             cert->len)) != 0)
        {
            Debug_LOG_RET_MBEDTLS("mbedtls_x509_crt_parse_der", rc);
            goto err1;
        }
        break;
    case CertParser_Cert_Encoding_PEM:
        if ((rc = mbedtls_x509_crt_parse(&cert->mbedtls.cert,
                                         cert->data,
                                         cert->len)) != 0)
        {
            Debug_LOG_RET_MBEDTLS("mbedtls_x509_crt_parse", rc);
            goto err1;
        }
        break;
    default:
        err = OS_ERROR_INVALID_PARAMETER;
        goto err1;
    }

    *self = cert;

    return OS_SUCCESS;

err1:
    mbedtls_x509_crt_free(&cert->mbedtls.cert);
    free(cert->data);
err0:
    free(cert);

    return err;
}

OS_Error_t
CertParser_Cert_free(
    CertParser_Cert_t* self)
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
CertParser_Cert_getAttrib(
    const CertParser_Cert_t*            self,
    const CertParser_Cert_Attrib_Type_t type,
    CertParser_Cert_Attrib_t*           attrib)
{
    int rc;

    switch (type)
    {
    case CertParser_Cert_Attrib_Type_PUBLICKEY:
        if ((rc = trentos_ssl_cli_export_cert_key(self->mbedtls.cert.sig_pk,
                                                  self->mbedtls.cert.pk.pk_ctx,
                                                  &attrib->data.publicKey)) != 0)
        {
            Debug_LOG_RET_MBEDTLS("trentos_ssl_cli_export_cert_key", rc);
            return OS_ERROR_ABORTED;
        }
        break;
    case CertParser_Cert_Attrib_Type_SUBJECT:
        if ((rc = mbedtls_x509_dn_gets(attrib->data.subject,
                                       CertParser_Cert_Attrib_Subject_MAX_LEN,
                                       &self->mbedtls.cert.subject)) < 0)
        {
            Debug_LOG_RET_MBEDTLS("mbedtls_x509_dn_gets", rc);
            return OS_ERROR_ABORTED;
        }
        break;
    case CertParser_Cert_Attrib_Type_ISSUER:
        if ((rc = mbedtls_x509_dn_gets(attrib->data.issuer,
                                       CertParser_Cert_Attrib_Issuer_MAX_LEN,
                                       &self->mbedtls.cert.issuer)) < 0)
        {
            Debug_LOG_RET_MBEDTLS("mbedtls_x509_dn_gets", rc);
            return OS_ERROR_ABORTED;
        }
        break;
    default:
        return OS_ERROR_INVALID_PARAMETER;
    }

    return OS_SUCCESS;
}

// --------------------------------- Chain -------------------------------------

OS_Error_t
CertParser_Chain_init(
    CertParser_Chain_t** self,
    const CertParser_t*  parser)
{
    CertParser_Chain_t* chain;

    if (NULL == parser || NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((chain = calloc(1, sizeof(CertParser_Chain_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    chain->chain = NULL;
    chain->certs = 0;

    *self = chain;

    return OS_SUCCESS;
}

OS_Error_t
CertParser_Chain_free(
    CertParser_Chain_t* self,
    const bool          freeCerts)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    // Free all certs associated with this chain
    if (freeCerts)
    {
        for (size_t i = 0; i < self->certs; i++)
        {
            CertParser_Cert_free((CertParser_Cert_t*)self->chain[i]);
        }
    }

    if (self->chain != NULL)
    {
        free(self->chain);
    }
    free(self);

    return OS_SUCCESS;
}

OS_Error_t
CertParser_Chain_addCert(
    CertParser_Chain_t*      self,
    const CertParser_Cert_t* cert)
{
    size_t sz;
    void* ptr;

    if (NULL == self || NULL == cert)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if (self->certs > 0)
    {
        // If this is not the first cert, at least we can check that the user
        // gives us an actual chain here
        if (x509_name_cmp(&self->chain[self->certs - 1]->mbedtls.cert.subject,
                          &cert->mbedtls.cert.issuer))
        {
            Debug_LOG_ERROR("Issuer of new cert does not match subject of last " \
                            "cert in chain");
            return OS_ERROR_ABORTED;
        }
    }

    // Add pointer to original cert
    sz  = (self->certs + 1) * sizeof(CertParser_Cert_t*);
    ptr = (self->chain == NULL) ? malloc(sz) : realloc(self->chain, sz);
    if (ptr == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }
    self->chain = ptr;
    self->chain[self->certs] = cert;
    self->certs++;

    return OS_SUCCESS;
}

OS_Error_t
CertParser_Chain_getCert(
    const CertParser_Chain_t* self,
    const size_t              index,
    CertParser_Cert_t const** cert)
{
    if (NULL == self || NULL == cert)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    if (index >= self->certs)
    {
        return OS_ERROR_NOT_FOUND;
    }

    *cert = self->chain[index];

    return OS_SUCCESS;
}

OS_Error_t
CertParser_Chain_getLength(
    const CertParser_Chain_t* self,
    size_t*                   len)
{
    if (NULL == self || NULL == len)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    *len = self->certs;

    return OS_SUCCESS;
}