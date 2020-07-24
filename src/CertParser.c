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

// Private static functions ----------------------------------------------------

OS_Error_t
convertChain(
    const OS_CertParserChain_t* chain,
    mbedtls_x509_crt*           mbedtls_chain)
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
        case OS_CertParserCert_Encoding_DER:
            rc = mbedtls_x509_crt_parse_der(mbedtls_chain,
                                            chain->chain[i]->data,
                                            chain->chain[i]->len);
            break;
        case OS_CertParserCert_Encoding_PEM:
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
OS_CertParser_init(
    OS_CertParser_Handle_t*       self,
    const OS_CertParser_Config_t* config)
{
    OS_CertParser_t* parser;

    if (NULL == self || NULL == config || NULL == config->hCrypto)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((parser = calloc(1, sizeof(OS_CertParser_t))) == NULL)
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
OS_CertParser_free(
    OS_CertParser_Handle_t self,
    const bool             freeChains)
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
            OS_CertParserChain_free((OS_CertParserChain_t*) self->trusted[i], true);
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
OS_CertParser_addTrustedChain(
    OS_CertParser_Handle_t            self,
    const OS_CertParserChain_Handle_t chain)
{
    size_t sz;
    void* ptr;

    if (NULL == self || NULL == chain || 0 == chain->certs)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    sz  = (self->chains + 1) * sizeof(OS_CertParserChain_t*);
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
OS_CertParser_verifyChain(
    const OS_CertParser_Handle_t      self,
    const size_t                      index,
    const OS_CertParserChain_Handle_t chain,
    OS_CertParser_VerifyFlags_t*      flags)
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
        *flags = OS_CertParser_VerifyFlags_NONE;
        if (mbedtls_flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)
        {
            *flags |= OS_CertParser_VerifyFlags_CN_MISMATCH;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_CN_MISMATCH;
        }
        if (mbedtls_flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
        {
            *flags |= OS_CertParser_VerifyFlags_INVALID_SIG;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        }
        if (mbedtls_flags & MBEDTLS_X509_BADCERT_BAD_KEY)
        {
            *flags |= OS_CertParser_VerifyFlags_INVALID_KEY;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_BAD_KEY;
        }
        if (mbedtls_flags & MBEDTLS_X509_BADCERT_KEY_USAGE ||
            mbedtls_flags & MBEDTLS_X509_BADCERT_EXT_KEY_USAGE ||
            mbedtls_flags & MBEDTLS_X509_BADCERT_NS_CERT_TYPE)
        {
            *flags |= OS_CertParser_VerifyFlags_EXT_MISMATCH;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_KEY_USAGE;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_EXT_KEY_USAGE;
            mbedtls_flags &= ~MBEDTLS_X509_BADCERT_NS_CERT_TYPE;
        }

        // If there are still bits set, we do not bother further and just return
        // a generic error:
        // - CRL problems               (CRLs are not supported)
        // - time issues                (we have no time so time is not checked)
        // - invalid hash/pk alorithms  (should be detected during cert creation)
        if (mbedtls_flags)
        {
            *flags |= OS_CertParser_VerifyFlags_OTHER_ERROR;
        }
    }

    mbedtls_x509_crt_free(&ca_chain);

    return err;
}

// --------------------------------- Cert --------------------------------------

OS_Error_t
OS_CertParserCert_init(
    OS_CertParserCert_Handle_t*        self,
    const OS_CertParser_Handle_t       parser,
    const OS_CertParserCert_Encoding_t encoding,
    const uint8_t*                     data,
    const size_t                       len)
{
    int rc;
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

    // Translate parsing errors due to unkown algos into NOT_SUPPORTED, so it
    // aligns with the follow-up check. UNKNOWN_SIG_ALG will be returned in cases
    // where mbedTLS has not been compiled for a certain algorithm. In our case,
    // mbedTLS may actually provide more algorithms than we want to have as per
    // the certProfile, so that is why we add a second check below.
    switch (encoding)
    {
    case OS_CertParserCert_Encoding_DER:
        if ((rc = mbedtls_x509_crt_parse_der(&cert->mbedtls.cert,
                                             cert->data,
                                             cert->len)) != 0)
        {
            Debug_LOG_RET_MBEDTLS("mbedtls_x509_crt_parse_der", rc);
            err = (rc & MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG) ?
                  OS_ERROR_NOT_SUPPORTED : OS_ERROR_ABORTED;
            goto err1;
        }
        break;
    case OS_CertParserCert_Encoding_PEM:
        if ((rc = mbedtls_x509_crt_parse(&cert->mbedtls.cert,
                                         cert->data,
                                         cert->len)) != 0)
        {
            Debug_LOG_RET_MBEDTLS("mbedtls_x509_crt_parse", rc);
            err = (rc & MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG) ?
                  OS_ERROR_NOT_SUPPORTED : OS_ERROR_ABORTED;
            goto err1;
        }
        break;
    default:
        err = OS_ERROR_INVALID_PARAMETER;
        goto err1;
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
        err = OS_ERROR_NOT_SUPPORTED;
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
                                       OS_CertParserCert_Attrib_Subject_MAX_LEN,
                                       &self->mbedtls.cert.subject)) < 0)
        {
            Debug_LOG_RET_MBEDTLS("mbedtls_x509_dn_gets", rc);
            return OS_ERROR_ABORTED;
        }
        break;
    case OS_CertParserCert_AttribType_ISSUER:
        if ((rc = mbedtls_x509_dn_gets(attrib->data.issuer,
                                       OS_CertParserCert_Attrib_Issuer_MAX_LEN,
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

// --------------------------------- Chain -------------------------------------

OS_Error_t
OS_CertParserChain_init(
    OS_CertParserChain_Handle_t* self,
    const OS_CertParser_Handle_t parser)
{
    OS_CertParserChain_t* chain;

    if (NULL == parser || NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((chain = calloc(1, sizeof(OS_CertParserChain_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    chain->chain = NULL;
    chain->certs = 0;

    *self = chain;

    return OS_SUCCESS;
}

OS_Error_t
OS_CertParserChain_free(
    OS_CertParserChain_Handle_t self,
    const bool                  freeCerts)
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
            OS_CertParserCert_free((OS_CertParserCert_t*)self->chain[i]);
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
OS_CertParserChain_addCert(
    OS_CertParserChain_Handle_t      self,
    const OS_CertParserCert_Handle_t cert)
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
    sz  = (self->certs + 1) * sizeof(OS_CertParserCert_t*);
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
OS_CertParserChain_getCert(
    const OS_CertParserChain_Handle_t self,
    const size_t                      index,
    OS_CertParserCert_Handle_t*       cert)
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
OS_CertParserChain_getLength(
    const OS_CertParserChain_Handle_t self,
    size_t*                           len)
{
    if (NULL == self || NULL == len)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    *len = self->certs;

    return OS_SUCCESS;
}