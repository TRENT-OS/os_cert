/**
 * Copyright (C) 2019-2020, HENSOLDT Cyber GmbH
 */

#include "OS_CertParser.h"
#include "OS_CertParser.int.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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

static inline OS_CertParser_VerifyFlags_t
translateMbedTlsVerifyFlags(
    uint32_t mbedtls_flags)
{
    // Parse the flag value which contains the aggregate of all problems
    // that were encountered during verification
    OS_CertParser_VerifyFlags_t flags = OS_CertParser_VerifyFlags_NONE;
    if (mbedtls_flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)
    {
        flags |= OS_CertParser_VerifyFlags_CN_MISMATCH;
        mbedtls_flags &= ~MBEDTLS_X509_BADCERT_CN_MISMATCH;
    }
    if (mbedtls_flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
    {
        flags |= OS_CertParser_VerifyFlags_INVALID_SIG;
        mbedtls_flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    }
    if (mbedtls_flags & MBEDTLS_X509_BADCERT_BAD_KEY)
    {
        flags |= OS_CertParser_VerifyFlags_INVALID_KEY;
        mbedtls_flags &= ~MBEDTLS_X509_BADCERT_BAD_KEY;
    }
    if (mbedtls_flags & MBEDTLS_X509_BADCERT_KEY_USAGE ||
        mbedtls_flags & MBEDTLS_X509_BADCERT_EXT_KEY_USAGE ||
        mbedtls_flags & MBEDTLS_X509_BADCERT_NS_CERT_TYPE)
    {
        flags |= OS_CertParser_VerifyFlags_EXT_MISMATCH;
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
        flags |= OS_CertParser_VerifyFlags_OTHER_ERROR;
    }

    return flags;
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

        *flags = translateMbedTlsVerifyFlags(mbedtls_flags);
    }

    mbedtls_x509_crt_free(&ca_chain);

    return err;
}
