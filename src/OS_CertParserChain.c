/**
 * Copyright (C) 2019-2020, HENSOLDT Cyber GmbH
 */

#include "OS_CertParser.h"
#include "OS_CertParser.int.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Public functions ------------------------------------------------------------

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