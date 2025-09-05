/*
 * Copyright (c) 2018-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "psa/initial_attestation.h"
#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "tfm_attest_defs.h"
#include "tfm_pox_wire.h"
#include <stdio.h>
#include <stdlib.h>

psa_status_t
psa_initial_attest_get_token(const uint8_t *auth_challenge,
                             size_t         challenge_size,
                             uint8_t       *token_buf,
                             size_t         token_buf_size,
                             size_t        *token_size)
{
    psa_status_t status;
    
    psa_invec in_vec[] = {
        {auth_challenge, challenge_size}
    };
    psa_outvec out_vec[] = {
        {token_buf, token_buf_size}
    };

    status = psa_call(TFM_ATTESTATION_SERVICE_HANDLE, TFM_ATTEST_GET_TOKEN,
                      in_vec, IOVEC_LEN(in_vec),
                      out_vec, IOVEC_LEN(out_vec));

    if (status == PSA_SUCCESS) {
        *token_size = out_vec[0].len;
    }

    return status;
}

psa_status_t
psa_initial_attest_get_token_size(size_t  challenge_size,
                                  size_t *token_size)
{
    psa_status_t status;
    psa_invec in_vec[] = {
        {&challenge_size, sizeof(challenge_size)}
    };
    psa_outvec out_vec[] = {
        {token_size, sizeof(size_t)}
    };

    status = psa_call(TFM_ATTESTATION_SERVICE_HANDLE, TFM_ATTEST_GET_TOKEN_SIZE,
                      in_vec, IOVEC_LEN(in_vec),
                      out_vec, IOVEC_LEN(out_vec));

    return status;
}

psa_status_t
psa_proof_of_execution_get_token(uintptr_t faddr,
                                 const uint8_t *auth_challenge,
                                 size_t         challenge_size,
                                 uint8_t       *token_buf,
                                 size_t         token_buf_size,
                                 size_t        *token_size)
{
    psa_status_t status;
    
    /* Mock up missing variables */
    const uint8_t *input_bytes = NULL;
    uint32_t input_len = 0;

    ns_pox_call_req_t req = {
        .challenge     = auth_challenge,
        .challenge_len = challenge_size,
        .function_addr = (uintptr_t)faddr,             /* treated as selector */
        .input         = input_bytes,
        .input_len     = input_len,
        .add_crc32     = true,
    };

    size_t needed = 0;
    if (pox_measure_ns_call(&req, &needed) != SER_OK) {
        // handle error
    }

    /* Allocate EXACTLY the needed size (heap or static pool) */
    uint8_t *inbuf = (uint8_t *)malloc(needed);
    size_t   inlen = 0;

    if (serialize_ns_pox_call(&req, inbuf, needed, &inlen) != SER_OK) {
        /* handle error */
    };
    printf("ptr=%p cap=%zu len=%zu\n", (void*)inbuf, needed, inlen);
    psa_invec in_vec[] = {
        {&faddr, sizeof(faddr)},
        {auth_challenge, challenge_size},
        {inbuf, inlen}
    };
    psa_outvec out_vec[] = {
        {token_buf, token_buf_size}
    };
    status = psa_call(TFM_ATTESTATION_SERVICE_HANDLE, TFM_ATTEST_GET_POX,
                      in_vec, IOVEC_LEN(in_vec),
                      out_vec, IOVEC_LEN(out_vec));
    if (status == PSA_SUCCESS) {
        *token_size = out_vec[0].len;
    }
    free(inbuf);
    return status;
}