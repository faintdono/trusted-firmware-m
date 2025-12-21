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
                                 const uint8_t *input_bytes,
                                 size_t input_len,
                                 const uint8_t *ns_output,
                                 size_t ns_output_sz,
                                 const uint8_t *auth_challenge,
                                 size_t         challenge_size,
                                 uint8_t       *token_buf,
                                 size_t         token_buf_size,
                                 size_t        *token_size)
{
    psa_status_t status;
    uint8_t inbuf[256]; /* size as needed; for max input size, scale accordingly */
    size_t  inlen = 0;
    // uint8_t ns_output[64] = {0};
    // size_t ns_output_sz = sizeof(ns_output);

    ns_pox_call_req_t r = {
        .challenge = auth_challenge,
        .challenge_len = challenge_size,   /* 32..64 */
        .function_addr = (uintptr_t)faddr,    /* Cast pointer to uintptr_t */
        .input = (uintptr_t)input_bytes,         /* may be NULL if input_len == 0 */
        .input_len = input_len,
        .output = (uintptr_t)ns_output,        /* may be NULL if output_len == 0 */
        .output_len = ns_output_sz
    };
    printf("Preparing POX call:\n");
                        printf(" - Challenge len = %u\n", r.challenge_len);
                        printf(" - Func addr ID = 0x%x\n", r.function_addr);
                        printf(" - Input    = 0x%x\n", r.input);
                        printf(" - Input len   = %d\n", r.input_len);
                        printf(" - Output   = 0x%x\n", r.output);
                        printf(" - Output len  = %d\n", r.output_len);

    if (serialize_ns_pox_call(&r, inbuf, sizeof(inbuf), &inlen) != SER_OK) {
        /* handle error */
        printf("Error: serialize_ns_pox_call() failed\n");
    };

    psa_invec in_vec[] = {
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

    return status;
}