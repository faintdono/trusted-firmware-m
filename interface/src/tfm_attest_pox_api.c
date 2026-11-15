/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * NS-side API for the Proof-of-Execution path inside the Initial
 * Attestation partition (TFM_ATTEST_GET_POX). Compiled only when the
 * attestation-PoX feature is enabled (ATTEST_POX secure-side,
 * CONFIG_TFM_PARTITION_ATTESTATION_POX in Zephyr).
 */

#include <stdio.h>

#include "psa/initial_attestation.h"
#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "tfm_attest_defs.h"
#include "tfm_pox_wire.h"

psa_status_t
psa_proof_of_execution_get_token(uintptr_t faddr,
                                 const uint8_t *input_bytes,
                                 size_t input_len,
                                 const uint8_t *ns_output,
                                 size_t ns_output_sz,
                                 const uint8_t *auth_challenge,
                                 size_t         challenge_size,
                                 const uint8_t *session_id,
                                 size_t         session_id_len,
                                 const uint8_t *sess_sig,
                                 size_t         sess_sig_len,
                                 uint32_t       seq,
                                 uint8_t       *token_buf,
                                 size_t         token_buf_size,
                                 size_t        *token_size)
{
    psa_status_t status;
    uint8_t inbuf[256]; /* size as needed; for max input size, scale accordingly */
    size_t  inlen = 0;

    /* Session credentials: both present, or both absent. Detailed
     * bounds are validated by the serializer. */
    if ((session_id == NULL) != (sess_sig == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ns_pox_call_req_t r = {
        .challenge = auth_challenge,
        .challenge_len = challenge_size,   /* 32..64 */
        .function_addr = (uintptr_t)faddr,    /* Cast pointer to uintptr_t */
        .input = (uintptr_t)input_bytes,         /* may be NULL if input_len == 0 */
        .input_len = input_len,
        .output = (uintptr_t)ns_output,        /* may be NULL if output_len == 0 */
        .output_len = ns_output_sz,
        .session_id = session_id,
        .session_id_len = session_id_len,
        .sess_sig = sess_sig,
        .sess_sig_len = sess_sig_len,
        /* seq == 0 means "no SEQ TLV" (verifier counters start at 1). */
        .seq = seq,
        .has_seq = (seq != 0u),
    };

    if (serialize_ns_pox_call(&r, inbuf, sizeof(inbuf), &inlen) != SER_OK) {
        /* handle error */
        printf("Error: serialize_ns_pox_call() failed\n");
        return PSA_ERROR_GENERIC_ERROR;
    }

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
