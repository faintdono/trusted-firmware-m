/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*
 * NS-side API for the standalone Proof-of-Execution (PoX) secure partition
 * (TFM_SP_POX, SID 0xFFFFF0E1).
 *
 * Mirrors the pattern of tfm_attest_api.c:
 *   1. Build an ns_pox_call_req_t.
 *   2. Serialise it into a stack buffer via serialize_ns_pox_call().
 *   3. Open a connection to TFM_POX_SERVICE, send the buffer, receive the
 *      signed COSE_Sign1 PoX token, close the connection.
 */

#include <stdint.h>
#include <stddef.h>

#include "psa/client.h"
#include "psa/error.h"
#include "psa/initial_attestation.h"   /* PSA_INITIAL_ATTEST_CHALLENGE_SIZE_* */
#include "tfm_pox_defs.h"
#include "tfm_pox_wire.h"

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

psa_status_t
psa_pox_get_token(uintptr_t      faddr,
                  const uint8_t *input,
                  size_t         input_len,
                  uint8_t       *output,
                  size_t         output_len,
                  const uint8_t *challenge,
                  size_t         challenge_size,
                  uint8_t       *token_buf,
                  size_t         token_buf_size,
                  size_t        *token_size)
{
    psa_status_t   status;
    psa_handle_t   handle;
    ser_status_t   ser_st;
    uint8_t        wire_buf[256];
    size_t         wire_len = 0;

    if (!challenge || challenge_size < PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32 ||
        challenge_size > PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!token_buf || token_buf_size == 0 || !token_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Build the wire request */
    ns_pox_call_req_t req = {
        .challenge      = challenge,
        .challenge_len  = (uint32_t)challenge_size,
        .function_addr  = (uint32_t)(uintptr_t)faddr,
        .input          = (uint32_t)(uintptr_t)input,
        .input_len      = (uint32_t)input_len,
        .output         = (uint32_t)(uintptr_t)output,
        .output_len     = (uint32_t)output_len,
        .add_crc32      = false,
    };

    ser_st = serialize_ns_pox_call(&req, wire_buf, sizeof(wire_buf), &wire_len);
    if (ser_st != SER_OK) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* Connect to the standalone PoX partition */
    handle = psa_connect(TFM_POX_SERVICE_SID, TFM_POX_SERVICE_VERSION);
    if (handle <= 0) {
        return PSA_ERROR_CONNECTION_REFUSED;
    }

    psa_invec  in_vec[]  = { { wire_buf,  wire_len        } };
    psa_outvec out_vec[] = { { token_buf, token_buf_size  } };

    status = psa_call(handle, TFM_POX_GET_TOKEN,
                      in_vec,  1,
                      out_vec, 1);

    if (status == PSA_SUCCESS) {
        *token_size = out_vec[0].len;
    }

    psa_close(handle);
    return status;
}
