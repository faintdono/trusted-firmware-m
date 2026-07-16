/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
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
 *
 * Session authentication: the verifier issues {session_id, challenge,
 * faddr} and signs the request transcript with its ECDSA P-256 private
 * key. The NS application is only a relay: it passes session_id and
 * sess_sig through verbatim and cannot forge or modify them (any change
 * invalidates the signature checked inside the secure partition).
 *
 * sess_sig format: 64-byte RAW r||s (PSA format, NOT ASN.1/DER) over:
 *   ver(1) | sid_len(1) | session_id | nonce_len(1) | challenge |
 *   faddr_le32(4)
 *
 * session_id/sess_sig may be NULL only when the secure partition is
 * built with POX_SESSION_AUTH disabled; otherwise the request is
 * rejected with PSA_ERROR_NOT_PERMITTED.
 * ---------------------------------------------------------------------- */

psa_status_t
psa_pox_get_token(uintptr_t      faddr,
                  const uint8_t *input,
                  size_t         input_len,
                  uint8_t       *output,
                  size_t         output_len,
                  const uint8_t *challenge,
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

    /* Session credentials: both present, or both absent. Detailed
     * bounds are validated by the serializer. */
    if ((session_id == NULL) != (sess_sig == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Build the wire request */
    ns_pox_call_req_t req = {
        .challenge       = challenge,
        .challenge_len   = (uint32_t)challenge_size,
        .function_addr   = (uint32_t)(uintptr_t)faddr,
        .input           = (uint32_t)(uintptr_t)input,
        .input_len       = (uint32_t)input_len,
        .output          = (uint32_t)(uintptr_t)output,
        .output_len      = (uint32_t)output_len,
        .session_id      = session_id,
        .session_id_len  = (uint32_t)session_id_len,
        .sess_sig        = sess_sig,
        .sess_sig_len    = (uint32_t)sess_sig_len,
        /* seq == 0 means "no SEQ TLV" (verifier counters start at 1). */
        .seq             = seq,
        .has_seq         = (seq != 0u),
        .add_crc32       = false,
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
