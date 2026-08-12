/*
 * pox_core.c
 *
 * Proof-of-Execution core logic; see pox.h for the flow.
 */

#include "pox.h"
#include "pox_encoder.h"
#include "pox_iat_decoder.h"
#include "pox_execute.h"

#include "psa/client.h"
#include "psa/initial_attestation.h"
#include "tfm_crypto_defs.h"

#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_key.h"
#include "t_cose/t_cose_common.h"
#include "pox_log.h"

#include <string.h>

static psa_status_t get_iat(const uint8_t *challenge, size_t challenge_size,
                             uint8_t *token_buf, size_t *token_size)
{
    POX_LOG_INF("[PoX] Requesting IAT token (challenge_size=%u)...\n",
               (unsigned int)challenge_size);

    psa_status_t status = psa_initial_attest_get_token(
                                challenge, challenge_size,
                                token_buf, ATT_MAX_TOKEN_SIZE,
                                token_size);
    if (status != PSA_SUCCESS) {
        POX_LOG_INF("[PoX] ERROR: psa_initial_attest_get_token failed (%d)\n",
                   (int)status);
    } else {
        POX_LOG_INF("[PoX] IAT token obtained, size=%u\n",
                   (unsigned int)*token_size);
    }
    return status;
}

static psa_status_t sign_pox_token(const uint8_t *payload, size_t payload_len,
                                   uint8_t *report_buf, size_t report_buf_sz,
                                   size_t *report_len)
{
    struct t_cose_sign1_sign_ctx sign_ctx;
    struct t_cose_key signing_key;
    UsefulBufC signed_out;
    enum t_cose_err_t err;

    signing_key.key.handle = (uint64_t)pox_get_signing_key_handle();

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sign_ctx, signing_key, NULL_Q_USEFUL_BUF_C);

    err = t_cose_sign1_sign(&sign_ctx,
                            (UsefulBufC){ payload, payload_len },
                            (UsefulBuf){ report_buf, report_buf_sz },
                            &signed_out);
    if (err != T_COSE_SUCCESS) {
        POX_LOG_INF("[PoX] ERROR: t_cose_sign1_sign failed (%d)\n", (int)err);
        return PSA_ERROR_GENERIC_ERROR;
    }

    *report_len = signed_out.len;
    return PSA_SUCCESS;
}

psa_status_t
proof_of_execution(uintptr_t faddr,
                   const uint8_t *input,  const uint32_t input_len,
                   uint8_t       *output, uint32_t       *output_len,
                   uint8_t *challenge_buf, size_t challenge_size,
                   const pox_session_ctx_t *sess,
                   void *token_buf, size_t token_buf_size,
                   size_t *token_size)
{
    if (!token_buf || !token_size || token_buf_size == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    uint8_t iat_token_buf[ATT_MAX_TOKEN_SIZE];
    size_t  iat_token_size = 0;

    psa_status_t status = get_iat(challenge_buf, challenge_size,
                                  iat_token_buf, &iat_token_size);
    if (status != PSA_SUCCESS) {
        return status;
    }
    POX_LOG_INF("[PoX] IAT token size: %u\n", (unsigned int)iat_token_size);

    *token_size = token_buf_size;
    return pox_create_token(iat_token_buf, iat_token_size,
                            faddr, input, input_len,
                            output, output_len,
                            challenge_buf, challenge_size, sess,
                            (uint8_t *)token_buf, token_size);
}

psa_status_t pox_create_token(const uint8_t *iat_token_buf, size_t iat_token_sz,
                               uintptr_t faddr,
                               const uint8_t *input,  uint32_t input_len,
                               uint8_t       *output, uint32_t *output_len,
                               const uint8_t *challenge_buf,
                               size_t challenge_size,
                               const pox_session_ctx_t *sess,
                               uint8_t *report_buf, size_t *report_size)
{
    static uint8_t cbor_scratch[POX_CBOR_SCRATCH_SIZE];
    static IATClaims claims;
    size_t cbor_len = 0;

    psa_status_t status = decode_iat_to_claims(iat_token_buf, iat_token_sz,
                                               &claims);
    if (status != PSA_SUCCESS) {
        POX_LOG_INF("[PoX] ERROR: decode_iat_to_claims failed (%d)\n",
                   (int)status);
        return status;
    }

    /*
     * The verifier nonce IS the IAT challenge: the attestation service
     * must have embedded exactly the authenticated bytes. A mismatch
     * means substitution or corruption, so no token may be issued.
     */
    if (challenge_buf == NULL ||
        claims.nonce_len != challenge_size ||
        memcmp(claims.nonce, challenge_buf, challenge_size) != 0) {
        POX_LOG_INF("[PoX] ERROR: IAT nonce does not match the "
                   "authenticated challenge\n");
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    int exec_result = 0;
    struct ns_exec_snapshot snap = { 0 };
    if (faddr != 0) {
        if (input_len > 0 && input != NULL && output != NULL) {
            exec_result = ns_execute(faddr, input, input_len,
                                     output, output_len, &snap);
        } else {
            exec_result = ns_execute_void(faddr);
        }
        POX_LOG_INF("[PoX] ns_execute return code: %d\n", exec_result);

        /* Nothing ran - a token here would attest an execution that
         * never happened. */
        if (exec_result == POX_EXEC_ERR_BAD_OUTPUT) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    /* Attest the Secure snapshot, never the caller's buffer (see
     * struct ns_exec_snapshot): the whole captured output where there
     * is one, the call's return code as a single byte otherwise (the
     * void-call behaviour). */
    uint8_t  exec_fallback = (uint8_t)exec_result;
    const uint8_t *exec_output;
    size_t         exec_output_len;

    if (snap.valid && snap.out_len > 0u) {
        exec_output     = snap.out;
        exec_output_len = snap.out_len;
    } else {
        exec_output     = &exec_fallback;
        exec_output_len = 1u;
    }

    POX_LOG_INF("[PoX] Execution value: %u byte(s), first 0x%x\n",
                (unsigned int)exec_output_len, (unsigned int)exec_output[0]);

    status = encode_pox_claims(&claims, faddr, exec_output, exec_output_len,
                               sess,
                               cbor_scratch, sizeof(cbor_scratch), &cbor_len);
    if (status != PSA_SUCCESS) {
        POX_LOG_INF("[PoX] ERROR: encode_pox_claims failed (%d)\n",
                   (int)status);
        return status;
    }

    status = sign_pox_token(cbor_scratch, cbor_len,
                            report_buf, *report_size, report_size);
    if (status != PSA_SUCCESS) {
        POX_LOG_INF("[PoX] ERROR: sign_pox_token failed (%d)\n", (int)status);
    }

    return status;
}
