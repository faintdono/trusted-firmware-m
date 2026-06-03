/*
 * pox_core.c
 *
 * Proof-of-Execution core logic:
 *
 *  1. Obtain an IAT token from the Initial Attestation service using
 *     the caller-supplied challenge.
 *  2. Decode the IAT token to extract EAT claims (no signature
 *     verification needed here; the attestation service already
 *     produced a valid token).
 *  3. Execute the requested non-secure function via ns_execute().
 *  4. Encode a new CBOR map with the forwarded EAT claims plus the
 *     PoX extension claims (faddr, exec_output).
 *  5. Sign the CBOR map with COSE_Sign1 using the PoX signing key.
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
#include "tfm_sp_log.h"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/**
 * @brief Request an IAT token from the attestation service.
 *
 * @param[in]  challenge       Raw challenge bytes
 * @param[in]  challenge_size  Length of the challenge (32, 48 or 64 bytes)
 * @param[out] token_buf       Output buffer (must be ATT_MAX_TOKEN_SIZE bytes)
 * @param[out] token_size      Actual token length written
 */
static psa_status_t get_iat(const uint8_t *challenge, size_t challenge_size,
                             uint8_t *token_buf, size_t *token_size)
{
    LOG_INFFMT("[PoX] Requesting IAT token (challenge_size=%u)...\n",
               (unsigned int)challenge_size);

    psa_status_t status = psa_initial_attest_get_token(
                                challenge, challenge_size,
                                token_buf, ATT_MAX_TOKEN_SIZE,
                                token_size);
    if (status != PSA_SUCCESS) {
        LOG_INFFMT("[PoX] ERROR: psa_initial_attest_get_token failed (%d)\n",
                   (int)status);
    } else {
        LOG_INFFMT("[PoX] IAT token obtained, size=%u\n",
                   (unsigned int)*token_size);
    }
    return status;
}

/**
 * @brief Sign a raw CBOR payload as a COSE_Sign1 structure.
 *
 * Uses the PoX volatile signing key (handle from pox_get_signing_key_handle()) with ES256.
 *
 * @param[in]  payload        CBOR bytes to sign
 * @param[in]  payload_len    Length of payload
 * @param[out] report_buf     Output buffer for the signed COSE_Sign1
 * @param[in]  report_buf_sz  Size of report_buf
 * @param[out] report_len     Actual bytes written
 */
static psa_status_t sign_pox_token(const uint8_t *payload, size_t payload_len,
                                   uint8_t *report_buf, size_t report_buf_sz,
                                   size_t *report_len)
{
    struct t_cose_sign1_sign_ctx sign_ctx;
    struct t_cose_key signing_key;
    UsefulBufC signed_out;
    enum t_cose_err_t err;

    /*
     * Use the actual volatile handle returned by psa_import_key() at
     * partition startup, not POX_SIGNING_KEY_ID. For volatile keys,
     * psa_set_key_id() is ignored by PSA Crypto and the real handle is
     * whatever imported_id psa_import_key() assigned (typically 0x40000000+).
     */
    signing_key.key.handle = (uint64_t)pox_get_signing_key_handle();

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sign_ctx, signing_key, NULL_Q_USEFUL_BUF_C);

    err = t_cose_sign1_sign(&sign_ctx,
                            (UsefulBufC){ payload, payload_len },
                            (UsefulBuf){ report_buf, report_buf_sz },
                            &signed_out);
    if (err != T_COSE_SUCCESS) {
        LOG_INFFMT("[PoX] ERROR: t_cose_sign1_sign failed (%d)\n", (int)err);
        return PSA_ERROR_GENERIC_ERROR;
    }

    *report_len = signed_out.len;
    return PSA_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

psa_status_t
proof_of_execution(uintptr_t faddr,
                   const uint8_t *input,  const uint32_t input_len,
                   uint8_t       *output, uint32_t       *output_len,
                   uint8_t *challenge_buf, size_t challenge_size,
                   void *token_buf, size_t token_buf_size,
                   size_t *token_size)
{
    if (!token_buf || !token_size || token_buf_size == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Step 1: Get the IAT token */
    uint8_t iat_token_buf[ATT_MAX_TOKEN_SIZE];
    size_t  iat_token_size = 0;

    psa_status_t status = get_iat(challenge_buf, challenge_size,
                                  iat_token_buf, &iat_token_size);
    if (status != PSA_SUCCESS) {
        return status;
    }
    LOG_INFFMT("[PoX] IAT token size: %u\n", (unsigned int)iat_token_size);

    /* Steps 2-5 delegated to pox_create_token.
     * Initialise *token_size with the buffer capacity so pox_create_token
     * can pass it as the report buffer size to sign_pox_token.
     */
    *token_size = token_buf_size;
    return pox_create_token(iat_token_buf, iat_token_size,
                            faddr, input, input_len,
                            output, output_len,
                            (uint8_t *)token_buf, token_size);
}

psa_status_t pox_create_token(const uint8_t *iat_token_buf, size_t iat_token_sz,
                               uintptr_t faddr,
                               const uint8_t *input,  uint32_t input_len,
                               uint8_t       *output, uint32_t *output_len,
                               uint8_t *report_buf, size_t *report_size)
{
    static uint8_t cbor_scratch[POX_CBOR_SCRATCH_SIZE];
    static IATClaims claims;
    size_t cbor_len = 0;

    /* Step 2: Decode the IAT token into structured EAT claims */
    psa_status_t status = decode_iat_to_claims(iat_token_buf, iat_token_sz,
                                               &claims);
    if (status != PSA_SUCCESS) {
        LOG_INFFMT("[PoX] ERROR: decode_iat_to_claims failed (%d)\n",
                   (int)status);
        return status;
    }

    /* Step 3: Execute the non-secure function */
    int exec_result = 0;
    if (faddr != 0) {
        if (input_len > 0 && input != NULL && output != NULL) {
            exec_result = ns_execute(faddr, input, input_len,
                                     output, output_len);
        } else {
            exec_result = ns_execute_void(faddr);
        }
        LOG_INFFMT("[PoX] ns_execute return code: %d\n", exec_result);
    }

    /*
     * Step 4: Encode the PoX CBOR map:
     *   - All EAT claims forwarded from the decoded IAT
     *   - faddr  (IAT_POX_FADDR)
     *   - exec_output (IAT_POX_OUT) — first byte of output buffer, or
     *     the direct return value when there is no output buffer
     */
    int exec_output = (output != NULL && output_len != NULL && *output_len > 0)
                      ? (int)output[0]
                      : exec_result;

    LOG_INFFMT("[PoX] Execution value: 0x%x (%d)\n", exec_output, exec_output);

    status = encode_pox_claims(&claims, faddr, exec_output,
                               cbor_scratch, sizeof(cbor_scratch), &cbor_len);
    if (status != PSA_SUCCESS) {
        LOG_INFFMT("[PoX] ERROR: encode_pox_claims failed (%d)\n",
                   (int)status);
        return status;
    }

    /* Step 5: Sign the CBOR map as a COSE_Sign1 token */
    status = sign_pox_token(cbor_scratch, cbor_len,
                            report_buf, *report_size, report_size);
    if (status != PSA_SUCCESS) {
        LOG_INFFMT("[PoX] ERROR: sign_pox_token failed (%d)\n", (int)status);
    }

    return status;
}