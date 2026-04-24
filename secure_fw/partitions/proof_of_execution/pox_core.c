#include "pox.h"
#include "psa/client.h"
#include "tfm_attest_iat_defs.h"
#include "qcbor/qcbor.h"
#include "psa/initial_attestation.h"



static psa_status_t sign_pox_payload(const uint8_t *payload, size_t payload_len,
                                     uint8_t *report_buf, size_t report_buf_sz, size_t *report_len) 
{
    struct t_cose_sign1_sign_ctx sign_ctx;
    struct t_cose_key signing_key;
    t_cose_key_init_psa(&signing_key, POX_SIGNING_KEY_ID);
    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sign_ctx, signing_key, NULL_Q_USEFUL_BUF_C);

    UsefulBufC signed_out;
    enum t_cose_err_t err = t_cose_sign1_sign(&sign_ctx, (UsefulBufC){payload, payload_len}, 
                                              (UsefulBuf){report_buf, report_buf_sz}, &signed_out);
    
    if (err != T_COSE_SUCCESS) return PSA_ERROR_GENERIC_ERROR;
    *report_len = signed_out.len;
    return PSA_SUCCESS;
}

psa_status_t att_get_iat(uint8_t *challenge, uint8_t *token_buf, size_t *sys_token_sz)
{
    size_t token_buf_size = ATT_MAX_TOKEN_SIZE;
    LOG_INFFMT("[Secure] Requesting attestation token...\n");

    psa_status_t status = psa_initial_attest_get_token(challenge, PSA_INITIAL_ATTEST_CHALLENGE_SIZE_32, token_buf, token_buf_size, sys_token_sz);
    if (status != PSA_SUCCESS)
    {
        LOG_INFFMT("[Secure] ERROR: Failed to get attestation token (status: %d)\n", status);
        return status;
    }
    LOG_INFFMT("[Secure] Attestation token size: %d\n", *sys_token_sz);

    return PSA_SUCCESS;
}

psa_status_t
proof_of_execution(uintptr_t faddr, const uint8_t *input, const uint32_t input_len,
                   uint8_t *output, uint32_t *output_len,
                   const void *challenge_buf, size_t challenge_size,
                   void *token_buf, size_t token_buf_size,
                   size_t *token_size)
{
    
}

psa_status_t pox_create_token(const uint8_t *iat_token_buf, size_t iat_token_sz,
                                  uintptr_t faddr, uintptr_t exec_output,
                                  uint8_t *report_buf, size_t *report_size)
{
    static uint8_t scratch[POX_CBOR_SCRATCH_SIZE];
    size_t scratch_len = 0;
    IATClaims claims;

    /* Step 1 & 2: Decode */
    psa_status_t status = decode_iat_to_claims(iat_token_buf, iat_token_sz, &claims);
    if (status != PSA_SUCCESS) return status;

    /* Step 3: Encode */
    status = encode_pox_claims(&claims, faddr, exec_output, 
                               scratch, sizeof(scratch), &scratch_len);
    if (status != PSA_SUCCESS) return status;

    /* Step 4: Sign */
    return sign_pox_payload(scratch, scratch_len, report_buf, *report_size, report_size);
}