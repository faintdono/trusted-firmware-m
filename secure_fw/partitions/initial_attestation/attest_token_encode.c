/*
 * attest_token_encode.c
 *
 * Copyright (c) 2018-2019, Laurence Lundblade. All rights reserved.
 *
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "attest_token.h"
#include "config_tfm.h"
#include "qcbor/qcbor.h"
#ifdef SYMMETRIC_INITIAL_ATTESTATION
#include "t_cose/t_cose_mac_compute.h"
#else
#include "t_cose/t_cose_sign1_sign.h"
#endif
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "psa/crypto.h"
#include "attest_key.h"
#include "tfm_crypto_defs.h"
#include "tfm_sp_log.h"

/**
 * \file attest_token_encode.c
 *
 * \brief Attestation token creation implementation
 */

/**
 * \brief Map t_cose error to attestation token error.
 *
 * \param[in] err   The t_cose error to map.
 *
 * \return the attestation token error.
 */
static enum attest_token_err_t t_cose_err_to_attest_err(enum t_cose_err_t err)
{
    switch(err) {

    case T_COSE_SUCCESS:
        return ATTEST_TOKEN_ERR_SUCCESS;

    case T_COSE_ERR_UNSUPPORTED_HASH:
        return ATTEST_TOKEN_ERR_HASH_UNAVAILABLE;

    case T_COSE_ERR_TOO_SMALL:
        return ATTEST_TOKEN_ERR_TOO_SMALL;

    default:
        /* A lot of the errors are not mapped because they are
         * primarily internal errors that should never happen. They
         * end up here.
         */
        return ATTEST_TOKEN_ERR_GENERAL;
    }
}

#ifdef SYMMETRIC_INITIAL_ATTESTATION
/*
 * Outline of token creation. Much of this occurs inside
 * t_cose_mac_encode_parameters() and t_cose_mac_encode_tag().
 *
 * - Create encoder context
 * - Open the CBOR array that hold the \c COSE_Mac0
 * - Write COSE Headers
 *   - Protected Header
 *      - Algorithm ID
 *   - Unprotected Headers
 *     - Key ID
 * - Open payload bstr
 *   - Write payload data, maybe lots of it
 *   - Get bstr that is the encoded payload
 * - Compute tag
 *   - Create a separate encoder context for \c MAC_structure
 *     - Encode CBOR context identifier
 *     - Encode protected headers
 *     - Encode an empty bstr for external_aad
 *     - Add one more empty bstr that is a "fake payload"
 *     - Close off \c MAC_structure
 *   - Call MAC API to compute the tag of all but "fake payload" of
 *     \c MAC_structure
 *   - Get payload bstr ptr and length
 *   - Update the real encoded payload into MAC operation
 *   - Complete MAC operation
 * - Write tag into the CBOR output
 * - Close CBOR array holding the \c COSE_Mac0
 */

/*
 * Public function. See attest_token.h
 */
enum attest_token_err_t
attest_token_encode_start(struct attest_token_encode_ctx *me,
                          int32_t key_select,
                          int32_t cose_alg_id,
                          const struct q_useful_buf *out_buf)
{
    psa_key_handle_t key_handle = TFM_BUILTIN_KEY_ID_IAK;
    struct t_cose_key attest_key;
    enum psa_attest_err_t attest_ret;
    enum t_cose_err_t cose_ret;
    enum attest_token_err_t return_value = ATTEST_TOKEN_ERR_SUCCESS;
    struct q_useful_buf_c attest_key_id;

    /* Remember some of the configuration values */
    me->key_select = key_select;

    t_cose_mac_compute_init(&(me->mac_ctx), 0, cose_alg_id);

    attest_key.key.handle = (uint64_t)key_handle;

    attest_ret = attest_get_initial_attestation_key_id(&attest_key_id);
    if (attest_ret != PSA_ATTEST_ERR_SUCCESS) {
        return ATTEST_TOKEN_ERR_GENERAL;
    } else if (!attest_key_id.ptr || !attest_key_id.len) {
        /* In case kid value is invalid, set it to NULL */
        attest_key_id = NULL_Q_USEFUL_BUF_C;
    }

    t_cose_mac_set_computing_key(&(me->mac_ctx),
                                 attest_key,
                                 attest_key_id);

    /* Spin up the CBOR encoder */
    QCBOREncode_Init(&(me->cbor_enc_ctx), *out_buf);

    /* This will cause the cose headers to be encoded and written into
     *  out_buf using me->cbor_enc_ctx
     */
    cose_ret = t_cose_mac_encode_parameters(&(me->mac_ctx),
                                            &(me->cbor_enc_ctx));
    if (cose_ret != T_COSE_SUCCESS) {
        return_value = t_cose_err_to_attest_err(cose_ret);
    }

    /* Wrapping the content of the token (payload) into a byte string
     * which then can be handed over as input to a hashing function
     * as part of signing it.
     */
    QCBOREncode_BstrWrap(&(me->cbor_enc_ctx));
    QCBOREncode_OpenMap(&(me->cbor_enc_ctx));

    return return_value;
}

/*
 * Public function. See attest_token.h
 */
enum attest_token_err_t
attest_token_encode_finish(struct attest_token_encode_ctx *me,
                           struct q_useful_buf_c *completed_token)
{
    enum attest_token_err_t return_value = ATTEST_TOKEN_ERR_SUCCESS;
    struct q_useful_buf_c   payload;
    /* The completed and tagged encoded COSE_Mac0 */
    struct q_useful_buf_c   completed_token_ub;
    QCBORError              qcbor_result;
    enum t_cose_err_t       cose_return_value;

    QCBOREncode_CloseMap(&(me->cbor_enc_ctx));
    QCBOREncode_CloseBstrWrap2(&(me->cbor_enc_ctx), false, &payload);

    /* -- Finish up the COSE_Mac0. This is where the MAC happens -- */
    cose_return_value = t_cose_mac_encode_tag(&(me->mac_ctx),
                                              payload,
                                              &(me->cbor_enc_ctx));
    if (cose_return_value) {
        /* Main errors are invoking the tagging */
        return_value = t_cose_err_to_attest_err(cose_return_value);
        goto Done;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Mac0
     */
    qcbor_result = QCBOREncode_Finish(&(me->cbor_enc_ctx), &completed_token_ub);
    if (qcbor_result == QCBOR_ERR_BUFFER_TOO_SMALL) {
           return_value = ATTEST_TOKEN_ERR_TOO_SMALL;
    } else if (qcbor_result != QCBOR_SUCCESS) {
        /* likely from array not closed, too many closes, ... */
        return_value = ATTEST_TOKEN_ERR_CBOR_FORMATTING;
    } else {
        *completed_token = completed_token_ub;
    }

Done:
    return return_value;
}
#else /* SYMMETRIC_INITIAL_ATTESTATION */
/*
 * Outline of token creation. Much of this occurs inside
 * t_cose_sign1_encode_parameters() and t_cose_sign1_encode_signature().
 *
 * - Create encoder context
 * - Open the CBOR array that hold the \c COSE_Sign1
 * - Write COSE Headers
 *   - Protected Header
 *      - Algorithm ID
 *   - Unprotected Headers
 *     - Key ID
 * - Open payload bstr
 *   - Write payload data, maybe lots of it
 *   - Get bstr that is the encoded payload
 * - Compute signature
 *   - Create a separate encoder context for \c Sig_structure
 *     - Encode CBOR context identifier
 *     - Encode protected headers
 *     - Encode two empty bstr
 *     - Add one more empty bstr that is a "fake payload"
 *     - Close off \c Sig_structure
 *   - Hash all but "fake payload" of \c Sig_structure
 *   - Get payload bstr ptr and length
 *   - Continue hash of the real encoded payload
 *   - Run ECDSA
 * - Write signature into the CBOR output
 * - Close CBOR array holding the \c COSE_Sign1
 */

 void generate_new_key(psa_key_handle_t *key_handle) {
    SPMLOG_INFMSG("[OAK] genearting key");
    psa_status_t status;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT); // Required for IAK
    psa_set_key_id(&attributes, 0x55);



    SPMLOG_INFMSG("[OAK] genearting key2");
    status = psa_generate_key(&attributes, key_handle);

    SPMLOG_INFMSGVAL("[INF] key handle: ", *key_handle);
    psa_reset_key_attributes(&attributes);

}

void import_fixed_key(psa_key_handle_t key_handle) {
    SPMLOG_INFMSG("[OAK] importing fixed key \n");
    psa_status_t status;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT); // Required for IAK
    psa_set_key_id(&attributes, 0x55); // persistent key ID

    uint8_t fixed_private_key[32] = {
        0xA9, 0xB4, 0x54, 0xB2, 0x6D, 0x6F, 0x90, 0xA4,
        0xEA, 0x31, 0x19, 0x35, 0x64, 0xCB, 0xA9, 0x1F,
        0xEC, 0x6F, 0x9A, 0x00, 0x2A, 0x7D, 0xC0, 0x50,
        0x4B, 0x92, 0xA1, 0x93, 0x71, 0x34, 0x58, 0x5F
    };

    status = psa_import_key(&attributes, fixed_private_key, sizeof(fixed_private_key), key_handle);
    if (status != PSA_SUCCESS) {
        SPMLOG_ERRMSGVAL("[OAK] Key import failed with status: ", status);
    } else {
        SPMLOG_INFMSGVAL("[INF] key handle: ",key_handle);
    }

    psa_reset_key_attributes(&attributes);
}

/*
 * Public function. See attest_token.h
 */
enum attest_token_err_t
attest_token_encode_start(struct attest_token_encode_ctx *me,
                          int32_t key_select,
                          int32_t cose_alg_id,
                          const struct q_useful_buf *out_buf)
{
    enum psa_attest_err_t attest_ret;
    enum t_cose_err_t cose_ret;
    struct t_cose_key attest_key;
    psa_key_handle_t private_key = TFM_BUILTIN_KEY_ID_IAK;
    struct q_useful_buf_c attest_key_id = NULL_Q_USEFUL_BUF_C;

    // psa_key_handle_t keyid;
    // import_fixed_key(&keyid);
    // private_key = keyid;
    
    /* Remember some of the configuration values */
    me->key_select = key_select;

    attest_ret = attest_get_initial_attestation_key_id(&attest_key_id);
    if (attest_ret != PSA_ATTEST_ERR_SUCCESS) {
        return ATTEST_TOKEN_ERR_GENERAL;
    }

    t_cose_sign1_sign_init(&(me->signer_ctx), 0, cose_alg_id);

    attest_key.key.handle = private_key;

    t_cose_sign1_set_signing_key(&(me->signer_ctx),
                                 attest_key,
                                 attest_key_id);

    /* Spin up the CBOR encoder */
    QCBOREncode_Init(&(me->cbor_enc_ctx), *out_buf);

    /* This will cause the cose headers to be encoded and written into
     *  out_buf using me->cbor_enc_ctx
     */
    cose_ret = t_cose_sign1_encode_parameters(&(me->signer_ctx),
                                              &(me->cbor_enc_ctx));
    if (cose_ret) {
        return t_cose_err_to_attest_err(cose_ret);
    }

    QCBOREncode_OpenMap(&(me->cbor_enc_ctx));

    return ATTEST_TOKEN_ERR_SUCCESS;
}

/*
 * Public function. See attest_token.h
 */
enum attest_token_err_t
attest_token_encode_finish(struct attest_token_encode_ctx *me,
                           struct q_useful_buf_c *completed_token)
{
    enum attest_token_err_t return_value = ATTEST_TOKEN_ERR_SUCCESS;
    /* The completed and signed encoded cose_sign1 */
    struct q_useful_buf_c   completed_token_ub;
    QCBORError              qcbor_result;
    enum t_cose_err_t       cose_return_value;

    QCBOREncode_CloseMap(&(me->cbor_enc_ctx));
    /* -- Finish up the COSE_Sign1. This is where the signing happens -- */
    cose_return_value = t_cose_sign1_encode_signature(&(me->signer_ctx),
                                                      &(me->cbor_enc_ctx));
    if (cose_return_value) {
        /* Main errors are invoking the hash or signature */
        return_value = t_cose_err_to_attest_err(cose_return_value);
        if (return_value == ATTEST_TOKEN_ERR_GENERAL){
            LOG_ERRFMT("[ERR] HI IAM ERROR");
        }
        goto Done;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    qcbor_result = QCBOREncode_Finish(&(me->cbor_enc_ctx), &completed_token_ub);
    if (qcbor_result == QCBOR_ERR_BUFFER_TOO_SMALL) {
           return_value = ATTEST_TOKEN_ERR_TOO_SMALL;
       } else if (qcbor_result != QCBOR_SUCCESS) {
           /* likely from array not closed, too many closes, ... */
           return_value = ATTEST_TOKEN_ERR_CBOR_FORMATTING;
       } else {
           *completed_token = completed_token_ub;
       }

Done:
        return return_value;
}
#endif /* SYMMETRIC_INITIAL_ATTESTATION */

/*
 * Public function. See attest_token.h
 */
QCBOREncodeContext *
attest_token_encode_borrow_cbor_cntxt(struct attest_token_encode_ctx *me)
{
    return &(me->cbor_enc_ctx);
}


/*
 * Public function. See attest_token.h
 */
void attest_token_encode_add_integer(struct attest_token_encode_ctx *me,
                                     int32_t label,
                                     int64_t value)
{
    QCBOREncode_AddInt64ToMapN(&(me->cbor_enc_ctx), label, value);
}


/*
 * Public function. See attest_token.h
 */
void attest_token_encode_add_bstr(struct attest_token_encode_ctx *me,
                                  int32_t label,
                                  const struct q_useful_buf_c *bstr)
{
    QCBOREncode_AddBytesToMapN(&(me->cbor_enc_ctx),
                               label,
                               *bstr);
}


/*
 * Public function. See attest_token.h
 */
void attest_token_encode_add_tstr(struct attest_token_encode_ctx *me,
                                  int32_t label,
                                  const struct q_useful_buf_c *tstr)
{
    QCBOREncode_AddTextToMapN(&(me->cbor_enc_ctx), label, *tstr);
}


/*
 * Public function. See attest_token.h
 */
void attest_token_encode_add_cbor(struct attest_token_encode_ctx *me,
                                  int32_t label,
                                  const struct q_useful_buf_c *encoded)
{
    QCBOREncode_AddEncodedToMapN(&(me->cbor_enc_ctx), label, *encoded);
}
