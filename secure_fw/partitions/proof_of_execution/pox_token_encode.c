#include "qcbor/qcbor.h"
#include "t_cose/t_cose_mac_compute.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "psa/crypto.h"
#include "tfm_crypto_defs.h"

/**
 * \file pox_token_encode.c
 *
 * \brief Attestation token creation implementation
 */

/**
 * \brief Map t_cose error to poxation token error.
 *
 * \param[in] err   The t_cose error to map.
 *
 * \return the poxation token error.
 */
static enum pox_token_err_t t_cose_err_to_pox_err(enum t_cose_err_t err)
{
    switch (err)
    {

    case T_COSE_SUCCESS:
        return POX_TOKEN_ERR_SUCCESS;

    case T_COSE_ERR_UNSUPPORTED_HASH:
        return POX_TOKEN_ERR_HASH_UNAVAILABLE;

    case T_COSE_ERR_TOO_SMALL:
        return POX_TOKEN_ERR_TOO_SMALL;

    default:
        /* A lot of the errors are not mapped because they are
         * primarily internal errors that should never happen. They
         * end up here.
         */
        return POX_TOKEN_ERR_GENERAL;
    }
}

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
 * Public function. See pox_token.h
 */
enum pox_token_err_t
pox_token_encode_start(struct pox_token_encode_ctx *me,
                       int32_t key_select,
                       int32_t cose_alg_id,
                       const struct q_useful_buf *out_buf)
{
    psa_key_handle_t key_handle = TFM_BUILTIN_KEY_ID_IAK;
    struct t_cose_key pox_key;
    enum psa_pox_err_t pox_ret;
    enum t_cose_err_t cose_ret;
    enum pox_token_err_t return_value = POX_TOKEN_ERR_SUCCESS;
    struct q_useful_buf_c pox_key_id;

    /* Remember some of the configuration values */
    me->key_select = key_select;

    t_cose_mac_compute_init(&(me->mac_ctx), 0, cose_alg_id);

    pox_key.key.handle = (uint64_t)key_handle;

    pox_ret = pox_get_initial_poxation_key_id(&pox_key_id);
    if (pox_ret != PSA_POX_ERR_SUCCESS)
    {
        return POX_TOKEN_ERR_GENERAL;
    }
    else if (!pox_key_id.ptr || !pox_key_id.len)
    {
        /* In case kid value is invalid, set it to NULL */
        pox_key_id = NULL_Q_USEFUL_BUF_C;
    }

    t_cose_mac_set_computing_key(&(me->mac_ctx),
                                 pox_key,
                                 pox_key_id);

    /* Spin up the CBOR encoder */
    QCBOREncode_Init(&(me->cbor_enc_ctx), *out_buf);

    /* This will cause the cose headers to be encoded and written into
     *  out_buf using me->cbor_enc_ctx
     */
    cose_ret = t_cose_mac_encode_parameters(&(me->mac_ctx),
                                            &(me->cbor_enc_ctx));
    if (cose_ret != T_COSE_SUCCESS)
    {
        return_value = t_cose_err_to_pox_err(cose_ret);
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
 * Public function. See pox_token.h
 */
enum pox_token_err_t
pox_token_encode_finish(struct pox_token_encode_ctx *me,
                        struct q_useful_buf_c *completed_token)
{
    enum pox_token_err_t return_value = POX_TOKEN_ERR_SUCCESS;
    struct q_useful_buf_c payload;
    /* The completed and tagged encoded COSE_Mac0 */
    struct q_useful_buf_c completed_token_ub;
    QCBORError qcbor_result;
    enum t_cose_err_t cose_return_value;

    QCBOREncode_CloseMap(&(me->cbor_enc_ctx));
    QCBOREncode_CloseBstrWrap2(&(me->cbor_enc_ctx), false, &payload);

    /* -- Finish up the COSE_Mac0. This is where the MAC happens -- */
    cose_return_value = t_cose_mac_encode_tag(&(me->mac_ctx),
                                              payload,
                                              &(me->cbor_enc_ctx));
    if (cose_return_value)
    {
        /* Main errors are invoking the tagging */
        return_value = t_cose_err_to_pox_err(cose_return_value);
        goto Done;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Mac0
     */
    qcbor_result = QCBOREncode_Finish(&(me->cbor_enc_ctx), &completed_token_ub);
    if (qcbor_result == QCBOR_ERR_BUFFER_TOO_SMALL)
    {
        return_value = POX_TOKEN_ERR_TOO_SMALL;
    }
    else if (qcbor_result != QCBOR_SUCCESS)
    {
        /* likely from array not closed, too many closes, ... */
        return_value = POX_TOKEN_ERR_CBOR_FORMATTING;
    }
    else
    {
        *completed_token = completed_token_ub;
    }

Done:
    return return_value;
}

/*
 * Public function. See pox_token.h
 */
QCBOREncodeContext *
pox_token_encode_borrow_cbor_cntxt(struct pox_token_encode_ctx *me)
{
    return &(me->cbor_enc_ctx);
}

/*
 * Public function. See pox_token.h
 */
void pox_token_encode_add_integer(struct pox_token_encode_ctx *me,
                                  int32_t label,
                                  int64_t value)
{
    QCBOREncode_AddInt64ToMapN(&(me->cbor_enc_ctx), label, value);
}

/*
 * Public function. See pox_token.h
 */
void pox_token_encode_add_bstr(struct pox_token_encode_ctx *me,
                               int32_t label,
                               const struct q_useful_buf_c *bstr)
{
    QCBOREncode_AddBytesToMapN(&(me->cbor_enc_ctx),
                               label,
                               *bstr);
}

/*
 * Public function. See pox_token.h
 */
void pox_token_encode_add_tstr(struct pox_token_encode_ctx *me,
                               int32_t label,
                               const struct q_useful_buf_c *tstr)
{
    QCBOREncode_AddTextToMapN(&(me->cbor_enc_ctx), label, *tstr);
}

/*
 * Public function. See pox_token.h
 */
void pox_token_encode_add_cbor(struct pox_token_encode_ctx *me,
                               int32_t label,
                               const struct q_useful_buf_c *encoded)
{
    QCBOREncode_AddEncodedToMapN(&(me->cbor_enc_ctx), label, *encoded);
}