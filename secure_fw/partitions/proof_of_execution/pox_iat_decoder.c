#include "pox_iat_decoder.h"
#include "tfm_attest_iat_defs.h"
#include "qcbor/qcbor_decode.h"
#include "t_cose/t_cose_sign1_verify.h"
#include <string.h>

/* Internal Helpers */
static size_t bstr_copy(uint8_t *dst, size_t dst_max, const void *src, size_t src_len) {
    size_t n = (src_len < dst_max) ? src_len : dst_max;
    memcpy(dst, src, n);
    return n;
}

static void tstr_copy(char *dst, size_t dst_max, const void *src, size_t src_len) {
    size_t n = (src_len < dst_max - 1) ? src_len : dst_max - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static psa_status_t parse_sw_component(QCBORDecodeContext *dc, SwComponent *sw) {
    memset(sw, 0, sizeof(*sw));
    QCBORDecode_EnterMap(dc, NULL);
    QCBORItem item;
    while (QCBORDecode_GetNext(dc, &item) == QCBOR_SUCCESS) {
        if (item.uDataType == QCBOR_TYPE_BREAK) break;
        if (item.uLabelType != QCBOR_TYPE_INT64) continue;

        switch (item.label.int64) {
            case IAT_SW_COMPONENT_MEASUREMENT_TYPE:
                if (item.uDataType == QCBOR_TYPE_TEXT_STRING) {
                    tstr_copy(sw->type, sizeof(sw->type), item.val.string.ptr, item.val.string.len);
                    sw->has_type = true;
                }
                break;
            case IAT_SW_COMPONENT_MEASUREMENT_VALUE:
                if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
                    sw->measurement_len = bstr_copy(sw->measurement, sizeof(sw->measurement), item.val.string.ptr, item.val.string.len);
                break;
            /* ... other cases (Version, Signer ID, etc) as per original Stage 2a ... */
        }
    }
    QCBORDecode_ExitMap(dc);
    return PSA_SUCCESS;
}

psa_status_t decode_iat_to_claims(const uint8_t *token_buf, size_t token_sz, IATClaims *out) {
    struct t_cose_sign1_verify_ctx ctx;
    t_cose_sign1_verify_init(&ctx, T_COSE_OPT_DECODE_ONLY);
    t_cose_sign1_set_verification_key(&ctx, T_COSE_NULL_KEY);

    UsefulBufC payload;
    UsefulBufC token = { token_buf, token_sz };
    if (t_cose_sign1_verify(&ctx, token, &payload, NULL) != T_COSE_SUCCESS)
        return PSA_ERROR_INVALID_ARGUMENT;

    memset(out, 0, sizeof(*out));
    QCBORDecodeContext dc;
    QCBORDecode_Init(&dc, payload, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&dc, NULL);

    QCBORItem item;
    while (QCBORDecode_GetNext(&dc, &item) == QCBOR_SUCCESS) {
        if (item.uDataType == QCBOR_TYPE_BREAK) break;
        int64_t lbl = item.label.int64;

        if (lbl == IAT_NONCE) {
            out->nonce_len = bstr_copy(out->nonce, sizeof(out->nonce), item.val.string.ptr, item.val.string.len);
        } else if (lbl == IAT_SW_COMPONENTS) {
            /* Loop through SW components and call parse_sw_component */
            uint16_t count = item.val.uCount;
            for (uint16_t i = 0; i < count && i < IAT_MAX_SW_COMPONENTS; i++) {
                parse_sw_component(&dc, &out->sw[out->sw_count++]);
            }
            out->has_sw = true;
        }
        /* ... remaining if/else logic for other labels ... */
    }

    QCBORDecode_ExitMap(&dc);
    return (QCBORDecode_Finish(&dc) == QCBOR_SUCCESS) ? PSA_SUCCESS : PSA_ERROR_INVALID_ARGUMENT;
}