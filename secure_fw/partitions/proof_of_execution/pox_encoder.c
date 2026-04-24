#include "pox_encoder.h"
#include "tfm_attest_iat_defs.h"
#include "qcbor/qcbor_encode.h"

psa_status_t encode_pox_claims(const IATClaims *iat,
                               uintptr_t        faddr,
                               int              exec_output,
                               uint8_t         *scratch,
                               size_t           scratch_sz,
                               size_t          *encoded_len) 
{
    QCBOREncodeContext ec;
    QCBOREncode_Init(&ec, (UsefulBuf){ scratch, scratch_sz });
    QCBOREncode_OpenMap(&ec);

    /* Mandatory Claims */
    QCBOREncode_AddBytesToMapN(&ec, IAT_NONCE, (UsefulBufC){ iat->nonce, iat->nonce_len });
    QCBOREncode_AddUInt64ToMapN(&ec, IAT_SECURITY_LIFECYCLE, iat->security_lifecycle);

    /* SW Components */
    if (iat->has_sw) {
        QCBOREncode_OpenArrayInMapN(&ec, IAT_SW_COMPONENTS);
        for (size_t i = 0; i < iat->sw_count; i++) {
            QCBOREncode_OpenMap(&ec);
            QCBOREncode_AddBytesToMapN(&ec, IAT_SW_COMPONENT_MEASUREMENT_VALUE, 
                (UsefulBufC){ iat->sw[i].measurement, iat->sw[i].measurement_len });
            QCBOREncode_CloseMap(&ec);
        }
        QCBOREncode_CloseArray(&ec);
    }

    /* PoX Extension Claims */
    QCBOREncode_AddUInt64ToMapN(&ec, IAT_POX_FADDR, (uint64_t)faddr);
    QCBOREncode_AddInt64ToMapN(&ec, IAT_POX_OUT, (int64_t)exec_output);

    QCBOREncode_CloseMap(&ec);

    UsefulBufC result;
    if (QCBOREncode_Finish(&ec, &result) != QCBOR_SUCCESS) return PSA_ERROR_BUFFER_TOO_SMALL;

    *encoded_len = result.len;
    return PSA_SUCCESS;
}