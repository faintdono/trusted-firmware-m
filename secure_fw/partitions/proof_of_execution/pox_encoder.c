/*
 * pox_encoder.c
 *
 * Encodes the PoX CBOR claims map from decoded IAT claims plus the
 * proof-of-execution extension claims (faddr, exec_output).
 *
 * CCA-only claims (IAT_PLATFORM_CONFIG, IAT_PLATFORM_HASH_ALGO_ID) are
 * guarded by #if ATTEST_TOKEN_PROFILE_ARM_CCA so they compile cleanly
 * under PSA_IOT_1 and PSA_2_0_0 profiles too.
 */

#include "pox_encoder.h"
#include "tfm_attest_iat_defs.h"

#include "qcbor/qcbor_encode.h"

#include <string.h>

psa_status_t encode_pox_claims(const IATClaims *iat,
                               uintptr_t        faddr,
                               int              exec_output,
                               uint8_t         *scratch,
                               size_t           scratch_sz,
                               size_t          *encoded_len)
{
    if (!iat || !scratch || !encoded_len) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    QCBOREncodeContext ec;
    QCBOREncode_Init(&ec, (UsefulBuf){ scratch, scratch_sz });
    QCBOREncode_OpenMap(&ec);

    /* ---------------------------------------------------------------- */
    /* Standard EAT claims forwarded from the decoded IAT token          */
    /* ---------------------------------------------------------------- */

    /* Nonce */
    if (iat->nonce_len > 0) {
        QCBOREncode_AddBytesToMapN(&ec, IAT_NONCE,
            (UsefulBufC){ iat->nonce, iat->nonce_len });
    }

    /* Instance ID */
    if (iat->instance_id_len > 0) {
        QCBOREncode_AddBytesToMapN(&ec, IAT_INSTANCE_ID,
            (UsefulBufC){ iat->instance_id, iat->instance_id_len });
    }

    /* Implementation ID */
    if (iat->implementation_id_len > 0) {
        QCBOREncode_AddBytesToMapN(&ec, IAT_IMPLEMENTATION_ID,
            (UsefulBufC){ iat->implementation_id,
                          iat->implementation_id_len });
    }

    /* Security lifecycle */
    QCBOREncode_AddUInt64ToMapN(&ec, IAT_SECURITY_LIFECYCLE,
                                (uint64_t)iat->security_lifecycle);

    /* Profile definition */
    if (iat->has_profile && iat->profile[0] != '\0') {
        QCBOREncode_AddTextToMapN(&ec, IAT_PROFILE_DEFINITION,
            (UsefulBufC){ iat->profile, strlen(iat->profile) });
    }

#if ATTEST_TOKEN_PROFILE_PSA_IOT_1 || ATTEST_TOKEN_PROFILE_PSA_2_0_0
    /* Boot seed */
    if (iat->has_boot_seed && iat->boot_seed_len > 0) {
        QCBOREncode_AddBytesToMapN(&ec, IAT_BOOT_SEED,
            (UsefulBufC){ iat->boot_seed, iat->boot_seed_len });
    }

    /* Client ID */
    if (iat->has_client_id) {
        QCBOREncode_AddInt64ToMapN(&ec, IAT_CLIENT_ID,
                                   (int64_t)iat->client_id);
    }

    /* Certification reference */
    if (iat->has_cert_ref && iat->cert_ref[0] != '\0') {
        QCBOREncode_AddTextToMapN(&ec, IAT_CERTIFICATION_REFERENCE,
            (UsefulBufC){ iat->cert_ref, strlen(iat->cert_ref) });
    }
#endif /* ATTEST_TOKEN_PROFILE_PSA_IOT_1 || ATTEST_TOKEN_PROFILE_PSA_2_0_0 */

#if ATTEST_TOKEN_PROFILE_ARM_CCA
    /* Platform config (CCA only) */
    if (iat->has_platform_config && iat->platform_config_len > 0) {
        QCBOREncode_AddBytesToMapN(&ec, IAT_PLATFORM_CONFIG,
            (UsefulBufC){ iat->platform_config, iat->platform_config_len });
    }

    /* Platform hash algo ID (CCA only) */
    if (iat->has_hash_algo_id && iat->hash_algo_id[0] != '\0') {
        QCBOREncode_AddTextToMapN(&ec, IAT_PLATFORM_HASH_ALGO_ID,
            (UsefulBufC){ iat->hash_algo_id, strlen(iat->hash_algo_id) });
    }
#endif /* ATTEST_TOKEN_PROFILE_ARM_CCA */

    /* Verification service (optional, present in all profiles) */
    if (iat->has_verif_service && iat->verif_service[0] != '\0') {
        QCBOREncode_AddTextToMapN(&ec, IAT_VERIFICATION_SERVICE,
            (UsefulBufC){ iat->verif_service, strlen(iat->verif_service) });
    }

    /* SW components */
    if (iat->has_sw && iat->sw_count > 0) {
        QCBOREncode_OpenArrayInMapN(&ec, IAT_SW_COMPONENTS);
        for (size_t i = 0; i < iat->sw_count; i++) {
            const SwComponent *sw = &iat->sw[i];
            QCBOREncode_OpenMap(&ec);

            if (sw->has_type && sw->type[0] != '\0') {
                QCBOREncode_AddTextToMapN(&ec,
                    IAT_SW_COMPONENT_MEASUREMENT_TYPE,
                    (UsefulBufC){ sw->type, strlen(sw->type) });
            }
            if (sw->measurement_len > 0) {
                QCBOREncode_AddBytesToMapN(&ec,
                    IAT_SW_COMPONENT_MEASUREMENT_VALUE,
                    (UsefulBufC){ sw->measurement, sw->measurement_len });
            }
            if (sw->has_version && sw->version[0] != '\0') {
                QCBOREncode_AddTextToMapN(&ec,
                    IAT_SW_COMPONENT_VERSION,
                    (UsefulBufC){ sw->version, strlen(sw->version) });
            }
            if (sw->has_signer_id && sw->signer_id_len > 0) {
                QCBOREncode_AddBytesToMapN(&ec,
                    IAT_SW_COMPONENT_SIGNER_ID,
                    (UsefulBufC){ sw->signer_id, sw->signer_id_len });
            }
            if (sw->has_meas_desc && sw->meas_desc[0] != '\0') {
                QCBOREncode_AddTextToMapN(&ec,
                    IAT_SW_COMPONENT_MEASUREMENT_DESC,
                    (UsefulBufC){ sw->meas_desc, strlen(sw->meas_desc) });
            }

            QCBOREncode_CloseMap(&ec);
        }
        QCBOREncode_CloseArray(&ec);
    } else if (iat->has_no_sw_components) {
        QCBOREncode_AddUInt64ToMapN(&ec, IAT_NO_SW_COMPONENTS,
                                    (uint64_t)iat->no_sw_components_val);
    }

    /* ---------------------------------------------------------------- */
    /* PoX extension claims                                              */
    /* ---------------------------------------------------------------- */
    QCBOREncode_AddUInt64ToMapN(&ec, IAT_POX_FADDR,  (uint64_t)faddr);
    QCBOREncode_AddInt64ToMapN(&ec,  IAT_POX_OUT,    (int64_t)exec_output);

    QCBOREncode_CloseMap(&ec);

    UsefulBufC result;
    if (QCBOREncode_Finish(&ec, &result) != QCBOR_SUCCESS) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    *encoded_len = result.len;
    return PSA_SUCCESS;
}