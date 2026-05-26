/*
 * pox_iat_decoder.c
 *
 * Decodes the CBOR payload of an IAT COSE_Sign1 token into an IATClaims
 * struct for use by the PoX encoder.
 *
 * Signature verification is intentionally skipped — the attestation
 * service already produced and verified the token.  We extract the
 * payload bstr from the COSE_Sign1 array directly with QCBOR and
 * decode the EAT claims map inside it.
 *
 * Uses QCBOR v1.2 API: QCBORDecode_GetAndResetError() to clear
 * accumulated errors after each optional field lookup.
 * (QCBORDecode_ClearError does not exist in v1.2.)
 */

#include "pox_iat_decoder.h"
#include "tfm_attest_iat_defs.h"
#include "tfm_sp_log.h"

#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

#include <string.h>

/* Shorthand: consume and discard any accumulated QCBOR error,
 * resetting the context so the next lookup can proceed.          */
#define QCBOR_IGNORE_ERR(dc)  (void)QCBORDecode_GetAndResetError(dc)

/* ------------------------------------------------------------------ */
/* Internal: parse one SW component map                                */
/* ------------------------------------------------------------------ */
static void parse_sw_component(QCBORDecodeContext *dc, SwComponent *sw)
{
    memset(sw, 0, sizeof(*sw));

    QCBORDecode_EnterMap(dc, NULL);

    /* Measurement type (text) */
    {
        UsefulBufC val;
        QCBORDecode_GetTextStringInMapN(dc,
                                        IAT_SW_COMPONENT_MEASUREMENT_TYPE,
                                        &val);
        if (QCBORDecode_GetError(dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(sw->type) - 1
                       ? val.len : sizeof(sw->type) - 1;
            memcpy(sw->type, val.ptr, l);
            sw->type[l] = '\0';
            sw->has_type = true;
        }
        QCBOR_IGNORE_ERR(dc);
    }

    /* Measurement value (bstr) */
    {
        UsefulBufC val;
        QCBORDecode_GetByteStringInMapN(dc,
                                        IAT_SW_COMPONENT_MEASUREMENT_VALUE,
                                        &val);
        if (QCBORDecode_GetError(dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(sw->measurement)
                       ? val.len : sizeof(sw->measurement);
            memcpy(sw->measurement, val.ptr, l);
            sw->measurement_len = (uint32_t)l;
        }
        QCBOR_IGNORE_ERR(dc);
    }

    /* Version (text) */
    {
        UsefulBufC val;
        QCBORDecode_GetTextStringInMapN(dc, IAT_SW_COMPONENT_VERSION, &val);
        if (QCBORDecode_GetError(dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(sw->version) - 1
                       ? val.len : sizeof(sw->version) - 1;
            memcpy(sw->version, val.ptr, l);
            sw->version[l] = '\0';
            sw->has_version = true;
        }
        QCBOR_IGNORE_ERR(dc);
    }

    /* Signer ID (bstr) */
    {
        UsefulBufC val;
        QCBORDecode_GetByteStringInMapN(dc, IAT_SW_COMPONENT_SIGNER_ID, &val);
        if (QCBORDecode_GetError(dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(sw->signer_id)
                       ? val.len : sizeof(sw->signer_id);
            memcpy(sw->signer_id, val.ptr, l);
            sw->signer_id_len = (uint32_t)l;
            sw->has_signer_id = true;
        }
        QCBOR_IGNORE_ERR(dc);
    }

    /* Measurement description (text, optional) */
    {
        UsefulBufC val;
        QCBORDecode_GetTextStringInMapN(dc,
                                        IAT_SW_COMPONENT_MEASUREMENT_DESC,
                                        &val);
        if (QCBORDecode_GetError(dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(sw->meas_desc) - 1
                       ? val.len : sizeof(sw->meas_desc) - 1;
            memcpy(sw->meas_desc, val.ptr, l);
            sw->meas_desc[l] = '\0';
            sw->has_meas_desc = true;
        }
        QCBOR_IGNORE_ERR(dc);
    }

    QCBORDecode_ExitMap(dc);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

psa_status_t decode_iat_to_claims(const uint8_t *iat_token_buf,
                                   size_t         iat_token_sz,
                                   IATClaims     *claims)
{
    if (!iat_token_buf || !claims || iat_token_sz == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    memset(claims, 0, sizeof(*claims));

    /*
     * COSE_Sign1 structure:
     *   array[ protected-bstr, unprotected-map, payload-bstr, sig-bstr ]
     *
     * We skip straight to the payload bstr at index [2].
     */
    QCBORDecodeContext outer;
    QCBORDecode_Init(&outer,
                     (UsefulBufC){ iat_token_buf, iat_token_sz },
                     QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&outer, NULL);
    if (QCBORDecode_GetError(&outer) != QCBOR_SUCCESS) {
        LOG_INFFMT("[PoX] decode_iat: not a CBOR array\n");
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Consume [0] protected header and [1] unprotected map */
    QCBORItem item;
    QCBORDecode_VGetNext(&outer, &item);
    QCBORDecode_VGetNext(&outer, &item);

    /* [2] payload bstr */
    UsefulBufC payload;
    QCBORDecode_GetByteString(&outer, &payload);
    if (QCBORDecode_GetError(&outer) != QCBOR_SUCCESS ||
        payload.ptr == NULL || payload.len == 0) {
        LOG_INFFMT("[PoX] decode_iat: payload bstr missing\n");
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    QCBORDecode_ExitArray(&outer);
    QCBORDecode_Finish(&outer);

    /* ---- Decode the EAT claims map inside the payload ---- */
    QCBORDecodeContext dc;
    QCBORDecode_Init(&dc, payload, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&dc, NULL);

    /* Nonce */
    {
        UsefulBufC val;
        QCBORDecode_GetByteStringInMapN(&dc, IAT_NONCE, &val);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(claims->nonce)
                       ? val.len : sizeof(claims->nonce);
            memcpy(claims->nonce, val.ptr, l);
            claims->nonce_len = (uint32_t)l;
        }
        QCBOR_IGNORE_ERR(&dc);
    }

    /* Instance ID */
    {
        UsefulBufC val;
        QCBORDecode_GetByteStringInMapN(&dc, IAT_INSTANCE_ID, &val);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(claims->instance_id)
                       ? val.len : sizeof(claims->instance_id);
            memcpy(claims->instance_id, val.ptr, l);
            claims->instance_id_len = (uint32_t)l;
        }
        QCBOR_IGNORE_ERR(&dc);
    }

    /* Implementation ID */
    {
        UsefulBufC val;
        QCBORDecode_GetByteStringInMapN(&dc, IAT_IMPLEMENTATION_ID, &val);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(claims->implementation_id)
                       ? val.len : sizeof(claims->implementation_id);
            memcpy(claims->implementation_id, val.ptr, l);
            claims->implementation_id_len = (uint32_t)l;
        }
        QCBOR_IGNORE_ERR(&dc);
    }

    /* Security lifecycle */
    {
        int64_t val = 0;
        QCBORDecode_GetInt64InMapN(&dc, IAT_SECURITY_LIFECYCLE, &val);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS) {
            claims->security_lifecycle = (uint32_t)val;
        }
        QCBOR_IGNORE_ERR(&dc);
    }

    /* Profile definition (text) */
    {
        UsefulBufC val;
        QCBORDecode_GetTextStringInMapN(&dc, IAT_PROFILE_DEFINITION, &val);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(claims->profile) - 1
                       ? val.len : sizeof(claims->profile) - 1;
            memcpy(claims->profile, val.ptr, l);
            claims->profile[l] = '\0';
            claims->has_profile = true;
        }
        QCBOR_IGNORE_ERR(&dc);
    }

#if ATTEST_TOKEN_PROFILE_PSA_IOT_1 || ATTEST_TOKEN_PROFILE_PSA_2_0_0
    /* Boot seed */
    {
        UsefulBufC val;
        QCBORDecode_GetByteStringInMapN(&dc, IAT_BOOT_SEED, &val);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(claims->boot_seed)
                       ? val.len : sizeof(claims->boot_seed);
            memcpy(claims->boot_seed, val.ptr, l);
            claims->boot_seed_len = (uint32_t)l;
            claims->has_boot_seed = true;
        }
        QCBOR_IGNORE_ERR(&dc);
    }

    /* Client ID */
    {
        int64_t val = 0;
        QCBORDecode_GetInt64InMapN(&dc, IAT_CLIENT_ID, &val);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS) {
            claims->client_id = (int32_t)val;
            claims->has_client_id = true;
        }
        QCBOR_IGNORE_ERR(&dc);
    }

    /* Certification reference (optional, text) */
    {
        UsefulBufC val;
        QCBORDecode_GetTextStringInMapN(&dc, IAT_CERTIFICATION_REFERENCE,
                                        &val);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(claims->cert_ref) - 1
                       ? val.len : sizeof(claims->cert_ref) - 1;
            memcpy(claims->cert_ref, val.ptr, l);
            claims->cert_ref[l] = '\0';
            claims->has_cert_ref = true;
        }
        QCBOR_IGNORE_ERR(&dc);
    }
#endif /* ATTEST_TOKEN_PROFILE_PSA_IOT_1 || ATTEST_TOKEN_PROFILE_PSA_2_0_0 */

#if ATTEST_TOKEN_PROFILE_ARM_CCA
    /* Platform config (bstr, CCA only) */
    {
        UsefulBufC val;
        QCBORDecode_GetByteStringInMapN(&dc, IAT_PLATFORM_CONFIG, &val);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(claims->platform_config)
                       ? val.len : sizeof(claims->platform_config);
            memcpy(claims->platform_config, val.ptr, l);
            claims->platform_config_len = (uint32_t)l;
            claims->has_platform_config = true;
        }
        QCBOR_IGNORE_ERR(&dc);
    }

    /* Platform hash algo ID (text, CCA only) */
    {
        UsefulBufC val;
        QCBORDecode_GetTextStringInMapN(&dc, IAT_PLATFORM_HASH_ALGO_ID, &val);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(claims->hash_algo_id) - 1
                       ? val.len : sizeof(claims->hash_algo_id) - 1;
            memcpy(claims->hash_algo_id, val.ptr, l);
            claims->hash_algo_id[l] = '\0';
            claims->has_hash_algo_id = true;
        }
        QCBOR_IGNORE_ERR(&dc);
    }
#endif /* ATTEST_TOKEN_PROFILE_ARM_CCA */

    /* Verification service (optional, all profiles) */
    {
        UsefulBufC val;
        QCBORDecode_GetTextStringInMapN(&dc, IAT_VERIFICATION_SERVICE, &val);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS && val.len > 0) {
            size_t l = val.len < sizeof(claims->verif_service) - 1
                       ? val.len : sizeof(claims->verif_service) - 1;
            memcpy(claims->verif_service, val.ptr, l);
            claims->verif_service[l] = '\0';
            claims->has_verif_service = true;
        }
        QCBOR_IGNORE_ERR(&dc);
    }

    /* SW components array */
    {
        QCBORDecode_EnterArrayFromMapN(&dc, IAT_SW_COMPONENTS);
        if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS) {
            claims->has_sw = true;
            claims->sw_count = 0;

            while (claims->sw_count < MAX_SW_COMPONENTS) {
                QCBORItem peek;
                QCBORError perr = QCBORDecode_PeekNext(&dc, &peek);
                if (perr == QCBOR_ERR_NO_MORE_ITEMS) {
                    break;
                }
                if (perr != QCBOR_SUCCESS) {
                    break;
                }
                parse_sw_component(&dc, &claims->sw[claims->sw_count]);
                if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS) {
                    QCBOR_IGNORE_ERR(&dc);
                    break;
                }
                claims->sw_count++;
            }
            QCBORDecode_ExitArray(&dc);
        } else {
            /* No SW-components array — check for the no-sw integer claim */
            QCBOR_IGNORE_ERR(&dc);
            int64_t val = 0;
            QCBORDecode_GetInt64InMapN(&dc, IAT_NO_SW_COMPONENTS, &val);
            if (QCBORDecode_GetError(&dc) == QCBOR_SUCCESS) {
                claims->has_no_sw_components = true;
                claims->no_sw_components_val = (int32_t)val;
            }
            QCBOR_IGNORE_ERR(&dc);
        }
    }

    QCBORDecode_ExitMap(&dc);

    QCBORError qerr = QCBORDecode_Finish(&dc);
    if (qerr != QCBOR_SUCCESS && qerr != QCBOR_ERR_EXTRA_BYTES) {
        LOG_INFFMT("[PoX] decode_iat: finish error %d\n", (int)qerr);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    LOG_INFFMT("[PoX] decode_iat: OK  nonce_len=%u  sw_count=%u\n",
               (unsigned int)claims->nonce_len,
               (unsigned int)claims->sw_count);

    return PSA_SUCCESS;
}