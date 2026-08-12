/*
 * pox_encoder.c
 *
 * Encodes the PoX CBOR claims map from decoded IAT claims plus the
 * extension claims (faddr, exec_output). CCA-only claims are guarded
 * by #if ATTEST_TOKEN_PROFILE_ARM_CCA so the file also compiles under
 * the PSA_IOT_1 and PSA_2_0_0 profiles.
 */

#include "pox_encoder.h"
#include "tfm_attest_iat_defs.h"

#include "qcbor/qcbor_encode.h"

#include <string.h>

psa_status_t encode_pox_claims(const IATClaims *iat,
                               uintptr_t        faddr,
                               const uint8_t   *exec_output,
                               size_t           exec_output_len,
                               const pox_session_ctx_t *sess,
                               uint8_t         *scratch,
                               size_t           scratch_sz,
                               size_t          *encoded_len)
{
    if (!iat || !scratch || !encoded_len) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Bound the claim here rather than trusting the caller's size_t:
     * a longer value silently changes what verifiers must parse. */
    if (!exec_output || exec_output_len == 0u ||
        exec_output_len > POX_EXEC_OUTPUT_MAX) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    QCBOREncodeContext ec;
    QCBOREncode_Init(&ec, (UsefulBuf){ scratch, scratch_sz });
    QCBOREncode_OpenMap(&ec);

    /*
     * Claim ordering matches attest_pox_create_token() in attest_core.c:
     *   faddr, exec_output, nonce,
     *   then claim_query_funcs order:
     *     boot_seed (PSA_IOT/2_0_0), instance_id, implementation_id,
     *     caller_id (PSA_IOT/2_0_0), security_lifecycle, sw_components,
     *     profile_definition, verification_service, cert_ref
     *   CCA: instance_id, implementation_id, security_lifecycle,
     *        sw_components, profile_definition, hash_algo_id,
     *        platform_config, verification_service
     */

    /* PoX extension claims — first, matching attest_pox_create_token() */
    QCBOREncode_AddUInt64ToMapN(&ec, IAT_POX_FADDR, (uint64_t)faddr);

    /* Byte string, matching attest_add_execution_value() on the
     * attestation-partition path. Signing the full value rather than
     * its first byte is what makes the claim an integrity check. */
    QCBOREncode_AddBytesToMapN(&ec, IAT_POX_OUT,
                               (UsefulBufC){ exec_output, exec_output_len });

    if (iat->nonce_len > 0) {
        QCBOREncode_AddBytesToMapN(&ec, IAT_NONCE,
            (UsefulBufC){ iat->nonce, iat->nonce_len });
    }

    if (sess != NULL) {
        if (sess->session_id != NULL && sess->session_id_len > 0) {
            QCBOREncode_AddBytesToMapN(&ec, POX_LABEL_SESSION_ID,
                (UsefulBufC){ sess->session_id, sess->session_id_len });
        }
        /* SPM-supplied, cannot be forged by the NS caller */
        QCBOREncode_AddInt64ToMapN(&ec, POX_LABEL_CALLER_ID,
                                   (int64_t)sess->caller_id);
#if POX_SESSION_AUTH
        /* Verifier authorization signature: embedded whenever session
         * auth is on (i.e. after it verified), making the token
         * self-contained evidence for third-party auditors. */
        if (sess->sess_sig != NULL && sess->sess_sig_len > 0) {
            QCBOREncode_AddBytesToMapN(&ec, POX_LABEL_SESS_SIG,
                (UsefulBufC){ sess->sess_sig, sess->sess_sig_len });
        }
#endif
#if POX_SESSION_AUTH
        QCBOREncode_AddUInt64ToMapN(&ec, POX_LABEL_BOOT_EPOCH,
                                    (uint64_t)sess->boot_epoch);
#endif
#if POX_SEQ_AUTH
        QCBOREncode_AddUInt64ToMapN(&ec, POX_LABEL_SEQ,
                                    (uint64_t)sess->seq);
#endif
    }

    /* Standard EAT claims — same order as claim_query_funcs[] */

#if ATTEST_TOKEN_PROFILE_PSA_IOT_1 || ATTEST_TOKEN_PROFILE_PSA_2_0_0
    if (iat->has_boot_seed && iat->boot_seed_len > 0) {
        QCBOREncode_AddBytesToMapN(&ec, IAT_BOOT_SEED,
            (UsefulBufC){ iat->boot_seed, iat->boot_seed_len });
    }
#endif

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

#if ATTEST_TOKEN_PROFILE_PSA_IOT_1 || ATTEST_TOKEN_PROFILE_PSA_2_0_0
    /* Caller / Client ID */
    if (iat->has_client_id) {
        QCBOREncode_AddInt64ToMapN(&ec, IAT_CLIENT_ID,
                                   (int64_t)iat->client_id);
    }
#endif

    QCBOREncode_AddUInt64ToMapN(&ec, IAT_SECURITY_LIFECYCLE,
                                (uint64_t)iat->security_lifecycle);

    /* SW components */
    if (iat->has_sw && iat->sw_count > 0) {
        QCBOREncode_OpenArrayInMapN(&ec, IAT_SW_COMPONENTS);
        for (size_t i = 0; i < iat->sw_count; i++) {
            const SwComponent *sw = &iat->sw[i];
            QCBOREncode_OpenMap(&ec);

            /* Field order matches attestation partition boot-data encoding:
             * type(1), version(4), signer_id(5), meas_desc(6), measurement(2) */
            if (sw->has_type && sw->type[0] != '\0') {
                QCBOREncode_AddTextToMapN(&ec,
                    IAT_SW_COMPONENT_MEASUREMENT_TYPE,
                    (UsefulBufC){ sw->type, strlen(sw->type) });
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
            if (sw->measurement_len > 0) {
                QCBOREncode_AddBytesToMapN(&ec,
                    IAT_SW_COMPONENT_MEASUREMENT_VALUE,
                    (UsefulBufC){ sw->measurement, sw->measurement_len });
            }

            QCBOREncode_CloseMap(&ec);
        }
        QCBOREncode_CloseArray(&ec);
    } else if (iat->has_no_sw_components) {
        QCBOREncode_AddUInt64ToMapN(&ec, IAT_NO_SW_COMPONENTS,
                                    (uint64_t)iat->no_sw_components_val);
    }

    if (iat->has_profile && iat->profile[0] != '\0') {
        QCBOREncode_AddTextToMapN(&ec, IAT_PROFILE_DEFINITION,
            (UsefulBufC){ iat->profile, strlen(iat->profile) });
    }

    if (iat->has_verif_service && iat->verif_service[0] != '\0') {
        QCBOREncode_AddTextToMapN(&ec, IAT_VERIFICATION_SERVICE,
            (UsefulBufC){ iat->verif_service, strlen(iat->verif_service) });
    }

#if ATTEST_TOKEN_PROFILE_PSA_IOT_1 || ATTEST_TOKEN_PROFILE_PSA_2_0_0
    if (iat->has_cert_ref && iat->cert_ref[0] != '\0') {
        QCBOREncode_AddTextToMapN(&ec, IAT_CERTIFICATION_REFERENCE,
            (UsefulBufC){ iat->cert_ref, strlen(iat->cert_ref) });
    }
#endif

#if ATTEST_TOKEN_PROFILE_ARM_CCA
    if (iat->has_hash_algo_id && iat->hash_algo_id[0] != '\0') {
        QCBOREncode_AddTextToMapN(&ec, IAT_PLATFORM_HASH_ALGO_ID,
            (UsefulBufC){ iat->hash_algo_id, strlen(iat->hash_algo_id) });
    }

    if (iat->has_platform_config && iat->platform_config_len > 0) {
        QCBOREncode_AddBytesToMapN(&ec, IAT_PLATFORM_CONFIG,
            (UsefulBufC){ iat->platform_config, iat->platform_config_len });
    }
#endif

    QCBOREncode_CloseMap(&ec);

    UsefulBufC result;
    if (QCBOREncode_Finish(&ec, &result) != QCBOR_SUCCESS) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    *encoded_len = result.len;
    return PSA_SUCCESS;
}