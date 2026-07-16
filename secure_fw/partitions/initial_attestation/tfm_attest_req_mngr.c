/*
 * Copyright (c) 2019-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>

#include "psa/error.h"
#include "psa/client.h"
#include "psa/initial_attestation.h"
#include "psa/crypto.h"
#include "attest.h"

#include "array.h"
#include "psa/framework_feature.h"
#include "psa/service.h"
#include "psa_manifest/tfm_initial_attestation.h"
#include "tfm_attest_defs.h"
#ifdef ATTEST_POX
#include "tfm_pox_wire.h"
#include "attest_session.h"
#endif

#define ECC_P256_PUBLIC_KEY_SIZE PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(256)

typedef psa_status_t (*attest_func_t)(const psa_msg_t *msg);

int32_t g_attest_caller_id;

#if PSA_FRAMEWORK_HAS_MM_IOVEC == 1
static psa_status_t psa_attest_get_token(const psa_msg_t *msg)
{
    psa_status_t status;
    const void *challenge_buff;
    void *token_buff;
    size_t challenge_size;
    size_t token_buff_size;
    size_t token_size;

    token_buff_size = msg->out_size[0];
    challenge_size = msg->in_size[0];

    if ((challenge_size > PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64)
        || (challenge_size == 0) || (token_buff_size == 0)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* store the client ID here for later use in service */
    g_attest_caller_id = msg->client_id;

    challenge_buff = psa_map_invec(msg->handle, 0);
    token_buff = psa_map_outvec(msg->handle, 0);

    status = initial_attest_get_token(challenge_buff, challenge_size,
                                      token_buff, token_buff_size, &token_size);
    if (status == PSA_SUCCESS) {
        psa_unmap_outvec(msg->handle, 0, token_size);
        psa_unmap_invec(msg->handle, 0);
    }

    return status;
}
#else /* PSA_FRAMEWORK_HAS_MM_IOVEC == 1 */
/* Buffer to store the created attestation token. */
static uint8_t token_buff[PSA_INITIAL_ATTEST_MAX_TOKEN_SIZE];

static psa_status_t psa_attest_get_token(const psa_msg_t *msg)
{
    psa_status_t status = PSA_SUCCESS;
    uint8_t challenge_buff[PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64];
    uint32_t bytes_read = 0;
    size_t challenge_size;
    size_t token_buff_size;
    size_t token_size;

    challenge_size = msg->in_size[0];
    token_buff_size = (msg->out_size[0] < sizeof(token_buff)) ?
                                          msg->out_size[0] : sizeof(token_buff);

    if ((challenge_size > PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64)
        || (challenge_size == 0) || (token_buff_size == 0)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* store the client ID here for later use in service */
    g_attest_caller_id = msg->client_id;

    bytes_read = psa_read(msg->handle, 0, challenge_buff, challenge_size);
    if (bytes_read != challenge_size) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    status = initial_attest_get_token(challenge_buff, challenge_size,
                                      token_buff, token_buff_size, &token_size);
    if (status == PSA_SUCCESS) {
        psa_write(msg->handle, 0, token_buff, token_size);
    }

    return status;
}
#endif /* PSA_FRAMEWORK_HAS_MM_IOVEC == 1 */

static psa_status_t psa_attest_get_token_size(const psa_msg_t *msg)
{
    psa_status_t status = PSA_SUCCESS;
    size_t challenge_size;
    size_t token_size;
    size_t bytes_read = 0;

    if ((msg->in_size[0] != sizeof(challenge_size))
        || (msg->out_size[0] != sizeof(token_size))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* store the client ID here for later use in service */
    g_attest_caller_id = msg->client_id;

    bytes_read = psa_read(msg->handle, 0,
                          &challenge_size, msg->in_size[0]);
    if (bytes_read != sizeof(challenge_size)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = initial_attest_get_token_size(challenge_size, &token_size);
    if (status == PSA_SUCCESS) {
        psa_write(msg->handle, 0, &token_size, sizeof(token_size));
    }

    return status;
}

#ifdef ATTEST_POX
static psa_status_t psa_attest_proof_of_execution(const psa_msg_t *msg)
{
    psa_status_t status = PSA_SUCCESS;
    uint32_t bytes_read = 0;
    size_t token_buff_size;
    size_t token_size;
    size_t inbuf_size;
    uint8_t inbuf[256];

    inbuf_size = msg->in_size[0];
    token_buff_size = (msg->out_size[0] < sizeof(token_buff))
                           ? msg->out_size[0]
                           : sizeof(token_buff);

    /* store the client ID here for later use in service */
    g_attest_caller_id = msg->client_id;

    /* NS-controlled length: never read more than the local buffer. */
    if (inbuf_size > sizeof(inbuf)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    bytes_read = psa_read(msg->handle, 0, inbuf, inbuf_size);
    if (bytes_read != inbuf_size) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    sec_pox_view_t view = {0};
    ser_status_t st = deserialize_ns_pox_call(inbuf, inbuf_size, &view);
    if (st != SER_OK) {
        return (st == SER_E2BIG) ? PSA_ERROR_INSUFFICIENT_MEMORY :
               (st == SER_ECRC)  ? PSA_ERROR_CORRUPTION_DETECTED :
                                   PSA_ERROR_INVALID_ARGUMENT;
    }

    if ((view.input_len > 0 && view.input == NULL) ||
        (view.output_len > 0 && view.output == NULL) ||
        (view.challenge_len > 0 && view.challenge == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (!view.challenge ||
        view.challenge_len == 0 ||
        view.challenge_len > PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 ||
        token_buff_size == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* ---------------- Phase 1: session authentication ----------------
     * Same policy as the standalone PoX partition, own instance and
     * own build flag (POX_SESSION_AUTH_ATT):
     * rule 1 invalid signature -> reject, end session;
     * rule 2 reused nonce      -> reject. */
#if POX_SESSION_AUTH_ATT
    if (view.session_id == NULL || view.sess_sig == NULL) {
        POX_LOG_INF("[Attest][PoX] Missing session credentials: rejecting\n");
        return PSA_ERROR_NOT_PERMITTED;
    }

    status = attest_session_authenticate(&view);
    if (status != PSA_SUCCESS) {
        POX_LOG_INF("[Attest][PoX] Session authentication failed (0x%x)\n",
                   (unsigned int)status);
        return status;
    }
#endif

    attest_session_ctx_t sess = {
        .session_id     = view.session_id,
        .session_id_len = view.session_id_len,
        .caller_id      = msg->client_id,
        .sess_sig       = view.sess_sig,
        .sess_sig_len   = view.sess_sig_len,
#if POX_SESSION_AUTH_ATT
        .boot_epoch     = attest_session_get_epoch(),
#endif
#if POX_SEQ_AUTH
        .seq            = view.seq,
#endif
    };

    status = attest_proof_of_execution(view.function_addr_le32,
                               view.input,
                               view.input_len,
                               view.output,
                               view.output_len,
                               view.challenge,
                               view.challenge_len,
                               &sess,
                               token_buff,
                               token_buff_size,
                               &token_size);

    if (status == PSA_SUCCESS) {
        psa_write(msg->handle, 0, token_buff, token_size);
    }
    
    return status;
}
#endif /* ATTEST_POX */

psa_status_t tfm_attestation_service_sfn(const psa_msg_t *msg)
{
    switch (msg->type) {
    case TFM_ATTEST_GET_TOKEN:
        return psa_attest_get_token(msg);
    case TFM_ATTEST_GET_TOKEN_SIZE:
        return psa_attest_get_token_size(msg);
#ifdef ATTEST_POX
    case TFM_ATTEST_GET_POX:
        return psa_attest_proof_of_execution(msg);
#endif
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t attest_partition_init(void)
{
    psa_status_t status = attest_init();

#ifdef ATTEST_POX
    /* Session auth for the PoX path. On failure the partition keeps
     * running but the PoX path fails closed: every TFM_ATTEST_GET_POX
     * request is rejected. IAT services are unaffected. */
    if (attest_session_init() != PSA_SUCCESS) {
        POX_LOG_INF("[Attest][PoX] WARNING: session auth init failed; "
                   "PoX requests will be rejected\n");
    }
#endif /* ATTEST_POX */

    return status;
}
