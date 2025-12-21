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
#include "tfm_pox_wire.h"
#include "tfm_sp_log.h"

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

    /* Log deserialization result and perform a basic sanity check */
    LOG_INFFMT("deserialize_ns_pox_call succeeded: func=0x%x, in_len=%u, out_len=%u, challenge_len=%u\n",
               (unsigned int)view.function_addr_le32,
               (unsigned int)view.input_len,
               (unsigned int)view.output_len,
               (unsigned int)view.challenge_len);

    if ((view.input_len > 0 && view.input == NULL) ||
        (view.output_len > 0 && view.output == NULL) ||
        (view.challenge_len > 0 && view.challenge == NULL)) {
        LOG_INFFMT("ERROR: Deserialized view has inconsistent pointers/lengths\n");
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (!view.challenge ||
        view.challenge_len == 0 ||
        view.challenge_len > PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 ||
        token_buff_size == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = proof_of_execution(view.function_addr_le32, 
                               view.input, 
                               view.input_len, 
                               view.output,
                               view.output_len,
                               view.challenge, 
                               view.challenge_len, 
                               token_buff, 
                               token_buff_size, 
                               &token_size);

    if (status == PSA_SUCCESS) {
        LOG_INFFMT("Proof of execution successful. Writing %u bytes to output\n", (unsigned int)token_size);
        psa_write(msg->handle, 0, token_buff, token_size);
    } else {
        LOG_INFFMT("ERROR: Proof of execution failed with status 0x%x\n", (unsigned int)status);
    }
    
    return status;
}

psa_status_t tfm_attestation_service_sfn(const psa_msg_t *msg)
{
    switch (msg->type) {
    case TFM_ATTEST_GET_TOKEN:
        return psa_attest_get_token(msg);
    case TFM_ATTEST_GET_TOKEN_SIZE:
        return psa_attest_get_token_size(msg);
    case TFM_ATTEST_GET_POX:
        return psa_attest_proof_of_execution(msg);
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t attest_partition_init(void)
{
    return attest_init();
}
