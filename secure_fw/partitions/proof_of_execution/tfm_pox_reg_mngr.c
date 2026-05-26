/*
 * tfm_pox_reg_mngr.c
 *
 * IPC request manager for the Proof-of-Execution (PoX) secure partition.
 * Deserializes the wire-format request from the NS caller, validates it,
 * then invokes proof_of_execution() and writes the resulting token back.
 */

#include "psa/error.h"
#include "psa/client.h"
#include "psa/initial_attestation.h"   /* PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 */

#include "psa/service.h"
#include "psa_manifest/tfm_proof_of_execution.h"
#include "pox.h"
#include "tfm_pox_wire.h"
#include "tfm_sp_log.h"

/* Shared output buffer for the signed PoX token */
static uint8_t token_buff[ATT_MAX_TOKEN_SIZE];

/* ------------------------------------------------------------------ */
/* PSA IPC call handler                                                 */
/* ------------------------------------------------------------------ */

static psa_status_t psa_proof_of_execution(const psa_msg_t *msg)
{
    psa_status_t status;
    uint32_t     bytes_read;
    size_t       token_buff_size;
    size_t       token_size;
    size_t       inbuf_size;
    uint8_t      inbuf[256];

    inbuf_size      = msg->in_size[0];
    token_buff_size = (msg->out_size[0] < sizeof(token_buff))
                      ? msg->out_size[0]
                      : sizeof(token_buff);

    /* Read the serialised request from the NS caller */
    bytes_read = psa_read(msg->handle, 0, inbuf, inbuf_size);
    if (bytes_read != inbuf_size) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* Deserialise the TLV wire format into a sec_pox_view_t */
    sec_pox_view_t view = {0};
    ser_status_t st = deserialize_ns_pox_call(inbuf, inbuf_size, &view);
    if (st != SER_OK) {
        return (st == SER_E2BIG) ? PSA_ERROR_INSUFFICIENT_MEMORY  :
               (st == SER_ECRC)  ? PSA_ERROR_CORRUPTION_DETECTED  :
                                   PSA_ERROR_INVALID_ARGUMENT;
    }

    LOG_INFFMT("[PoX] deserialize OK: func=0x%x in_len=%u out_len=%u "
               "challenge_len=%u\n",
               (unsigned int)view.function_addr_le32,
               (unsigned int)view.input_len,
               (unsigned int)view.output_len,
               (unsigned int)view.challenge_len);

    /* Sanity-check that non-zero lengths have corresponding addresses */
    if ((view.input_len  > 0 && view.input     == 0) ||
        (view.output_len > 0 && view.output    == 0) ||
        (view.challenge_len > 0 && view.challenge == NULL)) {
        LOG_INFFMT("[PoX] ERROR: inconsistent pointers/lengths\n");
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (view.challenge == NULL ||
        view.challenge_len == 0 ||
        view.challenge_len > PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 ||
        token_buff_size == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /*
     * view.input / view.output hold raw NS addresses (uintptr_t).
     * Cast them to pointers for the proof_of_execution call.
     *
     * view.output_len comes from the wire as a value; proof_of_execution
     * takes uint32_t * so we use a local copy.
     */
    uint32_t output_len = view.output_len;

    status = proof_of_execution(
                 view.function_addr_le32,
                 (const uint8_t *)(uintptr_t)view.input,
                 view.input_len,
                 (uint8_t *)(uintptr_t)view.output,
                 &output_len,
                 (uint8_t *)(uintptr_t)view.challenge,
                 view.challenge_len,
                 token_buff,
                 token_buff_size,
                 &token_size);

    if (status == PSA_SUCCESS) {
        LOG_INFFMT("[PoX] Success. Writing %u bytes to NS caller.\n",
                   (unsigned int)token_size);
        psa_write(msg->handle, 0, token_buff, token_size);
    } else {
        LOG_INFFMT("[PoX] ERROR: proof_of_execution failed (0x%x)\n",
                   (unsigned int)status);
    }

    return status;
}

/* ------------------------------------------------------------------ */
/* IPC signal handler and partition entry point                         */
/* ------------------------------------------------------------------ */

static psa_status_t pox_ipc_handler(psa_signal_t signal)
{
    psa_status_t status;
    psa_msg_t    msg;

    status = psa_get(signal, &msg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    switch (msg.type) {
    case PSA_IPC_CONNECT:
        psa_reply(msg.handle, PSA_SUCCESS);
        break;

    case PSA_IPC_CALL:
        status = psa_proof_of_execution(&msg);
        psa_reply(msg.handle, status);
        break;

    case PSA_IPC_DISCONNECT:
        psa_reply(msg.handle, PSA_SUCCESS);
        break;

    default:
        LOG_ERRFMT("[PoX] ERROR: unexpected message type %d\n", msg.type);
        psa_reply(msg.handle, PSA_ERROR_PROGRAMMER_ERROR);
        break;
    }

    return PSA_SUCCESS;
}

psa_status_t pox_init(void)
{
    psa_signal_t signals;

    while (1) {
        signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
        if (signals & TFM_POX_SERVICE_SIGNAL) {
            pox_ipc_handler(TFM_POX_SERVICE_SIGNAL);
        } else {
            psa_panic();
        }
    }

    return PSA_ERROR_SERVICE_FAILURE; /* unreachable */
}