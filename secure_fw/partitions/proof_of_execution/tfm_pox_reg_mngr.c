/*
 * tfm_pox_reg_mngr.c
 *
 * IPC request manager for the Proof-of-Execution (PoX) secure partition.
 * Deserializes the wire-format request from the NS caller, validates it,
 * authenticates the session (Phase 1: verifier signature + nonce-reuse
 * checks), then invokes proof_of_execution() and writes the resulting
 * token back.
 */

#include "psa/error.h"
#include "psa/client.h"
#include "psa/initial_attestation.h"   /* PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 */

#include "psa/service.h"
#include "psa_manifest/tfm_proof_of_execution.h"
#include "pox.h"
#include "pox_session.h"
#include "tfm_pox_wire.h"
#include "pox_log.h"

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

    /* NS-controlled length: never read more than the local buffer. */
    if (inbuf_size > sizeof(inbuf)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

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

    if ((view.input_len  > 0 && view.input     == 0) ||
        (view.output_len > 0 && view.output    == 0) ||
        (view.challenge_len > 0 && view.challenge == NULL)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (view.challenge == NULL ||
        view.challenge_len == 0 ||
        view.challenge_len > PSA_INITIAL_ATTEST_CHALLENGE_SIZE_64 ||
        token_buff_size == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* ---------------- Phase 1: session authentication ---------------- */
#if POX_SESSION_AUTH
    if (view.session_id == NULL || view.sess_sig == NULL) {
        POX_LOG_INF("[PoX] Missing session credentials: rejecting\n");
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* Rule 1: invalid signature -> reject, end session.
     * Rule 2: reused nonce      -> reject.
     * The nonce is recorded only after the signature verifies. */
    status = pox_session_authenticate(&view);
    if (status != PSA_SUCCESS) {
        POX_LOG_INF("[PoX] Session authentication failed (0x%x)\n",
                   (unsigned int)status);
        return status;
    }
#endif

    /* Session context for the token claims. caller_id comes from the
     * SPM and cannot be forged by the NS caller. */
    pox_session_ctx_t sess = {
        .session_id     = view.session_id,
        .session_id_len = view.session_id_len,
        .caller_id      = msg->client_id,
        .sess_sig       = view.sess_sig,
        .sess_sig_len   = view.sess_sig_len,
#if POX_SESSION_AUTH
        .boot_epoch     = pox_session_get_epoch(),
#endif
#if POX_SEQ_AUTH
        .seq            = view.seq,
#endif
    };

    uint32_t output_len = view.output_len;

    status = proof_of_execution(
                 view.function_addr_le32,
                 (const uint8_t *)(uintptr_t)view.input,
                 view.input_len,
                 (uint8_t *)(uintptr_t)view.output,
                 &output_len,
                 (uint8_t *)(uintptr_t)view.challenge,
                 view.challenge_len,
                 &sess,
                 token_buff,
                 token_buff_size,
                 &token_size);

    if (status == PSA_SUCCESS) {
        POX_LOG_INF("[PoX] Success. Writing %u bytes to NS caller.\n",
                   (unsigned int)token_size);
        psa_write(msg->handle, 0, token_buff, token_size);
    } else {
        POX_LOG_INF("[PoX] ERROR: proof_of_execution failed (0x%x)\n",
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
        POX_LOG_ERR("[PoX] ERROR: unexpected message type %d\n", msg.type);
        psa_reply(msg.handle, PSA_ERROR_PROGRAMMER_ERROR);
        break;
    }

    return PSA_SUCCESS;
}

psa_status_t pox_init(void)
{
    psa_signal_t signals;
    psa_status_t status;

    status = pox_register_signing_key();
    if (status != PSA_SUCCESS) {
        POX_LOG_ERR("[PoX] FATAL: cannot register signing key (%d)\n",
                   (int)status);
        psa_panic();
    }

    /* Session auth setup. On failure (e.g. placeholder verifier key in
     * a non-debug build) the partition keeps running but fails closed:
     * pox_session_authenticate() rejects every request. */
    status = pox_session_init();
    if (status != PSA_SUCCESS) {
        POX_LOG_ERR("[PoX] WARNING: session auth init failed (%d); "
                   "all requests will be rejected\n", (int)status);
    }

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
