#include "psa/error.h"
#include "psa/client.h"

#include "psa/service.h"
#include "psa_manifest/tfm_proof_of_execution.h"
#include "pox.h"

#include "tfm_pox_wire.h"
#include "tfm_sp_log.h" // TF-M Secure Partition Logging

// Securely stored values
static uint8_t stored_challenge[CHALLENGE_SIZE];
static uintptr_t stored_faddr;
static int execution_output;



static psa_status_t psa_proof_of_execution(const psa_msg_t *msg)
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

// PoX IPC Handler function
psa_status_t pox_ipc_handler(psa_signal_t signal)
{
    psa_status_t status;
	psa_msg_t msg;

    status = psa_get(signal, &msg);

    size_t sys_token_sz;                 
    uint8_t token_buf[TOKEN_BUF_SIZE];   
    uint8_t report_buf[REPORT_BUF_SIZE]; 
    size_t report_size = REPORT_BUF_SIZE;

    switch (msg->type)
    {
    case PSA_IPC_CONNECT:
        psa_reply(msg->handle, PSA_SUCCESS);
        break;

    case PSA_IPC_CALL:
        status = psa_proof_of_execution(&msg);
        psa_reply(msg->handle, status);
        break;

    case PSA_IPC_DISCONNECT:
        psa_reply(msg->handle, PSA_SUCCESS);
        break;

    default:
        LOG_ERRFMT("[Secure] ERROR: Invalid message type received: %d\n", msg->type);
        psa_reply(msg->handle, PSA_ERROR_PROGRAMMER_ERROR);
    }

    return PSA_SUCCESS;
}

psa_status_t pox_init(void)
{
	psa_signal_t signals = 0;

	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
		if (signals & TFM_POX_SERVICE_SIGNAL) {
			pox_ipc_handler(TFM_POX_SERVICE_SIGNAL);
		} else {
			psa_panic();
		}
	}

	return PSA_ERROR_SERVICE_FAILURE;
}