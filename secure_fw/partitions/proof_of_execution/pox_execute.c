#include "pox_execute.h"
#include "pox_log.h"
#include <arm_cmse.h> /* cmse_check_address_range() */
#include <stddef.h>   /* NULL */
#include <stdint.h>
#include <string.h>   /* memset */

bool pox_ns_buffer_ok(const void *p, uint32_t len)
{
    if (p == NULL || len == 0u) {
        return false;
    }

    /* Security attribution only; no CMSE_MPU_* flag, the NS MPU config
     * is the NS world's business. */
    return cmse_check_address_range((void *)p, (size_t)len,
                                    CMSE_NONSECURE) != NULL;
}

int ns_execute(uintptr_t faddr, const uint8_t *input, uint32_t input_len,
               uint8_t *output, uint32_t *output_len,
               struct ns_exec_snapshot *snap)
{
    if (snap != NULL) {
        memset(snap->out, 0, sizeof(snap->out));
        snap->out_len = 0u;
        snap->valid = false;
    }

    if (!faddr) {
        POX_LOG_ERR("[Secure] ERROR: Null function pointer.\n");
        return -1;
    }

    /* Validate the output buffer before running anything. */
    uint32_t produced = (output_len != NULL) ? *output_len : 0u;
    uint32_t take = (produced < POX_EXEC_OUTPUT_MAX)
                    ? produced : POX_EXEC_OUTPUT_MAX;

    if (output != NULL && take > 0u && !pox_ns_buffer_ok(output, take)) {
        POX_LOG_ERR("[Secure] ERROR: Output buffer is not Non-Secure.\n");
        return POX_EXEC_ERR_BAD_OUTPUT;
    }

    ns_function_ptr_with_args_t ns_function = (ns_function_ptr_with_args_t)(faddr | 1U);
    int ret = ns_function(input, input_len, output, output_len);

    /* Capture here and nowhere else: any later read of the NS buffer
     * gets memory the attested function no longer controls. */
    if (snap != NULL && output != NULL && take > 0u) {
        for (uint32_t i = 0; i < take; i++) {
            snap->out[i] = output[i];
        }
        snap->out_len = take;
        snap->valid = true;
    }

    return ret;
}

int ns_execute_void(uintptr_t faddr)
{
    if (!faddr) {
        POX_LOG_ERR("[Secure] ERROR: Null function pointer.\n");
        return -1;
    }

    ns_function_ptr_void_t ns_function = (ns_function_ptr_void_t)(faddr | 1U);
    int ret = ns_function();

    return ret;
}

/* Bytes go through a Secure bounce buffer: each is read once, here,
 * and the Crypto partition never sees an NS address from this one. */
#define POX_MEASURE_CHUNK 128u

static psa_status_t hash_ns_range(const uint8_t *p, uint32_t len,
                                  uint8_t digest[POX_MEASURE_HASH_LEN])
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    uint8_t chunk[POX_MEASURE_CHUNK];
    size_t digest_len = 0;
    psa_status_t status = psa_hash_setup(&op, PSA_ALG_SHA_256);

    for (uint32_t off = 0; status == PSA_SUCCESS && off < len; ) {
        uint32_t n = len - off;
        if (n > POX_MEASURE_CHUNK) {
            n = POX_MEASURE_CHUNK;
        }
        memcpy(chunk, p + off, n);
        status = psa_hash_update(&op, chunk, n);
        off += n;
    }

    if (status == PSA_SUCCESS) {
        status = psa_hash_finish(&op, digest, POX_MEASURE_HASH_LEN,
                                 &digest_len);
    }
    if (status != PSA_SUCCESS) {
        (void)psa_hash_abort(&op);
    }
    return status;
}

psa_status_t pox_ns_measure(uintptr_t faddr, uint32_t func_len,
                         const uint8_t *input, uint32_t input_len,
                         struct ns_exec_measurement *meas)
{
    const uint8_t *code = (const uint8_t *)(faddr & ~(uintptr_t)1u);

    if (meas == NULL || code == NULL ||
        func_len == 0u || func_len > POX_FUNC_LEN_MAX ||
        !pox_ns_buffer_ok(code, func_len)) {
        POX_LOG_ERR("[Secure] ERROR: Function range is not Non-Secure.\n");
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (input_len > POX_INPUT_HASH_MAX ||
        (input_len > 0u && !pox_ns_buffer_ok(input, input_len))) {
        POX_LOG_ERR("[Secure] ERROR: Input buffer is not Non-Secure.\n");
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = hash_ns_range(code, func_len, meas->func_hash);
    if (status != PSA_SUCCESS) {
        return status;
    }

    meas->has_input_value = (input_len <= POX_INPUT_CLAIM_MAX);
    meas->input_value_len = meas->has_input_value ? input_len : 0u;
    if (meas->has_input_value) {
        if (input_len > 0u) {
            memcpy(meas->input_value, input, input_len);
        }
        return hash_ns_range(meas->input_value, input_len, meas->input_hash);
    }
    return hash_ns_range(input, input_len, meas->input_hash);
}
