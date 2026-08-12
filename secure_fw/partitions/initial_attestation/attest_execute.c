#include "attest_execute.h"
#include <arm_cmse.h> /* cmse_check_address_range() */
#include <string.h>   /* memset */
#include "attest_session.h"
#include <stddef.h>   /* NULL */
#include <stdint.h>

bool attest_ns_buffer_ok(const void *p, uint32_t len)
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

    if (output != NULL && take > 0u &&
        !attest_ns_buffer_ok(output, take)) {
        POX_LOG_ERR("[Secure] ERROR: Output buffer is not Non-Secure.\n");
        return ATTEST_EXEC_ERR_BAD_OUTPUT;
    }

    ns_function_ptr_with_args_t ns_function = (ns_function_ptr_with_args_t)(faddr | 1U);
    int ret = ns_function(input, input_len, output, output_len);

    /* Capture here and nowhere else: any later read of the NS buffer
     * gets memory the untrusted world may have rewritten. */
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
