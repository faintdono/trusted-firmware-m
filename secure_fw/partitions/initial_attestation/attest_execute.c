#include "attest_execute.h"
#include "tfm_sp_log.h"
#include <stdint.h>

int ns_execute(uintptr_t faddr, const uint8_t *input, uint32_t input_len)
{
    if (!faddr)
    {
        LOG_ERRFMT("[Secure] ERROR: Null function pointer.\n");
        return -1;
    }

    // Cast to non-secure function pointer with cmse_nonsecure_call attribute
    ns_function_ptr_with_args_t ns_function = (ns_function_ptr_with_args_t)(faddr | 1U); // Set bit 0 for Thumb mode

    // Call the non-secure function
    int ret = ns_function(input, input_len);

    return ret;
}

// void ns_execute(uintptr_t faddr, const uint8_t *input, uint32_t input_len, uint8_t *output, uint32_t *output_len) -> or return int


int ns_execute_void(uintptr_t faddr)
{
    if (!faddr)
    {
        LOG_ERRFMT("[Secure] ERROR: Null function pointer.\n");
        return -1;
    }

    // Cast to non-secure function pointer with cmse_nonsecure_call attribute
    ns_function_ptr_void_t ns_function = (ns_function_ptr_void_t)(faddr | 1U); // Set bit 0 for Thumb mode

    // Call the non-secure function
    int ret = ns_function();

    return ret;
}