#include "pox_execute.h"
#include "pox_log.h"
#include <stdint.h>

int ns_execute(uintptr_t faddr, const uint8_t *input, uint32_t input_len,
               uint8_t *output, uint32_t *output_len)
{
    if (!faddr) {
        POX_LOG_ERR("[Secure] ERROR: Null function pointer.\n");
        return -1;
    }

    ns_function_ptr_with_args_t ns_function = (ns_function_ptr_with_args_t)(faddr | 1U);
    int ret = ns_function(input, input_len, output, output_len);

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
