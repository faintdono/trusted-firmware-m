#ifndef POX_EXECUTE_H
#define POX_EXECUTE_H
#include "tfm_sp_log.h"
#include <stdint.h>

typedef int (*ns_function_ptr_with_args_t)(const uint8_t *input, uint32_t input_len, uint8_t *output, uint32_t *output_len) __attribute__((cmse_nonsecure_call));
typedef int (*ns_function_ptr_void_t)(void) __attribute__((cmse_nonsecure_call));

/**
 * @brief Execute a non-secure function from the secure world via its address.
 *
 * @param faddr       Non-secure function address
 * @param input       Input buffer (may be NULL)
 * @param input_len   Length of input
 * @param output      Output buffer (may be NULL)
 * @param output_len  In: capacity; out: bytes written
 */
int ns_execute(uintptr_t faddr, const uint8_t *input, uint32_t input_len,
               uint8_t *output, uint32_t *output_len);
int ns_execute_void(uintptr_t faddr);

#endif // POX_EXECUTE_H