#ifndef ATTEST_EXECUTE_H
#define ATTEST_EXECUTE_H
#include "tfm_sp_log.h" // TF-M Secure Partition Logging
#include <stdint.h>

typedef int (*ns_function_ptr_with_args_t)(const uint8_t *input, uint32_t input_len, uint8_t *output, uint32_t *output_len) __attribute__((cmse_nonsecure_call));
typedef int (*ns_function_ptr_void_t)(void) __attribute__((cmse_nonsecure_call));

/**
 * @brief Function execution in Secure World via Function Address.
 *
 * @param faadr    Function Address
 */
int ns_execute(uintptr_t faddr, const uint8_t *input, uint32_t input_len,
               uint8_t *output, uint32_t *output_len);
int ns_execute_void(uintptr_t faddr);

#endif // ATTEST_EXECUTE_H
