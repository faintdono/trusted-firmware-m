#include "psa/client.h"
#include "tfm_attest_iat_defs.h"

psa_status_t
proof_of_execution(uintptr_t faddr, const uint8_t *input, const uint32_t input_len,
                   uint8_t *output, uint32_t *output_len,
                   const void *challenge_buf, size_t challenge_size,
                   void *token_buf, size_t token_buf_size,
                   size_t *token_size)
{
    // This function will be called by the IPC handler to execute the function at faddr,
    // generate a PoX report, and return the report as output.
    // The actual implementation of this function is in pox_execute.c, which is linked with this partition.
    return pox_execute(faddr, input, input_len, output, output_len,
                       challenge_buf, challenge_size, token_buf, token_buf_size, token_size);
}