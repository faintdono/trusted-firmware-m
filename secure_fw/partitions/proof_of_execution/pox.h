#ifndef POX_H
#define POX_H
#include "psa/error.h"
#include "psa/client.h"
#include "psa/crypto.h"

#define POX_CBOR_SCRATCH_SIZE 2048
#ifndef POX_SIGNING_KEY_ID
#  define POX_SIGNING_KEY_ID   ((psa_key_id_t)0x00000101U)
#endif
#define ATT_MAX_TOKEN_SIZE 0x240

psa_status_t
proof_of_execution(uintptr_t faddr, const uint8_t *input, const uint32_t input_len,
                   uint8_t *output, uint32_t *output_len,
                   uint8_t *challenge_buf, size_t challenge_size,
                   void *token_buf, size_t token_buf_size,
                   size_t *token_size);

psa_status_t 
pox_create_token(const uint8_t *iat_token_buf, size_t iat_token_sz,
                uintptr_t faddr, uint8_t *exec_output,
                uint8_t *report_buf, size_t *report_size);


#endif /* POX_H */