#ifndef POX_IAT_DECODER_H
#define POX_IAT_DECODER_H

#include "pox_common.h"
#include "psa/error.h"

/**
 * Decodes a signed IAT (COSE_Sign1) into an IATClaims structure.
 * Note: Performs DECODE_ONLY (does not verify IAK signature).
 */
psa_status_t decode_iat_to_claims(const uint8_t *token_buf, 
                                  size_t token_sz, 
                                  IATClaims *out_claims);

#endif /* POX_IAT_DECODER_H */