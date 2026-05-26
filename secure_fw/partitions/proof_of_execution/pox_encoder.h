#ifndef POX_ENCODER_H
#define POX_ENCODER_H

#include "pox_common.h"
#include "psa/error.h"

/**
 * @brief Encode the PoX CBOR payload from decoded IAT claims plus
 *        the proof-of-execution extension claims (faddr, exec_output).
 *
 * @param[in]  iat          Decoded EAT claims from the IAT token
 * @param[in]  faddr        Address of the non-secure function that was executed
 * @param[in]  exec_output  Return value / output byte from the NS execution
 * @param[out] scratch      Buffer to write the encoded CBOR into
 * @param[in]  scratch_sz   Size of scratch buffer
 * @param[out] encoded_len  Number of bytes written
 *
 * @return PSA_SUCCESS or PSA_ERROR_BUFFER_TOO_SMALL
 */
psa_status_t encode_pox_claims(const IATClaims *iat,
                               uintptr_t        faddr,
                               int              exec_output,
                               uint8_t         *scratch,
                               size_t           scratch_sz,
                               size_t          *encoded_len);

#endif /* POX_ENCODER_H */