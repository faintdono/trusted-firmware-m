#ifndef POX_ENCODER_H
#define POX_ENCODER_H

#include "pox_common.h"
#include "psa/error.h"

psa_status_t encode_pox_claims(const IATClaims *iat,
                               const uint8_t   *raw_iat,
                               size_t           raw_iat_sz,
                               uintptr_t        faddr,
                               int              exec_output,
                               uint8_t         *scratch,
                               size_t           scratch_sz,
                               size_t          *encoded_len);
#endif