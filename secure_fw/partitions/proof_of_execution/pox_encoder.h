#ifndef POX_ENCODER_H
#define POX_ENCODER_H

#include "pox_common.h"
#include "pox_execute.h"   /* POX_EXEC_OUTPUT_MAX */
#include "pox_session.h"
#include "psa/error.h"
#include <stddef.h>

/**
 * @brief Encode the PoX CBOR payload: IAT claims plus the PoX
 *        extension (faddr, exec_output) and session-auth claims.
 *
 * @param[in] sess             Validated session context; NULL emits
 *                             no session claims
 * @param[in] exec_output      Attested bytes, from a ns_exec_snapshot
 * @param[in] exec_output_len  1..POX_EXEC_OUTPUT_MAX
 * @return PSA_SUCCESS, PSA_ERROR_INVALID_ARGUMENT or
 *         PSA_ERROR_BUFFER_TOO_SMALL
 */
psa_status_t encode_pox_claims(const IATClaims *iat,
                               uintptr_t        faddr,
                               const uint8_t   *exec_output,
                               size_t           exec_output_len,
                               const pox_session_ctx_t *sess,
                               uint8_t         *scratch,
                               size_t           scratch_sz,
                               size_t          *encoded_len);

#endif /* POX_ENCODER_H */
