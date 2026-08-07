#ifndef POX_ENCODER_H
#define POX_ENCODER_H

#include "pox_common.h"
#include "pox_session.h"
#include "psa/error.h"

/**
 * @brief Encode the PoX CBOR payload: decoded IAT claims plus the
 *        extension claims (faddr, exec_output) and the session-auth
 *        claims.
 *
 * @param[in] sess  Validated session context; NULL emits no session
 *                  claims.
 * @return PSA_SUCCESS or PSA_ERROR_BUFFER_TOO_SMALL
 */
psa_status_t encode_pox_claims(const IATClaims *iat,
                               uintptr_t        faddr,
                               int              exec_output,
                               const pox_session_ctx_t *sess,
                               uint8_t         *scratch,
                               size_t           scratch_sz,
                               size_t          *encoded_len);

#endif /* POX_ENCODER_H */
