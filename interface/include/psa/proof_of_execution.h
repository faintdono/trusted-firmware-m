/*
 * Copyright (c) 2024, The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Non-secure callable PSA API for the Proof-of-Execution (PoX) service.
 *
 */

#ifndef PSA_PROOF_OF_EXECUTION_H
#define PSA_PROOF_OF_EXECUTION_H

#include <stddef.h>
#include <stdint.h>
#include "psa/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Maximum size of a PoX token buffer.
 *
 * Sized to match ATT_MAX_TOKEN_SIZE on the secure side (0x240 bytes).
 */
#define PSA_POX_MAX_TOKEN_SIZE  0x2C0U /* headroom for the embedded sess_sig claim */

/**
 * \brief Request a Proof-of-Execution token from the secure partition.
 *
 * The secure partition will:
 *   1. Authenticate the session: verify \p sess_sig with the embedded
 *      verifier public key over the request transcript
 *        ver(1)=0x02 | sid_len(1) | session_id | nonce_len(1) |
 *        challenge | faddr_le32(4)
 *      and reject reused challenges (bounded nonce-history ring).
 *   2. Obtain an IAT token using \p challenge as the nonce.
 *   3. Execute the non-secure function at \p faddr with \p input.
 *   4. Encode the EAT claims from the IAT plus the PoX extension
 *      claims (faddr, execution output, session_id, caller_id) into a
 *      CBOR map.
 *   5. Sign the map with COSE_Sign1 using the PoX signing key.
 *   6. Return the signed token in \p token_buf.
 *
 * The session credentials are produced by the verifier and relayed
 * verbatim by the NS application; it cannot forge or alter them.
 * \p sess_sig is the 64-byte RAW r||s ECDSA P-256 signature (PSA
 * format, NOT ASN.1/DER).
 *
 * \param[in]  faddr            Address of the NS function to execute.
 * \param[in]  input            Input buffer passed to the NS function
 *                              (may be NULL if \p input_len is 0).
 * \param[in]  input_len        Length of \p input in bytes.
 * \param[out] output           Output buffer for the NS function result
 *                              (may be NULL if no output is expected).
 * \param[in]  output_len       Capacity of \p output in bytes.
 * \param[in]  challenge        Challenge nonce bytes for the IAT request
 *                              (the verifier-issued session nonce).
 * \param[in]  challenge_size   Length of \p challenge (32, 48, or 64 bytes).
 * \param[in]  session_id       Verifier-assigned opaque session id,
 *                              8..32 bytes. NULL only when the secure
 *                              partition is built without session auth.
 * \param[in]  session_id_len   Length of \p session_id in bytes.
 * \param[in]  sess_sig         Verifier signature over the request
 *                              transcript, 64 bytes raw r||s. NULL only
 *                              when session auth is disabled.
 * \param[in]  sess_sig_len     Length of \p sess_sig (must be 64).
 * \param[out] token_buf        Buffer to receive the signed PoX token.
 * \param[in]  token_buf_size   Capacity of \p token_buf in bytes.
 * \param[out] token_size       Actual size of the token written to
 *                              \p token_buf on success.
 *
 * \retval #PSA_SUCCESS                  Token generated successfully.
 * \retval #PSA_ERROR_INVALID_ARGUMENT   A parameter is invalid or the
 *                                       challenge size is not supported.
 * \retval #PSA_ERROR_NOT_PERMITTED      Session authentication failed:
 *                                       missing credentials, invalid
 *                                       signature, or reused nonce.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL   \p token_buf_size is too small.
 * \retval #PSA_ERROR_GENERIC_ERROR      An internal error occurred.
 */
psa_status_t
psa_pox_get_token(uintptr_t      faddr,
                  const uint8_t *input,
                  size_t         input_len,
                  uint8_t       *output,
                  size_t         output_len,
                  const uint8_t *challenge,
                  size_t         challenge_size,
                  const uint8_t *session_id,
                  size_t         session_id_len,
                  const uint8_t *sess_sig,
                  size_t         sess_sig_len,
                  uint8_t       *token_buf,
                  size_t         token_buf_size,
                  size_t        *token_size);

#ifdef __cplusplus
}
#endif

#endif /* PSA_PROOF_OF_EXECUTION_H */
