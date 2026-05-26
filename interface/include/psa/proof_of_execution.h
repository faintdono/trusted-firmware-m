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
#define PSA_POX_MAX_TOKEN_SIZE  0x240U

/**
 * \brief Request a Proof-of-Execution token from the secure partition.
 *
 * The secure partition will:
 *   1. Obtain an IAT token using \p challenge as the nonce.
 *   2. Execute the non-secure function at \p faddr with \p input.
 *   3. Encode the EAT claims from the IAT plus the PoX extension
 *      claims (faddr, execution output) into a CBOR map.
 *   4. Sign the map with COSE_Sign1 using the PoX signing key.
 *   5. Return the signed token in \p token_buf.
 *
 * \param[in]  faddr            Address of the NS function to execute.
 * \param[in]  input            Input buffer passed to the NS function
 *                              (may be NULL if \p input_len is 0).
 * \param[in]  input_len        Length of \p input in bytes.
 * \param[out] output           Output buffer for the NS function result
 *                              (may be NULL if no output is expected).
 * \param[in,out] output_len    On entry: capacity of \p output.
 *                              On exit: bytes written by the NS function.
 * \param[in]  challenge        Challenge nonce bytes for the IAT request.
 * \param[in]  challenge_size   Length of \p challenge (32, 48, or 64 bytes).
 * \param[out] token_buf        Buffer to receive the signed PoX token.
 * \param[in]  token_buf_size   Capacity of \p token_buf in bytes.
 * \param[out] token_size       Actual size of the token written to
 *                              \p token_buf on success.
 *
 * \retval #PSA_SUCCESS                  Token generated successfully.
 * \retval #PSA_ERROR_INVALID_ARGUMENT   A parameter is invalid or the
 *                                       challenge size is not supported.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL   \p token_buf_size is too small.
 * \retval #PSA_ERROR_GENERIC_ERROR      An internal error occurred.
 */
psa_status_t
psa_pox_get_token(uintptr_t faddr,
                                 const uint8_t *input_bytes,
                                 size_t input_len,
                                 const uint8_t *ns_output,
                                 size_t ns_output_sz,
                                 const uint8_t *auth_challenge,
                                 size_t         challenge_size,
                                 uint8_t       *token_buf,
                                 size_t         token_buf_size,
                                 size_t        *token_size);

#ifdef __cplusplus
}
#endif

#endif /* PSA_PROOF_OF_EXECUTION_H */