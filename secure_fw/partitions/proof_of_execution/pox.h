#ifndef POX_H
#define POX_H

#include "psa/error.h"
#include "psa/client.h"
#include "psa/crypto.h"
#include <stdint.h>
#include <stddef.h>

#define POX_CBOR_SCRATCH_SIZE   2048

/* Maximum size for an IAT token buffer */
#define ATT_MAX_TOKEN_SIZE      0x240

/* ------------------------------------------------------------------ */
/* PoX signing key configuration                                        */
/* ------------------------------------------------------------------ */

/*
 * The PSA key id under which the PoX signing key is registered.
 * Must be in the user range [PSA_KEY_ID_USER_MIN, PSA_KEY_ID_USER_MAX]
 * and must not clash with any other key id in the system.
 */
#ifndef POX_SIGNING_KEY_ID
#  define POX_SIGNING_KEY_ID    ((psa_key_id_t)0x00000101U)
#endif

/*
 * Compile in pox_set_signing_key() to replace the hardcoded key at
 * runtime. Controlled by Kconfig (POX_ALLOW_RUNTIME_KEY_OVERRIDE).
 * If not defined by the build system, default to off.
 */
#ifndef POX_ALLOW_RUNTIME_KEY_OVERRIDE
#  define POX_ALLOW_RUNTIME_KEY_OVERRIDE 0
#endif

/* ------------------------------------------------------------------ */
/* API                                                                  */
/* ------------------------------------------------------------------ */

/**
 * @brief Import the hardcoded PoX signing key into PSA Crypto as a
 *        VOLATILE ECDSA P-256 key pair. Call exactly once from pox_init().
 *
 *        For volatile keys psa_set_key_id() is ignored by PSA Crypto;
 *        the real handle is stored internally and retrieved via
 *        pox_get_signing_key_handle().
 */
psa_status_t pox_register_signing_key(void);

/**
 * @brief Return the volatile PSA key handle assigned by psa_import_key()
 *        during pox_register_signing_key(). Returns 0 if the key has not
 *        been imported yet.
 */
psa_key_id_t pox_get_signing_key_handle(void);

#if POX_ALLOW_RUNTIME_KEY_OVERRIDE
/**
 * @brief Replace the currently registered PoX signing key with a
 *        caller-supplied 32-byte ECDSA P-256 private scalar.
 *
 * @param priv_key       Pointer to 32 raw private-scalar bytes (big-endian).
 * @param priv_key_len   Must be exactly 32.
 *
 * @retval PSA_SUCCESS                 New key is in place.
 * @retval PSA_ERROR_INVALID_ARGUMENT  Bad length or NULL pointer.
 * @retval Other PSA error             Import/destroy failed.
 */
psa_status_t pox_set_signing_key(const uint8_t *priv_key, size_t priv_key_len);
#endif

/**
 * @brief Full proof-of-execution flow:
 *        get IAT -> decode -> execute NS function -> encode PoX claims -> sign.
 *
 * @param faddr           Non-secure function address to execute
 * @param input           Input buffer for the NS function (may be NULL)
 * @param input_len       Length of input buffer (0 if none)
 * @param output          Output buffer for the NS function (may be NULL)
 * @param output_len      In: capacity of output; out: bytes written by NS fn
 * @param challenge_buf   Challenge bytes for the IAT token request
 * @param challenge_size  Length of challenge (32, 48 or 64 bytes)
 * @param token_buf       Output buffer for the signed PoX token
 * @param token_buf_size  Size of token_buf
 * @param token_size      Actual size of the signed token written
 */
psa_status_t
proof_of_execution(uintptr_t faddr,
                   const uint8_t *input,  const uint32_t input_len,
                   uint8_t       *output, uint32_t       *output_len,
                   uint8_t *challenge_buf, size_t challenge_size,
                   void *token_buf, size_t token_buf_size,
                   size_t *token_size);

/**
 * @brief Create a signed PoX token from an already-obtained IAT token.
 *
 * Decodes the IAT, executes the NS function, encodes EAT + PoX claims,
 * and signs the result.
 *
 * @param iat_token_buf  Raw IAT COSE_Sign1 token bytes
 * @param iat_token_sz   Length of the IAT token
 * @param faddr          Non-secure function address to execute
 * @param input          Input buffer for NS function (may be NULL)
 * @param input_len      Length of input (0 if none)
 * @param output         Output buffer for NS function (may be NULL)
 * @param output_len     In: capacity; out: bytes written
 * @param report_buf     Output buffer for the signed PoX report
 * @param report_size    In: capacity of report_buf; out: bytes written
 */
psa_status_t
pox_create_token(const uint8_t *iat_token_buf, size_t iat_token_sz,
                 uintptr_t faddr,
                 const uint8_t *input,  uint32_t  input_len,
                 uint8_t       *output, uint32_t *output_len,
                 uint8_t *report_buf, size_t *report_size);

#endif /* POX_H */