#ifndef POX_H
#define POX_H

#include "psa/error.h"
#include "psa/client.h"
#include "psa/crypto.h"
#include "pox_session.h"
#include <stdint.h>
#include <stddef.h>

#define POX_CBOR_SCRATCH_SIZE   2048

/* Maximum size for an IAT token buffer */
#define ATT_MAX_TOKEN_SIZE      0x2C0  /* headroom for the embedded sess_sig claim */

/* Must stay in [PSA_KEY_ID_USER_MIN, PSA_KEY_ID_USER_MAX] and must not
 * clash with any other key id in the system. */
#ifndef POX_SIGNING_KEY_ID
#  define POX_SIGNING_KEY_ID    ((psa_key_id_t)0x00000101U)
#endif

/* Kconfig-driven; default off if the build system does not define it. */
#ifndef POX_ALLOW_RUNTIME_KEY_OVERRIDE
#  define POX_ALLOW_RUNTIME_KEY_OVERRIDE 0
#endif

/**
 * @brief Import the hardcoded PoX signing key into PSA Crypto as a
 *        VOLATILE ECDSA P-256 key pair. Call exactly once from
 *        pox_init(). psa_set_key_id() is ignored for volatile keys, so
 *        the real handle comes from pox_get_signing_key_handle().
 */
psa_status_t pox_register_signing_key(void);

/** @brief Volatile key handle, or 0 if the key is not imported yet. */
psa_key_id_t pox_get_signing_key_handle(void);

#if POX_ALLOW_RUNTIME_KEY_OVERRIDE
/**
 * @brief Replace the registered signing key with a caller-supplied
 *        32-byte ECDSA P-256 private scalar (big-endian);
 *        priv_key_len must be exactly 32.
 */
psa_status_t pox_set_signing_key(const uint8_t *priv_key, size_t priv_key_len);
#endif

/**
 * @brief Full proof-of-execution flow:
 *        get IAT -> decode -> execute NS function -> encode PoX claims -> sign.
 *
 * @param output_len      In: capacity of output; out: bytes written by NS fn
 * @param challenge_buf   The authenticated verifier nonce, used as the
 *                        IAT request challenge (32, 48 or 64 bytes)
 * @param sess            Validated session context; may be NULL only
 *                        when session authentication is disabled.
 */
psa_status_t
proof_of_execution(uintptr_t faddr,
                   const uint8_t *input,  const uint32_t input_len,
                   uint8_t       *output, uint32_t       *output_len,
                   uint8_t *challenge_buf, size_t challenge_size,
                   const pox_session_ctx_t *sess,
                   void *token_buf, size_t token_buf_size,
                   size_t *token_size);

/**
 * @brief Create a signed PoX token from an already-obtained IAT token:
 *        decode the IAT, execute the NS function, encode EAT + PoX
 *        claims, sign.
 *
 * @param challenge_buf  Authenticated challenge; the decoded IAT nonce
 *                       must match it byte-for-byte
 * @param report_size    In: capacity of report_buf; out: bytes written
 *
 * @retval PSA_ERROR_CORRUPTION_DETECTED  IAT-embedded nonce does not
 *         match the authenticated challenge.
 */
psa_status_t
pox_create_token(const uint8_t *iat_token_buf, size_t iat_token_sz,
                 uintptr_t faddr,
                 const uint8_t *input,  uint32_t  input_len,
                 uint8_t       *output, uint32_t *output_len,
                 const uint8_t *challenge_buf, size_t challenge_size,
                 const pox_session_ctx_t *sess,
                 uint8_t *report_buf, size_t *report_size);

#endif /* POX_H */