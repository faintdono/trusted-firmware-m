/*
 * pox_session.h
 *
 * Session authentication for the PoX secure partition: the verifier
 * signs the request transcript with its ECDSA P-256 private key, the
 * SP verifies with the verifier's public key and holds NO session
 * secret. Invalid signature or replayed request -> reject.
 */

#ifndef POX_SESSION_H
#define POX_SESSION_H

#include "psa/crypto.h"
#include "tfm_pox_wire.h"
#include <stdint.h>
#include <stddef.h>

/* Kconfig-driven; default off if the build system does not define it. */
#ifndef POX_SESSION_AUTH
#  define POX_SESSION_AUTH 0
#endif

#ifndef POX_NONCE_HISTORY
#  define POX_NONCE_HISTORY 16
#endif

#ifndef POX_SEQ_AUTH
#  define POX_SEQ_AUTH 0
#endif

/* Seq covers in-boot replay only; cross-boot replay is the boot
 * epoch's job, which every session-auth build carries. */
#if POX_SEQ_AUTH && !POX_SESSION_AUTH
#  error "POX_SEQ_AUTH requires POX_SESSION_AUTH."
#endif

/*
 * Session transcript version.
 *   v2: ver | sid_len | sid | nonce_len | nonce | faddr_le32 |
 *       epoch_le32 - the boot epoch binds the authorization to the
 *       current boot; a signature from epoch N fails after reboot.
 *   v3 (POX_SEQ_AUTH): v2 | seq_le32 - adds the monotonic counter
 *       that replaces the nonce ring.
 */
#if POX_SEQ_AUTH
#  define POX_TRANSCRIPT_VERSION (3u)
#else
#  define POX_TRANSCRIPT_VERSION (2u)
#endif

/*
 * Validated session context, passed down to the encoder. No nonce
 * field on purpose: the verifier nonce IS the IAT challenge, reaching
 * the token via IAT_NONCE (bound into the signed IAT) and cross-checked
 * against the wire challenge in pox_create_token().
 */
typedef struct {
    const uint8_t *session_id;
    size_t         session_id_len;
    int32_t        caller_id;          /* msg->client_id, SPM-supplied */
    /* Verifier transcript signature; emitted as a claim whenever
     * session auth is enabled (i.e. only after it verified). */
    const uint8_t *sess_sig;
    size_t         sess_sig_len;
#if POX_SESSION_AUTH
    uint32_t       boot_epoch;
#endif
#if POX_SEQ_AUTH
    uint32_t       seq;            /* verifier-assigned monotonic seq */
#endif
} pox_session_ctx_t;

/**
 * @brief One-shot init from pox_init(): imports the verifier PUBLIC
 *        key as a VOLATILE PSA key and bumps the boot epoch counter
 *        (the partition's only ITS write).
 */
psa_status_t pox_session_init(void);

/**
 * @brief Verify the transcript (ECDSA-P256-SHA256), then anti-replay
 *        (seq high-water mark or nonce ring). Either failure ->
 *        PSA_ERROR_NOT_PERMITTED, no state change; replay state moves
 *        only after the signature verified.
 */
psa_status_t pox_session_authenticate(const sec_pox_view_t *view);

#if POX_SESSION_AUTH
/** @brief Current boot epoch (valid after pox_session_init()). */
uint32_t pox_session_get_epoch(void);
#endif

#endif /* POX_SESSION_H */
