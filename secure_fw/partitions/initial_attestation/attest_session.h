/*
 * attest_session.h
 *
 * Session authentication for the attestation partition's PoX path
 * (TFM_ATTEST_GET_POX). Self-contained: no dependency on the
 * standalone proof_of_execution partition, only on the shared wire
 * format header (tfm_pox_wire.h).
 *
 * Signature-only model, same protocol as the standalone PoX partition:
 * the verifier signs the request transcript with its ECDSA P-256
 * private key; this partition verifies with the verifier's public key
 * and holds NO session secret.
 *
 * Enforcement rules (in order, before any PoX processing):
 *   1. Invalid signature  -> reject request, end session.
 *   2. Reused nonce       -> reject request.
 *
 * Gated by POX_SESSION_AUTH_ATT (independent from the standalone
 * partition's POX_SESSION_AUTH) so the two PoX paths can be built
 * authenticated/unauthenticated separately for research comparison.
 */

#ifndef ATTEST_SESSION_H
#define ATTEST_SESSION_H

#include "psa/crypto.h"
#include "tfm_pox_wire.h"
#include <stdint.h>
#include <stddef.h>

/* Kconfig/CMake-driven; default off if the build system does not
 * define it. */
#ifndef POX_SESSION_AUTH_ATT
#  define POX_SESSION_AUTH_ATT 0
#endif

/* Switchable logging for the attestation partition's PoX path (same
 * flag as the standalone partition's pox_log.h; own copy to stay
 * decoupled). 0 compiles the calls out - benchmark baseline parity. */
#ifndef POX_LOG_ENABLE
#  define POX_LOG_ENABLE 0
#endif

#if POX_LOG_ENABLE
#  include "tfm_sp_log.h"
#  define POX_LOG_INF(...) LOG_INFFMT(__VA_ARGS__)
#  define POX_LOG_ERR(...) LOG_ERRFMT(__VA_ARGS__)
#else
#  define POX_LOG_INF(...) ((void)0)
#  define POX_LOG_ERR(...) ((void)0)
#endif

#ifndef POX_NONCE_HISTORY
#  define POX_NONCE_HISTORY 16
#endif

#ifndef POX_BOOT_EPOCH
#  define POX_BOOT_EPOCH 0
#endif

/* The boot epoch exists to witness (and, being bound into the signed
 * transcript, to prevent) reboot-replay of verifier-authorized
 * requests. Without session authentication there is no authorization
 * to replay and the claim would be a constant 0 that auditors might
 * trust: refuse the combination at build time. */
#if POX_BOOT_EPOCH && !POX_SESSION_AUTH_ATT
#  error "POX_BOOT_EPOCH requires POX_SESSION_AUTH_ATT on the attestation PoX path."
#endif

/*
 * Session transcript version. v2 covers
 *   ver | sid_len | sid | nonce_len | nonce | faddr_le32
 * v3 (POX_BOOT_EPOCH builds) appends epoch_le32, binding the verifier's
 * authorization to the current boot: a signature captured in epoch N
 * fails verification after reboot (epoch N+1), so reboot-replay is
 * rejected device-side instead of only being detectable in the token.
 * Must stay identical to pox_session.h in the standalone partition.
 */
#if POX_BOOT_EPOCH
#  define POX_TRANSCRIPT_VERSION (3u)
#else
#  define POX_TRANSCRIPT_VERSION (2u)
#endif

/*
 * PoX session-auth claim labels: CBOR private-use range. Values must
 * stay identical to pox_common.h in the standalone PoX partition so
 * both token flavours decode the same way verifier-side.
 */
#ifndef POX_LABEL_SESSION_ID
#  define POX_LABEL_SESSION_ID    (-65537)
#  define POX_LABEL_CALLER_ID     (-65538)
#  define POX_LABEL_BOOT_EPOCH    (-65539)
/* Verifier transcript signature (64B raw r||s), embedded whenever
 * session auth is enabled: makes the token self-contained
 * authorization evidence for third parties. */
#  define POX_LABEL_SESS_SIG      (-65540)
#endif

/*
 * Validated session context, passed down to the token encoder.
 * No nonce field on purpose: the verifier nonce IS the token
 * challenge and flows via the nonce claim.
 */
typedef struct {
    const uint8_t *session_id;
    size_t         session_id_len;
    int32_t        caller_id;          /* msg->client_id, SPM-supplied */
    /* Verifier transcript signature; emitted as a claim whenever
     * session auth is enabled (i.e. only after it verified). */
    const uint8_t *sess_sig;
    size_t         sess_sig_len;
#if POX_BOOT_EPOCH
    uint32_t       boot_epoch;
#endif
} attest_session_ctx_t;

/**
 * @brief One-shot init, call from attest_partition_init():
 *        imports the verifier PUBLIC key as a VOLATILE PSA key. On
 *        failure the PoX path fails closed (every request rejected);
 *        IAT services are unaffected.
 */
psa_status_t attest_session_init(void);

/**
 * @brief Phase-1 enforcement over the deserialized request view:
 *        1. ECDSA-P256-SHA256 verify over the transcript
 *           (ver | sid_len | sid | nonce_len | nonce | faddr_le32
 *           [| epoch_le32 in POX_BOOT_EPOCH builds]).
 *        2. Nonce-reuse check against this partition's bounded RAM
 *           ring; recorded only after the signature verifies.
 */
psa_status_t attest_session_authenticate(const sec_pox_view_t *view);

#if POX_BOOT_EPOCH
/**
 * @brief Current boot epoch (valid after attest_session_init()).
 */
uint32_t attest_session_get_epoch(void);
#endif

#endif /* ATTEST_SESSION_H */
