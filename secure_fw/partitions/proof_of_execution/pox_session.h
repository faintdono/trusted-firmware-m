/*
 * pox_session.h
 *
 * Phase-1 session authentication for the PoX secure partition.
 *
 * Signature-only model: the verifier signs the request transcript with
 * its ECDSA P-256 private key; the SP verifies with the verifier's
 * public key. The SP holds NO session secret.
 *
 * Enforcement rules (in order, before any PoX processing):
 *   1. Invalid signature  -> reject request, end session.
 *   2. Reused nonce       -> reject request.
 */

#ifndef POX_SESSION_H
#define POX_SESSION_H

#include "psa/crypto.h"
#include "tfm_pox_wire.h"
#include <stdint.h>
#include <stddef.h>

/* Kconfig-driven; default off if the build system does not define it,
 * matching the POX_ALLOW_RUNTIME_KEY_OVERRIDE pattern in pox.h. */
#ifndef POX_SESSION_AUTH
#  define POX_SESSION_AUTH 0
#endif

#ifndef POX_NONCE_HISTORY
#  define POX_NONCE_HISTORY 16
#endif

#ifndef POX_SEQ_AUTH
#  define POX_SEQ_AUTH 0
#endif

/* Monotonic sequence binding (transcript v3) replaces the bounded
 * nonce ring with an O(1) per-session high-water mark: a request is
 * accepted only if its verifier-assigned seq strictly exceeds the
 * highest accepted this boot, so there is no eviction window a
 * replayer can exploit. It only defends in-boot replay; cross-boot
 * replay is the boot epoch's job, which every session-auth build
 * carries. */
#if POX_SEQ_AUTH && !POX_SESSION_AUTH
#  error "POX_SEQ_AUTH requires POX_SESSION_AUTH."
#endif

/*
 * Session transcript version.
 *   v2: ver | sid_len | sid | nonce_len | nonce | faddr_le32 |
 *       epoch_le32 - the boot epoch binds the authorization to the
 *       current boot; a signature from epoch N fails after reboot.
 *       (Session auth without the epoch no longer exists: it left
 *       reboot-replay open, so the two were merged.)
 *   v3 (POX_SEQ_AUTH): v2 | seq_le32 - adds the monotonic counter
 *       that retires the nonce ring.
 */
#if POX_SEQ_AUTH
#  define POX_TRANSCRIPT_VERSION (3u)
#else
#  define POX_TRANSCRIPT_VERSION (2u)
#endif

/*
 * Validated session context, passed down to the encoder.
 *
 * NOTE: no nonce field on purpose — the verifier nonce IS the IAT
 * challenge. It reaches the PoX token via IATClaims.nonce (IAT_NONCE),
 * bound into the signed IAT by the attestation service, and is
 * cross-checked against the wire challenge in pox_create_token().
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
 * @brief One-shot init, call from pox_init() after the signing key
 *        registration:
 *        - imports the verifier PUBLIC key as a VOLATILE PSA key
 *          (integrity-, not confidentiality-sensitive: compile-time
 *          constant, no ITS, re-imported each boot);
 *        - reads, increments and writes back the boot epoch counter
 *          (one small ITS write per boot — the only ITS use in this
 *          partition).
 */
psa_status_t pox_session_init(void);

/**
 * @brief Phase-1 enforcement, in order:
 *        1. ECDSA-P256-SHA256 verify over the transcript
 *           (ver | sid_len | sid | nonce_len | nonce | faddr_le32 |
 *           epoch_le32 [| seq_le32 in POX_SEQ_AUTH builds]).
 *           Invalid -> PSA_ERROR_NOT_PERMITTED: reject, end session,
 *           no state change.
 *        2. Anti-replay: monotonic seq high-water mark (POX_SEQ_AUTH)
 *           or nonce-reuse check against the bounded RAM ring (the
 *           "prover's book"; the verifier keeps the authoritative
 *           book). Stale/reused -> PSA_ERROR_NOT_PERMITTED.
 *        3. State updated only after the signature verifies, so
 *           unauthenticated traffic cannot pollute it.
 */
psa_status_t pox_session_authenticate(const sec_pox_view_t *view);

#if POX_SESSION_AUTH
/**
 * @brief Current boot epoch (valid after pox_session_init()).
 */
uint32_t pox_session_get_epoch(void);
#endif

#endif /* POX_SESSION_H */
