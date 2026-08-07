/*
 * pox_session.c
 *
 * Session authentication for the PoX secure partition.
 *
 * Signature-only model: the verifier signs the request transcript
 *   v2: ver(1)=0x02 | sid_len(1) | session_id | nonce_len(1) |
 *       challenge | faddr_le32(4) | epoch_le32(4)
 *   v3 (POX_SEQ_AUTH builds): ver(1)=0x03 | v2 fields | seq_le32(4)
 * with its ECDSA P-256 private key (64-byte RAW r||s, PSA format).
 * The partition holds only the verifier PUBLIC key: no session secret,
 * no PSK; ITS holds only the boot epoch counter.
 *
 * Enforcement order: invalid signature -> reject; replayed request
 * (reused nonce / stale seq) -> reject. Anti-replay state is updated
 * ONLY after the signature verifies, so unauthenticated traffic
 * cannot pollute the prover's book.
 */

#include "pox_session.h"
#include "pox_log.h"
#include "cmsis_compiler.h"
#include <string.h>

#if POX_SESSION_AUTH

#include "psa/internal_trusted_storage.h"

/*
 * Verifier public key, SEC1 uncompressed: 0x04 || X(32) || Y(32).
 *
 * PLACEHOLDER: publicly known RFC 6979 (A.2.5) P-256 test-vector
 * coordinates, whose private key is published in the RFC — anyone
 * could authorize PoX requests on every device shipped with it.
 * Refused at runtime unless POX_ALLOW_PLACEHOLDER_KEY (debug only),
 * mirroring the pox_key.c policy. Convenient for bring-up: sign test
 * transcripts with the published private key.
 */
#define POX_VERIFIER_PLACEHOLDER_PUBKEY                   \
    0x04,                                                 \
    0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31,       \
    0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,       \
    0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C,       \
    0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,       \
    0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99,       \
    0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,       \
    0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51,       \
    0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99

/* ============================ EDIT BELOW ============================ */
/* Replace with your own verifier public key (65 bytes, 0x04||X||Y):
 *   openssl ecparam -name prime256v1 -genkey -noout -out verifier.pem
 *   openssl ec -in verifier.pem -pubout -conv_form uncompressed \
 *     -outform DER | tail -c 65 | xxd -i                             */
static const uint8_t POX_VERIFIER_PUBKEY_BYTES[65] = {
    POX_VERIFIER_PLACEHOLDER_PUBKEY
};
/* ============================ EDIT ABOVE ============================ */

#if !defined(POX_ALLOW_PLACEHOLDER_KEY)
static const uint8_t pox_verifier_placeholder_ref[65] = {
    POX_VERIFIER_PLACEHOLDER_PUBKEY
};
#endif

/* Zero means session auth is unusable: authenticate() fails closed. */
static psa_key_id_t verifier_key_handle = 0;

#if POX_SEQ_AUTH
/*
 * Monotonic sequence high-water mark ("prover's book", O(1) form): a
 * request is accepted only if its seq strictly exceeds this, so there
 * is no eviction window. RAM only - reboot resets it to 0, safe
 * because the boot epoch in the same transcript already invalidates
 * every pre-reboot authorization.
 */
static uint32_t last_seq = 0;
#else
/*
 * Nonce-reuse ring ("prover's book"): bounded RAM history of SHA-256
 * digests accepted this boot. The verifier keeps the authoritative
 * book; this only bounds what a replaying NS relay achieves.
 */
#define POX_NONCE_DIGEST_LEN 32u
static uint8_t nonce_ring[POX_NONCE_HISTORY][POX_NONCE_DIGEST_LEN];
static size_t  nonce_ring_count = 0;
static size_t  nonce_ring_next  = 0;
#endif

/* ITS UID for the boot epoch counter ("POXE") */
#define POX_EPOCH_ITS_UID ((psa_storage_uid_t)0x504F5845u)

static uint32_t boot_epoch_val = 0;

uint32_t pox_session_get_epoch(void)
{
    return boot_epoch_val;
}

static psa_status_t boot_epoch_init(void)
{
    uint32_t     prev = 0;
    size_t       got  = 0;
    psa_status_t status;

    status = psa_its_get(POX_EPOCH_ITS_UID, 0, sizeof(prev), &prev, &got);
    if (status == PSA_ERROR_DOES_NOT_EXIST) {
        prev = 0;
    } else if (status != PSA_SUCCESS || got != sizeof(prev)) {
        POX_LOG_ERR("[PoX] ERROR: boot epoch read failed (%d)\n",
                   (int)status);
        return (status == PSA_SUCCESS) ? PSA_ERROR_STORAGE_FAILURE
                                       : status;
    }

    boot_epoch_val = prev + 1u;

    status = psa_its_set(POX_EPOCH_ITS_UID, sizeof(boot_epoch_val),
                         &boot_epoch_val, PSA_STORAGE_FLAG_NONE);
    if (status != PSA_SUCCESS) {
        POX_LOG_ERR("[PoX] ERROR: boot epoch write failed (%d)\n",
                   (int)status);
        return status;
    }

    POX_LOG_INF("[PoX] Boot epoch: %u\n", (unsigned int)boot_epoch_val);
    return PSA_SUCCESS;
}

psa_status_t pox_session_init(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t         imported_id = 0;
    psa_status_t         status;

    /* Placeholder guard: on refusal the handle stays 0 and every
     * request is rejected (fail closed); the partition keeps running. */
#if !defined(POX_ALLOW_PLACEHOLDER_KEY)
    if (memcmp(POX_VERIFIER_PUBKEY_BYTES, pox_verifier_placeholder_ref,
               sizeof(POX_VERIFIER_PUBKEY_BYTES)) == 0) {
        POX_LOG_ERR("[PoX] FATAL: placeholder verifier public key detected "
                   "in production build. Replace POX_VERIFIER_PUBKEY_BYTES "
                   "in pox_session.c.\n");
        return PSA_ERROR_NOT_PERMITTED;
    }
#endif

    if (verifier_key_handle != 0) {
        (void)psa_destroy_key(verifier_key_handle);
        verifier_key_handle = 0;
    }

    /* VOLATILE: compile-time constant, only integrity-sensitive (it is
     * PUBLIC), so re-imported every boot and never stored in ITS. */
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE |
                                   PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attr,
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);

    status = psa_import_key(&attr, POX_VERIFIER_PUBKEY_BYTES,
                            sizeof(POX_VERIFIER_PUBKEY_BYTES),
                            &imported_id);
    psa_reset_key_attributes(&attr);

    if (status != PSA_SUCCESS) {
        POX_LOG_ERR("[PoX] ERROR: verifier pubkey import failed (%d)\n",
                   (int)status);
        return status;
    }

    verifier_key_handle = imported_id;
#if POX_SEQ_AUTH
    last_seq = 0;
#else
    nonce_ring_count = 0;
    nonce_ring_next  = 0;
#endif

    status = boot_epoch_init();
    if (status != PSA_SUCCESS) {
        /* Without a trustworthy epoch the freshness claim would lie:
         * fail closed. */
        (void)psa_destroy_key(verifier_key_handle);
        verifier_key_handle = 0;
        return status;
    }

#if POX_SEQ_AUTH
    POX_LOG_INF("[PoX] Session auth ready (verifier key handle=0x%x, "
               "monotonic seq)\n", (unsigned int)verifier_key_handle);
#else
    POX_LOG_INF("[PoX] Session auth ready (verifier key handle=0x%x, "
               "nonce ring=%u entries)\n",
               (unsigned int)verifier_key_handle,
               (unsigned int)POX_NONCE_HISTORY);
#endif
    return PSA_SUCCESS;
}

psa_status_t pox_session_authenticate(const sec_pox_view_t *view)
{
    uint8_t      transcript[1 + 1 + POX_SESSION_ID_MAX +
                            1 + POX_CHALLENGE_LEN_MAX + 4 + 4 + 4];
    size_t       off = 0;
    uint32_t     faddr;
#if !POX_SEQ_AUTH
    uint8_t      digest[POX_NONCE_DIGEST_LEN];
    size_t       digest_len = 0;
#endif
    psa_status_t status;

    if (view == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Fail closed if init was refused (e.g. placeholder key). */
    if (verifier_key_handle == 0) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (view->session_id == NULL || view->sess_sig == NULL ||
        view->session_id_len < POX_SESSION_ID_MIN ||
        view->session_id_len > POX_SESSION_ID_MAX ||
        view->sess_sig_len != POX_SESS_SIG_LEN ||
        view->challenge == NULL ||
        view->challenge_len < POX_CHALLENGE_LEN_MIN ||
        view->challenge_len > POX_CHALLENGE_LEN_MAX) {
        return PSA_ERROR_NOT_PERMITTED;
    }

#if POX_SEQ_AUTH
    /* 0 is reserved for "absent" (verifier counters start at 1). */
    if (!view->has_seq || view->seq == 0u) {
        return PSA_ERROR_NOT_PERMITTED;
    }
#endif

    transcript[off++] = (uint8_t)POX_TRANSCRIPT_VERSION;
    transcript[off++] = (uint8_t)view->session_id_len;
    memcpy(&transcript[off], view->session_id, view->session_id_len);
    off += view->session_id_len;
    transcript[off++] = (uint8_t)view->challenge_len;
    memcpy(&transcript[off], view->challenge, view->challenge_len);
    off += view->challenge_len;

    /* Re-encode LE32: function_addr_le32 is host order after the
     * deserializer's le32_load. */
    faddr = (uint32_t)view->function_addr_le32;
    transcript[off++] = (uint8_t)(faddr);
    transcript[off++] = (uint8_t)(faddr >> 8);
    transcript[off++] = (uint8_t)(faddr >> 16);
    transcript[off++] = (uint8_t)(faddr >> 24);

    /* Bind to the current boot: a signature issued in a previous epoch
     * fails here, so a captured request cannot be replayed across the
     * reboot that wiped the anti-replay state. */
    transcript[off++] = (uint8_t)(boot_epoch_val);
    transcript[off++] = (uint8_t)(boot_epoch_val >> 8);
    transcript[off++] = (uint8_t)(boot_epoch_val >> 16);
    transcript[off++] = (uint8_t)(boot_epoch_val >> 24);

#if POX_SEQ_AUTH
    transcript[off++] = (uint8_t)(view->seq);
    transcript[off++] = (uint8_t)(view->seq >> 8);
    transcript[off++] = (uint8_t)(view->seq >> 16);
    transcript[off++] = (uint8_t)(view->seq >> 24);
#endif

    /* sess_sig is 64-byte RAW r||s, not DER. */
    status = psa_verify_message(verifier_key_handle,
                                PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                transcript, off,
                                view->sess_sig, view->sess_sig_len);
    if (status != PSA_SUCCESS) {
        POX_LOG_ERR("[PoX] Session signature invalid (%d): request "
                   "rejected, session ended\n", (int)status);
        return PSA_ERROR_NOT_PERMITTED;
    }

#if POX_SEQ_AUTH
    /* Accept only if strictly greater than the highest accepted this
     * boot, updated only now that the signature verified. Atomic
     * check-then-update against preemption (SPM already serializes;
     * defence in depth) - pure RAM, so masking IRQs is safe here. */
    {
        uint32_t primask = __get_PRIMASK();
        bool     stale;

        __disable_irq();
        stale = (view->seq <= last_seq);
        if (!stale) {
            last_seq = view->seq;
        }
        __set_PRIMASK(primask);

        if (stale) {
            POX_LOG_ERR("[PoX] Stale seq %u (<= last %u): request "
                       "rejected\n", (unsigned int)view->seq,
                       (unsigned int)last_seq);
            return PSA_ERROR_NOT_PERMITTED;
        }
    }
#else
    status = psa_hash_compute(PSA_ALG_SHA_256,
                              view->challenge, view->challenge_len,
                              digest, sizeof(digest), &digest_len);
    if (status != PSA_SUCCESS || digest_len != POX_NONCE_DIGEST_LEN) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* Atomic check-then-record: scan and insert must not be separable,
     * or a preemption between them lets a second copy of the same nonce
     * pass the scan before the first is recorded (SPM already
     * serializes; defence in depth). Only pure RAM ops go inside - the
     * crypto IPC calls above must stay interruptible, as they
     * context-switch to the crypto partition and would deadlock with
     * interrupts masked. */
    {
        uint32_t primask = __get_PRIMASK();
        bool     reused  = false;

        __disable_irq();

        for (size_t i = 0; i < nonce_ring_count; i++) {
            if (memcmp(nonce_ring[i], digest, POX_NONCE_DIGEST_LEN) == 0) {
                reused = true;
                break;
            }
        }

        if (!reused) {
            /* Record only after the signature verified. */
            memcpy(nonce_ring[nonce_ring_next], digest,
                   POX_NONCE_DIGEST_LEN);
            nonce_ring_next = (nonce_ring_next + 1u) % POX_NONCE_HISTORY;
            if (nonce_ring_count < POX_NONCE_HISTORY) {
                nonce_ring_count++;
            }
        }

        __set_PRIMASK(primask);

        if (reused) {
            POX_LOG_ERR("[PoX] Nonce reuse detected: request rejected\n");
            return PSA_ERROR_NOT_PERMITTED;
        }
    }
#endif /* POX_SEQ_AUTH */

    return PSA_SUCCESS;
}

#else /* !POX_SESSION_AUTH */

/* Same link-time surface, so callers need no conditional compilation.
 * No epoch stub: the boot epoch only exists with session auth. */
psa_status_t pox_session_init(void)
{
    return PSA_SUCCESS;
}

psa_status_t pox_session_authenticate(const sec_pox_view_t *view)
{
    (void)view;
    return PSA_SUCCESS;
}

#endif /* POX_SESSION_AUTH */
