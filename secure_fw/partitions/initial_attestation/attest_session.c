/*
 * attest_session.c
 *
 * Session authentication for the attestation partition's PoX path.
 * Self-contained twin of the standalone partition's pox_session.c:
 * same protocol, same verifier public key, but a private key handle
 * and a private nonce ring. PSA volatile keys are owned by the
 * importing partition, so the two partitions cannot share one
 * instance (broken under isolation levels above 1).
 *
 * Transcript:
 *   v2: ver(1)=0x02 | sid_len(1) | session_id | nonce_len(1) |
 *       challenge | faddr_le32(4)
 *   v3 (POX_BOOT_EPOCH builds): ver(1)=0x03 | v2 fields | epoch_le32(4)
 * SIG: ECDSA-P256-SHA256, 64-byte RAW r||s (PSA format, NOT DER).
 */

#include "attest_session.h"
#include "cmsis_compiler.h"
#include <string.h>

#if POX_SESSION_AUTH_ATT

#if POX_BOOT_EPOCH
#include "psa/internal_trusted_storage.h"
#endif

/* ------------------------------------------------------------------ */
/* Verifier public key                                                  */
/* ------------------------------------------------------------------ */

/*
 * ECDSA P-256 public key of the verifier, SEC1 uncompressed form:
 * 0x04 || X(32 bytes) || Y(32 bytes).
 *
 * PLACEHOLDER: the publicly known RFC 6979 (A.2.5) P-256 test-vector
 * key, identical to the placeholder in the standalone partition's
 * pox_session.c. Registration is refused at runtime unless
 * POX_ALLOW_PLACEHOLDER_KEY is enabled (debug builds only). Keep both
 * copies in sync when provisioning the real verifier key.
 */
#define ATTEST_VERIFIER_PLACEHOLDER_PUBKEY                \
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
static const uint8_t ATTEST_VERIFIER_PUBKEY_BYTES[65] = {
    ATTEST_VERIFIER_PLACEHOLDER_PUBKEY
};
/* ============================ EDIT ABOVE ============================ */

#if !defined(POX_ALLOW_PLACEHOLDER_KEY)
static const uint8_t attest_verifier_placeholder_ref[65] = {
    ATTEST_VERIFIER_PLACEHOLDER_PUBKEY
};
#endif

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

/* Zero means unusable: attest_session_authenticate() fails closed. */
static psa_key_id_t verifier_key_handle = 0;

/* Nonce-reuse ring ("prover's book"), private to this partition. */
#define ATTEST_NONCE_DIGEST_LEN 32u
static uint8_t nonce_ring[POX_NONCE_HISTORY][ATTEST_NONCE_DIGEST_LEN];
static size_t  nonce_ring_count = 0;
static size_t  nonce_ring_next  = 0;

#if POX_BOOT_EPOCH
/* ITS UID for the boot epoch counter ("POXA"). ITS is namespaced per
 * partition, but a distinct UID keeps debugging unambiguous. */
#define ATTEST_EPOCH_ITS_UID ((psa_storage_uid_t)0x504F5841u)

static uint32_t boot_epoch_val = 0;

uint32_t attest_session_get_epoch(void)
{
    return boot_epoch_val;
}

static psa_status_t boot_epoch_init(void)
{
    uint32_t     prev = 0;
    size_t       got  = 0;
    psa_status_t status;

    status = psa_its_get(ATTEST_EPOCH_ITS_UID, 0, sizeof(prev), &prev, &got);
    if (status == PSA_ERROR_DOES_NOT_EXIST) {
        prev = 0;
    } else if (status != PSA_SUCCESS || got != sizeof(prev)) {
        POX_LOG_ERR("[Attest][PoX] ERROR: boot epoch read failed (%d)\n",
                   (int)status);
        return (status == PSA_SUCCESS) ? PSA_ERROR_STORAGE_FAILURE
                                       : status;
    }

    boot_epoch_val = prev + 1u;

    status = psa_its_set(ATTEST_EPOCH_ITS_UID, sizeof(boot_epoch_val),
                         &boot_epoch_val, PSA_STORAGE_FLAG_NONE);
    if (status != PSA_SUCCESS) {
        POX_LOG_ERR("[Attest][PoX] ERROR: boot epoch write failed (%d)\n",
                   (int)status);
        return status;
    }

    POX_LOG_INF("[Attest][PoX] Boot epoch: %u\n",
               (unsigned int)boot_epoch_val);
    return PSA_SUCCESS;
}
#endif /* POX_BOOT_EPOCH */

/* ------------------------------------------------------------------ */
/* Init                                                                 */
/* ------------------------------------------------------------------ */

psa_status_t attest_session_init(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t         imported_id = 0;
    psa_status_t         status;

    /* Placeholder guard: refuse the known-public dev key unless
     * explicitly allowed. On refusal the handle stays 0 and every PoX
     * request is rejected (fail closed); IAT is unaffected. */
#if !defined(POX_ALLOW_PLACEHOLDER_KEY)
    if (memcmp(ATTEST_VERIFIER_PUBKEY_BYTES, attest_verifier_placeholder_ref,
               sizeof(ATTEST_VERIFIER_PUBKEY_BYTES)) == 0) {
        POX_LOG_ERR("[Attest][PoX] FATAL: placeholder verifier public key "
                   "detected in production build. Replace "
                   "ATTEST_VERIFIER_PUBKEY_BYTES in attest_session.c.\n");
        return PSA_ERROR_NOT_PERMITTED;
    }
#endif

    if (verifier_key_handle != 0) {
        (void)psa_destroy_key(verifier_key_handle);
        verifier_key_handle = 0;
    }

    /* VOLATILE import: compile-time constant PUBLIC key, re-imported
     * each boot, never touches ITS. */
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE |
                                   PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attr,
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);

    status = psa_import_key(&attr, ATTEST_VERIFIER_PUBKEY_BYTES,
                            sizeof(ATTEST_VERIFIER_PUBKEY_BYTES),
                            &imported_id);
    psa_reset_key_attributes(&attr);

    if (status != PSA_SUCCESS) {
        POX_LOG_ERR("[Attest][PoX] ERROR: verifier pubkey import failed "
                   "(%d)\n", (int)status);
        return status;
    }

    verifier_key_handle = imported_id;
    nonce_ring_count = 0;
    nonce_ring_next  = 0;

#if POX_BOOT_EPOCH
    status = boot_epoch_init();
    if (status != PSA_SUCCESS) {
        (void)psa_destroy_key(verifier_key_handle);
        verifier_key_handle = 0;
        return status;
    }
#endif

    POX_LOG_INF("[Attest][PoX] Session auth ready (verifier key "
               "handle=0x%x, nonce ring=%u entries)\n",
               (unsigned int)verifier_key_handle,
               (unsigned int)POX_NONCE_HISTORY);
    return PSA_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Phase-1 enforcement                                                  */
/* ------------------------------------------------------------------ */

psa_status_t attest_session_authenticate(const sec_pox_view_t *view)
{
    /* Transcript v2: ver | sid_len | sid | nonce_len | nonce | faddr_le32
     * Transcript v3 (POX_BOOT_EPOCH): v2 fields | epoch_le32 */
    uint8_t      transcript[1 + 1 + POX_SESSION_ID_MAX +
                            1 + POX_CHALLENGE_LEN_MAX + 4 + 4];
    size_t       off = 0;
    uint32_t     faddr;
    uint8_t      digest[ATTEST_NONCE_DIGEST_LEN];
    size_t       digest_len = 0;
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

    transcript[off++] = (uint8_t)POX_TRANSCRIPT_VERSION;
    transcript[off++] = (uint8_t)view->session_id_len;
    memcpy(&transcript[off], view->session_id, view->session_id_len);
    off += view->session_id_len;
    transcript[off++] = (uint8_t)view->challenge_len;
    memcpy(&transcript[off], view->challenge, view->challenge_len);
    off += view->challenge_len;

    /* faddr re-encoded LE32 (host order after deserialize). */
    faddr = (uint32_t)view->function_addr_le32;
    transcript[off++] = (uint8_t)(faddr);
    transcript[off++] = (uint8_t)(faddr >> 8);
    transcript[off++] = (uint8_t)(faddr >> 16);
    transcript[off++] = (uint8_t)(faddr >> 24);

#if POX_BOOT_EPOCH
    /* v3: bind the authorization to the current boot. A signature the
     * verifier issued in a previous epoch fails here after reboot, so
     * a captured request cannot be replayed across the reboot that
     * wiped the nonce ring. */
    transcript[off++] = (uint8_t)(boot_epoch_val);
    transcript[off++] = (uint8_t)(boot_epoch_val >> 8);
    transcript[off++] = (uint8_t)(boot_epoch_val >> 16);
    transcript[off++] = (uint8_t)(boot_epoch_val >> 24);
#endif

    /* Rule 1: signature check. sess_sig is 64-byte RAW r||s. */
    status = psa_verify_message(verifier_key_handle,
                                PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                transcript, off,
                                view->sess_sig, view->sess_sig_len);
    if (status != PSA_SUCCESS) {
        POX_LOG_ERR("[Attest][PoX] Session signature invalid (%d): "
                   "request rejected, session ended\n", (int)status);
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* Rule 2: nonce-reuse check against this partition's ring. */
    status = psa_hash_compute(PSA_ALG_SHA_256,
                              view->challenge, view->challenge_len,
                              digest, sizeof(digest), &digest_len);
    if (status != PSA_SUCCESS || digest_len != ATTEST_NONCE_DIGEST_LEN) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* Atomic check-then-record: the scan and the insert must not be
     * separable, or a preemption in between could let a second copy of
     * the same nonce pass the scan before the first one is recorded.
     * The SPM already serializes messages per partition, so this is
     * defence in depth against any preemption path. Only pure RAM ops
     * go inside the critical section - the crypto IPC calls above must
     * stay interruptible (they context-switch to the crypto partition
     * and would deadlock with interrupts masked).
     * PRIMASK save/restore; this partition is PSA-RoT (privileged). */
    {
        uint32_t primask = __get_PRIMASK();
        bool     reused  = false;

        __disable_irq();

        for (size_t i = 0; i < nonce_ring_count; i++) {
            if (memcmp(nonce_ring[i], digest, ATTEST_NONCE_DIGEST_LEN) == 0) {
                reused = true;
                break;
            }
        }

        if (!reused) {
            /* Record only after the signature verified. */
            memcpy(nonce_ring[nonce_ring_next], digest,
                   ATTEST_NONCE_DIGEST_LEN);
            nonce_ring_next = (nonce_ring_next + 1u) % POX_NONCE_HISTORY;
            if (nonce_ring_count < POX_NONCE_HISTORY) {
                nonce_ring_count++;
            }
        }

        __set_PRIMASK(primask);

        if (reused) {
            POX_LOG_ERR("[Attest][PoX] Nonce reuse detected: request "
                       "rejected\n");
            return PSA_ERROR_NOT_PERMITTED;
        }
    }

    return PSA_SUCCESS;
}

#else /* !POX_SESSION_AUTH_ATT */

/* Session auth disabled for this path: same link surface, no-ops. */
psa_status_t attest_session_init(void)
{
    return PSA_SUCCESS;
}

psa_status_t attest_session_authenticate(const sec_pox_view_t *view)
{
    (void)view;
    return PSA_SUCCESS;
}

/* No epoch stub: POX_BOOT_EPOCH without POX_SESSION_AUTH_ATT is
 * refused at build time in attest_session.h. */

#endif /* POX_SESSION_AUTH_ATT */
