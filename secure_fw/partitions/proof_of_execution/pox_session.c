/*
 * pox_session.c
 *
 * Phase-1 session authentication for the PoX secure partition.
 *
 * Signature-only model: the verifier signs the request transcript
 *   ver(1)=0x02 | sid_len(1) | session_id | nonce_len(1) | challenge |
 *   faddr_le32(4)
 * with its ECDSA P-256 private key (64-byte RAW r||s, PSA format).
 * The partition holds only the verifier PUBLIC key: no session secret,
 * no PSK, no ITS dependency (except the optional boot epoch counter).
 *
 * Enforcement rules (in order, before any PoX processing):
 *   1. Invalid signature  -> reject request, end session.
 *   2. Reused nonce       -> reject request.
 * The nonce is recorded in the ring ONLY after the signature verifies,
 * so unauthenticated traffic cannot pollute the prover's book.
 */

#include "pox_session.h"
#include "tfm_sp_log.h"
#include <string.h>

#if POX_SESSION_AUTH

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
 * PLACEHOLDER: these are the publicly known RFC 6979 (A.2.5) P-256
 * test-vector coordinates. The matching private key
 * (C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721)
 * is published in the RFC, so anyone holding it could authorize PoX
 * requests on every device shipped with this key. Registration is
 * refused at runtime unless POX_ALLOW_PLACEHOLDER_KEY is enabled
 * (debug builds only), mirroring the pox_key.c placeholder policy.
 * The same RFC key pair is convenient for bring-up: use the published
 * private key on the verifier side to sign test transcripts.
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
/*
 * Replace with your own verifier public key (65 bytes, 0x04||X||Y).
 * Generate the pair with:
 *   openssl ecparam -name prime256v1 -genkey -noout -out verifier.pem
 *   openssl ec -in verifier.pem -pubout -conv_form uncompressed \
 *     -outform DER | tail -c 65 | xxd -i
 */
static const uint8_t POX_VERIFIER_PUBKEY_BYTES[65] = {
    POX_VERIFIER_PLACEHOLDER_PUBKEY
};
/* ============================ EDIT ABOVE ============================ */

#if !defined(POX_ALLOW_PLACEHOLDER_KEY)
static const uint8_t pox_verifier_placeholder_ref[65] = {
    POX_VERIFIER_PLACEHOLDER_PUBKEY
};
#endif

/* ------------------------------------------------------------------ */
/* State                                                                */
/* ------------------------------------------------------------------ */

/*
 * Volatile handle of the imported verifier public key. Zero means
 * session auth is unusable and pox_session_authenticate() fails closed.
 */
static psa_key_id_t verifier_key_handle = 0;

/*
 * Nonce-reuse ring: the "prover's book". Bounded RAM history of
 * SHA-256 digests of accepted challenges within this boot. The
 * verifier keeps the authoritative book; this ring only bounds what a
 * replaying NS relay can achieve device-side.
 */
#define POX_NONCE_DIGEST_LEN 32u
static uint8_t nonce_ring[POX_NONCE_HISTORY][POX_NONCE_DIGEST_LEN];
static size_t  nonce_ring_count = 0;   /* valid entries               */
static size_t  nonce_ring_next  = 0;   /* next slot to (over)write    */

#if POX_BOOT_EPOCH
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
        LOG_ERRFMT("[PoX] ERROR: boot epoch read failed (%d)\n",
                   (int)status);
        return (status == PSA_SUCCESS) ? PSA_ERROR_STORAGE_FAILURE
                                       : status;
    }

    boot_epoch_val = prev + 1u;

    status = psa_its_set(POX_EPOCH_ITS_UID, sizeof(boot_epoch_val),
                         &boot_epoch_val, PSA_STORAGE_FLAG_NONE);
    if (status != PSA_SUCCESS) {
        LOG_ERRFMT("[PoX] ERROR: boot epoch write failed (%d)\n",
                   (int)status);
        return status;
    }

    LOG_INFFMT("[PoX] Boot epoch: %u\n", (unsigned int)boot_epoch_val);
    return PSA_SUCCESS;
}
#endif /* POX_BOOT_EPOCH */

/* ------------------------------------------------------------------ */
/* Init                                                                 */
/* ------------------------------------------------------------------ */

psa_status_t pox_session_init(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t         imported_id = 0;
    psa_status_t         status;

    /*
     * Placeholder guard, mirroring pox_register_signing_key(): refuse
     * the known-public dev key unless explicitly allowed. On refusal
     * the handle stays 0 and every request is rejected (fail closed) -
     * the partition itself keeps running.
     */
#if !defined(POX_ALLOW_PLACEHOLDER_KEY)
    if (memcmp(POX_VERIFIER_PUBKEY_BYTES, pox_verifier_placeholder_ref,
               sizeof(POX_VERIFIER_PUBKEY_BYTES)) == 0) {
        LOG_ERRFMT("[PoX] FATAL: placeholder verifier public key detected "
                   "in production build. Replace POX_VERIFIER_PUBKEY_BYTES "
                   "in pox_session.c.\n");
        return PSA_ERROR_NOT_PERMITTED;
    }
#endif

    if (verifier_key_handle != 0) {
        (void)psa_destroy_key(verifier_key_handle);
        verifier_key_handle = 0;
    }

    /*
     * VOLATILE import: the key is a compile-time constant and only
     * integrity-sensitive (it is a PUBLIC key), so it is re-imported
     * on every boot and never touches ITS.
     */
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
        LOG_ERRFMT("[PoX] ERROR: verifier pubkey import failed (%d)\n",
                   (int)status);
        return status;
    }

    verifier_key_handle = imported_id;
    nonce_ring_count = 0;
    nonce_ring_next  = 0;

#if POX_BOOT_EPOCH
    status = boot_epoch_init();
    if (status != PSA_SUCCESS) {
        /* Without a trustworthy epoch the freshness claim would lie:
         * fail closed. */
        (void)psa_destroy_key(verifier_key_handle);
        verifier_key_handle = 0;
        return status;
    }
#endif

    LOG_INFFMT("[PoX] Session auth ready (verifier key handle=0x%x, "
               "nonce ring=%u entries)\n",
               (unsigned int)verifier_key_handle,
               (unsigned int)POX_NONCE_HISTORY);
    return PSA_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Phase-1 enforcement                                                  */
/* ------------------------------------------------------------------ */

psa_status_t pox_session_authenticate(const sec_pox_view_t *view)
{
    /* Transcript: ver | sid_len | sid | nonce_len | nonce | faddr_le32 */
    uint8_t      transcript[1 + 1 + POX_SESSION_ID_MAX +
                            1 + POX_CHALLENGE_LEN_MAX + 4];
    size_t       off = 0;
    uint32_t     faddr;
    uint8_t      digest[POX_NONCE_DIGEST_LEN];
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

    transcript[off++] = (uint8_t)POX_WIRE_VERSION;
    transcript[off++] = (uint8_t)view->session_id_len;
    memcpy(&transcript[off], view->session_id, view->session_id_len);
    off += view->session_id_len;
    transcript[off++] = (uint8_t)view->challenge_len;
    memcpy(&transcript[off], view->challenge, view->challenge_len);
    off += view->challenge_len;

    /* faddr re-encoded LE32: view->function_addr_le32 is host order
     * after the deserializer's le32_load. */
    faddr = (uint32_t)view->function_addr_le32;
    transcript[off++] = (uint8_t)(faddr);
    transcript[off++] = (uint8_t)(faddr >> 8);
    transcript[off++] = (uint8_t)(faddr >> 16);
    transcript[off++] = (uint8_t)(faddr >> 24);

    /* Rule 1: signature check. sess_sig is 64-byte RAW r||s. */
    status = psa_verify_message(verifier_key_handle,
                                PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                transcript, off,
                                view->sess_sig, view->sess_sig_len);
    if (status != PSA_SUCCESS) {
        LOG_ERRFMT("[PoX] Session signature invalid (%d): request "
                   "rejected, session ended\n", (int)status);
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* Rule 2: nonce-reuse check against the prover's book. */
    status = psa_hash_compute(PSA_ALG_SHA_256,
                              view->challenge, view->challenge_len,
                              digest, sizeof(digest), &digest_len);
    if (status != PSA_SUCCESS || digest_len != POX_NONCE_DIGEST_LEN) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    for (size_t i = 0; i < nonce_ring_count; i++) {
        if (memcmp(nonce_ring[i], digest, POX_NONCE_DIGEST_LEN) == 0) {
            LOG_ERRFMT("[PoX] Nonce reuse detected: request rejected\n");
            return PSA_ERROR_NOT_PERMITTED;
        }
    }

    /* Record only after the signature verified. */
    memcpy(nonce_ring[nonce_ring_next], digest, POX_NONCE_DIGEST_LEN);
    nonce_ring_next = (nonce_ring_next + 1u) % POX_NONCE_HISTORY;
    if (nonce_ring_count < POX_NONCE_HISTORY) {
        nonce_ring_count++;
    }

    return PSA_SUCCESS;
}

#else /* !POX_SESSION_AUTH */

/*
 * Session auth disabled: keep the same link-time surface so callers
 * need no conditional compilation of their own.
 */
psa_status_t pox_session_init(void)
{
    return PSA_SUCCESS;
}

psa_status_t pox_session_authenticate(const sec_pox_view_t *view)
{
    (void)view;
    return PSA_SUCCESS;
}

#if POX_BOOT_EPOCH
uint32_t pox_session_get_epoch(void)
{
    return 0;
}
#endif

#endif /* POX_SESSION_AUTH */
