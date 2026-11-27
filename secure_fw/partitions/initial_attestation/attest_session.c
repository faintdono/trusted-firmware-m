/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*
 * attest_session.c
 *
 * Session authentication for the attestation partition's PoX path.
 * Self-contained twin of the standalone partition's pox_session.c:
 * same protocol and verifier public key, but its own key handle and
 * anti-replay state — PSA volatile keys are owned by the importing
 * partition, so the two cannot share one instance (that breaks under
 * isolation levels above 1).
 *
 * Transcript:
 *   ver(1)=0x03 | sid_len(1) | session_id | nonce_len(1) |
 *   challenge | faddr_le32(4) | epoch_le32(4) | seq_le32(4)
 * SIG: ECDSA-P256-SHA256, 64-byte RAW r||s (PSA format, NOT DER).
 */

#include "attest_session.h"
#include "cmsis_compiler.h"
#include <string.h>

#if POX_REQUEST_AUTH_ATT

#include "psa/internal_trusted_storage.h"

/*
 * Verifier public key, SEC1 uncompressed: 0x04 || X(32) || Y(32).
 *
 * PLACEHOLDER: publicly known RFC 6979 (A.2.5) P-256 test-vector key,
 * identical to the one in pox_session.c. Refused at runtime unless
 * POX_ALLOW_PLACEHOLDER_KEY (debug builds only). Keep both copies in
 * sync when provisioning the real verifier key.
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

#ifdef POX_SYMMETRIC_REQUEST_AUTH
/*
 * POX_SYMMETRIC_REQUEST_AUTH: the Verifier authenticates each request
 * with HMAC-SHA256 under a key it shares with the device, instead of an
 * ECDSA signature. The device must then keep this key secret: anyone
 * who extracts it can authorize requests, unlike the public key above.
 *
 * PLACEHOLDER: SHA-256("PoX development request key"), public. Refused
 * at runtime unless POX_ALLOW_PLACEHOLDER_KEY, like the public key.
 * The same bytes must be in the other partition's copy and in the
 * verifier's credential tool.
 */
#define ATTEST_REQUEST_PLACEHOLDER_KEY                      \
    0x08, 0xDE, 0x59, 0x40, 0xC5, 0x4E, 0x96, 0xB4,       \
    0xC3, 0x2F, 0x22, 0x2C, 0xFD, 0x8E, 0x88, 0x2F,       \
    0xC6, 0x16, 0xF1, 0x7B, 0xC9, 0x08, 0x9A, 0x49,       \
    0xC0, 0xCD, 0x65, 0xC3, 0x2A, 0x79, 0xFB, 0x1E

/* ============================ EDIT BELOW ============================ */
static const uint8_t ATTEST_REQUEST_KEY_BYTES[32] = {
    ATTEST_REQUEST_PLACEHOLDER_KEY
};
/* ============================ EDIT ABOVE ============================ */

#if !defined(POX_ALLOW_PLACEHOLDER_KEY)
static const uint8_t attest_request_placeholder_ref[32] = {
    ATTEST_REQUEST_PLACEHOLDER_KEY
};
#endif
#define ATTEST_REQUEST_CRED_LEN  POX_SESS_MAC_LEN
#else
#define ATTEST_REQUEST_CRED_LEN  POX_SESS_SIG_LEN
#endif /* POX_SYMMETRIC_REQUEST_AUTH */

/* Zero means unusable: attest_session_authenticate() fails closed. */
static psa_key_id_t verifier_key_handle = 0;

/* Monotonic high-water mark, private to this partition; see
 * pox_session.c for the rationale. */
static uint32_t last_seq = 0;

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

psa_status_t attest_session_init(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t         imported_id = 0;
    psa_status_t         status;

    /* Placeholder guard: refuse the known-public dev key unless
     * explicitly allowed. On refusal the handle stays 0 and every PoX
     * request is rejected (fail closed); IAT is unaffected. */
#ifdef POX_SYMMETRIC_REQUEST_AUTH
#if !defined(POX_ALLOW_PLACEHOLDER_KEY)
    if (memcmp(ATTEST_REQUEST_KEY_BYTES, attest_request_placeholder_ref,
               sizeof(ATTEST_REQUEST_KEY_BYTES)) == 0) {
        POX_LOG_ERR("[Attest][PoX] FATAL: placeholder request key detected in "
                   "production build. Replace ATTEST_REQUEST_KEY_BYTES.\n");
        return PSA_ERROR_NOT_PERMITTED;
    }
#endif

    if (verifier_key_handle != 0) {
        (void)psa_destroy_key(verifier_key_handle);
        verifier_key_handle = 0;
    }

    /* VOLATILE: a SECRET shared with the Verifier, re-imported every
     * boot from the image, never stored in ITS. */
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, 256);

    status = psa_import_key(&attr, ATTEST_REQUEST_KEY_BYTES,
                            sizeof(ATTEST_REQUEST_KEY_BYTES),
                            &imported_id);
    psa_reset_key_attributes(&attr);
#else
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

#endif /* POX_SYMMETRIC_REQUEST_AUTH */

    if (status != PSA_SUCCESS) {
        POX_LOG_ERR("[Attest][PoX] ERROR: verifier pubkey import failed "
                   "(%d)\n", (int)status);
        return status;
    }

    verifier_key_handle = imported_id;
    last_seq = 0;

    status = boot_epoch_init();
    if (status != PSA_SUCCESS) {
        (void)psa_destroy_key(verifier_key_handle);
        verifier_key_handle = 0;
        return status;
    }

    POX_LOG_INF("[Attest][PoX] Session auth ready (verifier key "
               "handle=0x%x, monotonic seq)\n",
               (unsigned int)verifier_key_handle);
    return PSA_SUCCESS;
}

psa_status_t attest_session_authenticate(const sec_pox_view_t *view)
{
    uint8_t      transcript[1 + 1 + POX_SESSION_ID_MAX +
                            1 + POX_CHALLENGE_LEN_MAX + 4 + 4 + 4];
    size_t       off = 0;
    uint32_t     faddr;
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
        view->sess_sig_len != ATTEST_REQUEST_CRED_LEN ||
        view->challenge == NULL ||
        view->challenge_len < POX_CHALLENGE_LEN_MIN ||
        view->challenge_len > POX_CHALLENGE_LEN_MAX) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* 0 is reserved for "absent" (verifier counters start at 1). */
    if (!view->has_seq || view->seq == 0u) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    transcript[off++] = (uint8_t)POX_TRANSCRIPT_VERSION;
    transcript[off++] = (uint8_t)view->session_id_len;
    memcpy(&transcript[off], view->session_id, view->session_id_len);
    off += view->session_id_len;
    transcript[off++] = (uint8_t)view->challenge_len;
    memcpy(&transcript[off], view->challenge, view->challenge_len);
    off += view->challenge_len;

    /* Re-encode LE32 (host order after deserialize). */
    faddr = (uint32_t)view->function_addr_le32;
    transcript[off++] = (uint8_t)(faddr);
    transcript[off++] = (uint8_t)(faddr >> 8);
    transcript[off++] = (uint8_t)(faddr >> 16);
    transcript[off++] = (uint8_t)(faddr >> 24);

    /* Bind to the current boot: a signature issued in a previous epoch
     * fails here, killing replay across the reboot that wiped the
     * anti-replay state. */
    transcript[off++] = (uint8_t)(boot_epoch_val);
    transcript[off++] = (uint8_t)(boot_epoch_val >> 8);
    transcript[off++] = (uint8_t)(boot_epoch_val >> 16);
    transcript[off++] = (uint8_t)(boot_epoch_val >> 24);

    transcript[off++] = (uint8_t)(view->seq);
    transcript[off++] = (uint8_t)(view->seq >> 8);
    transcript[off++] = (uint8_t)(view->seq >> 16);
    transcript[off++] = (uint8_t)(view->seq >> 24);

#ifdef POX_SYMMETRIC_REQUEST_AUTH
    /* sess_sig is the 32-byte HMAC-SHA256 tag; psa_mac_verify compares
     * it in constant time. */
    status = psa_mac_verify(verifier_key_handle,
                            PSA_ALG_HMAC(PSA_ALG_SHA_256),
                            transcript, off,
                            view->sess_sig, view->sess_sig_len);
#else
    /* sess_sig is 64-byte RAW r||s, not DER. */
    status = psa_verify_message(verifier_key_handle,
                                PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                                transcript, off,
                                view->sess_sig, view->sess_sig_len);
#endif
    if (status != PSA_SUCCESS) {
        POX_LOG_ERR("[Attest][PoX] Session signature invalid (%d): "
                   "request rejected, session ended\n", (int)status);
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* Monotonic seq high-water mark; see pox_session.c. */
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
            POX_LOG_ERR("[Attest][PoX] Stale seq %u (<= last %u): "
                       "request rejected\n", (unsigned int)view->seq,
                       (unsigned int)last_seq);
            return PSA_ERROR_NOT_PERMITTED;
        }
    }

    return PSA_SUCCESS;
}

#else /* !POX_REQUEST_AUTH_ATT */

/* Same link surface, no-ops. No epoch stub: the boot epoch only
 * exists with session auth. */
psa_status_t attest_session_init(void)
{
    return PSA_SUCCESS;
}

psa_status_t attest_session_authenticate(const sec_pox_view_t *view)
{
    (void)view;
    return PSA_SUCCESS;
}

#endif /* POX_REQUEST_AUTH_ATT */
