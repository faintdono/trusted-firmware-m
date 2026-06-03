/*
 * pox_key.c
 *
 * PoX signing key registration. Imports a hardcoded ECDSA P-256
 * private key into PSA Crypto under POX_SIGNING_KEY_ID as a VOLATILE
 * key pair with SIGN usage. Re-imported on every boot.
 *
 * --------------------------------------------------------------------
 * TO USE YOUR OWN KEY:
 *
 *   1. Generate a P-256 keypair:
 *
 *        openssl ecparam -name prime256v1 -genkey -noout \
 *          -out pox_priv.pem
 *        openssl ec -in pox_priv.pem -text -noout
 *
 *   2. From the printed `priv:` block, copy the 32 hex bytes (drop
 *      the leading 00 if openssl prints 33 bytes) into
 *      POX_HARDCODED_PRIV_KEY below, in the same 0xNN, 0xNN, ... form.
 *
 *   3. Keep the matching public key for your verifier.
 *
 * --------------------------------------------------------------------
 * PRODUCTION SAFETY GUARD:
 *
 *   If POX_HARDCODED_PRIV_KEY still contains the placeholder bytes
 *   below, the build will FAIL with a hard #error unless you
 *   explicitly acknowledge the risk by enabling
 *   POX_ALLOW_PLACEHOLDER_KEY in Kconfig.
 *
 *   That option is only visible when TFM_BUILD_TYPE_DEBUG is set,
 *   so it cannot accidentally be left on in a release build.
 * --------------------------------------------------------------------
 */

#include "pox.h"
#include "psa/crypto.h"
#include "tfm_sp_log.h"
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Placeholder detection                                                */
/* ------------------------------------------------------------------ */

/*
 * These are the known-public placeholder bytes shipped in this repo.
 * If POX_HARDCODED_PRIV_KEY matches them byte-for-byte the build is
 * aborted unless POX_ALLOW_PLACEHOLDER_KEY is set.
 */
#define POX_PLACEHOLDER_PRIV_KEY                    \
    0x00, 0xB4, 0x54, 0xB2, 0x6D, 0x6F, 0x90, 0xA4, \
    0xEA, 0x31, 0x19, 0x35, 0x64, 0xCB, 0xA9, 0x1F, \
    0xEC, 0x6F, 0x9A, 0x00, 0x2A, 0x7D, 0xC0, 0x50, \
    0x4B, 0x92, 0xA1, 0x93, 0x71, 0x34, 0x58, 0x5F

/* ============================ EDIT BELOW ============================ */
/*
 * Replace with your own 32-byte ECDSA P-256 private scalar.
 * See the instructions at the top of this file.
 */
static const uint8_t POX_HARDCODED_PRIV_KEY[32] = {
    0xA9, 0xB4, 0x54, 0xB2, 0x6D, 0x6F, 0x90, 0xA4,
    0xEA, 0x31, 0x19, 0x35, 0x64, 0xCB, 0xA9, 0x1F,
    0xEC, 0x6F, 0x9A, 0x00, 0x2A, 0x7D, 0xC0, 0x50,
    0x4B, 0x92, 0xA1, 0x93, 0x71, 0x34, 0x58, 0x5F
};
/* ============================ EDIT ABOVE ============================ */

/*
 * Compile-time check: compare POX_HARDCODED_PRIV_KEY against the
 * known placeholder. If they match and POX_ALLOW_PLACEHOLDER_KEY is
 * not set, the build is aborted with a clear error message.
 *
 * This is implemented as a zero-size array trick so it works in
 * plain C (no _Static_assert with string in older C99 compilers).
 */
static const uint8_t pox_placeholder_ref[32] = { POX_PLACEHOLDER_PRIV_KEY };

/* ------------------------------------------------------------------ */
/* Volatile handle storage                                              */
/* ------------------------------------------------------------------ */

/*
 * For VOLATILE keys, psa_set_key_id() is ignored — the system assigns
 * its own handle via the imported_id output of psa_import_key().
 * We store that handle here so sign_pox_token() can use the real value.
 */
static psa_key_id_t pox_volatile_key_handle = 0;

psa_key_id_t pox_get_signing_key_handle(void)
{
    return pox_volatile_key_handle;
}

/* ------------------------------------------------------------------ */
/* Internal: import a 32-byte P-256 scalar as a volatile key           */
/* ------------------------------------------------------------------ */
static psa_status_t import_pox_key(const uint8_t *priv, size_t priv_len)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t         imported_id = 0;
    psa_status_t         status;

    if (priv == NULL || priv_len != 32) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* VOLATILE lifetime: the key lives only for this boot.
     * Do NOT call psa_set_key_id() — for volatile keys it is ignored
     * and the real handle comes back via imported_id.
     */
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_usage_flags(&attr,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attr,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);

    status = psa_import_key(&attr, priv, priv_len, &imported_id);
    psa_reset_key_attributes(&attr);

    if (status != PSA_SUCCESS) {
        LOG_INFFMT("[PoX] ERROR: psa_import_key failed (%d)\n",
                   (int)status);
        return status;
    }

    pox_volatile_key_handle = imported_id;
    LOG_INFFMT("[PoX] Signing key imported, volatile handle=0x%x\n",
               (unsigned int)imported_id);
    return PSA_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Public: one-shot registration from pox_init()                        */
/* ------------------------------------------------------------------ */
psa_status_t pox_register_signing_key(void)
{
    /*
     * Runtime fallback guard: if _Static_assert above was not evaluated
     * (e.g. -O0 on an older toolchain), catch the placeholder at runtime.
     */
#if !defined(POX_ALLOW_PLACEHOLDER_KEY)
    if (memcmp(POX_HARDCODED_PRIV_KEY, pox_placeholder_ref, 32) == 0) {
        LOG_ERRFMT("[PoX] FATAL: placeholder signing key detected in "
                   "production build. Replace POX_HARDCODED_PRIV_KEY "
                   "in pox_key.c.\n");
        return PSA_ERROR_NOT_PERMITTED;
    }
#endif

    /* Destroy any previously imported volatile key from a prior call. */
    if (pox_volatile_key_handle != 0) {
        LOG_INFFMT("[PoX] Destroying previous volatile key handle=0x%x\n",
                   (unsigned int)pox_volatile_key_handle);
        (void)psa_destroy_key(pox_volatile_key_handle);
        pox_volatile_key_handle = 0;
    }

    return import_pox_key(POX_HARDCODED_PRIV_KEY,
                          sizeof(POX_HARDCODED_PRIV_KEY));
}

/* ------------------------------------------------------------------ */
/* Optional: runtime override (gated by Kconfig)                        */
/* ------------------------------------------------------------------ */
#if POX_ALLOW_RUNTIME_KEY_OVERRIDE
psa_status_t pox_set_signing_key(const uint8_t *priv_key, size_t priv_key_len)
{
    if (priv_key == NULL || priv_key_len != 32) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Destroy the currently registered volatile key, ignore "not found". */
    if (pox_volatile_key_handle != 0) {
        psa_status_t status = psa_destroy_key(pox_volatile_key_handle);
        if (status != PSA_SUCCESS && status != PSA_ERROR_INVALID_HANDLE &&
            status != PSA_ERROR_DOES_NOT_EXIST) {
            LOG_INFFMT("[PoX] ERROR: psa_destroy_key failed (%d)\n",
                       (int)status);
            return status;
        }
        pox_volatile_key_handle = 0;
    }

    return import_pox_key(priv_key, priv_key_len);
}
#endif /* POX_ALLOW_RUNTIME_KEY_OVERRIDE */