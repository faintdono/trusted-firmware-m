/*
 * pox_common.h
 *
 * Shared types for the PoX IAT decoder and encoder.
 * IATClaims mirrors the EAT claims emitted by the attestation service,
 * with CCA-only fields guarded by ATTEST_TOKEN_PROFILE_ARM_CCA.
 */

#ifndef POX_COMMON_H
#define POX_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "config_tfm.h"   /* pulls in ATTEST_TOKEN_PROFILE_* defines */

/*
 * PoX session-authentication claim labels: CBOR private-use range
 * (negative, below the -65536 boundary reserved by CoRIM/EAT).
 */
#define POX_LABEL_SESSION_ID    (-65537)
#define POX_LABEL_CALLER_ID     (-65538)
#define POX_LABEL_BOOT_EPOCH    (-65539)
/* Verifier transcript signature (64B raw r||s), embedded whenever
 * session auth is enabled: makes the token self-contained
 * authorization evidence for third parties. */
#define POX_LABEL_SESS_SIG      (-65540)
/* Verifier-assigned monotonic request sequence (POX_SEQ_AUTH builds):
 * lets an auditor order executions within a boot and, with the boot
 * epoch, across boots. */
#define POX_LABEL_SEQ           (-65541)

#define MAX_SW_COMPONENTS       16
#define MAX_MEASUREMENT_LEN     64
#define MAX_SIGNER_ID_LEN       64
#define MAX_VERSION_LEN         32
#define MAX_TYPE_LEN            32
#define MAX_MEAS_DESC_LEN       64

typedef struct {
    bool     has_type;
    char     type[MAX_TYPE_LEN];

    uint8_t  measurement[MAX_MEASUREMENT_LEN];
    uint32_t measurement_len;

    bool     has_version;
    char     version[MAX_VERSION_LEN];

    bool     has_signer_id;
    uint8_t  signer_id[MAX_SIGNER_ID_LEN];
    uint32_t signer_id_len;

    bool     has_meas_desc;
    char     meas_desc[MAX_MEAS_DESC_LEN];
} SwComponent;

typedef struct {
    /* Nonce */
    uint8_t  nonce[64];
    uint32_t nonce_len;

    /* Instance ID */
    uint8_t  instance_id[33];
    uint32_t instance_id_len;

    /* Implementation ID */
    uint8_t  implementation_id[32];
    uint32_t implementation_id_len;

    /* Security lifecycle */
    uint32_t security_lifecycle;

    /* Profile definition */
    bool     has_profile;
    char     profile[64];

#if ATTEST_TOKEN_PROFILE_PSA_IOT_1 || ATTEST_TOKEN_PROFILE_PSA_2_0_0
    /* Boot seed (PSA_IOT_1 / PSA_2_0_0 only) */
    bool     has_boot_seed;
    uint8_t  boot_seed[32];
    uint32_t boot_seed_len;

    /* Client ID */
    bool     has_client_id;
    int32_t  client_id;

    /* Certification reference (optional) */
    bool     has_cert_ref;
    char     cert_ref[64];
#endif

#if ATTEST_TOKEN_PROFILE_ARM_CCA
    /* Platform config (CCA only) */
    bool     has_platform_config;
    uint8_t  platform_config[64];
    uint32_t platform_config_len;

    /* Platform hash algo ID (CCA only) */
    bool     has_hash_algo_id;
    char     hash_algo_id[32];
#endif

    /* Verification service (optional, all profiles) */
    bool     has_verif_service;
    char     verif_service[128];

    /* SW components */
    bool        has_sw;
    SwComponent sw[MAX_SW_COMPONENTS];
    size_t      sw_count;

    /* No-SW-components fallback */
    bool    has_no_sw_components;
    int32_t no_sw_components_val;
} IATClaims;

#endif /* POX_COMMON_H */