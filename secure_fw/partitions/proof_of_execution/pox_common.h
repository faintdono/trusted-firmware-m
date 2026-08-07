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
 * Session-auth claim labels: CBOR private-use range (negative, below
 * the -65536 boundary reserved by CoRIM/EAT). SESS_SIG carries the
 * 64B raw r||s verifier transcript signature, making the token
 * self-contained authorization evidence for third parties; SEQ lets
 * an auditor order executions within a boot (and, with BOOT_EPOCH,
 * across boots).
 */
#define POX_LABEL_SESSION_ID    (-65537)
#define POX_LABEL_CALLER_ID     (-65538)
#define POX_LABEL_BOOT_EPOCH    (-65539)
#define POX_LABEL_SESS_SIG      (-65540)
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
    uint8_t  nonce[64];
    uint32_t nonce_len;

    uint8_t  instance_id[33];
    uint32_t instance_id_len;

    uint8_t  implementation_id[32];
    uint32_t implementation_id_len;

    uint32_t security_lifecycle;

    bool     has_profile;
    char     profile[64];

#if ATTEST_TOKEN_PROFILE_PSA_IOT_1 || ATTEST_TOKEN_PROFILE_PSA_2_0_0
    bool     has_boot_seed;
    uint8_t  boot_seed[32];
    uint32_t boot_seed_len;

    bool     has_client_id;
    int32_t  client_id;

    bool     has_cert_ref;
    char     cert_ref[64];
#endif

#if ATTEST_TOKEN_PROFILE_ARM_CCA
    bool     has_platform_config;
    uint8_t  platform_config[64];
    uint32_t platform_config_len;

    bool     has_hash_algo_id;
    char     hash_algo_id[32];
#endif

    bool     has_verif_service;
    char     verif_service[128];

    bool        has_sw;
    SwComponent sw[MAX_SW_COMPONENTS];
    size_t      sw_count;

    bool    has_no_sw_components;
    int32_t no_sw_components_val;
} IATClaims;

#endif /* POX_COMMON_H */