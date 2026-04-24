#ifndef POX_COMMON_H
#define POX_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Sizing limits */
#define IAT_MAX_NONCE_LEN               64
#define IAT_MAX_INSTANCE_ID_LEN         33
#define IAT_MAX_IMPL_ID_LEN             32
#define IAT_MAX_BOOT_SEED_LEN           32
#define IAT_MAX_PROFILE_STR             80
#define IAT_MAX_CERT_REF_STR            64
#define IAT_MAX_VERIF_SVC_STR           64
#define IAT_MAX_SW_COMPONENTS           16
#define IAT_MAX_MTYPE_STR               32
#define IAT_MAX_VERSION_STR             24
#define IAT_MAX_MEASUREMENT_LEN         32
#define IAT_MAX_SIGNER_ID_LEN           32
#define IAT_MAX_MEASDESC_STR            32
#define IAT_MAX_PLATFORM_CONFIG_LEN     64
#define IAT_MAX_HASH_ALGO_STR           32

typedef struct {
    char    type[IAT_MAX_MTYPE_STR];
    bool    has_type;
    uint8_t measurement[IAT_MAX_MEASUREMENT_LEN];
    size_t  measurement_len;
    char    version[IAT_MAX_VERSION_STR];
    bool    has_version;
    uint8_t signer_id[IAT_MAX_SIGNER_ID_LEN];
    size_t  signer_id_len;
    bool    has_signer_id;
    char    meas_desc[IAT_MAX_MEASDESC_STR];
    bool    has_meas_desc;
} SwComponent;

typedef struct {
    uint8_t  nonce[IAT_MAX_NONCE_LEN];
    size_t   nonce_len;
    uint8_t  instance_id[IAT_MAX_INSTANCE_ID_LEN];
    size_t   instance_id_len;
    uint8_t  implementation_id[IAT_MAX_IMPL_ID_LEN];
    size_t   implementation_id_len;
    uint32_t security_lifecycle;
    char     profile[IAT_MAX_PROFILE_STR];
    bool     has_profile;
    SwComponent sw[IAT_MAX_SW_COMPONENTS];
    size_t      sw_count;
    bool        has_sw;
    int32_t  client_id;
    bool     has_client_id;
    uint8_t  boot_seed[IAT_MAX_BOOT_SEED_LEN];
    size_t   boot_seed_len;
    bool     has_boot_seed;
    char     cert_ref[IAT_MAX_CERT_REF_STR];
    bool     has_cert_ref;
    uint32_t no_sw_components_val;
    bool     has_no_sw_components;
    char     verif_service[IAT_MAX_VERIF_SVC_STR];
    bool     has_verif_service;
    uint8_t  platform_config[IAT_MAX_PLATFORM_CONFIG_LEN];
    size_t   platform_config_len;
    bool     has_platform_config;
    char     hash_algo_id[IAT_MAX_HASH_ALGO_STR];
    bool     has_hash_algo_id;
} IATClaims;

#endif /* POX_COMMON_H */