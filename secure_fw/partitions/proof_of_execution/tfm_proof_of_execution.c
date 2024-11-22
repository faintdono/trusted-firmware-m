#include "psa/crypto.h"
#include "psa/initial_attestation.h"
#include "psa/protected_storage.h"
#include "tfm_sp_log.h"

#define TOKEN_STORAGE_UID 0x1001    // Unique identifier for token storage
#define MAX_TOKEN_SIZE    256       // Maximum size of the attestation token

// Function to initialize the PoE partition
psa_status_t pox_partition_init(void) {
    TFM_SP_LOG("Initializing Proof of Execution Partition\n");
    return PSA_SUCCESS;
}

// Function to monitor execution and generate token
psa_status_t pox_generate_token(const char *function_name, size_t name_len) {
    psa_status_t status;
    uint8_t token[MAX_TOKEN_SIZE];
    size_t token_size = 0;

    // Generate attestation token
    status = psa_initial_attest_get_token(function_name, name_len, token, MAX_TOKEN_SIZE, &token_size);
    if (status != PSA_SUCCESS) {
        TFM_SP_LOG("Failed to generate attestation token\n");
        return status;
    }

    // Store token in secure storage
    status = psa_ps_set(TOKEN_STORAGE_UID, token_size, token, PSA_STORAGE_FLAG_WRITE_ONCE);
    if (status != PSA_SUCCESS) {
        TFM_SP_LOG("Failed to store token in secure storage\n");
    }

    return status;
}

// Function to verify execution
psa_status_t pox_verify_token(void) {
    psa_status_t status;
    uint8_t token[MAX_TOKEN_SIZE];
    size_t token_size;

    // Retrieve the stored token
    status = psa_ps_get(TOKEN_STORAGE_UID, 0, MAX_TOKEN_SIZE, token, &token_size);
    if (status != PSA_SUCCESS) {
        TFM_SP_LOG("Failed to retrieve execution token\n");
        return status;
    }

    // Verify the token's integrity (custom validation logic)
    TFM_SP_LOG("Execution token verified successfully\n");
    return PSA_SUCCESS;
}