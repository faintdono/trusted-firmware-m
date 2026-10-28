#ifndef ATTEST_EXECUTE_H
#define ATTEST_EXECUTE_H
#include "tfm_sp_log.h"
#include <stdbool.h>
#include <stdint.h>
#include "psa/crypto.h"
#include "tfm_pox_wire.h"   /* POX_FUNC_LEN_MAX, POX_INPUT_HASH_MAX */

typedef int (*ns_function_ptr_with_args_t)(const uint8_t *input, uint32_t input_len, uint8_t *output, uint32_t *output_len) __attribute__((cmse_nonsecure_call));
typedef int (*ns_function_ptr_void_t)(void) __attribute__((cmse_nonsecure_call));

/* 32 covers a SHA-256 digest. Must equal POX_EXEC_OUTPUT_MAX in the
 * other deployment: both emit the same IAT_POX_OUT claim and a verifier
 * cannot tell which produced a token. */
#define POX_EXEC_OUTPUT_MAX 32u

/**
 * @brief Secure-memory copy of what the attested function produced.
 *
 * The NS output buffer is attacker-writable, so encoding from it is a
 * TOCTOU; attest_ns_execute() copies here while still Secure. Exact only
 * under CONFIG_TFM_SECURE_THREAD_MASK_NS_INTERRUPT (default 0):
 * AIRCR.PRIS alone lets an NS IRQ preempt secure thread mode. Attest
 * from here, never from the NS buffer.
 */
struct ns_exec_snapshot {
    uint8_t  out[POX_EXEC_OUTPUT_MAX];
    uint32_t out_len;     /* bytes captured: min(*output_len, MAX) */
    bool     valid;
};

/* True when [p, p+len) is wholly Non-Secure. The caller names the
 * output address, and the snapshot copy reads it from Secure state, so
 * a Secure address would be signed into the token. */
bool attest_ns_buffer_ok(const void *p, uint32_t len);

/* attest_ns_execute() refused to run: output buffer was not Non-Secure. Not a
 * value an attested function can return, so callers can fail the
 * request instead of attesting it. */
#define ATTEST_EXEC_ERR_BAD_OUTPUT (-1000)

/**
 * @brief Execute a non-secure function from the secure world by address.
 *
 * @param output_len  bytes to attest, NOT buffer capacity; Secure
 *                    storage, the callback cannot write it
 * @param snap        NULL only if the result is not attested
 */
int attest_ns_execute(uintptr_t faddr, const uint8_t *input, uint32_t input_len,
               uint8_t *output, uint32_t *output_len,
               struct ns_exec_snapshot *snap);
int attest_ns_execute_void(uintptr_t faddr);


/* SHA-256 digest length of the pre-execution measurements. */
#define POX_MEASURE_HASH_LEN 32u

/**
 * @brief Secure-memory hashes of F's code and input, taken right before
 *        F runs. F can rewrite both while it runs; these record the
 *        state it started from.
 */
struct ns_exec_measurement {
    uint8_t func_hash[POX_MEASURE_HASH_LEN];
    uint8_t input_hash[POX_MEASURE_HASH_LEN];
    /* The input itself, valid when has_input_value. */
    uint8_t  input_value[POX_INPUT_CLAIM_MAX];
    uint32_t input_value_len;
    bool     has_input_value;
};

/**
 * @brief SHA-256 of [faddr & ~1, +func_len) and of [input, +input_len).
 *
 * Both ranges must be wholly Non-Secure: hashing Secure memory would
 * leak it into the token. An empty input hashes to SHA-256(""). An
 * input of at most POX_INPUT_CLAIM_MAX bytes is copied once into
 * meas->input_value and hashed from that copy, so the raw value and
 * the hash in the token always agree. Call
 * immediately before attest_ns_execute*().
 *
 * @retval PSA_ERROR_INVALID_ARGUMENT  bad range or length
 */
psa_status_t attest_ns_measure(uintptr_t faddr, uint32_t func_len,
                         const uint8_t *input, uint32_t input_len,
                         struct ns_exec_measurement *meas);

#endif // ATTEST_EXECUTE_H