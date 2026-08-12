#ifndef ATTEST_EXECUTE_H
#define ATTEST_EXECUTE_H
#include "tfm_sp_log.h" // TF-M Secure Partition Logging
#include <stdbool.h>
#include <stdint.h>

typedef int (*ns_function_ptr_with_args_t)(const uint8_t *input, uint32_t input_len, uint8_t *output, uint32_t *output_len) __attribute__((cmse_nonsecure_call));
typedef int (*ns_function_ptr_void_t)(void) __attribute__((cmse_nonsecure_call));

/* 32 covers a SHA-256 digest. Must equal POX_EXEC_OUTPUT_MAX in the
 * other deployment: both emit the same IAT_POX_OUT claim and a verifier
 * cannot tell which produced a token. */
#define POX_EXEC_OUTPUT_MAX 32u

/**
 * @brief Secure-memory copy of what the attested function produced.
 *
 * The output buffer is non-secure, so reading it at encode time is a
 * TOCTOU - the untrusted world may rewrite it after the function
 * returns. ns_execute() copies here instead, still in Secure state on
 * return. Exact only under CONFIG_TFM_SECURE_THREAD_MASK_NS_INTERRUPT
 * (default 0); AIRCR.PRIS alone lets an NS IRQ preempt secure thread
 * mode. Attest from here, never from the NS buffer.
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

/* ns_execute() refused to run: output buffer was not Non-Secure. Not a
 * value an attested function can return, so callers can fail the
 * request instead of attesting it. */
#define ATTEST_EXEC_ERR_BAD_OUTPUT (-1000)

/**
 * @brief Execute a non-secure function from the secure world by address.
 *
 * @param output_len  bytes of output to attest, NOT the buffer capacity.
 *                    Addresses Secure storage; the callback cannot write it.
 * @param snap        may be NULL only if the result is not attested.
 */
int ns_execute(uintptr_t faddr, const uint8_t *input, uint32_t input_len,
               uint8_t *output, uint32_t *output_len,
               struct ns_exec_snapshot *snap);
int ns_execute_void(uintptr_t faddr);

#endif // ATTEST_EXECUTE_H