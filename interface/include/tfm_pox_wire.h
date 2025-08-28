/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tfm_pox_wire.h
 *
 * Wire-format definitions, public structs, and function prototypes
 * for the Non-Secure serializer and the Secure-side deserializer
 * used to invoke an Initial Attestation wrapper over TF-M IPC.
 *
 * Wire format (little-endian):
 *   // Fixed header (12 bytes)
 *   u8  ver = 1
 *   u8  flags = 0
 *   u16 hdr_len = 12
 *   u16 tlv_count
 *   u16 reserved = 0
 *   u32 input_len_dup  // duplicate of INPUT TLV length for quick validation
 *
 *   // TLVs (tlv_count entries)
 *   repeated {
 *     u16 type   // see pox_tlv_type_t
 *     u16 len    // value length in bytes (NOTE: u16; max 65535)
 *     u8  val[len]
 *   }
 *
 * Mandatory TLVs:
 *   CHALLENGE (len in [32..64])
 *   FUNC_ADDR (len == 4)    // 32-bit value; treat as selector/ID, not a raw pointer
 *   INPUT     (len == input_len_dup)
 *
 * Security notes:
 *   - Treat FUNC_ADDR as an opaque selector; never jump to a Non-Secure
 *     address from Secure World. Map to an allowlisted secure handler.
 *   - If you need >64 KiB INPUT, switch TLV length to u32 in both ends.
 */

#ifndef TFM_POX_WIRE_H
#define TFM_POX_WIRE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------- Constants ---------------------------------- */

/** Current wire version placed in header.ver */
#define POX_WIRE_VERSION                (1u)

/** Fixed header size in bytes */
#define POX_WIRE_HEADER_LEN             (12u)

/** TLV type identifiers (u16) */
typedef enum {
    POX_TLV_CHALLENGE = 0x0001,  /**< value: 32..64 bytes */
    POX_TLV_FUNC_ADDR = 0x0002,  /**< value: le32 function selector/address */
    POX_TLV_INPUT     = 0x0003,  /**< value: arbitrary bytes; len must equal header.input_len_dup */
} pox_tlv_type_t;

/** Challenge length bounds (bytes) */
#define POX_CHALLENGE_LEN_MIN           (32u)
#define POX_CHALLENGE_LEN_MAX           (64u)

/* --------------------------- Status codes ------------------------------- */

typedef enum {
    SER_OK = 0,          /**< Success */
    SER_EINVAL,          /**< Invalid arguments / inconsistent fields */
    SER_E2BIG,           /**< Destination buffer too small */
    SER_EMALFORMED,      /**< Malformed input buffer (deserializer) */
} ser_status_t;

/* -------------------- Non-Secure side: serializer ----------------------- */

/**
 * Input parameters for Non-Secure serializer.
 * NOTE: On Armv8-M TF-M targets, pointers are 32-bit; the wire format encodes
 * FUNC_ADDR as 32-bit LE. Treat it as a selector/ID; do NOT execute it.
 */
typedef struct {
    const uint8_t *challenge;     /**< Must be non-NULL, length 32..64 */
    uint16_t       challenge_len; /**< 32..64 bytes */

    uintptr_t      function_addr; /**< 32-bit value on the wire (selector/ID) */

    const uint8_t *input;         /**< May be NULL if input_len == 0 */
    uint32_t       input_len;     /**< Length of arbitrary input payload */
} ns_pox_call_req_t;

/**
 * Serialize {challenge, function selector, input} into a single byte buffer
 * suitable for psa_invec[0]. Little-endian, TLV-based, versioned header.
 *
 * @param[in]  req      Populated request fields.
 * @param[out] out_buf  Destination buffer (caller-provided).
 * @param[in]  out_cap  Capacity of @out_buf in bytes.
 * @param[out] out_len  On success, number of bytes written.
 *
 * @return SER_OK on success; SER_EINVAL or SER_E2BIG otherwise.
 */
ser_status_t serialize_ns_pox_call(const ns_pox_call_req_t *req,
                                   uint8_t *out_buf, size_t out_cap,
                                   size_t *out_len);

/* ---------------------- Secure side: deserializer ----------------------- */

/**
 * Zero-copy view of the parsed request inside the TF-M partition.
 * Pointers refer to the original psa_invec buffer; copy if needed after unmap.
 */
typedef struct {
    /* Required */
    const uint8_t *challenge;
    uint16_t       challenge_len;       /**< 32..64 */

    uint32_t       function_addr_le32;  /**< Opaque 32-bit selector from Non-Secure */

    const uint8_t *input;               /**< Arbitrary payload (may be NULL if len==0) */
    uint32_t       input_len;           /**< Source: header.input_len_dup */

    /* Header metadata */
    uint8_t        version;             /**< Should be POX_WIRE_VERSION */
    uint16_t       tlv_count;
} sec_req_view_t;

/**
 * Parse the single invec produced by serialize_ns_pox_call().
 *
 * @param[in]  buf   Pointer to invec bytes.
 * @param[in]  len   Length of @buf in bytes.
 * @param[out] out   Filled view with pointers into @buf (no allocations).
 *
 * @return SER_OK on success; SER_EMALFORMED or SER_EINVAL on errors.
 */
ser_status_t deserialize_ns_pox_call(const uint8_t *buf, size_t len,
                                     sec_req_view_t *out);

/* ----------------------------- Options ---------------------------------- */

/**
 * Optional: compile-time guard to ensure 32-bit pointers on the Non-Secure build
 * if you include this header there. Define pox_REQUIRE_32BIT_PTRS to enforce.
 */
#if defined(POX_REQUIRE_32BIT_PTRS)
#  include <limits.h>
#  if UINTPTR_MAX != 0xFFFFFFFFu
#    error "This wire format encodes FUNC_ADDR as 32-bit; adjust the format or build flags."
#  endif
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* POX_WIRE_H */
