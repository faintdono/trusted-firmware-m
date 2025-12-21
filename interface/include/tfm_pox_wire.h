/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tfm_pox_wire.h
 *
 * Wire format for NS <-> TF-M PoX wrapper
 * - All multi-byte integers are little-endian
 * - TLV lengths are u32 (no 64 KiB cap)
 * - Optional CRC-32 appended at the end
 *
 * Wire (little-endian):
 *   // Fixed header (16 bytes)
 *   u8   ver = 1
 *   u8   flags;             // bit0: HAS_CRC32
 *   u16  hdr_len = 16
 *   u16  tlv_count
 *   u16  reserved = 0
 *   u32  input_len_dup
 *   u32  output_len_dup
 *
 *   // TLVs (tlv_count entries)
 *   u16  type  (pox_tlv_type_t)
 *   u16  reserved2 = 0
 *   u32  len
 *   u8   val[len]
 *
 *   [ u32 crc32 ]           // present iff (flags & HAS_CRC32)
 *
 * Mandatory TLVs:
 *   CHALLENGE (len in [32..64])
 *   FUNC_ADDR (len == 4, LE; selector/ID, NOT an executable pointer)
 *   INPUT_ADDR  (len == 4)   iff input_len_dup  != 0
 *   OUTPUT_ADDR (len == 4)   iff output_len_dup != 0
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

#define POX_WIRE_VERSION             (2u)

/* Fixed header length (see format above) */
#define POX_WIRE_HEADER_LEN          (16u)

/* flags */
#define POX_WIRE_F_HAS_CRC32         (1u << 0)

/* TLV types
 * NOTE: The output address type name is kept exactly as provided (POV_…).
 */
typedef enum {
    POX_TLV_CHALLENGE   = 0x0001,
    POX_TLV_FUNC_ADDR   = 0x0002,
    POX_TLV_INPUT_ADDR  = 0x0003,
    POX_TLV_OUTPUT_ADDR = 0x0004
} pox_tlv_type_t;

#define POX_CHALLENGE_LEN_MIN        (32u)
#define POX_CHALLENGE_LEN_MAX        (64u)

/* --------------------------- Status codes ------------------------------- */

typedef enum {
    SER_OK = 0,
    SER_EINVAL,
    SER_E2BIG,
    SER_EMALFORMED,
    SER_ECRC,
} ser_status_t;

/* -------------------- Non-Secure side: serializer ----------------------- */
/* The NS request encodes addresses as 32-bit on the wire (LE).
 * For 32-bit platforms, (uint32_t)(uintptr_t) identity holds.
 */

typedef struct {
    const uint8_t *challenge;     /* non-NULL, length 32..64 */
    uint32_t       challenge_len; /* 32..64 */

    uint32_t       function_addr; /* 32-bit on wire (selector/ID) */

    uint32_t       input;         /* NS address; may be 0 if input_len == 0 */
    uint32_t       input_len;     /* bytes */

    uint32_t       output;        /* NS address; may be 0 if output_len == 0 */
    uint32_t       output_len;    /* bytes (capacity) */

    bool           add_crc32;     /* append CRC-32 if true */
} ns_pox_call_req_t;

/* Serialize NS request into a wire buffer */
ser_status_t serialize_ns_pox_call(const ns_pox_call_req_t *req,
                                   uint8_t *out_buf, size_t out_cap,
                                   size_t *out_len);

/* Compute required wire buffer size for a given request */
ser_status_t pox_measure_ns_call(const ns_pox_call_req_t *req, size_t *needed);

/* ---------------------- Secure side: deserializer ----------------------- */
/* The Secure view points into the caller's buffer for CHALLENGE only.
 * Addresses are surfaced as uintptr_t after LE32 decode.
 */

typedef struct {
    /* Required views (CHALLENGE points into caller's buffer) */
    const uint8_t *challenge;
    uint32_t       challenge_len;

    uintptr_t      function_addr_le32;  /* selector/ID */
    uintptr_t      input;               /* NS address (0 if input_len == 0) */
    uint32_t       input_len;           /* from header (input_len_dup) */

    uintptr_t      output;              /* NS address (0 if output_len == 0) */
    uint32_t       output_len;          /* from header (output_len_dup) */

    /* Header meta */
    uint8_t        version;
    uint8_t        flags;
    uint16_t       tlv_count;
} sec_pox_view_t;

/* Deserialize a wire message into a Secure view */
ser_status_t deserialize_ns_pox_call(const uint8_t *buf, size_t len,
                                     sec_pox_view_t *out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* TFM_POX_WIRE_H */
