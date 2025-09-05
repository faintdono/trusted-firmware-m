/* SPDX-License-Identifier: Apache-2.0 */
/*
 * tfm_pox_wire.h
 *
 * Wire format for NS <-> TF-M wrapper:
 * - u32 TLV lengths (no 64 KiB cap)
 * - optional CRC-32 at the end
 *
 * Wire (little-endian):
 *   // Fixed header (12 bytes)
 *   u8   ver = 1
 *   u8   flags;          // bit0: HAS_CRC32
 *   u16  hdr_len = 12
 *   u16  tlv_count
 *   u16  reserved = 0
 *   u32  input_len_dup
 *
 *   // TLVs (tlv_count entries)
 *   u16  type  (pox_tlv_type_t)
 *   u16  reserved2 = 0
 *   u32  len
 *   u8   val[len]
 *
 *   [ u32 crc32 ]        // present iff (flags & HAS_CRC32)
 *
 * Mandatory TLVs:
 *   CHALLENGE (len in [32..64])
 *   FUNC_ADDR (len == 4, LE; selector/ID, NOT an executable pointer)
 *   INPUT     (len == input_len_dup)
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

#define POX_WIRE_VERSION            (1u)
#define POX_WIRE_HEADER_LEN         (12u)

/* flags */
#define POX_WIRE_F_HAS_CRC32        (1u << 0)

/* TLV types */
typedef enum {
    POX_TLV_CHALLENGE = 0x0001,
    POX_TLV_FUNC_ADDR = 0x0002,
    POX_TLV_INPUT     = 0x0003,
} pox_tlv_type_t;

#define POX_CHALLENGE_LEN_MIN       (32u)
#define POX_CHALLENGE_LEN_MAX       (64u)

/* --------------------------- Status codes ------------------------------- */

typedef enum {
    SER_OK = 0,
    SER_EINVAL,
    SER_E2BIG,
    SER_EMALFORMED,
    SER_ECRC,
} ser_status_t;

/* -------------------- Non-Secure side: serializer ----------------------- */

typedef struct {
    const uint8_t *challenge;     /* non-NULL, length 32..64 */
    uint32_t       challenge_len; /* 32..64 */

    uint32_t      function_addr; /* 32-bit on wire (selector/ID) */

    const uint8_t *input;         /* may be NULL if input_len == 0 */
    uint32_t       input_len;     /* arbitrary size (u32) */

    bool           add_crc32;     /* append CRC-32 if true */
} ns_pox_call_req_t;

ser_status_t serialize_ns_pox_call(const ns_pox_call_req_t *req,
                                   uint8_t *out_buf, size_t out_cap,
                                   size_t *out_len);
                                   
ser_status_t pox_measure_ns_call(const ns_pox_call_req_t *req, size_t *needed);

/* ---------------------- Secure side: deserializer ----------------------- */

typedef struct {
    /* Required views (point into caller's buffer) */
    const uint8_t *challenge;     
    uint32_t challenge_len;
    uintptr_t       function_addr_le32;   /* selector/ID */
    const uint8_t *input;         
    uint32_t input_len;

    /* Header meta */
    uint8_t        version;       
    uint8_t flags; uint16_t tlv_count;
} sec_pox_view_t;

ser_status_t deserialize_ns_pox_call(const uint8_t *buf, size_t len,
                                     sec_pox_view_t *out);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* POX_WIRE_H */
