#include "tfm_pox_wire.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* ---------- Implementation ---------- */

static inline void le16_store(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}
static inline void le32_store(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}
static inline bool add_overflow_size(size_t a, size_t b, size_t *out) {
#if defined(__has_builtin)
#  if __has_builtin(__builtin_add_overflow)
    return __builtin_add_overflow(a, b, out);
#  endif
#endif
    size_t s = a + b; *out = s; return s < a;
}

ser_status_t serialize_ns_pox_call(const ns_pox_call_req_t *req,
                                   uint8_t *out_buf, size_t out_cap,
                                   size_t *out_len)
{
    if (!req || !out_buf || !out_len) return SER_EINVAL;
    if (!req->challenge) return SER_EINVAL;
    if (req->challenge_len < POX_CHALLENGE_LEN_MIN || req->challenge_len > POX_CHALLENGE_LEN_MAX) return SER_EINVAL;
    if (req->input_len > 0 && req->input == NULL) return SER_EINVAL;

    /* This wire format encodes function address as 32-bit.
       On Armv8-M TF-M targets, pointers are 32-bit; assert at build time. */
    _Static_assert(sizeof(uintptr_t) == 4, "This serializer assumes 32-bit pointers.");

    size_t off = 0;

    /* Header: 12 bytes */
    if (out_cap < POX_WIRE_HEADER_LEN) return SER_E2BIG;
    out_buf[off++] = POX_WIRE_VERSION;               /* ver */
    out_buf[off++] = 0;               /* flags */
    le16_store(&out_buf[off], POX_WIRE_HEADER_LEN); off += 2;  /* hdr_len */
    size_t tlv_count_pos = off; off += 2;     /* to be patched */
    le16_store(&out_buf[off], 0);     off += 2;  /* reserved */
    le32_store(&out_buf[off], req->input_len); off += 4;  /* input_len_dup */

    uint16_t tlv_count = 0;

    /* TLV: CHALLENGE */
    {
        size_t need;
        if (add_overflow_size(off, 4u + req->challenge_len, &need)) return SER_E2BIG;
        if (need > out_cap) return SER_E2BIG;
        le16_store(&out_buf[off], POX_TLV_CHALLENGE); off += 2;
        le16_store(&out_buf[off], req->challenge_len); off += 2;
        memcpy(&out_buf[off], req->challenge, req->challenge_len); off += req->challenge_len;
        tlv_count++;
    }

    /* TLV: FUNC_ADDR (4 bytes, LE) */
    {
        size_t need = off + 4u + 4u;
        if (need > out_cap) return SER_E2BIG;
        le16_store(&out_buf[off], POX_TLV_FUNC_ADDR); off += 2;
        le16_store(&out_buf[off], 4);            off += 2;
        le32_store(&out_buf[off], (uint32_t)req->function_addr); off += 4;
        tlv_count++;
    }

    /* TLV: INPUT (may be empty) */
    {
        size_t need;
        if (add_overflow_size(off, 4u + req->input_len, &need)) return SER_E2BIG;
        if (need > out_cap) return SER_E2BIG;
        le16_store(&out_buf[off], POX_TLV_INPUT); off += 2;
        le16_store(&out_buf[off], (uint16_t)((req->input_len <= 0xFFFFu) ? req->input_len : 0xFFFFu)); /* len field is u16 in TLV */
        /* IMPORTANT: To carry arbitrary 32-bit input_len, we rely on the header's input_len_dup for the true length.
           The TLV length here carries up to 65535 bytes. If you need >64KB, chunk or adjust TLV to u32 length. */
        uint16_t tlv_len = (uint16_t)((req->input_len <= 0xFFFFu) ? req->input_len : 0xFFFFu);
        if (tlv_len) { memcpy(&out_buf[off], req->input, tlv_len); }
        off += tlv_len;
        tlv_count++;
    }

    /* Patch tlv_count */
    le16_store(&out_buf[tlv_count_pos], tlv_count);

    *out_len = off;
    return SER_OK;
}
