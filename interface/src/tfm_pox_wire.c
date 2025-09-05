#include "tfm_pox_wire.h"
#include <string.h>

_Static_assert(sizeof(uintptr_t) == 4,
               "FUNC_ADDR on wire is 32-bit; adjust format or target.");

static inline void le16_store(uint8_t *p, uint16_t v){ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static inline void le32_store(uint8_t *p, uint32_t v){
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static inline uint32_t crc32_le(const uint8_t *data, size_t len){
    uint32_t crc=0xFFFFFFFFu;
    for(size_t i=0;i<len;i++){ crc^=data[i];
        for(unsigned k=0;k<8;k++){ uint32_t m=-(crc&1u); crc=(crc>>1)^(0xEDB88320u & m); } }
    return ~crc;
}
static inline bool add_ov(size_t a, size_t b, size_t *o){
#if defined(__has_builtin) && __has_builtin(__builtin_add_overflow)
    return __builtin_add_overflow(a,b,o);
#else
    size_t s=a+b; *o=s; return s<a;
#endif
}

static ser_status_t put_tlv(uint8_t *out, size_t cap, size_t *off,
                            uint16_t type, const void *val, uint32_t len,
                            uint16_t *tlv_count)
{
    size_t need;
    if (add_ov(*off, (size_t)8 + (size_t)len, &need)) return SER_E2BIG;
    if (need > cap) return SER_E2BIG;

    le16_store(&out[*off], type); *off += 2;
    le16_store(&out[*off], 0);    *off += 2;         /* reserved2 */
    le32_store(&out[*off], len);  *off += 4;

    if (len) { memcpy(&out[*off], val, len); *off += len; }
    (*tlv_count)++;
    return SER_OK;
}

ser_status_t serialize_ns_pox_call(const ns_pox_call_req_t *req,
                                   uint8_t *out, size_t cap, size_t *out_len)
{
    if(!req || !out || !out_len) return SER_EINVAL;
    if(!req->challenge) return SER_EINVAL;
    if(req->challenge_len < POX_CHALLENGE_LEN_MIN ||
       req->challenge_len > POX_CHALLENGE_LEN_MAX) return SER_EINVAL;
    if(req->input_len && !req->input) return SER_EINVAL;

    size_t off = 0;
    if(cap < POX_WIRE_HEADER_LEN) return SER_E2BIG;

    /* header */
    out[off++] = POX_WIRE_VERSION;
    out[off++] = (uint8_t)(req->add_crc32 ? POX_WIRE_F_HAS_CRC32 : 0);
    le16_store(&out[off], POX_WIRE_HEADER_LEN); off += 2;
    size_t tlv_count_pos = off; off += 2;
    le16_store(&out[off], 0); off += 2;                   /* reserved */
    le32_store(&out[off], req->input_len); off += 4;      /* input_len_dup */

    uint16_t tlv_count = 0;

    /* TLV: CHALLENGE */
    { ser_status_t st = put_tlv(out, cap, &off, POX_TLV_CHALLENGE,
                                req->challenge, req->challenge_len, &tlv_count);
      if(st != SER_OK) return st; }

    /* TLV: FUNC_ADDR (4 bytes LE) */
    { uint8_t tmp[4]; le32_store(tmp, (uint32_t)req->function_addr);
      ser_status_t st = put_tlv(out, cap, &off, POX_TLV_FUNC_ADDR,
                                tmp, 4, &tlv_count);
      if(st != SER_OK) return st; }

    /* TLV: INPUT */
    { ser_status_t st = put_tlv(out, cap, &off, POX_TLV_INPUT,
                                req->input, req->input_len, &tlv_count);
      if(st != SER_OK) return st; }

    /* patch tlv_count */
    le16_store(&out[tlv_count_pos], tlv_count);

    /* optional CRC32 */
    if(req->add_crc32){
        size_t need;
        if(add_ov(off, (size_t)4, &need)) return SER_E2BIG;
        if(need > cap) return SER_E2BIG;
        uint32_t crc = crc32_le(out, off);
        le32_store(&out[off], crc); off += 4;
    }

    *out_len = off;
    return SER_OK;
}

ser_status_t pox_measure_ns_call(const ns_pox_call_req_t *req, size_t *needed)
{
    if (!req || !needed) return SER_EINVAL;
    if (!req->challenge) return SER_EINVAL;
    if (req->challenge_len < POX_CHALLENGE_LEN_MIN ||
        req->challenge_len > POX_CHALLENGE_LEN_MAX) return SER_EINVAL;
    if (req->input_len && !req->input) return SER_EINVAL;

    size_t n = 0, tmp;

    // header
    n = POX_WIRE_HEADER_LEN;

    // TLV: CHALLENGE (8 + challenge_len)
    if (add_ov(n, 8u + (size_t)req->challenge_len, &tmp)) return SER_E2BIG; n = tmp;

    // TLV: FUNC_ADDR (8 + 4)
    if (add_ov(n, 8u + 4u, &tmp)) return SER_E2BIG; n = tmp;

    // TLV: INPUT (8 + input_len)
    if (add_ov(n, 8u + (size_t)req->input_len, &tmp)) return SER_E2BIG; n = tmp;

    // Optional CRC
    if (req->add_crc32) { if (add_ov(n, 4u, &tmp)) return SER_E2BIG; n = tmp; }

    *needed = n;
    return SER_OK;
}
