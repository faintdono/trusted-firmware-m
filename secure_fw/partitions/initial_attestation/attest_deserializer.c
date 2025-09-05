#include "tfm_pox_wire.h"
#include <string.h>

static inline uint16_t le16_load(const uint8_t *p){ return (uint16_t)(p[0] | ((uint16_t)p[1]<<8)); }
static inline uint32_t le32_load(const uint8_t *p){ return (uint32_t)(p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24)); }
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

ser_status_t deserialize_ns_pox_call(const uint8_t *buf, size_t len,
                                     sec_pox_view_t *out)
{
    if(!buf || !out) return SER_EINVAL;
    memset(out, 0, sizeof(*out));

    if(len < POX_WIRE_HEADER_LEN) return SER_EMALFORMED;

    const uint8_t  ver      = buf[0];
    const uint8_t  flags    = buf[1];
    const uint16_t hdr_len  = le16_load(&buf[2]);
    const uint16_t tlv_cnt  = le16_load(&buf[4]);
    const uint32_t in_len_d = le32_load(&buf[8]);

    if(ver != POX_WIRE_VERSION) return SER_EMALFORMED;
    if(hdr_len != POX_WIRE_HEADER_LEN) return SER_EMALFORMED;
    if(hdr_len > len) return SER_EMALFORMED;

    size_t tlvs_end = len;
    if(flags & POX_WIRE_F_HAS_CRC32){
        if(len < 4) return SER_EMALFORMED;
        uint32_t got = le32_load(&buf[len-4]);
        uint32_t exp = crc32_le(buf, len-4);
        if(got != exp) return SER_ECRC;
        tlvs_end = len - 4;
    }

    out->version = ver; out->flags = flags; out->tlv_count = tlv_cnt;
    out->input_len = in_len_d;

    size_t off = hdr_len;
    bool saw_ch=false, saw_fn=false, saw_in=false;

    for(uint16_t i=0; i<tlv_cnt; ++i){
        if(off > tlvs_end || (tlvs_end - off) < 8) return SER_EMALFORMED;

        uint16_t t = le16_load(&buf[off]); off += 2;
        /* uint16_t reserved2 = */ (void)le16_load(&buf[off]); off += 2;
        uint32_t l = le32_load(&buf[off]); off += 4;

        size_t new_off;
        if(add_ov(off, (size_t)l, &new_off)) return SER_EMALFORMED;
        if(new_off > tlvs_end) return SER_EMALFORMED;

        const uint8_t *val = &buf[off];

        switch(t){
        case POX_TLV_CHALLENGE:
            if(saw_ch) return SER_EMALFORMED;
            if(l < POX_CHALLENGE_LEN_MIN || l > POX_CHALLENGE_LEN_MAX) return SER_EMALFORMED;
            out->challenge = val; out->challenge_len = l; saw_ch = true;
            break;

        case POX_TLV_FUNC_ADDR:
            if(saw_fn) return SER_EMALFORMED;
            if(l != 4) return SER_EMALFORMED;
            out->function_addr_le32 = le32_load(val); saw_fn = true;
            break;

        case POX_TLV_INPUT:
            if(saw_in) return SER_EMALFORMED;
            if(l != in_len_d) return SER_EMALFORMED;
            out->input = val; out->input_len = l; saw_in = true;
            break;

        default:
            /* skip unknown */
            break;
        }

        off = new_off;
    }

    if(!saw_ch || !saw_fn || !saw_in) return SER_EMALFORMED;
    if(off != tlvs_end) return SER_EMALFORMED;

    return SER_OK;
}
