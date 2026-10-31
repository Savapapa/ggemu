/*
 * gg_proto.c — wire framing primitives, see gg_proto.h.
 */
#include "gg_proto.h"

static void put16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void put32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void put64(uint8_t *p, uint64_t v)
{ int i; for (i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }

static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1]<<8)); }
static uint32_t get32(const uint8_t *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }
static uint64_t get64(const uint8_t *p)
{ uint64_t v=0; int i; for (i=7;i>=0;i--) v=(v<<8)|p[i]; return v; }

/* ------------------------------------------------------------------ */

void gg_greeting_pack(uint8_t out[GG_GREETING_SIZE], const gg_greeting *g)
{
    put32(out + 0x00, g->magic);
    put32(out + 0x04, g->sig);
    put16(out + 0x08, g->reserved);
    put64(out + 0x0A, g->session);
}

int gg_greeting_unpack(const uint8_t in[GG_GREETING_SIZE], gg_greeting *g)
{
    g->magic    = get32(in + 0x00);
    g->sig      = get32(in + 0x04);
    g->reserved = get16(in + 0x08);
    g->session  = get64(in + 0x0A);
    if (g->magic != GG_GREETING_MAGIC || g->sig != GG_GREETING_SIG)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------ */

int gg_login_parse(const uint8_t *payload, uint32_t len, gg_login *out)
{
    if (len != GG_LOGIN_MIN_SIZE && len != GG_LOGIN_EXT_SIZE)
        return GG_LOGIN_ERR_LENGTH;          /* "wRONG length, %d." */
    out->type = payload[0];
    out->steam_id = get64(payload + 1);
    if (out->steam_id == 0)
        return GG_LOGIN_ERR_NOTLOGGED;       /* "User not logged in." */
    if (len == GG_LOGIN_EXT_SIZE) {
        int i;
        for (i = 0; i < 5; i++) out->extra[i] = payload[9 + i];
    }
    return GG_LOGIN_OK;
}

uint32_t gg_login_pack(uint8_t *dst, uint32_t cap, const gg_login *in)
{
    uint32_t n = 9;
    int has_extra = in->extra[0] | in->extra[1] | in->extra[2]
                  | in->extra[3] | in->extra[4];
    if (cap < (has_extra ? GG_LOGIN_EXT_SIZE : GG_LOGIN_MIN_SIZE)) return 0;
    dst[0] = in->type;
    put64(dst + 1, in->steam_id);
    if (has_extra) {
        int i;
        for (i = 0; i < 5; i++) dst[9 + i] = in->extra[i];
        n = GG_LOGIN_EXT_SIZE;
    }
    return n;
}

/* ------------------------------------------------------------------ */

static const char HEXL[] = "0123456789abcdef";

static size_t hex32(char *dst, uint32_t v)
{
    int i;
    for (i = 0; i < 8; i++)
        dst[i] = HEXL[(v >> (28 - 4 * i)) & 0xF];
    return 8;
}

int gg_pipe_name(char *dst, size_t cap, int variant,
                 uint32_t tick_low, uint32_t tick_high)
{
    /* original format: "\??\pipe\steam_pipe_%d_%.8x%.8x"
     * (rva 0x1ABEE0 -> variant 1, rva 0x1ABB10 -> variant 2);
     * the two hex words are TickCount.LowPart / High1Time (KUSD+0x320) */
    static const char PFX[] = "\\??\\pipe\\steam_pipe_";
    size_t need = sizeof(PFX) - 1 + 1 + 1 + 16 + 1;
    size_t o = 0;
    if (cap < need) return -1;
    {
        size_t i;
        for (i = 0; i < sizeof(PFX) - 1; i++) dst[o++] = PFX[i];
        dst[o++] = (char)('0' + (variant <= 9 ? variant : 1));
        dst[o++] = '_';
        o += hex32(dst + o, tick_low);
        o += hex32(dst + o, tick_high);
    }
    dst[o] = 0;
    return (int)o;
}

/* ------------------------------------------------------------------ */

int gg_frame_write(uint8_t *dst, size_t cap, const void *payload, uint32_t len)
{
    if (cap < (size_t)len + 4) return -1;
    put32(dst, len);
    {
        uint32_t i;
        const uint8_t *s = (const uint8_t *)payload;
        for (i = 0; i < len; i++) dst[4 + i] = s[i];
    }
    return (int)(len + 4);
}

/* ------------------------------------------------------------------ */

void gg_cmdhdr_pack(uint8_t out[GG_CMDHDR_SIZE], const gg_cmdhdr *h)
{
    int i;
    for (i = 0; i < GG_CMDHDR_SIZE; i++) out[i] = 0;
    put32(out + 0x08, h->flags);
    put32(out + 0x10, h->size);
    put32(out + 0x18, h->id);
}

int gg_cmdhdr_unpack(const uint8_t in[GG_CMDHDR_SIZE], gg_cmdhdr *h)
{
    h->flags = get32(in + 0x08);
    h->size  = get32(in + 0x10);
    h->id    = get32(in + 0x18);
    return 0;
}
