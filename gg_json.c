/*
 * gg_json.c — byte-exact JSON composer (see gg_json.h).
 * Emits STRICT ASCII JSON identical to the original composer chain
 * META(0x15B4A0)->SEP(0x15BC80)->QSTR(0xBF860)/NUM(0xC0CD0)->'}'(0xC0930).
 */
#include "gg_json.h"

static const char HEXU[] = "0123456789ABCDEF";

void ggj_init(gg_jctx *ctx, void *buf, size_t cap)
{
    ctx->p        = (char *)buf;
    ctx->end      = (char *)buf + cap;
    ctx->first    = 1;
    ctx->overflow = 0;
}

static void put(gg_jctx *ctx, char c)
{
    if (ctx->p < ctx->end) *ctx->p++ = c;
    else                   ctx->overflow++;
}

void ggj_raw(gg_jctx *ctx, char c) { put(ctx, c); }

void ggj_meta(gg_jctx *ctx)
{
    put(ctx, '{');
    ctx->first = 1;
}

void ggj_sep(gg_jctx *ctx, const char *key)
{
    if (!ctx->first) put(ctx, ',');
    ctx->first = 0;
    ggj_qstr(ctx, key);
    put(ctx, ':');
}

size_t ggj_escape(const uint8_t *s, size_t n, gg_jctx *ctx)
{
    size_t i, out = 0;
    for (i = 0; i < n; i++) {
        uint8_t b = s[i];
        if (b == 0x00) break;               /* terminator */
        if (b == 0x22) { put(ctx, '\\'); put(ctx, '"');  out += 2; continue; }
        if (b == 0x5C) { put(ctx, '\\'); put(ctx, '\\'); out += 2; continue; }
        if (b <= 0x1F || b == 0x7F) {
            put(ctx, '\\'); put(ctx, 'u');
            put(ctx, '0'); put(ctx, '0');
            put(ctx, HEXU[(b >> 4) & 0xF]); put(ctx, HEXU[b & 0xF]);
            out += 6;
            continue;
        }
        if (b >= 0x80) {                    /* one \uFFXX unit per raw byte */
            put(ctx, '\\'); put(ctx, 'u');
            put(ctx, 'F'); put(ctx, 'F');
            put(ctx, HEXU[(b >> 4) & 0xF]); put(ctx, HEXU[b & 0xF]);
            out += 6;
            continue;
        }
        put(ctx, (char)b);                  /* 0x20..0x7E literal */
        out++;
    }
    return out;
}

void ggj_qstr(gg_jctx *ctx, const char *s)
{
    put(ctx, '"');
    ggj_escape((const uint8_t *)s, (size_t)-1, ctx);
    put(ctx, '"');
}

void ggj_num(gg_jctx *ctx, uint32_t v)
{
    /* unsigned itoa base 10 (original: 0xBE268, div — UNSIGNED) */
    char tmp[10];
    int  i = 0;
    do { tmp[i++] = (char)('0' + (v % 10u)); v /= 10u; } while (v);
    while (i) put(ctx, tmp[--i]);
}

void ggj_num64(gg_jctx *ctx, uint64_t v)
{
    char tmp[20];
    int  i = 0;
    do { tmp[i++] = (char)('0' + (int)(v % 10u)); v /= 10u; } while (v);
    while (i) put(ctx, tmp[--i]);
}

void ggj_close(gg_jctx *ctx) { put(ctx, '}'); }

void ggj_key_qstr(gg_jctx *ctx, const char *key, const char *val)
{
    ggj_sep(ctx, key);
    ggj_qstr(ctx, val);
}

void ggj_key_num(gg_jctx *ctx, const char *key, uint32_t v)
{
    ggj_sep(ctx, key);
    ggj_num(ctx, v);
}
