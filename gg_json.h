/*
 * gg_json.h — byte-exact reimplementation of acdrv.sys JSON composer primitives
 *            (original addresses: META 0x15B4A0, SEP 0x15BC80, QSTR 0xBF860,
 *             ESC 0xBF230, NUM 0xC0CD0 via itoa 0xBE268, close 0xC0930).
 *
 * Clean-room protocol implementation. NO obfuscation, NO detection logic.
 * Byte format verified against live-driver emulation fixtures
 * (work/json_bytes.txt, scripts/112_json_prims_emu.py).
 */
#ifndef GG_JSON_H
#define GG_JSON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Writer context. The original driver keeps [ctx+0x00]=buffer end and
 * [ctx+0x44]="first field" flag; we keep the same semantics in a clean struct. */
typedef struct gg_jctx {
    char  *p;          /* current write cursor                    */
    char  *end;        /* one-past-end of destination buffer      */
    int    first;      /* 1 -> next SEP emits no leading comma    */
    size_t overflow;   /* counts bytes that did not fit           */
} gg_jctx;

void ggj_init(gg_jctx *ctx, void *buf, size_t cap);

/* META  (0x15B4A0): emits '{' and sets first=1                    */
void ggj_meta(gg_jctx *ctx);
/* SEP   (0x15BC80): [","]"key":                                   */
void ggj_sep(gg_jctx *ctx, const char *key);
/* QSTR  (0xBF860):  "\"" ESC(str) "\""                            */
void ggj_qstr(gg_jctx *ctx, const char *s);
/* NUM   (0xC0CD0): unsigned itoa base 10, no quoting              */
void ggj_num(gg_jctx *ctx, uint32_t v);
/* NUM64: same decimal writer, 64-bit (composes via two NUM calls
 * in the original when needed)                                    */
void ggj_num64(gg_jctx *ctx, uint64_t v);
/* close (0xC0930): emits '}'                                      */
void ggj_close(gg_jctx *ctx);
/* raw byte writer (0xC0930 with arbitrary byte)                   */
void ggj_raw(gg_jctx *ctx, char c);

/* ESC (0xBF230): append escaped bytes of s (stops at NUL).
 * Returns bytes appended (logical). Escape table (verified on all
 * 256 byte values):
 *   0x00        -> stop
 *   0x22        -> \"
 *   0x5C        -> \\
 *   0x01..0x1F  -> \u00XX  (hex UPPERCASE, 4 digits)
 *   0x7F        -> \u007F
 *   0x20..0x7E  -> literal byte
 *   0x80..0xFF  -> \uFFXX  (one unit per raw byte, hex UPPERCASE)
 * NOTE: no short forms: 0x0A -> \u000A, 0x0D -> \u000D, 0x09 -> \u0009. */
size_t ggj_escape(const uint8_t *s, size_t n, gg_jctx *ctx);

/* helpers mirroring event-builder idioms */
void ggj_key_qstr(gg_jctx *ctx, const char *key, const char *val);
void ggj_key_num (gg_jctx *ctx, const char *key, uint32_t v);

#ifdef __cplusplus
}
#endif
#endif /* GG_JSON_H */
