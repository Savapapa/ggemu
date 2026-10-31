/*
 * test_json.c — byte-exact validation of the JSON composer against
 * fixtures recorded from the REAL acdrv.sys code executed in Unicorn
 * (work/json_bytes.txt, scripts/112_json_prims_emu.py).
 *
 * Every hex string below is copied verbatim from the fixture log.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../proto/gg_json.h"

static int fails = 0, total = 0;

static int check(const char *name, const char *expect_hex,
                 const gg_jctx *ctx, const char *buf)
{
    size_t n = strlen(expect_hex) / 2;
    size_t i;
    int ok = 1;
    char gotbuf[600];
    total++;
    if ((size_t)(ctx->p - buf) != n) ok = 0;
    for (i = 0; ok && i < n; i++) {
        unsigned v;
        sscanf(expect_hex + i * 2, "%2x", &v);
        if ((unsigned char)buf[i] != v) ok = 0;
    }
    if (ok) {
        printf("PASS %-28s (%zu bytes)\n", name, n);
    } else {
        size_t m = n < sizeof(gotbuf) / 2 ? n : sizeof(gotbuf) / 2 - 1;
        for (i = 0; i < m; i++) sprintf(gotbuf + i * 2, "%02x", (unsigned char)buf[i]);
        gotbuf[m * 2] = 0;
        printf("FAIL %-28s\n  expect %s\n  got    %s\n", name, expect_hex, gotbuf);
        fails++;
    }
    return ok;
}

#define BEGIN(buf, cap) gg_jctx ctx; ggj_init(&ctx, buf, cap)

int main(void)
{
    char buf[512];

    /* ---- QSTR fixtures ---- */
    {
        BEGIN(buf, sizeof(buf));
        ggj_qstr(&ctx, "hello");
        check("QSTR 'hello'", "2268656c6c6f22", &ctx, buf);
    }
    {
        BEGIN(buf, sizeof(buf));
        ggj_qstr(&ctx, "a\"b\\c");
        check("QSTR quote/backslash", "22615c22625c5c6322", &ctx, buf);
    }
    {
        BEGIN(buf, sizeof(buf));
        ggj_qstr(&ctx, "x\x01y");
        check("QSTR 0x01 -> \\u0001", "22785c75303030317922", &ctx, buf);
    }
    {
        BEGIN(buf, sizeof(buf));
        ggj_qstr(&ctx, "x\x1fy");
        check("QSTR 0x1F -> \\u001F", "22785c75303031467922", &ctx, buf);
    }
    {
        BEGIN(buf, sizeof(buf));
        ggj_qstr(&ctx, "x\x7fy");
        check("QSTR 0x7F -> \\u007F", "22785c75303037467922", &ctx, buf);
    }
    {
        /* raw bytes C2 80 (UTF-8 U+0080) -> \uFFC2\uFF80 (no quotes:
         * ggj_escape alone) */
        BEGIN(buf, sizeof(buf));
        ggj_escape((const uint8_t *)"x\xc2\x80y", 4, &ctx);
        check("ESC byte 0xC2 0x80", "785c75464643325c754646383079", &ctx, buf);
    }
    {
        /* fixture 'x0xFFy': char U+00FF = UTF-8 C3 BF -> \uFFC3\uFFBF */
        BEGIN(buf, sizeof(buf));
        ggj_escape((const uint8_t *)"x\xc3\xbfy", 4, &ctx);
        check("ESC byte 0xC3 0xBF", "785c75464643335c754646424679", &ctx, buf);
    }
    {
        /* full quoted version of the same */
        BEGIN(buf, sizeof(buf));
        ggj_qstr(&ctx, "x\xd0\x98y");
        check("QSTR UTF-8 И", "22785c75464644305c75464639387922", &ctx, buf);
    }
    {
        /* UTF-8 ☺ = E2 98 BA -> \uFFE2\uFF98\uFFBA */
        BEGIN(buf, sizeof(buf));
        ggj_qstr(&ctx, "x\xe2\x98\xbay");
        check("QSTR UTF-8 U+263A", "22785c75464645325c75464639385c75464642417922", &ctx, buf);
    }
    {
        /* UTF-8 中 = E4 B8 AD -> \uFFE4\uFFB8\uFFAD */
        BEGIN(buf, sizeof(buf));
        ggj_qstr(&ctx, "x\xe4\xb8\xady");
        check("QSTR UTF-8 U+4E2D", "22785c75464645345c75464642385c75464641447922", &ctx, buf);
    }
    {
        /* UTF-8 surrogate pair U+1D11E = F0 9D 84 9E -> 4 units */
        BEGIN(buf, sizeof(buf));
        ggj_qstr(&ctx, "x\xf0\x9d\x84\x9ey");
        check("QSTR UTF-8 U+1D11E", "22785c75464646305c75464639445c75464638345c75464639457922", &ctx, buf);
    }
    {
        BEGIN(buf, sizeof(buf));
        ggj_qstr(&ctx, "");
        check("QSTR empty", "2222", &ctx, buf);
    }
    {
        /* LF must NOT become \n */
        BEGIN(buf, sizeof(buf));
        ggj_qstr(&ctx, "a\nb");
        check("QSTR LF -> \\u000A", "22615c75303030416222", &ctx, buf);
    }

    /* ---- NUM fixtures ---- */
    {
        BEGIN(buf, sizeof(buf));
        ggj_num(&ctx, 0);
        check("NUM 0", "30", &ctx, buf);
    }
    {
        BEGIN(buf, sizeof(buf));
        ggj_num(&ctx, 12345);
        check("NUM 12345", "3132333435", &ctx, buf);
    }
    {
        BEGIN(buf, sizeof(buf));
        ggj_num(&ctx, 0xFFFFFFFFu);
        check("NUM 0xFFFFFFFF", "34323934393637323935", &ctx, buf);
    }
    {
        BEGIN(buf, sizeof(buf));
        ggj_num(&ctx, 0x80000000u);
        check("NUM 0x80000000", "32313437343833363438", &ctx, buf);
    }
    {
        BEGIN(buf, sizeof(buf));
        ggj_num(&ctx, 0xDEADBEEFu);
        check("NUM 0xDEADBEEF", "33373335393238353539", &ctx, buf);
    }

    /* ---- META / SEP ---- */
    {
        BEGIN(buf, sizeof(buf));
        ggj_meta(&ctx);
        check("META '{'", "7b", &ctx, buf);
    }
    {
        BEGIN(buf, sizeof(buf));
        ggj_sep(&ctx, "cmd");   /* ggj_init leaves first=1 */
        check("SEP(first) 'cmd'", "22636d64223a", &ctx, buf);
    }
    {
        BEGIN(buf, sizeof(buf));
        ggj_sep(&ctx, "cmd");
        ggj_sep(&ctx, "hash");
        check("SEP(second) 'hash'", "22636d64223a2c2268617368223a", &ctx, buf);
    }

    /* ---- full mini event (fixture MINI-EVENT) ---- */
    {
        BEGIN(buf, sizeof(buf));
        ggj_meta(&ctx);
        ggj_sep(&ctx, "cmd");   ggj_qstr(&ctx, "hwid_confirm");
        ggj_sep(&ctx, "dlen");  ggj_num(&ctx, 1234);
        check("MINI-EVENT", "7b22636d64223a22687769645f636f6e6669726d222c22646c656e223a31323334", &ctx, buf);
    }
    /* ---- close brace ---- */
    {
        BEGIN(buf, sizeof(buf));
        ggj_meta(&ctx);
        ggj_sep(&ctx, "cmd"); ggj_qstr(&ctx, "hwid_confirm");
        ggj_sep(&ctx, "dlen"); ggj_num(&ctx, 1234);
        ggj_close(&ctx);
        check("MINI-EVENT + '}'", "7b22636d64223a22687769645f636f6e6669726d222c22646c656e223a313233347d", &ctx, buf);
    }
    /* ---- serials block (order of emission per 0xD3D8C) ---- */
    {
        BEGIN(buf, sizeof(buf));
        ggj_meta(&ctx);
        ggj_sep(&ctx, "cmd");    ggj_qstr(&ctx, "hwid_confirm");
        ggj_sep(&ctx, "confirm");ggj_qstr(&ctx, "C");
        ggj_sep(&ctx, "hash");   ggj_qstr(&ctx, "H");
        ggj_sep(&ctx, "dhash");  ggj_qstr(&ctx, "D");
        ggj_sep(&ctx, "dlen");   ggj_num(&ctx, 4);
        ggj_sep(&ctx, "dhash0"); ggj_qstr(&ctx, "D0");
        ggj_sep(&ctx, "dlen0");  ggj_num(&ctx, 8);
        ggj_sep(&ctx, "serials");ggj_meta(&ctx);
        ggj_sep(&ctx, "serial1");ggj_qstr(&ctx, "SER");
        ggj_sep(&ctx, "serial1_len"); ggj_num(&ctx, 3);
        ggj_close(&ctx); /* serials */
        ggj_close(&ctx); /* event */
        check("hwid_confirm full", 
              "7b22636d64223a22687769645f636f6e6669726d222c22636f6e6669726d223a2243222c2268617368223a2248222c226468617368223a2244222c22646c656e223a342c22646861736830223a224430222c22646c656e30223a382c2273657269616c73223a7b2273657269616c31223a22534552222c2273657269616c315f6c656e223a337d7d",
              &ctx, buf);
    }

    printf("\n== json: %d/%d passed ==\n", total - fails, total);
    return fails ? 1 : 0;
}
