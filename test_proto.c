/*
 * test_proto.c — framing, greeting, login and dispatcher tests.
 * Expectations come from the RE of threads 0x792F4 / 0x8F938 and the
 * command executor 0x9358C.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../proto/gg_proto.h"
#include "../proto/gg_cmds.h"

static int fails = 0, total = 0;

static int check_bin(const char *name, const uint8_t *got, size_t gotn,
                     const char *expect_hex)
{
    size_t n = strlen(expect_hex) / 2, i;
    int ok = (gotn == n);
    char gb[256];
    total++;
    for (i = 0; ok && i < n; i++) {
        unsigned v;
        sscanf(expect_hex + i * 2, "%2x", &v);
        if (got[i] != (uint8_t)v) ok = 0;
    }
    if (ok) { printf("PASS %-32s (%zu bytes)\n", name, n); return 1; }
    for (i = 0; i < gotn && i < sizeof(gb) / 2; i++)
        sprintf(gb + i * 2, "%02x", got[i]);
    gb[gotn * 2 < sizeof(gb) ? gotn * 2 : sizeof(gb) - 1] = 0;
    printf("FAIL %-32s\n  expect(%zu) %s\n  got(%zu)    %s\n",
           name, n, expect_hex, gotn, gb);
    fails++;
    return 0;
}

static int check_int(const char *name, long got, long want)
{
    total++;
    if (got == want) { printf("PASS %-32s (%ld)\n", name, got); return 1; }
    printf("FAIL %-32s got=%ld want=%ld\n", name, got, want);
    fails++;
    return 0;
}

int main(void)
{
    uint8_t buf[512];

    /* ---- greeting pack: exact 18 bytes {0xE, 0x10101, 0, u64} ---- */
    {
        gg_greeting g;
        g.magic = GG_GREETING_MAGIC; g.sig = GG_GREETING_SIG;
        g.reserved = 0; g.session = 0x1122334455667788ull;
        gg_greeting_pack(buf, &g);
        check_bin("greeting pack", buf, 18,
                  "0e0000000101010000008877665544332211");
    }
    {
        /* original greeting from thread dump: 0E 00 00 00 | 01 01 01 00 | 00 00 */
        gg_greeting g;
        uint8_t raw[18] = {0x0e,0,0,0, 0x01,0x01,0x01,0, 0,0, 0x7a,0x1c,0,0,0,0,0,0};
        check_int("greeting unpack magic/sig",
                  gg_greeting_unpack(raw, &g) == 0 && g.magic == 0xE && g.sig == 0x10101, 1);
        check_int("greeting session", (long)(g.session & 0xffff), 0x1c7a);
    }

    /* ---- pipe name: \??\pipe\steam_pipe_N_%08x%08x ---- */
    {
        char name[80];
        int n = gg_pipe_name(name, sizeof(name), 1, 0x12345678u, 0x9abcdef0u);
        check_int("pipe name len", n, (long)strlen("\\??\\pipe\\steam_pipe_1_123456789abcdef0"));
        check_int("pipe name str",
                  strcmp(name, "\\??\\pipe\\steam_pipe_1_123456789abcdef0") == 0, 1);
        gg_pipe_name(name, sizeof(name), 2, 1, 2);
        check_int("pipe name v2",
                  strcmp(name, "\\??\\pipe\\steam_pipe_2_0000000100000002") == 0, 1);
    }

    /* ---- framing: u32 LE length + payload ---- */
    {
        int n = gg_frame_write(buf, sizeof(buf), "AB", 2);
        check_bin("frame u32+len", buf, (size_t)n, "020000004142");
    }

    /* ---- login: valid 9 bytes ---- */
    {
        uint8_t pl[9] = {0x01, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x08};
        gg_login lg;
        check_int("login 9B ok", gg_login_parse(pl, 9, &lg), GG_LOGIN_OK);
        check_int("login steam_id", (long)(lg.steam_id & 0xffffffff), (long)0x44332211);
    }
    {
        /* wire: u32 len=9 + payload {02 10 00 00 00 00 00 00 00} */
        gg_login lg;
        uint8_t msg[4 + 9];
        int n = gg_frame_write(msg, sizeof(msg), (uint8_t[]){0x02,0x10,0,0,0,0,0,0,0}, 9);
        check_bin("login frame on wire", msg, (size_t)n,
                  "09000000021000000000000000");
        check_int("login frame parse",
                  gg_login_parse(msg + 4, 9, &lg), GG_LOGIN_OK);
    }
    {
        uint8_t pl[5] = {1,2,3,4,5};
        gg_login lg;
        check_int("login wrong len", gg_login_parse(pl, 5, &lg), GG_LOGIN_ERR_LENGTH);
    }
    {
        uint8_t pl[9] = {0x01, 0,0,0,0,0,0,0,0};
        gg_login lg;
        check_int("login zero steamid", gg_login_parse(pl, 9, &lg), GG_LOGIN_ERR_NOTLOGGED);
    }
    {
        /* 14-byte extended variant */
        uint8_t pl[14] = {0x03, 0x99,0,0,0,0,0,0,0, 1,2,3,4,5};
        gg_login lg;
        check_int("login 14B ok", gg_login_parse(pl, 14, &lg), GG_LOGIN_OK);
        check_int("login 14B extra", lg.extra[4], 5);
    }

    /* ---- command header: {+8 flags, +0x10 size, +0x18 id} ---- */
    {
        gg_cmdhdr h; h.flags = 0xAABBCCDD; h.size = 4; h.id = 0xC050;
        gg_cmdhdr_pack(buf, &h);
        check_bin("cmdhdr pack", buf, 0x20,
                  "0000000000000000ddccbbaa00000000040000000000000050c0000000000000");
    }

    /* ---- dispatcher semantics ---- */
    {
        gg_session_state st; gg_session_init(&st);
        gg_cmdhdr h; memset(&h, 0, sizeof(h));
        uint32_t n;

        /* unknown id -> 0xC0000010 */
        h.id = 0xDEAD; h.size = 0; n = 0;
        check_int("unknown id -> C0000010",
                  gg_cmds_dispatch(&st, &h, buf, &n), (long)(int32_t)0xC0000010);

        /* noop -> success */
        h.id = GG_CMD_NOOP; n = 0;
        check_int("0xC0C0 noop", gg_cmds_dispatch(&st, &h, buf, &n), 0);

        /* bool validate small -> 0xC0000023 */
        h.id = GG_CMD_BOOL_VALIDATE; n = 0;
        check_int("0x5C too small -> C0000023",
                  gg_cmds_dispatch(&st, &h, buf, &n), (long)(int32_t)0xC0000023);
        buf[0] = 1; n = 1;
        check_int("0x5C ok", gg_cmds_dispatch(&st, &h, buf, &n), 0);

        /* global reader returns 4 bytes */
        st.global_c591d = 0x12345678;
        h.id = GG_CMD_GET_GLOBAL_0xC591D; n = 16;
        check_int("0xC01C status", gg_cmds_dispatch(&st, &h, buf, &n), 0);
        check_int("0xC01C len", n, 4);
        {
            uint32_t v; memcpy(&v, buf, 4);
            check_int("0xC01C value", v, 0x12345678);
        }
        /* same reader with empty payload: buffer >= 0x100 is guaranteed
         * by the original allocator (max(size,0x100)) -> still success */
        h.id = GG_CMD_GET_GLOBAL_0xC591D; n = 0;
        check_int("0xC01C empty payload ok", gg_cmds_dispatch(&st, &h, buf, &n), 0);
        check_int("0xC01C empty payload len", n, 4);

        /* session update */
        h.id = GG_CMD_SESSION_UPDATE; n = 16;
        memcpy(buf, (uint8_t[]){1,0,0,0, 2,0,0,0, 3,0,0,0, 4,0,0,0}, 16);
        check_int("0xC050 status", gg_cmds_dispatch(&st, &h, buf, &n), 0);
        check_int("0xC050 g20", st.sess_1c5920, 1);
        check_int("0xC050 g38", st.sess_1c5938, 4);

        /* status block 0x128 */
        h.id = GG_CMD_STATUS_BLOCK; n = sizeof(buf);
        check_int("0xC0A8 status", gg_cmds_dispatch(&st, &h, buf, &n), 0);
        check_int("0xC0A8 len", n, 0x128);

        /* UI event sub-id 4 (GUI closed) */
        h.id = GG_CMD_UI_EVENT; buf[0] = 4; n = 1;
        check_int("0xC0B4 sub4", gg_cmds_dispatch(&st, &h, buf, &n), 0);
        check_int("0xC0B4 ui_state", st.ui_state, 4);
        buf[0] = 9; n = 1;
        check_int("0xC0B4 bad sub -> C0000010",
                  gg_cmds_dispatch(&st, &h, buf, &n), (long)(int32_t)0xC0000010);
    }

    printf("\n== proto: %d/%d passed ==\n", total - fails, total);
    return fails ? 1 : 0;
}
