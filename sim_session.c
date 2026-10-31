/*
 * sim_session.c — end-to-end conversation demo of the GGEmu wire logic.
 *
 * Both endpoints are driven by the SAME protocol core that compiles
 * into the kernel driver (proto/*.c), connected over a socketpair:
 *
 *   KM side (emulator, mirrors pipes.c of the driver):
 *     -> builds pipe name from TickCount (simulated clock)
 *     -> sends 18-byte greeting {0xE, 0x10101, 0, u64 session}
 *     -> reads framed login (u32 len in {9,14} + payload)
 *     -> validates, registers steamID, session state 3
 *   UM side (test client, mirrors um/test_client.c):
 *     <- reads greeting, validates
 *     -> sends login {type, u64 steamID}
 *   then a command exchange over the framed channel:
 *     UM -> {flags,size,id}+payload ; KM answers with the original
 *     status semantics (unknown->0xC0000010, small->0xC0000023, ...)
 *   and one KM->UM JSON event (byte-exact composer).
 *
 * The transcript is printed as hex so it can be diffed against the RE.
 *
 * Build: gcc -O2 -Wall -o sim_session sim_session.c ../proto/*.c -lpthread
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>

#include "../proto/gg_proto.h"
#include "../proto/gg_cmds.h"
#include "../proto/gg_json.h"

/* ---------------- shared channel ------------------------------------ */
static int CH_KM = -1, CH_UM = -1;

static int ch_write(int fd, const void *b, size_t n)
{
    const uint8_t *p = b; size_t off = 0;
    while (off < n) {
        ssize_t r = write(fd, p + off, n - off);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

static int ch_read(int fd, void *b, size_t n)
{
    uint8_t *p = b; size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, p + off, n - off);
        if (r <= 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

static void hexlog(const char *side, const char *dir,
                   const uint8_t *b, size_t n)
{
    size_t i;
    printf("[%s %s %4zuB] ", side, dir, n);
    for (i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

/* ---------------- KM side ------------------------------------------- */
typedef struct { uint64_t steam_id; uint8_t type; } km_user;

static km_user KM_USERS[16];
static int KM_USERS_N = 0;
static gg_session_state KM_CMDS;

static void *km_thread(void *arg)
{
    uint8_t buf[1024];
    gg_greeting g;
    uint32_t lo = 0x12345678u, hi = 0x00abcdefu; /* simulated TickCount */
    char pname[80];

    (void)arg;

    /* 1. pipe name: \??\pipe\steam_pipe_1_%08x%08x */
    gg_pipe_name(pname, sizeof(pname), 1, lo, hi);
    printf("[KM  ] pipe server: %s\n", pname);

    /* 2. greeting */
    g.magic = GG_GREETING_MAGIC; g.sig = GG_GREETING_SIG;
    g.reserved = 0; g.session = ((uint64_t)hi << 32) | lo;
    gg_greeting_pack(buf, &g);
    hexlog("KM  ", "out>", buf, 18);
    ch_write(CH_KM, buf, 18);

    /* 3. framed login */
    {
        uint32_t len;
        gg_login login;
        ch_read(CH_KM, buf, 4);
        memcpy(&len, buf, 4);
        ch_read(CH_KM, buf, len);
        hexlog("KM  ", "in <", buf, len);
        if (len != GG_LOGIN_MIN_SIZE && len != GG_LOGIN_EXT_SIZE) {
            printf("[KM  ] wRONG length, %u.\n", len);
            return NULL;
        }
        if (gg_login_parse(buf, len, &login) != GG_LOGIN_OK) {
            printf("[KM  ] User not logged in.\n");
            return NULL;
        }
        KM_USERS[KM_USERS_N].steam_id = login.steam_id;
        KM_USERS[KM_USERS_N].type = login.type;
        KM_USERS_N++;
        printf("[KM  ] login ok: type=%u steamid=%llu (state 3)\n",
               login.type, (unsigned long long)login.steam_id);
    }

    /* 4. command exchange: read framed cmd, dispatch, answer in place */
    for (;;) {
        uint8_t hdr[GG_CMDHDR_SIZE];
        gg_cmdhdr h;
        uint32_t plen;
        int32_t st;

        ch_read(CH_KM, buf, 4);
        memcpy(&plen, buf, 4);
        ch_read(CH_KM, hdr, GG_CMDHDR_SIZE);
        if (plen) ch_read(CH_KM, buf, plen);
        memcpy(&h.flags, hdr + 8, 4);
        memcpy(&h.size, hdr + 0x10, 4);
        memcpy(&h.id, hdr + 0x18, 4);
        printf("[KM  ] cmd id=0x%04x size=%u flags=0x%x\n", h.id, h.size, h.flags);

        st = gg_cmds_dispatch(&KM_CMDS, &h, buf, &plen);

        /* reply frame: u32 status + u32 len + payload (also for 0xFFFF
         * so the UM side never blocks on the end marker) */
        {
            uint8_t out[512];
            memcpy(out, &st, 4);
            memcpy(out + 4, &plen, 4);
            memcpy(out + 8, buf, plen);
            hexlog("KM  ", "out>", out, (size_t)plen + 8);
            ch_write(CH_KM, out, (size_t)plen + 8);
        }
        if (h.id == 0xFFFF) break;  /* session end marker */
    }

    /* 5. KM->UM JSON event (ping_results, byte-exact composer) */
    {
        gg_jctx jc;
        uint32_t n;
        ggj_init(&jc, (char *)buf + 4, sizeof(buf) - 4);
        {
            extern void ggj_close(gg_jctx *);
            ggj_meta(&jc);
            ggj_key_num(&jc, "cmd", 0x24);
            ggj_key_qstr(&jc, "type", "ping_results");
            ggj_key_qstr(&jc, "ping_results", "");
            ggj_key_num(&jc, "timeout_ms", 3000);
            ggj_sep(&jc, "results");
            ggj_meta(&jc);
            ggj_key_qstr(&jc, "name", "node1");
            ggj_key_qstr(&jc, "status", "ok");
            ggj_key_num(&jc, "trip_time_ms", 42);
            ggj_close(&jc);
            ggj_close(&jc);
        }
        n = (uint32_t)(jc.p - (char *)(buf + 4));
        gg_frame_write(buf, sizeof(buf), buf + 4, n);
        hexlog("KM  ", "out>", buf, (size_t)n + 4);
        printf("[KM  ] event json: %.*s\n", (int)n, buf + 4);
        ch_write(CH_KM, buf, (size_t)n + 4);
    }
    return NULL;
}

/* ---------------- UM side ------------------------------------------- */
static void *um_thread(void *arg)
{
    uint8_t buf[1024];
    gg_greeting g;
    gg_login login;
    gg_session_state um_state_mirror;

    (void)arg;
    gg_session_init(&um_state_mirror);

    /* 1. greeting */
    ch_read(CH_UM, buf, 18);
    hexlog("UM  ", "in <", buf, 18);
    if (gg_greeting_unpack(buf, &g) != 0) {
        printf("[UM  ] greeting MISMATCH\n");
        return NULL;
    }
    printf("[UM  ] greeting ok: magic=0x%x sig=0x%x session=0x%016llx\n",
           g.magic, g.sig, (unsigned long long)g.session);

    /* 2. login */
    login.type = 1;
    login.steam_id = 76561198000000000ull;
    memset(login.extra, 0, sizeof(login.extra));
    {
        uint8_t payload[9];
        uint32_t n = gg_login_pack(payload, sizeof(payload), &login);
        memcpy(buf, &n, 4);
        memcpy(buf + 4, payload, n);
        hexlog("UM  ", "out>", buf, (size_t)n + 4);
        ch_write(CH_UM, buf, (size_t)n + 4);
    }

    /* 3. commands: valid, too-small, unknown, end */
    {
        struct { uint32_t id, size; const char *data; uint32_t len; } seq[] = {
            { GG_CMD_NOOP,                 0, NULL,        0 },
            { GG_CMD_GET_GLOBAL_0xC591D,   0, NULL,        0 },
            { GG_CMD_BOOL_VALIDATE,        1, "\x01",      1 },
            { GG_CMD_BOOL_VALIDATE,        0, NULL,        0 }, /* too small */
            { 0xDEAD,                      0, NULL,        0 }, /* unknown  */
            { GG_CMD_SESSION_UPDATE,      16,
              "\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00", 16 },
            { 0xFFFF,                      0, NULL,        0 },
        };
        size_t i;
        for (i = 0; i < sizeof(seq) / sizeof(seq[0]); i++) {
            uint8_t hdr[GG_CMDHDR_SIZE];
            uint8_t out[512];
            gg_cmdhdr h;
            int32_t st;
            uint32_t plen;

            h.flags = 0; h.size = seq[i].size; h.id = seq[i].id;
            gg_cmdhdr_pack(hdr, &h);
            memcpy(out, &seq[i].len, 4);
            memcpy(out + 4, hdr, GG_CMDHDR_SIZE);
            if (seq[i].len) memcpy(out + 4 + GG_CMDHDR_SIZE, seq[i].data, seq[i].len);
            hexlog("UM  ", "out>", out,
                   (size_t)seq[i].len + 4 + GG_CMDHDR_SIZE);
            ch_write(CH_UM, out, (size_t)seq[i].len + 4 + GG_CMDHDR_SIZE);

            ch_read(CH_UM, out, 8);
            memcpy(&st, out, 4);
            memcpy(&plen, out + 4, 4);
            if (plen) ch_read(CH_UM, out + 8, plen);
            printf("[UM  ] cmd 0x%04x -> status=0x%08x len=%u\n",
                   seq[i].id, (uint32_t)st, plen);
        }
    }

    /* 4. event read */
    {
        uint32_t len;
        ch_read(CH_UM, buf, 4);
        memcpy(&len, buf, 4);
        ch_read(CH_UM, buf, len);
        printf("[UM  ] event: %.*s\n", (int)len, buf);
    }
    return NULL;
}

int main(void)
{
    pthread_t tkm, tum;
    int sv[2];

    setvbuf(stdout, NULL, _IONBF, 0);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        perror("socketpair");
        return 1;
    }
    CH_KM = sv[0];
    CH_UM = sv[1];
    gg_session_init(&KM_CMDS);

    printf("=== GGEmu end-to-end wire simulation (KM<->UM 1:1) ===\n");
    pthread_create(&tkm, NULL, km_thread, NULL);
    usleep(50000);
    pthread_create(&tum, NULL, um_thread, NULL);
    pthread_join(tkm, NULL);
    pthread_join(tum, NULL);
    printf("=== session complete ===\n");
    return 0;
}
