/*
 * gg_proto.h — wire protocol of acdrv.sys KM<->UM communication,
 *              reconstructed byte-for-byte from the original driver.
 *
 * Channels:
 *   A) Login pipes  \??\pipe\steam_pipe_{1,2}_%08x%08x   (KM = server)
 *   B) Command channel (registry HKLM\Software\Gameguard "cmd" + pipe)
 *      40 command IDs, executor 0x9358C
 *   C) Event channel KM->UM: u32-length framed JSON (composer 0xBCC8)
 *
 * Clean-room protocol implementation. NO anti-debug, NO obfuscation,
 * NO cheat detection.
 */
#ifndef GG_PROTO_H
#define GG_PROTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Channel A: login pipes                                             */
/* ------------------------------------------------------------------ */

/* Session greeting written by KM right after pipe creation
 * (original: pipe_io thread 0x792F4, write site 0x7988E-0x7991A).
 * Layout on the wire (18 bytes, little-endian):
 *   +0x00 u32 0x0000000E   magic/version tag ("E")
 *   +0x04 u32 0x00010101   protocol signature
 *   +0x08 u16 0x0000       reserved
 *   +0x0A u64 session      correlation value (TickCount qword at
 *                          pipe creation in the original)          */
#define GG_GREETING_SIZE        18
#define GG_GREETING_MAGIC       0x0000000Eu
#define GG_GREETING_SIG         0x00010101u

typedef struct gg_greeting {
    uint32_t magic;
    uint32_t sig;
    uint16_t reserved;
    uint64_t session;
} gg_greeting;

void gg_greeting_pack(uint8_t out[GG_GREETING_SIZE], const gg_greeting *g);
int  gg_greeting_unpack(const uint8_t in[GG_GREETING_SIZE], gg_greeting *g);

/* Login message UM->KM (original: thread 0x792F4 read loop):
 *   u32 LE length N, then N payload bytes.
 * Valid N: 9 or 14 ("wRONG length, %d." otherwise).
 * payload[0]      = type byte
 * payload[1..8]   = u64 LE steamID (0 -> "User not logged in.")
 * payload[9..13]  = extra bytes, only when N == 14                  */
#define GG_LOGIN_MIN_SIZE        9
#define GG_LOGIN_EXT_SIZE       14

typedef struct gg_login {
    uint8_t  type;
    uint64_t steam_id;
    uint8_t  extra[5];
} gg_login;

/* returns 0 = OK, negative = status (mirrors original diagnostics) */
#define GG_LOGIN_OK              0
#define GG_LOGIN_ERR_LENGTH    (-1)   /* "wRONG length, %d."            */
#define GG_LOGIN_ERR_NOTLOGGED (-2)   /* "User not logged in."          */

int  gg_login_parse(const uint8_t *payload, uint32_t len, gg_login *out);
uint32_t gg_login_pack(uint8_t *dst, uint32_t cap, const gg_login *in);

/* pipe name generator (original: 0x8F938, format rva 0x1ABEE0/0x1ABB10,
 * "%08x%08x" = TickCount KSYSTEM_TIME {LowPart, High1Time} from
 * KUSER_SHARED_DATA + 0x320). Variant is 1 or 2. */
int gg_pipe_name(char *dst, size_t cap, int variant,
                 uint32_t tick_low, uint32_t tick_high);

/* ------------------------------------------------------------------ */
/* Framing (both directions on the byte-stream pipe)                  */
/* ------------------------------------------------------------------ */

/* Every logical message travels as u32 LE length + payload. */
int gg_frame_write(uint8_t *dst, size_t cap, const void *payload, uint32_t len);

/* ------------------------------------------------------------------ */
/* Channel B: command header (original ctx+0xB8 block, see MD 27.1)   */
/* ------------------------------------------------------------------ */

/* Original header offsets inside [ctx+0xB8]: +0x08 flags, +0x10 size,
 * +0x18 id. Full on-wire header block (0x20 bytes) keeps the same
 * relative layout; fields at +0x00/+0x04/+0x0C/+0x14/+0x1C are
 * reserved (zero in observed traffic). */
#define GG_CMDHDR_SIZE          0x20

typedef struct gg_cmdhdr {
    uint32_t flags;      /* +0x08 in original layout */
    uint32_t size;       /* +0x10: payload size      */
    uint32_t id;         /* +0x18: command ID        */
} gg_cmdhdr;

void gg_cmdhdr_pack(uint8_t out[GG_CMDHDR_SIZE], const gg_cmdhdr *h);
int  gg_cmdhdr_unpack(const uint8_t in[GG_CMDHDR_SIZE], gg_cmdhdr *h);

/* NTSTATUS values used by the command executor (0x9358C) */
#define GG_STATUS_SUCCESS               ((int32_t)0x00000000)
#define GG_STATUS_INVALID_DEVICE_REQUEST ((int32_t)0xC0000010L)
#define GG_STATUS_BUFFER_TOO_SMALL      ((int32_t)0xC0000023L)
#define GG_STATUS_UNSUCCESSFUL          ((int32_t)0xC0000001L)

/* command IDs executed without GGEB payload envelope */
#define GG_CMD_RAW_0xC08C               0xC08Cu
#define GG_CMD_RAW_0xC0C4               0xC0C4u

#ifdef __cplusplus
}
#endif
#endif /* GG_PROTO_H */
