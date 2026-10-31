/*
 * gg_cmds.h — UM->KM command dispatcher (original executor 0x9358C).
 *
 * Command header (original [ctx+0xB8]): +0x08 flags, +0x10 payload size,
 * +0x18 command ID. Executor rules recovered from the original:
 *   - IDs {0xC0C4, 0xC08C} or payload size == 0 -> raw path (no GGEB)
 *   - otherwise payload is GGEB-wrapped (ktrc tag 0x42454747, decrypt
 *     0xBC164) — the emulator keeps the hook point but does not
 *     implement the obfuscated cipher (documented in DIFF doc)
 *   - unknown ID -> STATUS_INVALID_DEVICE_REQUEST (0xC0000010)
 *   - payload smaller than the handler minimum -> 0xC0000023
 *   - response is written in-place; length returned via out_len
 *
 * 40 IDs with handlers/semantics per work/cmdexec_dispatch.json.
 */
#ifndef GG_CMDS_H
#define GG_CMDS_H

#include <stdint.h>
#include <stddef.h>
#include "gg_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* command IDs (original addresses in comments) */
enum gg_cmd_id {
    GG_CMD_ADAPT_COLLECT     = 0x000C,  /* 0x8A168 adapters MAC/IP/DNS/gw  */
    GG_CMD_SMBIOS_COLLECT    = 0x0014,  /* 0x84914 SMBIOS                  */
    GG_CMD_SCAN_PAUSE_RESUME = 0x0028,  /* 0x9E548 "scan is resumed"       */
    GG_CMD_PROC_QUERY        = 0x0030,  /* 0x8A540 ZwQueryVirtualMemory    */
    GG_CMD_GPU_ENV           = 0x004C,  /* 0x9EA2C D3D environment         */
    GG_CMD_BOOL_VALIDATE     = 0x005C,  /* 0x1753C -> 0xC0000023 if small  */
    GG_CMD_SVC_KTRC          = 0x0064,  /* 0x9ECD4                         */
    GG_CMD_NOOP              = 0x00C0,  /* inline no-op, success           */
    GG_CMD_STORAGE_SERIALS   = 0xC004,  /* 0xAC15C storage serials         */
    GG_CMD_SVC_T1_84_85_A    = 0xC008,  /* 0x66788                         */
    GG_CMD_SET_INTERVALS_1   = 0xC010,  /* 0x666D8 scan intervals          */
    GG_CMD_CONFIG_UPDATE     = 0xC018,  /* 0x9384D TLV config update       */
    GG_CMD_GET_GLOBAL_0xC591D= 0xC01C,  /* inline read global -> 4 bytes   */
    GG_CMD_SVC_RAWIP         = 0xC020,  /* 0x373A4                         */
    GG_CMD_SVC_KTRC_B        = 0xC024,  /* 0x7E104                         */
    GG_CMD_SVC_T1_84_85_B    = 0xC02C,  /* 0x76EA4                         */
    GG_CMD_SVC_T1_170_A      = 0xC034,  /* 0x32B50                         */
    GG_CMD_SIGNFILTERS_LOAD  = 0xC038,  /* 0x946A5 (len,off)-pairs, GGSI   */
    GG_CMD_GET_GLOBAL_0xC5398= 0xC03C,  /* inline read global -> 4 bytes   */
    GG_CMD_U32_ARG           = 0xC040,  /* 0x1AD74 takes payload[0] u32    */
    GG_CMD_SVC_KTRC_C        = 0xC044,  /* 0x25A4                          */
    GG_CMD_GLOBAL_0xC5368    = 0xC048,  /* 0x666B0 global + bool(payload)  */
    GG_CMD_SESSION_UPDATE    = 0xC050,  /* 0x94F61 TLV -> globals 0x1C5920 */
    GG_CMD_SVC_T1_SET_A      = 0xC054,  /* 0x74710                         */
    GG_CMD_CALL_T1_0x520     = 0xC058,  /* 0x68E50                         */
    GG_CMD_SVC_T1_84_85_C    = 0xC060,  /* 0x790BC                         */
    GG_CMD_SVC_T1_93_A       = 0xC06C,  /* 0x69100                         */
    GG_CMD_SVC_T1_84_85_D    = 0xC070,  /* 0x7E618                         */
    GG_CMD_SVC_T1_93_B       = 0xC078,  /* 0x6906C                         */
    GG_CMD_SCAN_OPS          = 0xC07C,  /* 0xB8D10 " scan ..."             */
    GG_CMD_SET_INTERVALS_2   = 0xC080,  /* 0x36994 backRemoval/bigpool/... */
    GG_CMD_SET_INTERVALS_3   = 0xC084,  /* 0x66618 scan intervals          */
    GG_CMD_SVC_U32_REPLY     = 0xC088,  /* 0x7F19C -> u32 reply            */
    GG_CMD_MEMACCESS_LOG     = 0xC08C,  /* 0x4CA70 raw payload (no GGEB)   */
    GG_CMD_SVC_T1_SET_B      = 0xC090,  /* 0x6650C                         */
    GG_CMD_REG_CALLBACKS     = 0xC094,  /* 0x744C4 registry/callbacks      */
    GG_CMD_SVC_T1_84_85_E    = 0xC098,  /* 0x7F510                         */
    GG_CMD_CODE_POINTS       = 0xC09C,  /* 0x9EE28 "Code Points ..."       */
    GG_CMD_SVC_T1_170_B      = 0xC0A0,  /* 0x378A0                         */
    GG_CMD_SVC_KTRC_D        = 0xC0A4,  /* 0x2454                          */
    GG_CMD_STATUS_BLOCK      = 0xC0A8,  /* 0x95C9F 0x128-byte status block */
    GG_CMD_STRUCT_VALIDATE   = 0xC0B0,  /* 0x968CF 0x14-byte structures     */
    GG_CMD_UI_EVENT          = 0xC0B4,  /* 0x95E66 sub-ids 1..6            */
    GG_CMD_GLOBAL_0xC5328    = 0xC0B8,  /* 0x95E55 -> 0x7E9E4              */
    GG_CMD_BIN_PASSTHRU_1    = 0xC0BC,  /* 0x95D91 {u64 ptr, u64 len} raw  */
    GG_CMD_BIN_PASSTHRU_2    = 0xC0C4   /* raw path, no GGEB               */
};

/* dispatcher: returns NTSTATUS (as int32_t), writes reply into
 * in-place payload buffer, sets *out_len. */
typedef int32_t (*gg_cmd_handler)(void *user,
                                  const gg_cmdhdr *hdr,
                                  uint8_t *payload,   /* in/out, in-place */
                                  uint32_t *io_len);

int32_t gg_cmds_dispatch(void *user, const gg_cmdhdr *hdr,
                         uint8_t *payload, uint32_t *io_len);

/* built-in clean handlers (used by both emulator driver and tests);
 * handlers for scan/detection commands are protocol-level stubs that
 * mirror ONLY the wire behavior (status + reply shape) — see DIFF doc. */
int32_t gg_cmd_noop(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n);
int32_t gg_cmd_get_global(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n);
int32_t gg_cmd_status_block(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n);
int32_t gg_cmd_u32_reply(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n);
int32_t gg_cmd_bool_validate(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n);
int32_t gg_cmd_ui_event(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n);

/* session state the handlers may touch (clean replacement of globals
 * 0x1C5920-0x1C5938 / 0x1C5398 / 0x1C591D / 0x1C5368 / 0x1C5328) */
typedef struct gg_session_state {
    uint32_t global_c591d;      /* GG_CMD_GET_GLOBAL_0xC591D  */
    uint32_t global_c5398;      /* GG_CMD_GET_GLOBAL_0xC5398  */
    uint32_t global_c5368;      /* GG_CMD_GLOBAL_0xC5368      */
    uint32_t global_c5328;      /* GG_CMD_GLOBAL_0xC5328      */
    uint32_t sess_1c5920;       /* GG_CMD_SESSION_UPDATE TLV  */
    uint32_t sess_1c5928;
    uint32_t sess_1c5930;
    uint32_t sess_1c5938;
    uint32_t intervals[8];      /* settable intervals         */
    uint32_t scan_paused;
    uint32_t ui_state;          /* last UI sub-id from 0xC0B4 */
} gg_session_state;

void gg_session_init(gg_session_state *st);

#ifdef __cplusplus
}
#endif
#endif /* GG_CMDS_H */
