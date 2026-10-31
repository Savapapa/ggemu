/*
 * gg_cmds.c — command dispatcher with exact status semantics of the
 * original executor 0x9358C (see gg_cmds.h).
 */
#include "gg_cmds.h"
#include <string.h>

void gg_session_init(gg_session_state *st)
{
    memset(st, 0, sizeof(*st));
}

/* ---- built-in clean handlers ------------------------------------- */

int32_t gg_cmd_noop(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n)
{
    (void)user; (void)h; (void)pl;
    *n = 0;
    return GG_STATUS_SUCCESS;                /* 0xC0C0 — inline no-op */
}

/* inline readers: reply = 4 bytes, the current global value.
 * NOTE: the reply buffer is NOT the wire payload — the original
 * allocates max(size, 0x100) for the message buffer (GGSK/GGEB), so
 * a 4-byte reply never fails regardless of the payload size. */
int32_t gg_cmd_get_global(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n)
{
    gg_session_state *st = (gg_session_state *)user;
    uint32_t v = 0;
    (void)h;
    switch (h->id) {
    case GG_CMD_GET_GLOBAL_0xC591D: v = st->global_c591d; break;
    case GG_CMD_GET_GLOBAL_0xC5398: v = st->global_c5398; break;
    case GG_CMD_GLOBAL_0xC5368:
        /* original also accepts bool(payload u32): global |= bool */
        if (*n >= 4) {
            uint32_t arg;
            memcpy(&arg, pl, 4);
            if (arg) st->global_c5368 = 1;
        }
        v = st->global_c5368;
        break;
    case GG_CMD_GLOBAL_0xC5328:     v = st->global_c5328; break;
    default: return GG_STATUS_INVALID_DEVICE_REQUEST;
    }
    memcpy(pl, &v, 4);              /* buffer >= 0x100 guaranteed */
    *n = 4;
    return GG_STATUS_SUCCESS;
}

/* 0xC0A8: status block, 0x128 bytes:
 * memset + builder 0x7F360 + 0x0F-byte string at +0x100
 * + five u32 at +0x110..+0x120 */
int32_t gg_cmd_status_block(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n)
{
    gg_session_state *st = (gg_session_state *)user;
    static const char tag[0xF] = "GGEMU-STATUS-00";
    (void)h;
    if (*n < 0x128) { *n = 0; return GG_STATUS_BUFFER_TOO_SMALL; }
    memset(pl, 0, 0x128);
    memcpy(pl + 0x100, tag, sizeof(tag));
    memcpy(pl + 0x110, &st->scan_paused,  4);
    memcpy(pl + 0x114, &st->ui_state,     4);
    memcpy(pl + 0x118, &st->sess_1c5920,  4);
    memcpy(pl + 0x11C, &st->sess_1c5928,  4);
    memcpy(pl + 0x120, &st->sess_1c5930,  4);
    *n = 0x128;
    return GG_STATUS_SUCCESS;
}

/* 0xC088: service reply = one u32 */
int32_t gg_cmd_u32_reply(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n)
{
    gg_session_state *st = (gg_session_state *)user;
    uint32_t v = st->sess_1c5938;
    (void)h;
    if (*n < 4) { *n = 0; return GG_STATUS_BUFFER_TOO_SMALL; }
    memcpy(pl, &v, 4);
    *n = 4;
    return GG_STATUS_SUCCESS;
}

/* 0x5C: bool-validation of payload; too small -> 0xC0000023 */
int32_t gg_cmd_bool_validate(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n)
{
    (void)user; (void)h;
    if (*n < 1) { *n = 0; return GG_STATUS_BUFFER_TOO_SMALL; }
    return pl[0] ? GG_STATUS_SUCCESS : GG_STATUS_UNSUCCESSFUL;
}

/* 0xC0B4: UI event, sub-id payload[0] in {1..6}; id 4 -> GUI closed */
int32_t gg_cmd_ui_event(void *user, const gg_cmdhdr *h, uint8_t *pl, uint32_t *n)
{
    gg_session_state *st = (gg_session_state *)user;
    (void)h;
    if (*n < 1) { *n = 0; return GG_STATUS_BUFFER_TOO_SMALL; }
    if (pl[0] < 1 || pl[0] > 6) return GG_STATUS_INVALID_DEVICE_REQUEST;
    st->ui_state = pl[0];
    *n = 0;
    return GG_STATUS_SUCCESS;
}

/* ---- dispatcher --------------------------------------------------- */

int32_t gg_cmds_dispatch(void *user, const gg_cmdhdr *hdr,
                         uint8_t *payload, uint32_t *io_len)
{
    gg_session_state *st = (gg_session_state *)user;

    /* raw path: no GGEB envelope (original rule) */
    if (hdr->id == GG_CMD_BIN_PASSTHRU_2 || hdr->id == GG_CMD_MEMACCESS_LOG
        || hdr->size == 0) {
        switch (hdr->id) {
        case GG_CMD_NOOP:
            return gg_cmd_noop(user, hdr, payload, io_len);
        case GG_CMD_GET_GLOBAL_0xC591D:
        case GG_CMD_GET_GLOBAL_0xC5398:
            return gg_cmd_get_global(user, hdr, payload, io_len);
        default:
            break; /* fall through to table */
        }
    }

    switch (hdr->id) {
    /* HWID collectors: replies carry collected structures; the clean
     * implementations live in km/hwid.c and are wired at runtime. */
    case GG_CMD_ADAPT_COLLECT:
    case GG_CMD_SMBIOS_COLLECT:
    case GG_CMD_STORAGE_SERIALS:
    case GG_CMD_GPU_ENV:
    case GG_CMD_PROC_QUERY:
        /* protocol-level answer: NOT_IMPLEMENTED content keeps wire
         * shape (0-length reply + success) unless a collector is
         * registered by the host process via gg_cmds_set_collector. */
        *io_len = 0;
        return GG_STATUS_SUCCESS;

    case GG_CMD_NOOP:
        return gg_cmd_noop(user, hdr, payload, io_len);

    case GG_CMD_BOOL_VALIDATE:
        return gg_cmd_bool_validate(user, hdr, payload, io_len);

    case GG_CMD_GET_GLOBAL_0xC591D:
    case GG_CMD_GET_GLOBAL_0xC5398:
    case GG_CMD_GLOBAL_0xC5368:
    case GG_CMD_GLOBAL_0xC5328:
        return gg_cmd_get_global(user, hdr, payload, io_len);

    case GG_CMD_STATUS_BLOCK:
        return gg_cmd_status_block(user, hdr, payload, io_len);

    case GG_CMD_SVC_U32_REPLY:
        return gg_cmd_u32_reply(user, hdr, payload, io_len);

    case GG_CMD_UI_EVENT:
        return gg_cmd_ui_event(user, hdr, payload, io_len);

    case GG_CMD_U32_ARG:
        /* takes u32 from payload[0], no reply */
        if (*io_len < 4) { *io_len = 0; return GG_STATUS_BUFFER_TOO_SMALL; }
        *io_len = 0;
        return GG_STATUS_SUCCESS;

    case GG_CMD_SCAN_PAUSE_RESUME:
        /* " scan is resumed"/"…n is not running" — state flip only */
        st->scan_paused = st->scan_paused ? 0 : 1;
        *io_len = 0;
        return GG_STATUS_SUCCESS;

    case GG_CMD_SET_INTERVALS_1:
    case GG_CMD_SET_INTERVALS_2:
    case GG_CMD_SET_INTERVALS_3: {
        /* payload = array of u32 intervals (original parses several
         * fixed offsets); clean model: copy up to 8 u32 */
        uint32_t i, cnt = *io_len / 4;
        if (cnt > 8) cnt = 8;
        for (i = 0; i < cnt; i++) memcpy(&st->intervals[i], payload + 4 * i, 4);
        *io_len = 0;
        return GG_STATUS_SUCCESS;
    }

    case GG_CMD_SESSION_UPDATE: {
        /* TLV -> globals 0x1C5920/28/30/38 (u32 quadruple) */
        if (*io_len < 16) { *io_len = 0; return GG_STATUS_BUFFER_TOO_SMALL; }
        memcpy(&st->sess_1c5920, payload +  0, 4);
        memcpy(&st->sess_1c5928, payload +  4, 4);
        memcpy(&st->sess_1c5930, payload +  8, 4);
        memcpy(&st->sess_1c5938, payload + 12, 4);
        *io_len = 0;
        return GG_STATUS_SUCCESS;
    }

    case GG_CMD_MEMACCESS_LOG:
    case GG_CMD_BIN_PASSTHRU_1:
    case GG_CMD_BIN_PASSTHRU_2:
        /* raw passthrough: consumed, no reply body */
        *io_len = 0;
        return GG_STATUS_SUCCESS;

    default:
        *io_len = 0;
        return GG_STATUS_INVALID_DEVICE_REQUEST;   /* 0xC0000010 */
    }
}
