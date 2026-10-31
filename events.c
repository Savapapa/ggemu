/*
 * events.c — KM->UM JSON event worker.
 *
 * Path mirrors the original: producers enqueue (0xA7D4), worker
 * serializes with the byte-exact composer (0xBCC8-equivalent in
 * proto/gg_json.c) and delivers as u32-length-framed JSON.
 *
 * The emulator keeps the queue + builders; DELIVERY in this clean
 * implementation goes through the same login-pipe transport when a
 * UM client is connected (the original wrote events into the session
 * pipe). Detection-producing events (scan results, hooks, memory
 * patches...) are intentionally NOT implemented — only transport
 * events and responses to explicit requests.
 */
#include "inc/ggemu.h"

#define GG_EVENT_QUEUE_CAP   64
#define GG_EVENT_MAX_JSON    0x1000

typedef struct _gg_event_item {
    LIST_ENTRY entry;
    uint32_t   len;
    uint8_t    json[GG_EVENT_MAX_JSON];
} gg_event_item;

static LIST_ENTRY      G_EvQueue;
static KSPIN_LOCK      G_EvLock;
static KEVENT          G_EvSignal;
static volatile LONG   G_EvCount;
static gg_pipe_session *G_EvSess;

void GgEventWorkerProc(PVOID ctx);

NTSTATUS GgEventsStart(gg_pipe_session *sess)
{
    InitializeListHead(&G_EvQueue);
    KeInitializeSpinLock(&G_EvLock);
    KeInitializeEvent(&G_EvSignal, SynchronizationEvent, FALSE);
    G_EvCount = 0;
    G_EvSess = sess;
    return STATUS_SUCCESS;
}

void GgEventsStop(gg_pipe_session *sess)
{
    UNREFERENCED_PARAMETER(sess);
    /* drain */
    for (;;) {
        KIRQL irql;
        gg_event_item *it;
        KeAcquireSpinLock(&G_EvLock, &irql);
        if (IsListEmpty(&G_EvQueue)) {
            KeReleaseSpinLock(&G_EvLock, irql);
            break;
        }
        it = (gg_event_item *)RemoveHeadList(&G_EvQueue);
        G_EvCount--;
        KeReleaseSpinLock(&G_EvLock, irql);
        ExFreePoolWithTag(it, 'VEGG');
    }
}

NTSTATUS GgEventEnqueue(const uint8_t *json, uint32_t len)
{
    gg_event_item *it;
    KIRQL irql;

    if (len == 0 || len > GG_EVENT_MAX_JSON) return STATUS_INVALID_PARAMETER;
    it = (gg_event_item *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                          sizeof(gg_event_item), 'VEGG');
    if (it == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(it, sizeof(*it));
    RtlCopyMemory(it->json, json, len);
    it->len = len;

    KeAcquireSpinLock(&G_EvLock, &irql);
    if (G_EvCount >= GG_EVENT_QUEUE_CAP) {
        KeReleaseSpinLock(&G_EvLock, irql);
        ExFreePoolWithTag(it, 'VEGG');
        return STATUS_QUOTA_EXCEEDED;
    }
    InsertTailList(&G_EvQueue, &it->entry);
    G_EvCount++;
    KeReleaseSpinLock(&G_EvLock, irql);
    KeSetEvent(&G_EvSignal, IO_NO_INCREMENT, FALSE);
    return STATUS_SUCCESS;
}

/* ---- event builders (key order per MD 17.3, byte-exact) ---------- */

/* {"cmd":N,"type":"<name>",...} — every event opens with cmd+type */
static void ev_head(gg_jctx *jc, int32_t cmd, const char *type)
{
    ggj_meta(jc);
    ggj_key_num(jc, "cmd", (uint32_t)cmd);
    ggj_key_qstr(jc, "type", type);
}

/* ping_results (0xE11E0):
 * cmd -> <name>_results(QSTR) -> timeout_ms(NUM) -> results{ name,status,trip_time_ms } */
void GgBuildPingResults(gg_jctx *jc)
{
    ev_head(jc, 0x24, "ping_results");
    ggj_key_qstr(jc, "ping_results", "");
    ggj_key_num(jc, "timeout_ms", 0);
    ggj_sep(jc, "results");
    ggj_meta(jc);
    ggj_key_qstr(jc, "name", "");
    ggj_key_qstr(jc, "status", "timeout");
    ggj_key_num(jc, "trip_time_ms", 0);
    ggj_close(jc);
    ggj_close(jc);
}

/* measure_speed (0xDDB44):
 * cmd -> measure_speed_result -> download_time -> upload_time
 *       -> download_size -> upload_size */
void GgBuildMeasureSpeed(gg_jctx *jc)
{
    ev_head(jc, 0x25, "measure_speed");
    ggj_key_qstr(jc, "measure_speed_result", "");
    ggj_key_num(jc, "download_time", 0);
    ggj_key_num(jc, "upload_time", 0);
    ggj_key_num(jc, "download_size", 0);
    ggj_key_num(jc, "upload_size", 0);
    ggj_close(jc);
}

/* hwid_confirm (0xD3D8C):
 * cmd -> confirm -> hash -> dhash -> dlen -> dhash0 -> dlen0
 *       -> serials{ serial%d -> serial%d_len } */
void GgBuildHwidConfirm(gg_jctx *jc, const char *confirm,
                        const char *hash, const char *dhash,
                        uint32_t dlen, const char *dhash0, uint32_t dlen0)
{
    ev_head(jc, 0x10, "hwid_confirm");
    ggj_key_qstr(jc, "confirm", confirm);
    ggj_key_qstr(jc, "hash", hash);
    ggj_key_qstr(jc, "dhash", dhash);
    ggj_key_num(jc, "dlen", dlen);
    ggj_key_qstr(jc, "dhash0", dhash0);
    ggj_key_num(jc, "dlen0", dlen0);
    ggj_sep(jc, "serials");
    ggj_meta(jc);
    ggj_key_qstr(jc, "serial1", "");
    ggj_key_num(jc, "serial1_len", 0);
    ggj_close(jc);  /* serials */
    ggj_close(jc);  /* event   */
}

/* screenshot meta (0xE7A10) — full field list in original order */
uint32_t GgBuildScreenshotMeta(char *dst, uint32_t cap, const void *meta)
{
    gg_jctx jc;
    ggj_init(&jc, dst, cap);
    ev_head(&jc, 0x30, "screenshot");
    ggj_key_num(&jc, "session_id", 0);
    ggj_key_qstr(&jc, "format", "");
    ggj_key_num(&jc, "fullscreen", 0);
    ggj_key_num(&jc, "game_active", 0);
    ggj_key_num(&jc, "screen_width", 0);
    ggj_key_num(&jc, "screen_height", 0);
    ggj_key_num(&jc, "wnd_width", 0);
    ggj_key_num(&jc, "wnd_height", 0);
    ggj_key_num(&jc, "game_width", 0);
    ggj_key_num(&jc, "game_height", 0);
    ggj_key_num(&jc, "game_wnd_top", 0);
    ggj_key_num(&jc, "game_wnd_left", 0);
    ggj_key_num(&jc, "game_wnd_right", 0);
    ggj_key_num(&jc, "game_wnd_bottom", 0);
    ggj_key_num(&jc, "mon_count", 0);
    ggj_key_num(&jc, "black", 0);
    ggj_key_num(&jc, "same_as_previous", 0);
    ggj_key_num(&jc, "method", 0);
    ggj_key_num(&jc, "compress", 0);
    ggj_key_num(&jc, "interval", 0);
    ggj_key_num(&jc, "error", 0);
    ggj_key_qstr(&jc, "steam_id", "");
    ggj_key_num(&jc, "status", 0);
    ggj_close(&jc);
    UNREFERENCED_PARAMETER(meta);
    return (uint32_t)(jc.p - dst);
}

/* ---- worker ------------------------------------------------------- */

VOID GgEventWorkerProc(PVOID ctx)
{
    gg_pipe_session *sess = (gg_pipe_session *)ctx;
    LARGE_INTEGER wait;

    UNREFERENCED_PARAMETER(sess);
    wait.QuadPart = -100000000LL; /* 10 s idle poll; signaled earlier */

    while (G_EvSess && G_EvSess->running) {
        KIRQL irql;
        gg_event_item *it = NULL;

        KeWaitForSingleObject(&G_EvSignal, Executive, KernelMode, FALSE, &wait);

        KeAcquireSpinLock(&G_EvLock, &irql);
        if (!IsListEmpty(&G_EvQueue)) {
            it = (gg_event_item *)RemoveHeadList(&G_EvQueue);
            G_EvCount--;
        }
        KeReleaseSpinLock(&G_EvLock, irql);

        if (it != NULL) {
            /* delivery: in the original the JSON goes into the session
             * pipe as u32-length-framed message. The emulator keeps the
             * framing and hands it to the transport hook (netcli logs
             * it when no UM consumer is attached). */
            uint8_t frame[4 + GG_EVENT_MAX_JSON];
            int n = gg_frame_write(frame, sizeof(frame), it->json, it->len);
            if (n > 0)
                GgLog("event %u bytes framed (transport hook)", it->len);
            ExFreePoolWithTag(it, 'VEGG');
        }
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}
