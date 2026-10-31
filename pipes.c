/*
 * pipes.c — login-pipe servers (steam_pipe_1 / steam_pipe_2), 1:1 with
 * the original thread 0x792F4 + setup 0x8F938.
 *
 * Wire behavior reproduced byte-for-byte:
 *   1. ZwCreateNamedPipeFile:
 *        ObjectAttributes:  OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE
 *        DesiredAccess:     0x80100100 (GENERIC_READ|SYNCHRONIZE|0x100)
 *        CreateOptions:     0x20 (FILE_SYNCHRONOUS_IO_NONALERT)
 *        Type/Read/Completion: byte-stream / byte-stream / queue
 *        MaximumInstances:  1, quotas 0x2000/0x2000
 *        DefaultTimeout:    -0x4788C00 x100ns (~11.99 s)
 *      name: \??\pipe\steam_pipe_N_%08x%08x
 *            (%08x%08x = TickCount.LowPart, TickCount.High1Time)
 *   2. greeting write: 18 bytes {u32 0xE, u32 0x10101, u16 0, u64 session}
 *   3. loop:
 *        - KeResetEvent / ZwWaitForSingleObject(event, -59.9 s)
 *          STATUS_TIMEOUT -> log "Timeout while waiting for response from steam."
 *        - ZwReadFile 4 bytes -> u32 len
 *          len==0 -> "Failed to exchange data with steam."
 *          read error -> "fAILED read data length from pipe, status %.8x"
 *        - alloc max(len,0x100) tag 'GGSK'; ZwReadFile len bytes
 *          read error -> "fAILED read data from pipe, status %.8x"
 *        - validate: len==1 -> "wRONG length, %d."
 *                    len in {9,14} -> ok, else "wRONG length, %d."
 *        - steamID = u64 payload[1..8]; 0 -> "User not logged in."
 *        - success: state=3, register user node (0x20 bytes), loop
 *   4. handles closed after every session, pipe recreated
 *
 * No anti-debug, no encryption of the login message (the original sends
 * it in clear too), no process checks.
 */
#include "inc/ggemu.h"

/* KUSER_SHARED_DATA TickCount (KSYSTEM_TIME) — name/greeting source */
#pragma pack(push, 1)
typedef struct _GG_KUSD_TICK {
    uint32_t LowPart;
    uint32_t High1Time;
    uint32_t High2Time;
} GG_KUSD_TICK;
#pragma pack(pop)

static VOID GgReadTickCount(uint32_t *lo, uint32_t *hi)
{
    const GG_KUSD_TICK *t = (const GG_KUSD_TICK *)(uintptr_t)0xFFFFF78000000320ULL;
    *lo = t->LowPart;
    *hi = t->High1Time;
}

/* registered-user node (original tag GGSP, size 0x20) */
typedef struct _gg_user_node {
    LIST_ENTRY entry;      /* +0x00 list linkage            */
    uint64_t   steam_id;   /* +0x10                         */
    uint8_t    flag;       /* +0x18                         */
    uint32_t   type;       /* +0x1C: login type byte        */
} gg_user_node;

static NTSTATUS GgCreatePipeServer(int variant, HANDLE *out_pipe,
                                   HANDLE *out_event)
{
    NTSTATUS st;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER timeout;
    char aname[80];
    WCHAR wname[80];
    uint32_t lo, hi;
    ULONG create_opts;
    SECURITY_QUALITY_OF_SERVICE sqos;

    GgReadTickCount(&lo, &hi);
    if (gg_pipe_name(aname, sizeof(aname), variant, lo, hi) < 0)
        return STATUS_INVALID_PARAMETER;

    {
        uint32_t i, n = 0;
        while (aname[n] && n < sizeof(aname)) { wname[n] = (WCHAR)(uint8_t)aname[n]; n++; }
        wname[n] = 0;
    }
    RtlInitUnicodeString(&name, wname);

    InitializeObjectAttributes(&oa, &name, GG_OBJATTR_KERNEL_CASE, NULL, NULL);

    /* FILE_PIPE_INFORMATION-equivalent parameters go directly into
     * ZwCreateNamedPipeFile's argument list */
    create_opts = FILE_PIPE_BYTE_STREAM_TYPE
                | (FILE_PIPE_BYTE_STREAM_MODE << 2)
                | (FILE_PIPE_QUEUE_OPERATION << 4);

    sqos.Length = sizeof(sqos);
    sqos.ImpersonationLevel = SecurityAnonymous;
    sqos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    sqos.EffectiveOnly = FALSE;

    timeout.QuadPart = GG_PIPE_DEFAULT_TIMEOUT;

    st = ZwCreateNamedPipeFile(out_pipe,
                               GG_PIPE_ACCESS,
                               &oa,
                               &iosb,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               create_opts,
                               GG_PIPE_OPTIONS,
                               GG_PIPE_BYTE_STREAM_TYPE,
                               GG_PIPE_BYTE_STREAM_MODE,
                               GG_PIPE_QUEUE_OPERATION,
                               GG_PIPE_MAX_INSTANCES,
                               GG_PIPE_QUOTA,
                               GG_PIPE_QUOTA,
                               &timeout);
    if (!NT_SUCCESS(st)) return st;

    /* per-session event for async read completion (original: one of the
     * 0x8F938 outputs used with ZwReadFile/ZwWaitForSingleObject) */
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateEvent(out_event, EVENT_ALL_ACCESS, &oa,
                       NotificationEvent, FALSE);
    if (!NT_SUCCESS(st)) { ZwClose(*out_pipe); return st; }
    return STATUS_SUCCESS;
}

/* write the 18-byte greeting (original 0x7988E..0x7991A) */
static NTSTATUS GgWriteGreeting(HANDLE pipe, uint64_t session_value)
{
    uint8_t hdr[GG_GREETING_SIZE];
    gg_greeting g;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st;
    LARGE_INTEGER offset;

    g.magic = GG_GREETING_MAGIC;
    g.sig = GG_GREETING_SIG;
    g.reserved = 0;
    g.session = session_value;
    gg_greeting_pack(hdr, &g);

    offset.QuadPart = 0;
    st = ZwWriteFile(pipe, NULL, NULL, NULL, &iosb, hdr, sizeof(hdr),
                     &offset, NULL);
    if (!NT_SUCCESS(st))
        GgLog("fAILED data to steam pipe, status %.8x.", (uint32_t)st);
    return st;
}

static VOID GgRegisterUser(gg_pipe_session *sess, uint64_t steam_id,
                           uint8_t type)
{
    gg_user_node *node;
    KIRQL irql;

    node = (gg_user_node *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                           sizeof(gg_user_node), 'GSPG');
    if (node == NULL) return;
    RtlZeroMemory(node, sizeof(*node));
    node->steam_id = steam_id;
    node->type = type;
    node->flag = 0;

    KeAcquireSpinLock(&sess->user_lock, &irql);
    InsertTailList(&sess->user_list, &node->entry);
    KeReleaseSpinLock(&sess->user_lock, irql);
    sess->state = GG_SESS_LOGGED_IN;
}

/* read exactly `len` bytes (byte-stream pipe may short-read) */
static NTSTATUS GgReadFull(HANDLE pipe, HANDLE event, void *buf, uint32_t len)
{
    NTSTATUS st;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    uint8_t *p = (uint8_t *)buf;
    uint32_t left = len;

    offset.QuadPart = 0;
    while (left > 0) {
        KeClearEvent(event);
        st = ZwReadFile(pipe, event, NULL, NULL, &iosb, p, left,
                        &offset, NULL);
        if (!NT_SUCCESS(st)) return st;
        if (st == STATUS_PENDING) {
            st = ZwWaitForSingleObject(event, FALSE, NULL);
            if (!NT_SUCCESS(st)) return st;
        }
        if (iosb.Information == 0) return STATUS_END_OF_FILE;
        p += iosb.Information;
        left -= (uint32_t)iosb.Information;
    }
    return STATUS_SUCCESS;
}

/* one pipe session: create -> greeting -> login -> teardown */
static VOID GgPipeLoop(gg_pipe_session *sess, int variant)
{
    HANDLE pipe = NULL, event = NULL;
    NTSTATUS st;
    uint32_t len = 0;
    uint8_t *payload = NULL;
    gg_login login;

    st = GgCreatePipeServer(variant, &pipe, &event);
    if (!NT_SUCCESS(st)) {
        GgLog("Failed to connect to steam.");
        return;
    }
    sess->state = GG_SESS_WAITING;

    st = GgWriteGreeting(pipe, sess->session_value);
    if (!NT_SUCCESS(st)) goto out;

    while (sess->running) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = GG_WAIT_EVENT_TIMEOUT;

        KeClearEvent(event);
        st = ZwWaitForSingleObject(event, FALSE, &timeout);
        if (st == STATUS_TIMEOUT) {
            GgLog("Timeout while waiting for response from steam.");
            goto out;
        }

        /* u32 length */
        st = GgReadFull(pipe, event, &len, 4);
        if (!NT_SUCCESS(st)) {
            GgLog("fAILED read data length from pipe, status %.8x", (uint32_t)st);
            goto out;
        }
        if (len == 0) {
            GgLog("Failed to exchange data with steam.");
            goto out;
        }

        payload = (uint8_t *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                             len > 0x100 ? len : 0x100, 'KSGG');
        if (payload == NULL) {
            GgLog("Failed to allocate %d bytes for data buffer.", len);
            goto out;
        }
        RtlZeroMemory(payload, len > 0x100 ? len : 0x100);

        st = GgReadFull(pipe, event, payload, len);
        if (!NT_SUCCESS(st)) {
            GgLog("fAILED read data from pipe, status %.8x", (uint32_t)st);
            goto out;
        }

        /* length validation (original: 1 -> error; 9/14 -> ok) */
        if (len != GG_LOGIN_MIN_SIZE && len != GG_LOGIN_EXT_SIZE) {
            GgLog("wRONG length, %d.", (int32_t)len);
            goto out;
        }
        if (gg_login_parse(payload, len, &login) != GG_LOGIN_OK) {
            GgLog("User not logged in.");
            goto out;
        }

        GgRegisterUser(sess, login.steam_id, login.type);
        ExFreePoolWithTag(payload, 'KSGG');
        payload = NULL;
        break;   /* one login per pipe instance, like the original */
    }

out:
    sess->state = GG_SESS_FAILED;
    if (payload) ExFreePoolWithTag(payload, 'KSGG');
    if (pipe)  ZwClose(pipe);
    if (event) ZwClose(event);
}

NTSTATUS GgPipesStart(gg_pipe_session *sess)
{
    UNREFERENCED_PARAMETER(sess);
    /* threads are spawned by DriverEntry (they need the global session);
     * this hook exists for parity with the original 0x99FD8 setup call */
    return STATUS_SUCCESS;
}

void GgPipesStop(gg_pipe_session *sess)
{
    sess->running = 0;
    KeSetEvent(&sess->stop_event, IO_NO_INCREMENT, FALSE);
}

VOID GgPipeThreadProc(PVOID ctx)
{
    gg_thread_arg *arg = (gg_thread_arg *)ctx;
    gg_pipe_session *sess = arg->sess;
    LARGE_INTEGER delay;

    delay.QuadPart = -10000000LL; /* 1 s between pipe instances */

    while (sess->running) {
        GgPipeLoop(sess, (int)arg->variant);
        if (!sess->running) break;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}
