/*
 * ggemu.c — driver entry of the GGEmu communication emulator.
 *
 * Boot sequence mirrors the ORIGINAL observable behavior at the
 * communication level only:
 *   1. two login-pipe servers (steam_pipe_1 / steam_pipe_2)
 *   2. event worker (KM->UM JSON events)
 *   3. network client thread (C2, config-driven)
 * DriverEntry keeps the system thread alive until service stop.
 *
 * Deliberately absent (emulation contract): VM/obfuscation layers,
 * export-table checks, bugcheck guards, process/patch detection.
 */
#include "inc/ggemu.h"

#pragma warning(disable: 4995 4996)
#include <ntstrsafe.h>

gg_pipe_session G_Session;

/* per-thread argument (variant index for pipe threads) */
static gg_thread_arg G_ArgPipe1, G_ArgPipe2;

VOID GgPipeThreadProc(PVOID ctx);
VOID GgEventWorkerProc(PVOID ctx);
VOID GgNetThreadProc(PVOID ctx);

void GgLog(const char *fmt, ...)
{
    NTSTATUS st;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    st = RtlStringCbVPrintfA(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (NT_SUCCESS(st))
        DbgPrint("GGEMU: %s\n", buf);
}

static VOID GgSessionInit(void)
{
    const uint64_t *kusd_tick;

    RtlZeroMemory(&G_Session, sizeof(G_Session));
    InitializeListHead(&G_Session.user_list);
    KeInitializeSpinLock(&G_Session.user_lock);
    KeInitializeEvent(&G_Session.stop_event, NotificationEvent, FALSE);
    G_Session.running = 1;
    G_Session.state = GG_SESS_WAITING;
    gg_session_init(&G_Session.cmds);

    /* session correlation value: TickCount (KUSER_SHARED_DATA + 0x320,
     * KSYSTEM_TIME {LowPart, High1Time}) — the same source the original
     * uses for pipe names and for the greeting u64 */
    kusd_tick = (const uint64_t *)(uintptr_t)0xFFFFF78000000320ULL;
    G_Session.session_value = *kusd_tick;
}

typedef struct _gg_thread_pkg {
    HANDLE handle;
} gg_thread_pkg;

static NTSTATUS GgSpawn(PVOID proc, PVOID arg, gg_thread_pkg *out)
{
    OBJECT_ATTRIBUTES oa;
    HANDLE h = NULL;
    NTSTATUS st;

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    st = PsCreateSystemThread(&h, THREAD_ALL_ACCESS, &oa, NULL, NULL,
                              (PKSTART_ROUTINE)proc, arg);
    if (!NT_SUCCESS(st)) return st;
    out->handle = h;
    return STATUS_SUCCESS;
}

static VOID GgJoin(gg_thread_pkg *t)
{
    PVOID wait_obj;
    if (t->handle == NULL) return;
    if (NT_SUCCESS(ObReferenceObjectByHandle(t->handle, SYNCHRONIZE, NULL,
                                             KernelMode, &wait_obj, NULL))) {
        KeWaitForSingleObject(wait_obj, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(wait_obj);
    }
    ZwClose(t->handle);
    t->handle = NULL;
}

static VOID GgStopAll(void)
{
    G_Session.running = 0;
    KeSetEvent(&G_Session.stop_event, IO_NO_INCREMENT, FALSE);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING regpath)
{
    NTSTATUS st = STATUS_SUCCESS;
    gg_thread_pkg t_pipe1 = {0}, t_pipe2 = {0}, t_evt = {0}, t_net = {0};

    UNREFERENCED_PARAMETER(regpath);

    GgSessionInit();

    G_ArgPipe1.sess = &G_Session; G_ArgPipe1.variant = 1;
    G_ArgPipe2.sess = &G_Session; G_ArgPipe2.variant = 2;

    st = GgSpawn(GgPipeThreadProc, &G_ArgPipe1, &t_pipe1);
    if (!NT_SUCCESS(st)) goto fail;
    st = GgSpawn(GgPipeThreadProc, &G_ArgPipe2, &t_pipe2);
    if (!NT_SUCCESS(st)) goto fail;
    st = GgSpawn(GgEventWorkerProc, &G_Session, &t_evt);
    if (!NT_SUCCESS(st)) goto fail;
    st = GgSpawn(GgNetThreadProc, &G_Session, &t_net);
    if (!NT_SUCCESS(st)) goto fail;

    /* block the system thread until stop */
    KeWaitForSingleObject(&G_Session.stop_event, Executive, KernelMode,
                          FALSE, NULL);

    GgNetStop(&G_Session);
    GgEventsStop(&G_Session);
    GgPipesStop(&G_Session);

    GgJoin(&t_net);
    GgJoin(&t_evt);
    GgJoin(&t_pipe2);
    GgJoin(&t_pipe1);
    return STATUS_SUCCESS;

fail:
    GgStopAll();
    GgJoin(&t_net); GgJoin(&t_evt); GgJoin(&t_pipe2); GgJoin(&t_pipe1);
    return STATUS_UNSUCCESSFUL;
}
