/*
 * ggemu.h — internal context of the GGEmu kernel driver.
 *
 * GGEmu is a clean-room communication emulator of the GameGuard acdrv.sys
 * KM<->UM and KM->C2 channels:
 *   - login pipes  \??\pipe\steam_pipe_{1,2}_%08x%08x  (KM = server)
 *   - greeting frame {u32 0xE, u32 0x10101, u16 0, u64 session}
 *   - login messages (9/14 bytes, u64 steamID)
 *   - registry channel HKLM\Software\Gameguard value "cmd"
 *   - 40 command IDs with the original status semantics
 *   - KM->UM JSON events (byte-exact composer)
 *   - C2 client (config-driven TLS/HTTP)
 *
 * NOT implemented by design (per the emulation contract):
 *   - anti-debug / anti-analysis of any kind
 *   - code obfuscation / VM / mutation
 *   - cheat, scan and integrity detection mechanics
 */
#ifndef GGEMU_H
#define GGEMU_H

#include <ntddk.h>
#include "gg_proto.h"
#include "gg_cmds.h"

#define GGEMU_TAG_SRVR  'S'<<24|'G'<<16|'G'<<8|'G'   /* 'GGGS' server ctx */
#define GGEMU_TAG_THRD  'T'<<24|'S'<<16|'G'<<8|'G'   /* 'GGST' thread ctx */
#define GGEMU_TAG_EVNT  'V'<<24|'E'<<16|'G'<<8|'G'   /* 'GGEV' event      */
#define GGEMU_TAG_GENL  'M'<<24|'Y'<<16|'N'<<8|'E'   /* 'ENYM' general    */

/* pipe session states (mirror of original ctx+0x58 machine) */
#define GG_SESS_WAITING   2
#define GG_SESS_LOGGED_IN 3
#define GG_SESS_FAILED    4

/* pipe creation parameters, byte-exact with the original 0x8F938 */
#define GG_PIPE_ACCESS        0x80100100u  /* GENERIC_READ|SYNCHRONIZE|0x100 */
#define GG_PIPE_OPTIONS       0x20u        /* FILE_SYNCHRONOUS_IO_NONALERT   */
#define GG_PIPE_QUOTA         0x2000u
#define GG_PIPE_MAX_INSTANCES 1
#define GG_PIPE_DEFAULT_TIMEOUT (-0x4788C00LL)  /* ~ -11.99s (100ns units)  */
#define GG_OBJATTR_KERNEL_CASE (OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE)

/* read-loop waits (original constants) */
#define GG_WAIT_EVENT_TIMEOUT (-0x23C34600LL) /* ~ -59.9s */
#define GG_LOCK_FALLBACK_TIMEOUT (-0x1879A0LL)/* ~ -1.59s */

typedef struct gg_pipe_session {
    LIST_ENTRY   user_list;       /* registered steam users (GGSP nodes) */
    KSPIN_LOCK   user_lock;
    KEVENT       stop_event;
    volatile LONG running;
    volatile LONG state;          /* GG_SESS_* */
    uint64_t     session_value;   /* greeting u64                              */
    gg_session_state cmds;        /* command executor state                    */
} gg_pipe_session;

/* per-thread argument (pipe variant index) */
typedef struct _gg_thread_arg {
    gg_pipe_session *sess;
    LONG             variant;    /* 1 or 2 for pipe threads */
} gg_thread_arg;

/* ---------------- pipes.c ---------------- */
NTSTATUS GgPipesStart(gg_pipe_session *sess);
void     GgPipesStop(gg_pipe_session *sess);

/* thread body (one per pipe variant) */
VOID     GgPipeThreadProc(PVOID ctx);

/* ---------------- regchan.c ---------------- */
NTSTATUS GgRegCmdWrite(const char *utf8, uint32_t len);   /* "Logout STEAM: %s" path */
NTSTATUS GgRegCmdRead(uint8_t *buf, uint32_t cap, uint32_t *len);
NTSTATUS GgRegEnsureKey(void);

/* ---------------- events.c ---------------- */
NTSTATUS GgEventsStart(gg_pipe_session *sess);
void     GgEventsStop(gg_pipe_session *sess);
/* enqueue a JSON event (buffer copied); worker frames and delivers it */
NTSTATUS GgEventEnqueue(const uint8_t *json, uint32_t len);

/* event builders (byte-exact key sequences, see MD 17.3) */
void     GgBuildPingResults(gg_jctx *jc);          /* 0xE11E0 */
void     GgBuildMeasureSpeed(gg_jctx *jc);         /* 0xDDB44 */
void     GgBuildHwidConfirm(gg_jctx *jc, const char *confirm,
                            const char *hash, const char *dhash,
                            uint32_t dlen, const char *dhash0, uint32_t dlen0);

/* ---------------- netcli.c ---------------- */
NTSTATUS GgNetStart(gg_pipe_session *sess);
void     GgNetStop(gg_pipe_session *sess);
/* screenshot meta-event JSON (0xE7A10 field order) built into a buffer */
uint32_t GgBuildScreenshotMeta(char *dst, uint32_t cap, const void *meta);

/* ---------------- hwid.c (clean collectors) ---------------- */
NTSTATUS GgHwidCollectAdapters(uint8_t *out, uint32_t cap, uint32_t *len);
NTSTATUS GgHwidCollectSmbios(uint8_t *out, uint32_t cap, uint32_t *len);
NTSTATUS GgHwidCollectStorage(uint8_t *out, uint32_t cap, uint32_t *len);
NTSTATUS GgHwidCollectGpu(uint8_t *out, uint32_t cap, uint32_t *len);

/* ---------------- ggemu.c ---------------- */
extern gg_pipe_session G_Session;
void GgLog(const char *fmt, ...);

#endif /* GGEMU_H */
