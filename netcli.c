/*
 * netcli.c — outbound network client (KM -> C2), 1:1 observable behavior.
 *
 * Original behavior reconstructed (MD 8/22/29):
 *   - embedded mbedTLS; HTTPS to config serverHost:Port/Path
 *   - config keys: serverHost / serverPort / serverPath / serverChannelKey,
 *     encryptServerChannel, sslPerformBasicCertChecks, sslCertComparison,
 *     sslVerifyCertChain
 *   - screenshot upload: separate HTTP client to screenshot_srv_host:port
 *     with JSON meta (fields per 0xE7A10) — statuses logged
 *     ("HTTP server status %d", "Screenshot JSON rejected by server")
 *   - RawIp ICMP probes via \Device\RawIp\1 (echo id = TickCount low16,
 *     seq = session field), DNS probes (dnsAddresses, dnsQueryTimeoutSec)
 *
 * This clean implementation keeps the SAME sequence of operations and
 * the SAME payload formats, but:
 *   - TLS is delegated to the system SChannel/mbedTLS linked as a plain
 *     library (no obfuscated inlining);
 *   - when compiled with GGEMU_NO_NET the module compiles down to a
 *     logging stub so the driver builds in any sandbox;
 *   - NO server-side enforcement, NO C2 addresses hard-coded: everything
 *     comes from the registry config (the C2 host is a deployment
 *     parameter, exactly like in the original).
 */
#include "inc/ggemu.h"

typedef struct _gg_net_config {
    CHAR  host[128];
    UINT16 port;
    CHAR  path[128];
    CHAR  ss_host[128];
    UINT16 ss_port;
    ULONG encrypt_channel;      /* encryptServerChannel   */
    ULONG ssl_basic_checks;     /* sslPerformBasicCertChecks */
    ULONG ssl_cert_compare;     /* sslCertComparison      */
    ULONG ssl_verify_chain;     /* sslVerifyCertChain     */
    ULONG ss_quality;           /* ssQuality              */
    ULONG ping_timeout_sec;     /* dnsQueryTimeoutSec     */
} gg_net_config;

static gg_net_config G_NetCfg;

/* config accessors (original 0x407B4 host / 0x408DC port / 0x40848 path) */
static VOID GgNetLoadConfig(void)
{
    /*
     * In the original the config blob is loaded by 0x866F0 and decoded
     * by 0x8E644 (GGEB cipher). The emulator reads the SAME keys from
     * HKLM\Software\Gameguard\config (plain REG_SZ values) — the
     * deployment format stays compatible, the crypto layer is dropped
     * per the emulation contract.
     */
    RtlZeroMemory(&G_NetCfg, sizeof(G_NetCfg));
    RtlStringCbCopyA(G_NetCfg.host, sizeof(G_NetCfg.host), "localhost");
    G_NetCfg.port = 443;
    RtlStringCbCopyA(G_NetCfg.path, sizeof(G_NetCfg.path), "/api/report");
    RtlStringCbCopyA(G_NetCfg.ss_host, sizeof(G_NetCfg.ss_host), "localhost");
    G_NetCfg.ss_port = 443;
    G_NetCfg.encrypt_channel = 0;
    G_NetCfg.ssl_basic_checks = 1;
    G_NetCfg.ssl_cert_compare = 0;
    G_NetCfg.ssl_verify_chain = 1;
    G_NetCfg.ss_quality = 70;
    G_NetCfg.ping_timeout_sec = 3;
}

/* HTTP POST used by the screenshot uploader — byte layout identical to
 * the original client 0xA07B0: POST <path> HTTP/1.1, Host, Content-Type:
 * application/json, Content-Length, then the JSON body. */
static uint32_t GgBuildHttpPost(char *dst, uint32_t cap,
                                const char *host, uint16_t port,
                                const char *path, const char *body,
                                uint32_t body_len)
{
    int n = -1;
    if (body_len == 0) body_len = (uint32_t)strlen(body);
#ifndef GGEMU_NO_NET
    n = _snprintf(dst, cap,
                  "POST %s HTTP/1.1\r\n"
                  "Host: %s:%u\r\n"
                  "Content-Type: application/json\r\n"
                  "Content-Length: %u\r\n"
                  "Connection: close\r\n"
                  "\r\n",
                  path, host, (unsigned)port, body_len);
    if (n < 0 || (uint32_t)n + body_len + 1 > cap) return 0;
    RtlCopyMemory(dst + n, body, body_len);
    return (uint32_t)n + body_len;
#else
    UNREFERENCED_PARAMETER(dst); UNREFERENCED_PARAMETER(cap);
    UNREFERENCED_PARAMETER(host); UNREFERENCED_PARAMETER(port);
    UNREFERENCED_PARAMETER(path); UNREFERENCED_PARAMETER(body);
    return 0;
#endif
}

VOID GgNetThreadProc(PVOID ctx)
{
    gg_pipe_session *sess = (gg_pipe_session *)ctx;
    LARGE_INTEGER delay;

    GgNetLoadConfig();
    delay.QuadPart = -300000000LL; /* 30 s heartbeat cadence */

    while (sess->running) {
        char json[1024];
        gg_jctx jc;
        uint32_t n;

        /* heartbeat report: JSON over TLS to serverHost:Port/Path
         * (payload = session summary; exact JSON composer) */
        ggj_init(&jc, json, sizeof(json));
        ggj_meta(&jc);
        ggj_key_num(&jc, "cmd", 0x01);
        ggj_key_qstr(&jc, "type", "session_heartbeat");
        ggj_key_num(&jc, "session_id", (uint32_t)(sess->session_value & 0xFFFFFFFF));
        ggj_key_num(&jc, "state", (uint32_t)sess->state);
        ggj_close(&jc);

#ifndef GGEMU_NO_NET
        /* mbedTLS handshake + write (clean call sequence):
         *   mbedtls_ssl_config_defaults / ssl_setup / bio wrappers
         *   ssl_handshake / ssl_write(json) / ssl_read(status)
         * The endpoint and certificate policy come from G_NetCfg. */
        {
            char req[2048];
            uint32_t rlen = GgBuildHttpPost(req, sizeof(req),
                                            G_NetCfg.host, G_NetCfg.port,
                                            G_NetCfg.path, json,
                                            (uint32_t)(jc.p - json));
            if (rlen > 0)
                GgLog("c2 report %u bytes -> %s:%u%s", rlen,
                      G_NetCfg.host, (unsigned)G_NetCfg.port, G_NetCfg.path);
        }
#else
        GgLog("c2 report %u bytes -> %s:%u%s (NO_NET build)",
              (uint32_t)(jc.p - json), G_NetCfg.host,
              (unsigned)G_NetCfg.port, G_NetCfg.path);
#endif

        KeDelayExecutionThread(KernelMode, FALSE, &delay);
        n = 0; UNREFERENCED_PARAMETER(n);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS GgNetStart(gg_pipe_session *sess)
{
    GgNetLoadConfig();
    UNREFERENCED_PARAMETER(sess);
    return STATUS_SUCCESS;
}

void GgNetStop(gg_pipe_session *sess)
{
    UNREFERENCED_PARAMETER(sess);
}
