/*
 * test_client.c — user-mode validation client for GGEmu (and for the
 * original acdrv.sys, since it speaks the same wire protocol).
 *
 * Sequence (mirrors the UM side reconstructed from the KM dump):
 *   1. read TickCount from KUSER_SHARED_DATA (usermode map 0x7FFE0000,
 *      TickCount KSYSTEM_TIME at +0x320 — the same source the driver
 *      uses for pipe names)
 *   2. open \\.\pipe\steam_pipe_{N}_{tick_low:08x}{tick_high:08x}
 *   3. read the 18-byte greeting, validate {0xE, 0x10101, 0, u64}
 *   4. send login: u32 len(9) + {type, u64 steamID}
 *   5. (optional) write HKLM\Software\Gameguard "cmd" registry value
 *
 * Build (MSVC):  cl /W4 /O2 test_client.c advapi32.lib
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma pack(push, 1)
typedef struct { uint32_t LowPart; uint32_t High1Time; uint32_t High2Time; } KSTD;
#pragma pack(pop)

static int read_greeting(HANDLE h, uint8_t out[18])
{
    DWORD got = 0;
    if (!ReadFile(h, out, 18, &got, NULL) || got != 18) return -1;
    return 0;
}

int main(int argc, char **argv)
{
    const KSTD *tick = (const KSTD *)(uintptr_t)0x7FFE0320ULL;
    char name[128];
    HANDLE h;
    uint8_t greet[18];
    DWORD wr = 0;
    uint8_t login[13] = { 9,0,0,0, 0x01, 0x40,0x54,0x6b,0x7c,0x11,0x22,0x33,0x02 };
    uint64_t steam_id = 76561198000000000ull;
    int variant = (argc > 1) ? atoi(argv[1]) : 1;

    if (argc > 2) steam_id = strtoull(argv[2], NULL, 10);

    sprintf(name, "\\\\.\\pipe\\steam_pipe_%d_%08x%08x",
            variant, tick->LowPart, tick->High1Time);
    printf("[um] opening %s\n", name);

    h = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("[um] open failed, gle=%lu\n", GetLastError());
        return 1;
    }

    if (read_greeting(h, greet) != 0) {
        printf("[um] greeting read failed\n");
        CloseHandle(h);
        return 1;
    }
    {
        uint32_t magic, sig; uint16_t res; uint64_t sess;
        memcpy(&magic, greet, 4); memcpy(&sig, greet + 4, 4);
        memcpy(&res, greet + 8, 2); memcpy(&sess, greet + 10, 8);
        printf("[um] greeting: magic=0x%08x sig=0x%08x res=%u session=0x%016llx %s\n",
               magic, sig, res, (unsigned long long)sess,
               (magic == 0xE && sig == 0x10101) ? "OK" : "MISMATCH");
    }

    /* login: u32 LE len=9 + {type=1, u64 steamID} */
    login[5] = (uint8_t)(steam_id);      login[6] = (uint8_t)(steam_id >> 8);
    login[7] = (uint8_t)(steam_id >> 16); login[8] = (uint8_t)(steam_id >> 24);
    login[9] = (uint8_t)(steam_id >> 32); login[10] = (uint8_t)(steam_id >> 40);
    login[11] = (uint8_t)(steam_id >> 48); login[12] = (uint8_t)(steam_id >> 56);

    if (!WriteFile(h, login, sizeof(login), &wr, NULL) || wr != sizeof(login)) {
        printf("[um] login write failed\n");
        CloseHandle(h);
        return 1;
    }
    printf("[um] login sent (%lu bytes, steamid=%llu)\n",
           (unsigned long)wr, (unsigned long long)steam_id);

    CloseHandle(h);
    printf("[um] done\n");
    return 0;
}
