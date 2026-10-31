/*
 * regchan.c — registry command channel HKLM\Software\Gameguard.
 *
 * The original uses the value "cmd" in both directions:
 *   - reads it every cycle of the pipe thread (backup UM->KM channel)
 *   - writes "Logout STEAM: %s" on session teardown
 * Values are read/written with Zw*Key APIs with KernelMode handles,
 * exactly like the original, but WITHOUT PreviousMode spoofing (the
 * emulator runs everything at PASSIVE_LEVEL with explicit KernelMode
 * access — clean and equivalent for kernel handles).
 */
#include "inc/ggemu.h"

static const WCHAR GG_REG_KEY[] = L"\\Registry\\Machine\\Software\\Gameguard";
static const WCHAR GG_REG_CMD[] = L"cmd";

NTSTATUS GgRegEnsureKey(void)
{
    NTSTATUS st;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING key;
    HANDLE h;

    RtlInitUnicodeString(&key, GG_REG_KEY);
    InitializeObjectAttributes(&oa, &key, GG_OBJATTR_KERNEL_CASE, NULL, NULL);
    st = ZwCreateKey(&h, KEY_READ | KEY_WRITE, &oa, 0, NULL,
                     REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(st)) return st;
    ZwClose(h);
    return STATUS_SUCCESS;
}

NTSTATUS GgRegCmdWrite(const char *utf8, uint32_t len)
{
    NTSTATUS st;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING key, val;
    HANDLE h = NULL;
    WCHAR wval[16];
    uint32_t i;

    RtlInitUnicodeString(&key, GG_REG_KEY);
    InitializeObjectAttributes(&oa, &key, GG_OBJATTR_KERNEL_CASE, NULL, NULL);
    st = ZwOpenKey(&h, KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(st)) return st;

    for (i = 0; i < sizeof(GG_REG_CMD) / sizeof(WCHAR); i++) wval[i] = GG_REG_CMD[i];
    RtlInitUnicodeString(&val, wval);

    st = ZwSetValueKey(h, &val, 0, REG_SZ, (PVOID)utf8, len);
    ZwClose(h);
    return st;
}

NTSTATUS GgRegCmdRead(uint8_t *buf, uint32_t cap, uint32_t *len)
{
    NTSTATUS st;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING key, val;
    HANDLE h = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION info;
    ULONG retlen = 0;
    uint32_t i;
    WCHAR wval[16];

    *len = 0;
    RtlInitUnicodeString(&key, GG_REG_KEY);
    InitializeObjectAttributes(&oa, &key, GG_OBJATTR_KERNEL_CASE, NULL, NULL);
    st = ZwOpenKey(&h, KEY_QUERY_VALUE, &oa);
    if (!NT_SUCCESS(st)) return st;

    for (i = 0; i < sizeof(GG_REG_CMD) / sizeof(WCHAR); i++) wval[i] = GG_REG_CMD[i];
    RtlInitUnicodeString(&val, wval);

    st = ZwQueryValueKey(h, &val, KeyValuePartialInformation, NULL, 0, &retlen);
    if (st != STATUS_BUFFER_TOO_SMALL && st != STATUS_BUFFER_OVERFLOW) {
        ZwClose(h);
        return STATUS_NOT_FOUND;
    }
    info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, retlen, 'GERG');
    if (info == NULL) { ZwClose(h); return STATUS_INSUFFICIENT_RESOURCES; }

    st = ZwQueryValueKey(h, &val, KeyValuePartialInformation, info, retlen, &retlen);
    if (NT_SUCCESS(st) && info->Type == REG_SZ) {
        uint32_t n = info->DataLength;
        if (n > cap) n = cap;
        /* value stored as ANSI text written by GgRegCmdWrite */
        RtlCopyMemory(buf, info->Data, n);
        *len = n;
    }
    ExFreePoolWithTag(info, 'GERG');
    ZwClose(h);
    return st;
}
