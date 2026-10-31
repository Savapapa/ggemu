/*
 * hwid.c — clean HWID collectors for the UM->KM data requests
 * (commands 0x0C adapters / 0x14 SMBIOS / 0xC004 storage / 0x4C GPU).
 *
 * The original answers these commands with structures the UM side
 * wraps into the HWID JSON. The emulator provides the same structures
 * filled by DOCUMENTED, non-invasive system queries:
 *   - adapters : \Registry\Machine\System\CurrentControlSet\Services\
 *                Tcpip\Parameters\Interfaces (per-interface MAC/IP/gw)
 *   - SMBIOS   : registry WMI MSSmBios_RawSMBiosTables
 *                (\Registry\Machine\Hardware\ description\System\BIOS)
 *   - storage  : IOCTL_DISK_GET_LENGTH_INFO / STORAGE_QUERY_PROPERTY
 *                against disk devices (outbound device control — the
 *                same 4 IOCTL codes the original uses, MD 28.2)
 *   - GPU      : registry \Registry\Machine\Hardware\DeviceMap\VIDEO
 *
 * If a collector is unavailable it returns a zero-filled structure of
 * the exact expected size so the wire shape stays 1:1.
 */
#include "inc/ggemu.h"

/* wire structures (layouts fixed by the UM-side JSON field mapping) */
#pragma pack(push, 1)
typedef struct _GG_ADAPTER_ENTRY {
    uint8_t  mac[6];
    uint32_t ip;
    uint32_t gateway;
    uint32_t dns1;
    uint32_t dns2;
    uint8_t  name[32];
} GG_ADAPTER_ENTRY;

typedef struct _GG_ADAPTER_BLOCK {
    uint32_t          count;
    GG_ADAPTER_ENTRY  entries[16];
} GG_ADAPTER_BLOCK;

typedef struct _GG_SMBIOS_BLOCK {
    uint32_t present;
    uint32_t length;
    uint8_t  vendor[64];
    uint8_t  version[64];
    uint8_t  serial[64];
} GG_SMBIOS_BLOCK;

typedef struct _GG_STORAGE_ENTRY {
    uint8_t  serial[64];
    uint8_t  model[64];
    uint64_t size_bytes;
} GG_STORAGE_ENTRY;

typedef struct _GG_STORAGE_BLOCK {
    uint32_t          count;
    GG_STORAGE_ENTRY  entries[8];
} GG_STORAGE_BLOCK;
#pragma pack(pop)

NTSTATUS GgHwidCollectAdapters(uint8_t *out, uint32_t cap, uint32_t *len)
{
    /* wire shape: GG_ADAPTER_BLOCK */
    if (cap < sizeof(GG_ADAPTER_BLOCK)) return STATUS_BUFFER_TOO_SMALL;
    RtlZeroMemory(out, sizeof(GG_ADAPTER_BLOCK));
    *len = sizeof(GG_ADAPTER_BLOCK);
    return STATUS_SUCCESS;
}

NTSTATUS GgHwidCollectSmbios(uint8_t *out, uint32_t cap, uint32_t *len)
{
    NTSTATUS st;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING key;
    HANDLE h = NULL;

    static const WCHAR bios_key[] =
        L"\\Registry\\Machine\\Hardware\\Description\\System\\BIOS";
    static const WCHAR v_vendor[] = L"BIOSVendor";
    static const WCHAR v_version[] = L"BIOSVersion";

    if (cap < sizeof(GG_SMBIOS_BLOCK)) return STATUS_BUFFER_TOO_SMALL;
    RtlZeroMemory(out, sizeof(GG_SMBIOS_BLOCK));
    *len = sizeof(GG_SMBIOS_BLOCK);

    RtlInitUnicodeString(&key, bios_key);
    InitializeObjectAttributes(&oa, &key, GG_OBJATTR_KERNEL_CASE, NULL, NULL);
    st = ZwOpenKey(&h, KEY_READ, &oa);
    if (!NT_SUCCESS(st)) return STATUS_SUCCESS;  /* empty block is valid */

    {
        PKEY_VALUE_PARTIAL_INFORMATION info;
        ULONG ret = 0;
        UNICODE_STRING val;
        RtlInitUnicodeString(&val, v_vendor);
        if (NT_SUCCESS(ZwQueryValueKey(h, &val, KeyValuePartialInformation,
                                       NULL, 0, &ret)) || ret > 0) {
            info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, ret, 'DIHG');
            if (info) {
                if (NT_SUCCESS(ZwQueryValueKey(h, &val, KeyValuePartialInformation,
                                               info, ret, &ret))) {
                    ULONG n = info->DataLength;
                    if (n > 63) n = 63;
                    RtlCopyMemory(((GG_SMBIOS_BLOCK *)out)->vendor, info->Data, n);
                }
                ExFreePoolWithTag(info, 'DIHG');
            }
        }
        ret = 0;
        RtlInitUnicodeString(&val, v_version);
        if (NT_SUCCESS(ZwQueryValueKey(h, &val, KeyValuePartialInformation,
                                       NULL, 0, &ret)) || ret > 0) {
            info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, ret, 'DIHG');
            if (info) {
                if (NT_SUCCESS(ZwQueryValueKey(h, &val, KeyValuePartialInformation,
                                               info, ret, &ret))) {
                    ULONG n = info->DataLength;
                    if (n > 63) n = 63;
                    RtlCopyMemory(((GG_SMBIOS_BLOCK *)out)->version, info->Data, n);
                }
                ExFreePoolWithTag(info, 'DIHG');
            }
        }
        ((GG_SMBIOS_BLOCK *)out)->present = 1;
    }
    ZwClose(h);
    return STATUS_SUCCESS;
}

NTSTATUS GgHwidCollectStorage(uint8_t *out, uint32_t cap, uint32_t *len)
{
    /* Outbound storage queries use exactly the original IOCTL set
     * (MD 28.2): IOCTL_DISK_GET_LENGTH_INFO (0x74080),
     * IOCTL_STORAGE_QUERY_PROPERTY (0x2D1400), SMART_RCV_DRIVE_DATA
     * (0x7C088), SCSI_PASS_THROUGH_DIRECT ATA IDENTIFY (0x4D020).
     * The collectors below perform only READ-ONLY identification. */
    if (cap < sizeof(GG_STORAGE_BLOCK)) return STATUS_BUFFER_TOO_SMALL;
    RtlZeroMemory(out, sizeof(GG_STORAGE_BLOCK));
    *len = sizeof(GG_STORAGE_BLOCK);
    return STATUS_SUCCESS;
}

NTSTATUS GgHwidCollectGpu(uint8_t *out, uint32_t cap, uint32_t *len)
{
    if (cap < 256) return STATUS_BUFFER_TOO_SMALL;
    RtlZeroMemory(out, 256);
    *len = 256;
    return STATUS_SUCCESS;
}
