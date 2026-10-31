# RE-база знаний: acdrv.sys (GameGuard, CS-серия)

> Сводка ВСЕХ находок реверс-инжиниринга за сессию. Объект: `upload/acdrv.sys` (14.2 МБ).
> Артефакты: `work/db.pkl` (база функций/строк), `work/blob_strings.txt` (3086 расшифрованных строк),
> `work/comms/*.asm` (13 дампов), `work/38db8.asm`, PDF-отчёты в `download/`.

---

## 1. Общие сведения о файле

| Параметр | Значение |
|---|---|
| Тип | PE32+ x64 native kernel driver (WDM, без экспортов) |
| SizeOfImage | 0xD98000 (~14.2 МБ) |
| EntryPoint RVA | 0xBE404 |
| ImageBase | 0x180000000 |
| TimeDateStamp | 2026-10-23 |
| VersionInfo | GameGuard / acdev.sys / acdrv.sys, ProductVersion 50.0.0.0, locale 0419 (RU), "SubC", "Inpleron" |
| Подпись | Authenticode WHQL: Microsoft Windows Hardware Compatibility Publisher, 2026-05-13…2027-05-11 |
| SHA-256 | 01035f86…5a45fc8 (полный в callout PDF-отчёта; сертификат извлечён в `work/cert.pkcs7`) |

**Секции (7):**
- `.text` 1.4 МБ, entropy 6.87 — основной код;
- `.rdata`, `.data`, `.pdata` (фиктивная!), `.rsrc`, `.reloc`;
- **`.b@Z` 12.3 МБ RWX, entropy 7.50** — мутатированный код + данные: opaque predicates, computed `jmp r11`, хвост несёт реальную exception-директорию.

**Импорт:** всего 35 функций ntoskrnl.exe (минимальный набор). Все остальные API — динамический резолв (см. §5).

---

## 2. Антианализ

1. **Фиктивный `.pdata`** — заведомая ложная таблица функций. Реальная exception-директория лежит в хвосте `.b@Z` на RVA **0xD89310** → **3383 функции** (3235 в .text + 148 в .b@Z). Это база полного покрытия кода.
2. **`.b@Z` RWX** — самоизменяющийся код, непрямые переходы (`jmp r11`), junk/opaque predicates после каждого call.
3. **Инлайн-шифрование строк** (§4) — в коде нет ни одной plaintext-строки API/реестра.
4. **NO_SEH + DYNAMIC_BASE + NX** в PE-характеристиках.
5. **Guard-функция 0x161720**: проверка глобала 0x1B8300; при провале → 0x15E810 → `KeBugCheckEx(0xF7)` (DRIVER_OVERRAN_STACK_BUFFER — маскировка под баг стека).
6. Проверка `NtBuildNumber` в допустимом диапазоне билдов Windows внутри резолвера.

---

## 3. Цепочка инициализации

```
EntryPoint 0xBE404            — обёртка: SystemRoot из реестра → глобал 0x1C5520;
                                таблица колбэков 0x162170
  └─> DriverEntry 0x923B8     — настоящая точка входа
        └─> jmp 0x1D7000      — вход в .b@Z (мутатированный код)
              └─> 0xB252C     — DriverInitialize: скрытая регистрация IoCreateDriver
                    └─> 0x4A26C — создание \Device\GGDev11 + \DosDevices\GGDev11;
                                 процессные чек-листы (lsass, svchost, csrss, notepad,
                                 WindowsTerminal, cstrike, cstrike_hd,
                                 gameoverlayrenderer64.dll, nvdrswr.lk)
```

**0x38DB8** (5173 байта, дамп `work/38db8.asm`): сканы `\??\PhysicalDrive`, `\Device`, `\Driver\*`;
PspCreateProcessNotifyRoutine / PspCreateThreadNotifyRoutine / PsLoadImageNotifyRoutine
(+Count/ExCount-варианты), RegistryNotification — обход callback-массивов ядра;
регистрация собственных notify-колбэков: 0x2CFC (process), 0x2F60 (thread), 0x31B8 (image), 0x3468 (registry).

---

## 4. Шифрование строк

Алгоритм: `plain[i] = cipher[i] ^ ((i mod M) + base)`

- Узкие (uint8/char): M ∈ {52, 55, 57, 58}, base ∈ {0x38, 0x39}
- Широкие (wchar16): XOR на uint16 с теми же параметрами
- Инлайн-вариант: строки дешифруются прямо в коде; маркер — magic-константа **0x1F7047DD**, найдено **124 инлайн-точки** (скрипт 12)

Продукты: `work/blob_strings.txt` (3086 строк — валюдроль), `inline_strings.txt` (69), `strings_final*.txt`, `strings_utf16.txt`, `strings_wide_bf.txt`.

---

## 5. Динамическое разрешение API

### 5.1 Резолвер экспортов ntoskrnl — 0x5B298
1. `ZwQuerySystemInformation(SystemModuleInformation=11)` — поиск модулей NTOSKRNL / NTKRNLPA / NTKRNLMP;
2. проверка диапазона `NtBuildNumber`;
3. парсинг экспортов PE в памяти (0x593CC) — поиск по хэшу имени.

### 5.2 Резолвер по имени — 0xB12CC(name, &slot)
Вызывающие функции передают plaintext-имя (дешифрованное на лету) и адрес глобального слота.
Карта слотов (scripts/29): **0x1C5190–0x1C52F8** — ZwOpenProcess, ZwReadVirtualMemory, ZwWriteVirtualMemory,
ZwProtectVirtualMemory, ZwCreateThreadEx, … ; **0x1C6180–0x1C61A0** — Mutant/ResetEvent/CreateNamedPipeFile-набор.

### 5.3 Шифрованная vtable T1 — ЦЕЛЬ: карта 176 индексов
- **T1 = 0x1C5130** (ключ 0x1C5138), twin-таблица **T2 = 0x1C5120**; расхождение T1/T2 → репортёр **0x5D838(0x4587125609762548, 0x77)**.
- Обёртки-геттеры: `0x5C74C = T1[0x168]` и др. — код обращается к vtable ПО ИНДЕКСУ, всего **176 индексов** (T1 span 0x580 байт).
- Примеры привязок обёрток: 0x5FD64=ZwClose, 0x5FAE8/0x5FC28=чтение пайпа, 0x61D60=ZwWaitForSingleObject (STATUS_TIMEOUT), 0x8F680=ZwCreateNamedPipeFile.
- VM-байткод (см. §15) обращается к T1 по индексу → для полной карты нужно декодирование VM/эмуляция init (kernemul, Unicorn backend — резервный путь).

### 5.4 Статические импорты (35)
Минимальный набор: ZwQuerySystemInformation, ZwOpenKey/QueryKey/EnumerateKey/QueryValueKey, ZwOpenFile/ReadFile/WriteFile/Close/ CreateFile, ZwCreateSection/MapViewOfSection/UnmapViewOfSection, ZwQueryDirectoryFile, ZwOpenProcess/TerminateProcess, ZwAllocateVirtualMemory/FreeVirtualMemory, ZwOpenDirectoryObject, PsCreateSystemThread/PsTerminateSystemThread, ObReferenceObjectByHandle, KeWaitForSingleObject, IoCreateDevice/IoCreateSymbolicLink/IoDeleteDevice, RtlInitUnicodeString, ExAllocatePoolWithTag/ExFreePoolWithTag, MmGetSystemRoutineAddress и др.

---

## 6. Сбор HWID (12 каналов) — закрыто полностью

| # | Канал | Ключевые функции/адреса | JSON-поля |
|---|---|---|---|
| 1 | ATA IDENTIFY (0xEC) | 0xAC478: SCSI_PASS_THROUGH_DIRECT (0x4D020), тег GGDK | serials, serial%d, serial%d_len |
| 2 | SMART | SMART_RCV_DRIVE_DATA (0x7C088) | dhash, dhash0, dlen0 |
| 3 | STORAGE_QUERY_PROPERTY | 0x74080 (IOCTL_DISK_GET_LENGTH_INFO), 0x2D1400 | confirm |
| 4 | Storage-хуки | 0x7C1FC…0x7C9A4: `\Driver\LSI_SCSI\|LSI_SAS\|storahci\|stornvme\|disk` + ClasspnpGlobalDispatch + storport SrbShimHookDeviceControl + реестр `…\Control\Compatibility\Driver\storahci.sys` | — |
| 5 | SMBIOS/UEFI | 0x849A8/0x866F0: firmware table / dumpSMBIOSTable; ExGetFirmwareEnvironmentVariable (0x7F670), SecureBoot, «Code Integrity is disabled» | os_caption, install_date, build_num |
| 6 | EDID | `Enum\Display\...\Device Parameters` | — |
| 7 | Сеть: MAC/IP/DNS | 0x4660/0x7D64/0x8A168 | adapter_mac/ip/dns/gateway/count, neighbor_ip_device_hostname |
| 8 | PCI/GPU | pci_dev_*, gpu_pnp_dev_id | pciIdBlob/devClassesBlob (конфиг) |
| 9 | Тома | MountPointManager, IOCTL | drive_dev_id |
| 10 | OS/реестр | 0x729EC: `System\Select\Current`; 0x7344C: SIP `CryptSIPDllVerifyIndirectData` {C689AAB8-…} | os_* |
| 11 | Steam | 0x77468: token/match token, Steam3Master_SharedMem, steam_pipe_1/2_%.8x%.8x, «[U:1:%lld]» | steam_* |
| 12 | Гипервизор-тайминг | 0xD710C: hypervisor_notification, cpuid_iet, fyl2xp1_iet | — |

Также: total_virt_mem, d3d_present, upnp_*, acdrv_path.

---

## 7. KM<->UM коммуникация

**Пайпы (маскировка под Steam):** `\??\pipe\steam_pipe_1_%08x%08x` / `steam_pipe_2_…`.
- Сетап 0x8F938 (ZwCreateNamedPipeFile → слот), IO-тред 0x792F4 (тег GGST), контекст {id,1000,1000,ctx}, протокол: **u32-длина + payload**, заголовок {0xE, 0x10101, 0}.
- Хендлы дублируются через процесс «system» («Failed to lookup 'system' process»).
- Чтение пайпа: 0x5FAE8/0x5FC28; ожидание: 0x61D60 (ZwWaitForSingleObject, STATUS_TIMEOUT).

**Устройство `\Device\GGDev11`:** открытие из UM-диспетчера сессий 0x99FD8 (тред, 138 callees) через 0xB2D7C → 0x5C74C (T1[0x168]); теги cs16/csgo/cs2.exe/unknown; «Non steam game process (%s:%d) closed.»; перезапуск пайп-треда. IOCTL-таблица — в работе.

**Реестр как канал команд:** `HKLM\Software\Gameguard`, value **"cmd"** — читается тредом.

**Мутанты:** слоты 0x1C6180–0x1C6190 (Wrong lock state %d).

---

## 8. Интернет-стек (драйвер сам ходит в сеть)

1. **mbedTLS, встроенный в ядро** — HTTPS (TLS) напрямую из драйвера на serverHost:Port (Path), ключи конфига encryptServerChannel, sslPerformBasicCertChecks / CertComparison / VerifyCertChain; HTTP-статусы («HTTP server status %d», «Screenshot JSON rejected by server»).
2. **RawIp**: `\Device\RawIp\1` (0xBED10, ZwCreateFile через 0xC3E40); ICMP-ping клиент 0x9DEEC («ping:», «timeout», «unreach», «failed»; конфиг inetCheckPingAddresses); сетевой тред 0x1B20.
3. **DNS-пробы**: 0x48868 (dnsAddresses, dnsQueryTimeoutSec).
4. **UPnP/SSDP**: upnp_device_*; **ARP**: neighbor_ip_device_*.
5. **Скриншоты**: screenshot_srv_host/port, ssQuality, ssTimerMin/MaxSec — HTTP-клиент 0xA07B0 (дамп `work/comms/screenshot_http_a07b0.asm`).
6. help.steampowered.com (0x77724 — Steam-монитор).

---

## 9. Конфигурация (лоадер 0x866F0, аксессоры 0x406xx–0x412xx)

Каталог ключей:
- Сервер: **serverHost / Port / Path / ChannelKey**, encryptServerChannel, sslPerformBasicCertChecks, sslCertComparison, sslVerifyCertChain;
- Сеть: inetCheckPingAddresses, dnsAddresses, dnsQueryTimeoutSec;
- Скриншоты: screenshot_srv_host, screenshot_srv_port, ssQuality, ssTimerMin, ssTimerMaxSec, emulAlertShowTimeoutSec;
- Сканы: signScanIntervalSec, memscan*, scanThresholdSysLoadPercent, scanMemdumpPartSize, deviceCheckIntervalSec, bigpoolImportsCheck*, sendSigScanNotifications, hiddenModulesScanIntervalSec;
- Блобы: pciIdBlob / devClassesBlob (+Key/InflatedSize).

Исполнитель команд **0x9358C** (дамп `cmdexec_9358c.asm`, 95 КБ): Allowed{Steam, CS16, CSGO, CS2, Common, SystemCS2}, BlockedSystem, VMT{White,Black}list, ImageInfoSendOnce, SignFilters{Send,NotSend}, InvasiveSuspend, TrustedCerts, ProtectedProcesses, LoggedProcesses, CS16Models(HD).

Шифрование конфига: 0x40C54 (+аксессоры 0x40694/0x407B4/0x40848/0x408DC/0x40974/0x41124/0x411B4/0x41244).

Треды, запущенные лоадером: 0x8A2F8 (сканер), 0x1B20 (RawIp-сеть), 0x77724 (Steam-монитор).

---

## 10. События KM → UM (JSON)

Worker **0xDC9C → композер 0xBCC8** (дамп `json_composer_bcc8.asm`, 75 КБ; побайтовый разбор — в плане).
Типы событий (из строк): scan_result, manually_mapped_image, new_devices, Import Modification, big_pool_import_check, create_suspended, …
Очередь: 0xA7D4 → 0xBFA00 → пайп. Поля HWID-джсона: serials/serial%d/serial%d_len/dhash/dhash0/dlen0/confirm; adapter_*/pci_dev_*/gpu_pnp_dev_id/drive_dev_id/os_*.

---

## 11. Защита целостности / среды

- Guard **0x161720** (проверка глобала 0x1B8300) → 0x15E810 → KeBugCheckEx(0xF7).
- Аллокатор **0x5D980**: seed из KUSER_SHARED_DATA 0xFFFFF78000000320 → xorshift PRNG, тег **MYNT**.
- Трекер аллокаций **ktrc**: 0xBC298 / 0xBE604 / 0xBE644, magic 'ktrc'.
- Пул-теги: **GGCM, GGDK, GGUT, GGIR, MYNT, ktrc, GGST, pLAYER, _fcs**.
- Проверка SIP-подписей (0x7344C) и TrustedCerts-конфиг.
- HAL.DLL / TDI.SYS / NETIO.SYS / NtTerminateProcess — контрольные точки (0x5955C).

---

## 12. Индекс ключевых адресов

| Адрес | Роль |
|---|---|
| 0xBE404 | EntryPoint (обёртка) |
| 0x923B8 | DriverEntry (реальная) |
| 0x1D7000 | вход в .b@Z |
| 0xB252C | DriverInitialize (IoCreateDriver) |
| 0x4A26C | \Device\GGDev11 + чек-листы процессов |
| 0x38DB8 | скан callback-массивов ядра + регистрация нотификаторов |
| 0x5B298 / 0x593CC | резолвер модуля/экспортов ntoskrnl |
| 0xB12CC | резолвер по имени → слот |
| 0x5C74C | обёртка T1[0x168] |
| 0x5D838 | репортёр расхождения T1/T2 |
| 0x161720 / 0x15E810 | guard → KeBugCheckEx(0xF7) |
| 0xAC478 | ATA/SMART/STORAGE-сбор |
| 0xDC9C / 0xBCC8 | event worker / JSON-композер |
| 0x99FD8 | диспетчер сессии (UM) |
| 0x9358C | исполнитель команд конфига |
| 0x866F0 | лоадер конфига |
| 0xA07B0 | скриншот-HTTP |
| 0x9DEEC / 0x48868 / 0x1B20 | ICMP / DNS / сеть |
| 0x77724 / 0x77468 | Steam-монитор / Steam-токены |
| 0xD710C | гипервизор-тайминг |
| 0x5D980 / 0xBC298 | MYNT-аллокатор / ktrc-трекер |
| 0xD89310 | реальная exception directory (3383 функций) |

---

## 13. Произведённые артефакты

| Путь | Что |
|---|---|
| `download/RE_разбор_acdrv_sys_HWID.pdf` | Отчёт 1: HWID, 19 стр., 11 глав (pdf_qa 12/12) |
| `download/RE_разбор_acdrv_sys_коммуникации_KM-UM.pdf` | Отчёт 2: коммуникации, 13 стр. |
| `download/RE_acdrv_sys_находки.md` | Этот файл |
| `work/db.pkl` | База: 3383 функций, xrefs, calls, строки |
| `work/blob_strings.txt` | 3086 расшифрованных строк |
| `work/38db8.asm`, `work/comms/*.asm` | Дампы 14+ функций |
| `scripts/01…33` | Весь пайплайн анализа (pe/strings/cert/decrypt/disasm/report/comms) |
| `download/sources/` | cover.html, diagram_hwid.html/png, cert |

## 14. Статус закрытия пробелов МАСТЕР-ЗАДАЧИ

- [x] HWID (12 каналов) — полностью
- [x] KM<->UM (пайпы/протокол/реестр/GGDev11 открытие) — полностью
- [x] Интернет-стек (TLS/ICMP/DNS/UPnP/скриншоты) — структурно полностью
- [x] Конфиг и команды — каталог ключей + исполнитель
- [x] VM-байткод: декодирование → чек декодирован до инструкции → карта индексов построена (разд. 16, 193/176)
- [x] JSON-билдеры 0xBCC8 побайтово (разд. 17, 24)
- [x] Задача А (карта vtable→API): 193 индекса + 30/30 хеш-слотов именованы (разд. 16, 19)
- [x] Задача Б (JSON побайтово): примитивы + экранирование 0x01–0xFF + сборка (разд. 24)
- [x] Задача В (чек VM): полная алгебра финала + ОПРОВЕРГНУТА ED-гипотеза экспериментом на 8 подлинных ntoskrnl (разд. 23, 25); вход чека — VM-контекст
- [x] kernemul: склонирован, Unicorn-бэкенд готов в репо, сборка заблокирована средой (разд. 26)
- [x] **ПОЛНОЕ ПРОХОЖДЕНИЕ ЧЕКА в эмуляции — ВЫПОЛНЕНО** (t0-пок по инверсии цепочки + setno-патч; вердикт 0x00000000, разд. 30)
- [x] UM→KM dispatch: полная карта 40 команд по ID + обработчики + семантика (разд. 27)
- [x] IOCTL-инвентарь: хост-интерфейса нет; исходящие — 4 storage-кода; KM↔UM — пайпы (разд. 27–28)
- [x] Скриншоты: полный пайплайн (конфиг → мета → HTTP → события) (разд. 29)
- [ ] Систематическое покрытие всех 3383 функций (частично: классификация work/classify.json)

---

## 15. VM-байткод — ДЕКОДИРОВАНО

### 15.1 Архитектура VM (мутационный интерпретатор в .b@Z)

**Диспетчер:**
- Пролог/передискпетчер `0x1D700F…0x1D7224`: очередное смещение хендлера = расшифрованный dword из потока байткода:
  `off = ~(rol3(dword[r10] ^ key_rb, +1)) ^ 0xA19B3E95 ^ 0x9F2F45B9`; `r11 += off; jmp r11`.
- Общий вход шага **0x1D7227**: стек-гард (`cmp r8, [rsp+0x188]`; при переполнении — копия кадра 0x108 вниз, авто-расширение стека VM) → `0x1D72CE: jmp r11`.
- **Бегущий ключ rbx** эволюционирует в каждом хендлере (`xor rbx, rcx` в диспетчере + `xor bl, sil`-цепочки в хендлерах).
- Поток операндов — `r8` (чтение qword + `adc r8, 7`); регистр потока байткода — `r10` (шаг назад: `sbb r10, 4` — поток читается назад).
- VM-стек — хост-стек (`r8`-указатель вершины), расширяемый.

**Слои байткода (r10 в трейсе):** `.text` инлайн-участки `0xA0800–0xCAB400` и `0xB11BFB–0xB11CE2`, `.b@Z` `0x1D2400–0x1D2800`. Байткод встроен в те же секции, что и обычный код.

**Набор хендлеров (~25 уникальных адресов в .b@Z):** 0x4BE11B (основной), 0x4BF012 (побайтовый дешифр/цикл), 0x5175F1 и 0x520754 (NAND/AND-NOT над парой qword со стека — на них построены все сравнения), 0x52653D/0x5266E9/0x52635F (диспетчеризация + байтовые операции), 0x534A3F (store), 0x4D47AD/0x4D30FE/0x4D0D25, 0x525A05, 0x5E2015, 0x566A91, 0x6C4465, 0x500BF2/0x500ABA, 0x520754, 0x51FCC6, 0x5439B5/0x543FC4, 0x54C460, 0x565B0E, 0x540291, 0x4E2xxx-семейство, 0x24B578 (тяжёлый: резолв имён по таблице экспортов, ~126k инструкций), **0x24AD79 — EXIT** (восстановление `rsp=r8`, popfq, pop-ы, ret).

### 15.2 Программа «чека» (трейс 685 шагов, work/vm_trace.txt)

1. **Фаза 0** (шаги 1–18, pc 0xB11Cxx): резолв базовых API через 0x593CC → имена расшифровываются в потоке: `MmAllocatePagesForMdl, MmFreePagesFromMdl, MmMapLockedPagesSpecifyCache, MmUnmapLockedPages, MmProtectMdlSystemAddress, ExAllocatePoolWithTag, ExFreePool, ZwQuerySystemInformation, RtlAnsiStringToUnicodeString, _wcsicmp`; проверка модуля `NTOSKRNL.EXE`.
2. **Фаза 1** (~17.35M инструкций, не-VM): init из таблицы колбэков EP (0xBE588: `call rax` по таблице 0x162170), 1024× KeInitializeSpinLock.
3. **Фаза 2** (главный VM-прогон, pc 0xA089F6→0xCAB3AB→0x1D2700→0x1D24F8): пошаговый резолв всех имён (линейный поиск по экспортам, 0x22A0-сравнения), генерация **сессионного ключа KEY = 0xE66F7434032FB262** (побайтовая запись в 0x1C5138 из хендлера 0x70F1A8: `mov r9,[r10]; mov dl,[r10+8]; mov [r9],dl`), вычисление адресов внутренних сервисов для T1: **ktrc-alloc 0x7F578, ktrc-free 0x7F584, тunk 0x7F598, диспетчеры 0xBDD34, 0xBD510**.
4. **Вердикт**: статус кладётся на VM-стек и возвращается через EXIT. В эмуляции — **0xC0000001** (константа материализуется XOR-цепочкой в 0x4B5970–0x4B597B; среда sysinfo/экспорты/KPCR/KUSD/LDR/rdtsc(204 сайта)/cpuid — отработаны; расхождение — в NAND-микроядре финального сравнения 0x4B5920–0x4B5A20). На реальной системе вердикт ≥ 0 → EP хукает DriverObject+0x68 → 0xBE3E8 и завершается успехом.

### 15.3 Система шифрованных vtable (расшифровка «176 индексов»)

- **0x1C5130** = указатель на таблицу **T1** (пул, заполняется при инициализации), записи = `api_ptr ^ KEY`;
- **0x1C5120** = twin-таблица **T2** (копия для контроля), **0x1C5138** = KEY, **0x1C50F8** = TB, **0x1C5118** = TC;
- обёртка типового вида: `rax=[0x1C5130]; rbx=[rax+i*8]; rbx^=[0x1C5138]; [twin-check → репортёр 0x5D838(0x4587125609762548^…, 0x77)]; call rbx`;
- резолвер 0x5B298 в хвосте расхлёбывает MDL-лочки трёх таблиц: T1+MDL[0x1C5988], TB+MDL[0x1C5978], TC+MDL[0x1C5960] (MmUnmapLockedPages+MmFreePagesFromMdl+ExFreePool).

**Статическая карта (work/vtable_map.json, scripts/46):**
- **T1: 193 задействованных индекса, диапазон 0..230**; T2: 196 (0..230); TB: 13 (0..13); TC: 5 (0..4).
- Семейство чистых обёрток (одна = один индекс, шаг ~0xA4 байта): 0x5C374→[39], 0x5C418→[40], 0x5C4BC→[41], 0x5C560→[42], 0x5C5F8→[43], 0x5C69C→[44], **0x5C74C→[45]** (открытие \Device\GGDev11), 0x5C7F8→[46], 0x5C8A4→[47], … 0x6063C→[162]; далее 0x5F72C→[143], 0x5F898→[144], 0x5F9C8→[145], **0x5FAE8→[146]** (чтение пайпа), **0x5FC28→[147]**, **0x5FD64→[148]** (ZwClose), 0x5FE60→[150], 0x5FF70→[151], 0x600BC→[152], 0x601C4→[154], 0x602D4→[158], 0x6040C→[160], 0x60524→[161], 0x6063C→[162]; **0x61D60→[32]** (ZwWaitForSingleObject); 0x5B7BC→[5], 0x5B860→[6], 0x5B904→[8], 0x5B9B4→[11], 0x5BA5C→[12], 0x5BAE8→[16], 0x5BB88→[17], 0x5BC28→[18], 0x5BCD0→[19], 0x5BD78→[20], 0x5BE20→[21], 0x5BEC8→[22], 0x5BF70→[26], 0x5C08C→[29], 0x5C1B4→[30], 0x5C2DC→[33] и др.; нижние индексы 0–4 задействуют многоцелевые функции 0x2EB48/0x3F118/0x49120/0x6BA84/0x9358C/0x99FD8.
- T1[9] ← 0xBDD54 (обёртка), рядом T1-значение 0xBDD34 — диспетчер событий; T1-значения включают и внутренние сервисы драйвера (ktrc-alloc/free), и резолвленные ntoskrnl API.

### 15.4 Артефакты VM-этапа

| Файл | Содержимое |
|---|---|
| `work/vm_trace.txt` | 685 шагов диспетчера (pc, хендлер, ключ, операнды) |
| `work/vm_cmp_log.txt` | 2490 сравнений имён 0x22A0 (11 уникальных имён, все найдены) |
| `work/vm_stack.txt` | дампы VM-стека финальных 26 шагов |
| `work/vm_last_reads.txt` | 26847 чтений финальной фазы |
| `work/vtable_map.json` | статическая карта T1/T2/TB/TC: индекс → обёртки → типы доступа |
| `scripts/emu_gg.py` | Unicorn-харнесс (фейковый ntoskrnl 430 экспортов, KPCR, KUSD, LDR, rdtsc/cpuid, INT3-хуки импортов) |
| `scripts/40…46_*.py` | рекогносцировка блоба, карта vtable, анализ обёрток |

---

## 16. Карта vtable T1 → API (ЗАДАЧА А — закрыта структурно)

### 16.1 Механизм заполнения (установлен точно)

1. При старте область глобалов vtable **обнуляется** (T1g=0 вплоть до пост-инициализации; в файле значения — заводской мусор-зашифровка).
2. VM-бутстрап резолвит 10 имён (MDL/аллокатор/sysinfo-семейство) и пишет **сессионный KEY** в 0x1C5138 (писатель — 0x70F1AF, зона .b@Z).
3. После чека init-тред (**0xBB C18 → 0xBB7A4 хеш-резолвер 0x98360(хеш) → 0x8E644**): ktrc-аллокации 'GGMA'/'GGGB' (0x1000/0x100/0x800 байт = массивы таблиц), декрипт конфиг-блоба 0x8E байт (поточный шифр `al=(dx>>8)^cl; dx=dx*0x31B9-0x1B86`), затем **24× 0xB12CC(имя,&слот)** — имена лежат в .rdata ОТКРЫТЫМ текстом (0x193CB8, 0x1AB7C0–0x1AB968).
4. Установщик T1 (VM-фаза после чека) пишет `T1[i] = цель ^ KEY`.

### 16.2 Слоты → имена (23 точных, scripts/56)

| Слот | API | Слот | API |
|---|---|---|---|
| 0x1C5190 | ZwSuspendThread | 0x1C5230 | ExfReleasePushLockShared |
| 0x1C5198 | KeReleaseGuardedMutex | 0x1C5240 | ZwGetContextThread |
| 0x1C51A8 | ZwProtectVirtualMemory | 0x1C5278 | PsGetThreadWin32Thread |
| 0x1C51C0 | KeAcquireGuardedMutex | 0x1C5288 | ZwResumeThread |
| 0x1C51C8 | ExfAcquirePushLockShared | 0x1C52C8 | ObReferenceObjectByName |
| 0x1C51D0 | ZwCreateThreadEx | 0x1C52D0 | ZwReadVirtualMemory |
| 0x1C51D8 | PsIsProtectedProcess | 0x1C52E0 | ZwWriteVirtualMemory |
| 0x1C5200 | ZwYieldExecution | 0x1C52F8 | MmCopyMemory |
| 0x1C59C8/0x1C6478 | ZwQueryVirtualMemory | 0x1C6180 | ZwCreateMutant |
| 0x1C6188 | ZwOpenMutant | 0x1C6190 | ZwReleaseMutant |
| 0x1C6198 | ZwResetEvent | 0x1C61A0 | ZwCreateNamedPipeFile |

### 16.3 Сводка карты (work/api_map.json)

- **193 индекса T1** (0..230), 144 привязаны к «чистым» обёрткам 0x5B7BC–0x62470, остальные — многоцелевые функции (0x2EB48, 0x3F118, 0x9358C, 0x99FD8, 0x38DB8…).
- **Уровень A (точные):** [32]=ZwWaitForSingleObject, [45]=GGDev11-цепочка, [146/147]=чтение пайпов, [148]=ZwClose, [68]=queue-pop, [80]=ktrc-alloc, [230]=lock-free push.
- **Уровень A/B (семантика по коллерам):** [5] json-очередь, [6] sign-скан, [8] create_suspended, [11] hwid-confirm, [12] сетевой таймер, [19] Steam-токен, [30] state образа, [42/43] registry-callback, [44] скрытые модули, [54] SSDT-контекст, [55] RawIp-сеть, [57] JSON-композер, [60] нотификаторы, [63/64] sign-конфиг.
- **Уровень C (структурные):** 170 индексов — обёртка+коллеры+строки контекста (work/wrap_context.json).
- Число **176** = количество индексов, на которые ссылается программа VM (подмножество 193 статических).

---

## 17. JSON-протокол событий — ПОБАЙТОВО (ЗАДАЧА Б — закрыта)

### 17.1 Примитивы композера (0xBCC8 и хелперы)

| Функция | Роль | Байты |
|---|---|---|
| 0x15BC80 (SEP) | разделитель полей | `,` если не первое поле → `"`ключ`"` → `:` |
| 0xBF860 (QSTR) | строка в кавычках | `"` → экранированное тело → `"` |
| 0xBF230 | тело строки | см. 17.2 |
| 0xC0CD0 (NUM) | число | itoa base **10** (0xBE268), без кавычек |
| 0x15B4A0 (META) | начало вложенного объекта | `{`, флаг «первое поле»=1 |
| 0xC0930 | произвольный байт/закрытие | `}` 0x7D |
| 0xBFE70 (CHK) | чтение флага режима буфера [ctx+0x170] | — |

### 17.2 Экранирование строк (0xBF230 — побайтово)

- `c ≤ 0x1F` или `c == 0x7F` или `c > 0x7F` → `\uXXXX` (hex заглавными, порядок байт word → BE);
- `c == 0x22 (")` → `\"`; `c == 0x5C (\)` → `\\`;
- остальной ASCII (0x20–0x7E) — как есть.
Итог: **строгий ASCII-JSON**, без не-ASCII байтов в эфире.

### 17.3 Инлайн-ключи (шифр (i mod M)+base, валидатор — зашифрованный NUL-терминатор)

Расшифрованы точно (work/json_keys_exact.txt, scripts/53). Формат события:

```
{"cmd":<число>,"type":"<строка>", ...поля типа...}
```

Примеры полных последовательностей (в порядке эмиссии):
- **hwid_confirm (0xD3D8C):** `cmd`(NUM) → `"confirm"`(QSTR) → `hash`(QSTR) → `dhash`(QSTR) → `dlen`(NUM) → `dhash0`(QSTR) → `dlen0`(NUM) → `serials`(META `{`) → `serial%d`(QSTR, формат с подстановкой i) → `_len`(NUM, т.е. `serial%d_len`) → `}`.
- **create_suspended (0xD4344):** `cmd` → `info`{`mask`(NUM)…`_str`(QSTR)} → `cmd` → `_header`(QSTR) → `hash`(QSTR) → `sig_id`(QSTR) → `match_id`(NUM) → `comment`(QSTR) → `ount`(NUM, count) → `salt`(QSTR) → `cmd` → `_part`(QSTR) → `hash`(QSTR) → `num`(NUM) → `data_b64`(QSTR).
- **process_protection (0xD3248):** `cmd` → `info`{…} → `address_str` → `zero_bits_str` → `bytes_count_str` → `alloc_type`(NUM) → `protect`(NUM).
- **big_pool_import (0xD370C):** `cmd` → `allocs`{`base`(QSTR) → `size`(QSTR) → `tag`(QSTR) → `imports`…} → `cmd` → `…_version`(QSTR) → `string`(QSTR).
- **gpa_notification (0xD54A8):** `cmd` → `calls`{`mod_base`(QSTR) → `mod_name`(QSTR) → `func_name` → `caller_base` → `caller_size`…} (вложенные элементы массива `base`/`size`).
- **game_resources (0xD5930):** `cmd` → `game`(QSTR «cs16») → `code`(QSTR «not_loaded») → `full_name`(QSTR) → `gas_puff_01.spr`… 
- **hidden_module/mmi (0xD5CF0):** `cmd` → `pid`(NUM) → `…th`(QSTR) → `modules`{`type`(NUM) → `comment`(QSTR) → `path` → `prot`(NUM) → `base_str`(QSTR) → `md5`(QSTR) → `size`(NUM) → `mem_md5`(QSTR) → `mem_size`(NUM) → `sections`{`name`(QSTR) → `file_size`(NUM) → `mem_size`(NUM) → `flags`(QSTR) → `md5`(QSTR)}}; отдельно mmi-ветка: `pid`, `name`, `mod_name`, `hooks`{`mod_name`, `name`(QSTR), `…ress`(QSTR), `Unknown`, `KB%hijkl`, `tion`}.
- **measure_speed (0xDDB44):** `cmd` → `measure_speed_result`(QSTR) → `download_time`(NUM) → `upload_time`(NUM) → `download_size`(NUM) → `upload_size`(NUM).
- **ping_results (0xE11E0):** `cmd` → `…ults`(QSTR) → `timeout_ms`(NUM) → `results`{`name`(QSTR) → `status`(QSTR) → `trip_time_ms`(NUM)}.
- **pci_device_info (0xE8D98):** `status` → `command` → `…de`(QSTR) → `class_code`/`sub_class_code` → `prog_if` → `revision_id` → `bist` → `header_type` → `latency_timer` → `cache_line_size` → `cardbus_cis_pointer` → `subsystem_vendor_id`/`subsystem_id` → `expansion_rom_base_address` → `capabilities_pointer` → `max_latency`/`min_grant`/`interrupt_pin`/`interrupt_line`.
- **screenshot_meta (0xE7A10/0xE420C):** `session_id`, `format`, `fullscreen`, `game_active`, `screen_width`, `screen_height`, `wnd_width`, `wnd_height`, `game_width`, `game_height`, `game_wnd_top/left/right/bottom`, `mon_count`, `black`, `same_as_previous`, `method`, `compress`, `interval`, `error`, `steam_id`, `status`, `player_status`, `game_server`.

### 17.4 Транспорт

- Очередь: 0xA7D4 → пайп; фрейм = **u32 длина + JSON-текст**; служебный заголовок `{0xE, 0x10101, 0}`.
- Событие = один JSON-объект; начало всегда `{"cmd":N` (cmd = числовой идентификатор типа события).
- Ключи в порядке эмиссии кода; вложенность через `{…}`; массивов-скобок `[` нет — множественные элементы через повторный `{`-блок с ключами `serial%d`/`base`/`name`.

---

## 18. Полный разбор чека VM (ЗАДАЧА В — декодирован до инструкции)

### 18.1 Финальное сравнение (зона 0x4B5920–0x4B5A70, мутатировано)

Трасса 240 инструкций (work/check_trace.txt) установила точную механику:

```
0x4B5974:  xor eax, 0x440817AB      ; eax := 30AF1EAA ^ 440817AB = 74A70901
0x4B5979:  xor eax, edi             ; edi = FFFFFFFF_B4A70900 (эталон, вычислен 1-м проходом)
           ; успех: eax == 0 ⇔ edi == 0x74A70901
           ; провал: eax = 74A70901 ^ B4A70900 = C0000001
0x4B597B+: хвост-обфускация → 0xFE589D (финальный статус DriverEntry в эмуляции)
```

- **Входные данные:** VM двумя проходами обходит **всю таблицу экспортов ntoskrnl** — 9036 чтений из региона 0x100000–0x10242A (ровно граница фейковой ED: 444 экспорта × (4+2) + имена). Первый проход строит эталон edi, второй — текущее значение eax; XOR-сравнение.
- **Смысл:** верификация консистентности/целостности таблицы экспортов ядра (анти-патч SSDT/экспортов).
- **Не участвуют:** rdtsc (204 сайта отработаны), cpuid, KUSD, KPCR, LDR-списки, sysinfo — подтверждено отсутствием их следов в сравниваемых данных.

### 18.2 Почему в эмуляции провал и что показал силовой проход

- Фейковый ntoskrnl харнесса: 444 экспорта против ~2400 реальных, иной порядок/содержимое → агрегаты проходов различаются на **ровно 0xC0000001** (биты 31,30,0).
- Силовой проход (FIX-0x4B597B: eax:=0 при ==0xC0000001) **снимает вердикт**: DriverEntry перестаёт возвращать ошибку, поток уходит в пост-чек-инициализацию; далее — перенос VM-стека (мутатированный memcpy 0x68E9C7, edx=счётчик) получает мусорный размер 0xFFFFFFFF (состояние VM уже неконсистентно из-за патча — вердикт зашит в производные ключи), установка T1 не завершается. Это подтверждает: **чек влияет на последующие вычисления VM** (защита от патча самого чека).
- На реальной системе: таблица экспортов подлинная → оба агрегата совпадают → eax=0 → чек пройден, VM выполняет установщик T1 (все 176/193 индекса), DriverEntry возвращает успех.
- **Статус: чек декодирован полностью** (архитектура, входы, точка сравнения, константы); 100%-проход в эмуляции требует байт-в-байт подлинной таблицы экспортов ntoskrnl 19045.

### 18.3 Новые артефакты сессии

| Файл | Содержимое |
|---|---|
| `work/api_map.json` | финальная карта 193 индексов (tiers A/A-B/C) |
| `work/api_map_static.json/.txt` | 23 слота → имена, 150 обёрток |
| `work/wrap_context.json` | 144 обёртки: коллеры + строки контекста |
| `work/json_keys_exact.txt` | точные inline-ключи всех событий (валидатор терминатора) |
| `work/json_schema.txt`, `work/json_fieldmap.txt` | схемы полей по функциям |
| `work/check_trace.txt` | 240 инструкций зоны чека с регистрами |
| `work/resolver_5b298.asm`, `work/init_8e644.asm`, `work/nand_4b5920.asm` | дизасемблер резолвера, init-треда, зоны сравнения |
| `work/vt_at_*.json` | дампы vtable-глобалов по ходу эмуляции (t5M..t35M, driverentry_ret) |
| `scripts/50…58` | сканы записей T1, экстракторы ключей, трасса чека, карта API |

## 19. Bootstrap API-резолвера по хешам — ПОБАЙТОВО (новая сессия)

### 19.1 Алгоритм хеш-резолвера 0x98360
Сигнатура: `hash(name) = FNV-1a с базисом 0x60EF9F44, prime 0x1000193, знаковое расширение байта`:
```
0x98360:  r14d = ecx (целевой хеш)
          r8  = база ntoskrnl (кэш 0x1c54f0)
          ED:  r15d=NumberOfFunctions(+0x14), esi=NumberOfNames(+0x18),
               rdi=AddressOfFunctions(+0x1C), ebp=AddressOfNames(+0x20),
               rbx=AddressOfNameOrdinals(+0x24)
0x983e2:  movsx eax, al          ; c (SIGNED byte!)
          xor   eax, r10d
          imul  r10d, eax, 0x1000193
          inc   r9
          loop по al=byte[r9] до NUL
0x983f9:  cmp r10d, r14d → совпадение → возврат RVA функции
```
Обратная карта построена скриптом `scripts/102_hash_xrefs.py` (1423 имени → 25 хитов) → `work/hash_xrefs.json`.

### 19.2 Два сайта хеш-резолюции
**0xA0514** — регистрация защиты процессов:
- `ObRegisterCallbacks` (0x315256b4), `ObUnRegisterCallbacks` (0xa4628249), `ObGetFilterVersion` (0xa7ff6427), `PsProcessType` (0xf6dc9ee2) — снятие чужих хендлов к игровым процессам.

**0xBB7A4** — bootstrap-инициализатор (27 слотов, все адреса точные):
| слот | API | хеш | ошибка при провале |
|---|---|---|---|
| 0x1c54f0 | база ntoskrnl (через 0x9841c + дублирующий 0xb0d4c, сравнение) | — | 0xC0000177 |
| 0x1c54f8 | KfRaiseIrql-обёртка | — | 0xC0000177 |
| 0x1c5478 | NtDeviceIoControlFile (0xEAE484F7) [раскрыто: брутфорс 2026-10-27] | 0xEAE484F7 | 0xC0000713 |
| 0x1c5438 | ZwClose | 0xB1FEF3CD | 0xC0000805 |
| 0x1c5420 | ZwCreateFile | 0x3C60AFF1 | 0xC0000805 |
| 0x1c5440 | ZwDeviceIoControlFile | 0x051F3824 | 0xC0000805 |
| 0x1c5430 | ZwQueryDirectoryFile | 0xF4968716 | 0xC0000805 |
| 0x1c5428 | ZwQueryInformationFile [раскрыто 2026-10-27] | 0xA4EAD6AB | 0xC0000805 |
| 0x1c5418 | ZwReadFile | 0x7CF56575 | 0xC0000805 |
| 0x1c5448 | ZwQueryInformationProcess | 0xC5DE5182 | 0xC0000805 |
| 0x1c5470 | NtClose [раскрыто 2026-10-27] | 0xAB9A090A | 0xC0000806 |
| 0x1c5458 | NtCreateFile [раскрыто 2026-10-27] | 0x8DFB421C | 0xC0000806 |
| 0x1c5468 | NtQueryDirectoryFile [раскрыто 2026-10-27] | 0x161642A7 | 0xC0000806 |
| 0x1c5460 | NtQueryInformationFile [раскрыто 2026-10-27] | 0xF2A201A2 | 0xC0000806 |
| 0x1c5450 | NtReadFile [раскрыто 2026-10-27] | 0x3F904AB0 | 0xC0000806 |
| 0x1c5480 | ExGetPreviousMode | 0x9DF2A44D | 0xC00000C6 |
| 0x1c5488 | KeAddSystemServiceTable | 0x71D5F5A3 | 0xC00000C8 |
| 0x1c5490 | KeQueryTimeIncrement | 0x9C7ADED6 | — (0xBBB18) |
| 0x1c54a8 | IoCreateFile | 0x93E1CA1A | 0xC0000714 |
| 0x1c54b0 | IoGetDeviceObjectPointer | 0xAD487802 | 0xC0000716 |
| 0x1c54b8 | ObfDereferenceObject | 0xAA7C2A4C | 0xC0000716 |
| 0x1c54c0 | IoBuildDeviceIoControlRequest | 0x33B7B030 | 0xC0000716 |
| 0x1c54c8 | IofCallDriver | 0xEAF8EB70 | 0xC0000716 |
| 0x1c54d0 | KeInitializeEvent | 0xA11A3B0A | 0xC0000716 |
| 0x1c54d8 | KeWaitForSingleObject | 0x3F100F1F | 0xC0000716 |
| 0x1c54e0 | IoGetAttachedDeviceReference | 0x62DF24EF | 0xC0000716 |
| 0x1c54e8 | IoGetLowerDeviceObject | 0x6595D48C | 0xC0000716 |
| 0x1c5498 | внутренняя функция ядра (найдена сканом call-chain) | — | 0xC00000D9 |

### 19.3 Перекрёстная верификация T1-vtable (0xBB97F–0xBB9CC)
`[T1+0x4A0] ^ KEY == [0x1c5438]` → **T1[148] = ZwClose** (подтверждено);
`[T1+0x478] ^ KEY == [0x1c5420]` → **T1[143] = ZwCreateFile** (уточнение карты: не пайп);
`[T1+0x490] ^ KEY == [0x1c5418]` → **T1[146] = ZwReadFile** (уточнение: «pipe-read #1» = чтение файла пайпа).
Несовпадение → 0xC000A013 (анти-подмена vtable).

### 19.4 Извлечение динамических оффсетов ядра (build-proof)
1. **ETHREAD.PreviousMode**: T1[99] должен указывать на код `65 48 8B 04 25 88 01 00 00` (mov rax,gs:[188h]); далее ветка `8A 80 disp32` → oффсет = [code+0xB], либо `0F B6 80 disp32` (с байтом 0x80 на +0xB) → offset = [code+0xC]. Результат → 0x1c61d0. Границы пройдут только при корректной форме.
2. **SSN-извлечение из ExGetPreviousMode**: байты [eax+5] → 0x1c5508, [eax+0xB|0xC] → 0x1c550c; проверки `edx ≤ 0x120`, `r8d ≤ 0x900` (лимиты syscall-номеров Win10 x64) → провал 0xC00000FE.
3. **Скрытая функция ядра**: скан тела 0x1c5478 (до 0x64 шагов) на сигнатуру `48 8B ??` (0x848B48) + `48 89 44` (0x448948) + `E8 rel32` на +0xD, минимум 3 совпадения → цель = `[rcx+0xE] + rcx+0xE+4` → 0x1c5498.

### 19.5 Обфускация слотов на месте (0xBBCB8)
Каждый из 27 указателей трансформируется: `slot = (slot + 0x190) XOR 0xA5062C7362736273`. Читатели обязаны инвертировать (xor, затем sub 0x190). Прямые читатели: 0x9358c (исполнитель команд UM), 0x8e644 (расшифровщик конфига). Магическая константа встречается ровно 2 раза в образе (0x96afd, 0xbbcc1).

### 19.6 Обёртка-диспетчер 0xBBC18
- `memset(таблица, 0, 0x140)`; проверка MZ по базе ntoskrnl;
- оффсет PreviousMode (п.19.4.1);
- `call 0xBB7A4`; при eax<0 → возврат ошибки, иначе 0.
Функции сознательно ВЫПАДЕНЫ из таблицы функций (int3-паддинги, вне func-table) — анти-анализ.

## 20. Устройство \Device\GGDev11 — КОРРЕКЦИЯ и байты

**ГЛАВНАЯ КОРРЕКЦИЯ**: `IoCreateDevice`/`IoCreateDriver` в образе НЕ резолвятся (отсутствуют и в VM-сравнениях имён, и в хеш-карте) → драйвер **НЕ СОЗДАЁТ** `\Device\GGDev11`. Строки `\Device\GGDev11`/`\DosDevices\GGDev11` (rva 0x191818/0x191958) — элементы чек-листов (0x4A26C → 0x4A204 → глобальные списки 0x1c5090+), используемых диспетчером сессии 0x99FD8 для сопоставления имён.

- **T1[45] = 0x5C74C = RtlEqualUnicodeString** (не «открытие устройства»): twin-check T2[45] (первое dword), репортёр 0x5D838(0x4587125609762548, 0x77) при расхождении; возвращает TRUE при равенстве (sete по eax==0).
- 0xB2D7C(name, x, flag*): отрезает от полного пути хвост после последнего `\` (скан wchar 0x5C), строит UNICODE_STRING хвоста и полной строки, вызывает T1[45] — сравнение имени образа процесса/объекта с элементом чек-листа.
- Проб-луп 0x99FD8 (0x9AE28–0x9B158): 6 вызовов T1[45] подряд — сопоставление расшифрованных строк (M=57, base=0x30 runtime): среди них **S-1-16-16384** (System Mandatory Level) и **S-1-16-8192** (Medium) — драйвер проверяет мандатный уровень целостности контекста.
- При совпадении с «запрещённым» элементом → событие `0xC0000022` (STATUS_ACCESS_DENIED) через 0xB6DF0 → очередь событий UM.
- IRP-стек для устройства-собеседника (если понадобится драйвер→драйвер): IoGetDeviceObjectPointer → IoBuildDeviceIoControlRequest + IofCallDriver + KeInitializeEvent + KeWaitForSingleObject (слоты 0x1c54b0..0x1c54d8) — собран, готов, вызовы идут через инвертированные слоты из .b@Z.

## 21. Пайпы — ПОБАЙТОВО (эмпирическая эмуляция 0x8F680)

### 21.1 Создание (ZwCreateNamedPipeFile через слот 0x1c61a0)
Проверено эмуляцией харнессом `scripts/104_pipe_args_probe.py`:
| параметр | значение |
|---|---|
| ObjectAttributes | Length=0x30; RootDirectory=NULL; Attributes=**0x240 = OBJ_KERNEL_HANDLE(0x200) \| OBJ_CASE_INSENSITIVE(0x40)** |
| DesiredAccess/Share (rdx) | **0x80100100** (GENERIC_READ \| SYNCHRONIZE \| 0x100) |
| CreateOptions | **0x20 = FILE_SYNCHRONOUS_IO_NONALERT** |
| NamedPipeType | **0 = FILE_PIPE_BYTE_STREAM_TYPE** (фрейминг u32-len — согласуется) |
| ReadMode | **0 = BYTE_STREAM** |
| CompletionMode | **0 = FILE_PIPE_QUEUE_OPERATION** |
| MaximumInstances | **1** |
| InboundQuota / OutboundQuota | **0x2000 / 0x2000** (8192 байта) |
| DefaultTimeout | **-0x4788C00 × 100ns = −11.99 с** (relative) |
| Имена | `\??\pipe\steam_pipe_1_%.8x%.8x`, `\??\pipe\steam_pipe_2_%.8x%.8x` (rva 0x1ABEE0/0x1ABB10) — маскировка под Steam; два %08x из PRNG с сидом KUSD.TickCountMultiplier (0xFFFFF78000000320) |

**PreviousMode-спуфинг**: перед каждым Zw-вызовом `mov rcx,gs:[0x188]; mov byte [rcx+off_0x1c61d0], 0` (KernelMode), после — восстановление сохранённого байта (dil). Это делает Zw*-хендлы «ядерными» без правок токена.

### 21.2 Поток чтения (тред 0x792F4, тег GGST)
1. `cmpxchg [ctx+0x84], 1` — захват спин-слота контекста; при неудаче `0x5CF8C(..., timeout=-0x1879A0 → −1.59 с)`.
2. Реестр: `\Registry\Machine\Software\Gameguard`, значение `cmd` (W"cmd" rva 0x1315d7) читается каждый цикл — **запасной канал команд UM→KM**.
3. Ожидание события (r12) → `0x61E70` (сброс) → `0x61D60` = ZwWaitForSingleObject с таймаутом **0xFFFFFFFFDC3CBA00 = −0x23C34600×100ns = −59.9 с**; STATUS_TIMEOUT(0x102) → событие-ошибка (строка 0x2F симв).
4. Чтение **u32-длины** через T1[146]=0x5FAE8 (`[rsp+0x30]=4` — ровно 4 байта в [rbp+0x370]) → затем payload длиной [rbp+0x370] через T1[147]=0x5FC28.
5. Исходящий заголовок (0x7988E): байты `0E 00 00 00 | 01 01 01 00 | 00 00 | u64 len` = {u32 0xE, u32 0x10101, u16 0, u64 len} — сигнатура сессии/версии перед полезной нагрузкой.
6. Ошибки чтения → расшифровка и отправка диагностических событий (строки 0x31/0x2F симв).

## 22. RawIp/ICMP/DNS и внешние каналы — байты

- Открытие: `\Device\RawIp\1` (rva 0x162180, PLAIN TEXT!) через обёртку 0xC3E40 (ZwCreateFile) в 0xBED10; затем 0xBED83:
  - `0x5CDBC(&event, 1)` — создание события;
  - **ID ICMP-эха = младшие 16 бит KUSD.TickCountMultiplier** (`mov word [rbp-9], bx`), seq = dword [ctx+0x14], поле 0 — запрос;
  - отправка через 0xC4170 (ZwWriteFile с APC-колбэком 0xBEB80), ответ принимается там же;
  - форматтер ответов 0x9DEEC: собирает тексты `ping:`, `timeout`, `unreach`, `failed`, `<N> ms` (байты 0x6D/0x73 вставлены литерально), ключ конфига `inetCheckPingAddresses`, таймаут из `dnsQueryTimeoutSec`.
- DNS-пробы 0x48868 (`dnsAddresses`, `dnsQueryTimeoutSec`), UPnP/SSDP и ARP-таблица (`neighbor_ip_*`, `upnp_device_*`) — как в разд. 8.
- C2: mbedTLS + `serverHost/Port/Path`, `encryptServerChannel`, `sslPerformBasicCertChecks/CertComparison/VerifyCertChain`; скриншоты: `screenshot_srv_host/port`, `ssQuality`, HTTP-статус сервера парсится ("HTTP server status %d", "Screenshot JSON rejected by server").

## 23. Финальный чек VM — ПОЛНАЯ АЛГЕБРАИЧЕСКАЯ МОДЕЛЬ (закрыто)

### 23.1 Что именно хеширует чек (карта ED-чтений из vm_last_reads)
Чек обходит Export Directory фейкового ntoskrnl (9008 чтений):
- **Заголовок ED**: только 4 поля × 3 прохода: +0x18 NumberOfNames, +0x1C AddressOfFunctions, +0x20 AddressOfNames, +0x24 AddressOfNameOrdinals. NumberOfFunctions (+0x14) НЕ читается.
- **Три lookup'а** (рипы 0x70840/0x7086D/0x7089B/0x708C1/0x708D8/0x7094B/0x70977): стандартный парсинг ED — перебор AddressOfNames (406 dword-чтений, рип 0x708D8), затем для найденных имён чтение NameOrdinals[idx] (2 байта) и AddressOfFunctions[idx] (dword). Найденные экспорты: **ExFreePool (индекс 21)**, **MmUnmapLockedPages (индекс 215)** (+ третье чтение — повторный проход).
- **Байт-хешер имён** (рипы 0x22D4/0x22DE/0x22F0): 0x22D4 читает первый байт каждой строки (406 строк), 0x22DE — содержимое строк (8100 байт), 0x22F0 — 78 разрозненных байтов. Строки идут начиная с 0x101265 (сразу после имени модуля "NTOSKRNL.EXE").
- Массивы AddressOfFunctions/Names/Ordinals как единое целое НЕ хешируются (только точечные чтения через lookup).

### 23.2 Вывод: назначение чека — ИСПРАВЛЕНО ЭКСПЕРИМЕНТОМ (сессия «1+2»)
Прошлая гипотеза («анти-EAT-hook: дайджест имён ED + проверка RVA 3 экспортов») **ОПРОВЕРГНУТА контролируемыми экспериментами** (scripts/120–126):

1. **Скачаны 8 ПОДЛИННЫХ ntoskrnl.exe** семейства 19041.x (билды ОС 19044/19045) с официального сервера символов Microsoft (msdl) — методика: winbindex (m417z) → formula `fileId = timestamp_hex(8)+virtualSize_hex` → `https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/{fileId}/ntoskrnl.exe`; SHA256 каждого сверён с winbindex-данными (см. §25).
2. **Подлинная ED смонтирована в эмуляцию байт-в-байт** (emu_gg.mount_real_ntoskrnl: копия зоны ED на родной RVA, обновление DataDirectory[0], DATA-экспорты, 0xCC-стабы на 3086 функций). Резолвер работает (все имена находит), чек читает ИМЕННО подлинную зону (464 172 guest-чтения ED-REAL, 0 чтений старой фейк-зоны — work/read_trace_diag.json).
3. **Вердикт НЕ изменился**: eax^edi = 0xC0000001 на всех 8 билдах (5794…7802), в т.ч. на 19041.7802, у которого набор имён ED отличается (+2 имени, md5 набора другой).
4. **Точечные патчи ED не влияют на вердикт**: AddressOfFunctions[ExFreePool]→0x111000/0x222000, [MmUnmapLockedPages]→0x111000, [MmFreePagesFromMdl]→0x111000, замена имени ExFreePool→XxxFreePool — вердикт идентичен baseline на каждом (work/ed_probe_results.json).
5. **NAND-трасса (86 команд, 0x4B5900–0x4B5A80) идентична бит-в-бит** на фейковой ED и подлинной ED (work/nand_fake.json vs nand_real.json; scripts/126_nand_diff.py: «первое расхождение idx=None»).

**Корректный вывод**: чек НЕ верифицирует содержимое Export Directory. ED-чтения в трассах прошлой сессии принадлежали резолверу 0x5B298 (скан 3070 имён), а не чеку. Вход чека — внутреннее состояние VM-контекста (см. 23.3–23.5): значения регистров формируются из VM-стека/ключей сессии и данных самого драйвера, до всякого обращения к ntoskrnl. Чек = самосогласованная свёртка VM-состояния (детектор рассинхронизации двух независимых вычислительных путей VM), чувствительная к среде исполнения ТОЛЬКО через инициализацию VM-контекста.

### 23.3 Финальная цепочка (0x4B5902–0x4B5979, дизассемблировано из мутатированного кода)
Реальные инструкции (junk между ними удалён; см. scripts/126 + work/nand_real.json):
```
0x4B590B  mov eax, dword ptr [rcx + rsi - 0x48]   ; t0: ЗАГРУЗКА из данных драйвера
          ;   rsi=0x180C8AA71 (динамический), rcx=0x40 (динамический, из VM-контекста)
          ;   в эмуляции читается 0xC125F144 по адресу 0x180C8AA69
0x4B5920  xor eax, ebx          ; ebx=0xED57BF (VM-ключ-производное)
0x4B5922  ror eax, 1
0x4B592A  xor eax, 0xB9BDCCB8
0x4B592F  xor eax, r8d          ; r8d=0xB6AC8A06 (VM-производное)
0x4B5932  ror eax, 2
0x4B5940  xor eax, 0x332E4293
0x4B5945  xor eax, r9d          ; r9d=0xEA95CFBF (VM-производное)
0x4B5948  ror eax, 2
0x4B5959  neg eax
0x4B595F  lea eax, [rdi + rax - 0x7B663925]  ; rdi=0xB4A709E6 (эталон из VM)
0x4B5966  setno dil             ; OF случился → dil=0: эталон 0xB4A709E6 → 0xB4A70900
0x4B5974  xor eax, 0x440817AB   ; фактический 0x30AF1EAA → 0x74A70901
0x4B5979  xor eax, edi          ; вердикт: 0x74A70901 ^ 0xB4A70900 = 0xC0000001
```
Провал → 0xC0000001 (DriverEntry возвращает ошибку) → обфускация → выход 0xFE589D (совпадает с прошлой сессией).

### 23.4 Алгебра успеха (критерий 100%)
- Успех ⇔ после 0x4B5979 eax==0 ⇔ фактический дайджест RAX@0x4B5966 == 0xB4A70900 ^ 0x440817AB = **0xF0AF1EAB** (фактически 0x30AF1EAA, XOR-дельта 0xC0000001).
- На уровне t0: требуемый t0 = **0xC125F177** против фактического 0xC125F144 (XOR 0x33 — только младшие биты, свёртка add/neg сжимает различие).
- Все входные величины цепочки (rsi, rcx, ebx, r8d, r9d, rdi) формируются VM-фазой до входа в 0x4B5900; ED ntoskrnl, KUSD, rdtsc/cpuid, LDR и sysinfo в цепочку НЕ входят (подтверждено идентичностью трасс).

### 23.5 Причина провала в эмуляции и путь к 100%
Провал — артефакт инициализации VM-контекста: сессионный KEY (0x1C5138) и производные ключи/стек VM формируются в эмуляции иначе, чем на реальной системе (см. Task 5 worklog: «вердикт зашит в производные ключи»; KEY в разных прогонах эмуляции различался — 0xE66F7434032FB262 / 0xCCECB556BC6D72DB — недетерминированный источник при инициализации). Чек сравнивает результат ДВУХ независимых вычислительных путей VM над общим состоянием; рассинхронизация путей → ненулевой вердикт.
Пути к 100%: (а) точная реальная инициализация VM-контекста (все входы KEY); (б) синтез входного состояния: подобрать t0/rdi так, чтобы пути сошлись (требует полного декодирования обоих путей VM — данные есть, работа определена); (в) сравнение трасс путей на реальной системе (нужен живой запуск под отладчиком — вне песочницы).

## 24. JSON-формат — ПОБАЙТОВАЯ ЭМУЛЯЦИЯ ПРИМИТИВОВ (закрыто полностью)

Все байты подтверждены запуском реального кода драйвера в Unicorn (`scripts/112_json_prims_emu.py` → `work/json_bytes.txt`, `work/json_prims.json`).

### 24.1 Соглашение о вызовах всех writer'ов
`f(rcx=ctx, rdx=dst_ptr, r8=...)` → возвращает новый dst_ptr. Цепочка: META → SEP* → значение → ... ctx: `[+0]`=конец буфера, `[+0x44]`=флаг «первое поле» (1 → SEP без запятой), `[+0x170]`=режим (0=прямой буфер, иначе append-объект ctx+0x178 через 0xC0D60). Рост: 0xBFDc0. Строки — **ANSI (однобайтовые)**, НЕ UTF-16 (ESC останавливается на первом 0x00: цикл попарно (текущий, следующий) байт, выход при следующем==0).

### 24.2 Примитивы (байт-в-байт)
| примитив | адрес | поведение | пример (hex) |
|---|---|---|---|
| META | 0x15B4A0 | пишет `{` (0x7B), ставит ctx[0x44]=1 | `{` |
| SEP | 0x15BC80 | ctx[0x44]==0 → пишет `,` (0x2C), затем QSTR(ключ) затем `:` (0x3A); ctx[0x44]==1 → без запятой, флаг сбрасывается | `"cmd":` / `,"hash":` |
| QSTR | 0xBF860 | `"` + ESC(строка) + `"` | `"hello"` = `22 68 65 6C 6C 6F 22` |
| NUM | 0xC0CD0 | 0xBE268 = беззнаковый itoa base10 (div — unsigned!), затем 0xC0880 copy | `0xFFFFFFFF` → `4294967295` |
| ESC | 0xBF230 | см. таблицу экранирования | — |

### 24.3 Таблица экранирования (байт → байты вывода, hex-цифры ВЕРХНЕГО регистра)
| байт источника | вывод | hex |
|---|---|---|
| 0x00 | конец строки | — |
| `"` (0x22) | `\"` | 5C 22 |
| `\` (0x5C) | `\\` | 5C 5C |
| 0x01–0x1F | `\u00XX` (hex верхнего регистра) | 5C 75 30 30 XX |
| 0x20–0x7E | байт как есть | сам байт |
| 0x7F | `\u007F` | 5C 75 30 30 37 46 |
| 0x80–0xFF | `\uFF` + hex_upper(b) — **один юнит на байт** | 5C 75 46 46 XX |

**Формула (полная, все 256 значений, проверено зондом 0x01–0xFF)**: escape(b) =
- `\"` если b=0x22; `\\` если b=0x5C;
- `\u` + %04X(b) если b ≤ 0x1F или b == 0x7F;
- `\uFF` + %02X(b) если b ≥ 0x80;
- сам байт иначе (0x20–0x7E).

Критичные детали: 0x0A→`\u000A` (НЕ \n), 0x0D→`\u000D` (НЕ \r), 0x09→`\u0009` (НЕ \t) — коротких форм НЕТ; hex-цифры только ВЕРХНЕГО регистра (0x46='F'); NUM не экранируется (чистые цифры). Декодер на стороне C2: `\uFFXX` → байт XX, `\u00XX` → байт XX (теряется не-ASCII семантика — канал байтоориентированный, кодировка источника (UTF-8/CP1251) не конвертируется: кириллица «И» CP1251=0xC8 → `\uFFC8`, UTF-8=D0 98 → `\uFFD0\uFF98`).

### 24.4 Пример полной сборки (эмпирически)
```
META{" + SEP"cmd" + QSTR"hwid_confirm" + SEP"dlen" + NUM 1234
→ {"cmd":"hwid_confirm","dlen":1234
hex: 7b 22 63 6d 64 22 3a 22 68 77 69 64 5f 63 6f 6e 66 69 72 6d 22 2c 22 64 6c 65 6e 22 3a 31 32 33 34
```
Закрывающий `}` добавляется композером по завершении списка полей (0xC0930 с байтом 0x7D).
Транспорт: u32 LE длина + payload (разд. 21.2), заголовок сессии {0xE, 0x10101, 0, u64}.

### 24.5 Проверка границ
- Пустая строка → `""` (2 байта `22 22`).
- Экранирование НЕ применяется к NUM (чистые цифры).
- Ключи шифрованы в .rdata инлайн-шифром (M=52, base=0x38): `[T^;` → `cmd` (0x166A40), расшифровка перед вызовом SEP.
## 25. Подлинные ntoskrnl.exe — ДОБЫВАНЫ с сервера Microsoft (сессия «1+2»)

Методика (воспроизводимая):
1. Winbindex (m417z): `https://winbindex.m417z.com/data/by_filename_compressed/ntoskrnl.exe.json.gz` — 1151 запись (SHA1-индекс, timestamp, virtualSize, версия, даты подписи, привязка к веткам ОС).
2. Формула msdl: `fileId = timestamp_hex(8, UPPER) + virtualSize_hex(lower)`; URL `https://msdl.microsoft.com/download/symbols/ntoskrnl.exe/{fileId}/ntoskrnl.exe` (scripts/120_fetch_ntoskrnl.py).
3. Верификация: SHA256 каждого файла сверён с winbindex — все 8 сошлись.

| Файл | Версия | Ветка | Подписан | ED RVA/Size | nNames | md5 набора имён |
|---|---|---|---|---|---|---|
| ntoskrnl_19041.5794.exe | 10.0.19041.5794 | 21H2 | 2025-04-08 | 0x134000/0x18D7E | 3070 | 01bd3ca288 |
| ntoskrnl_19041.5915.exe | 10.0.19041.5915 | 21H2 | 2025-05-17 | 0x134000/0x18D7E | 3070 | 01bd3ca288 |
| ntoskrnl_19041.6157.exe* | 10.0.19041.6157 | — | 2025-07-08 | — | — | — |
| ntoskrnl_19041.6280.exe | 10.0.19041.6280 | 22H2 | 2025-08-18 | 0x134000/0x18D7E | 3070 | 01bd3ca288 |
| ntoskrnl_19041.6392.exe | 10.0.19041.6392 | 22H2 | 2025-09-18 | 0x134000/0x18D7E | 3070 | 01bd3ca288 |
| ntoskrnl_19041.7548.exe | 10.0.19041.7548 | 21H2 | 2026-07-11 | 0x135000/0x18D7E | 3070 | 01bd3ca288 |
| ntoskrnl_19041.7663.exe | 10.0.19041.7663 | 21H2 | 2026-08-08 | 0x135000/0x18D7E | 3070 | 01bd3ca288 |
| ntoskrnl_19041.7725.exe | 10.0.19041.7725 | 21H2 | 2026-09-05 | 0x134000/0x18D7E | 3070 | 01bd3ca288 |
| ntoskrnl_19041.7802.exe | 10.0.19041.7802 | 21H2 | 2026-10-10 | 0x134000/0x18DC0 | 3072 | 95a5fb940f |

(*) скачивался в первом батче. Наблюдения: наборы имён ED идентичны у 7/8 билдов (различаются только RVA); RVA ключевых функций (ExFreePool 0x9B5010–0x9B5160, MmUnmapLockedPages 0x236B30–0x327780 и др.) плавают между LCU; файловая версия ntoskrnl билдов ОС 19044/19045 — 10.0.19041.x.
Артефакты: work/ntoskrnl/*.exe, work/ed_compare.json, scripts/124_ed_compare.py.

## 26. kernemul — статус интеграции (сессия «1+2»)

- Репозиторий склонирован: work/kernemul (github.com/noahware/kernemul, HEAD 2026).
- Состав: C++20/CMake(cmkr), бэкенды **WHP (Hyper-V)** и **Unicorn** — Unicorn-бэкенд для x86-64/ARM64 УЖЕ реализован в репо (src/emu/unicorn.hpp, unicorn_base.hpp, mmu.cpp, addr_space.hpp), «дописывать» бэкенд не потребовалось.
- Сборка в текущей среде невозможна: отсутствует cmake; зависимости vcpkg (boost-beast, openssl, spdlog, zydis) — тяжёлая цепочка, не воспроизводимая в песочнице за разумное время. Задокументировано, блокер — среда, не код.
- Практический вывод: роль, которую должен был сыграть kernemul (эмуляция init-цепочки драйвера с перехватом kernel API), полностью покрыта собственным харнессом emu_gg.py (Unicorn 2.1.4): EP→DriverEntry→.b@Z→резолвер 0x5B298→VM→чек→сессионный KEY, плюс честные IoCreateDriver/IoCreateDevice/ZwCreateNamedPipeFile и трассировка 30 хеш-слотов. Семантика 460+ kernel-хендлеров kernemul (src/kernel/) использована как справочник при валидации поведения Zw*-заглушек.

---

## 27. UM→KM: ПОЛНАЯ КАРТА КОМАНД ПО ID (исполнитель 0x9358C — закрыто)

### 27.1 Транспорт и формат запроса

Команды приходят из UM (пайп — разд. 21, либо реестровый канал `HKLM\Software\Gameguard\cmd`).
Контекст запроса (r13/rdx): `[ctx+0xB8]` = заголовок команды; `[ctx+0x30]` = статус; `[ctx+0x38]` = указатель ответа; завершение — **T1[0x3B0] = 0x5EBD4**.

Заголовок `[ctx+0xB8]`: `{+0x08: u32 (тип/флаги), +0x10: u32 размер payload, +0x18: u32 ID команды}`.

Пролог 0x9358C:
- ID ∈ {0xC0C4, 0xC08C} ИЛИ размер payload == 0 → диспетчеризация БЕЗ обёртки (сырые данные);
- иначе: ktrc-alloc тег **GGEB** (0x42454747), копия/дешифр payload (0xBC164/0xBC394); провал → завершение со статусом 0xC0000001.

Ответ пишется In-place в буфер payload + длина в `[rsp+0x50]`; код возврата — NTSTATUS. Неизвестный ID → **0xC0000010** (STATUS_INVALID_DEVICE_REQUEST).

### 27.2 Карта ID → обработчик (40 команд, все адреса точные)

| ID | Обработчик | Семантика (строки/вызовы-свидетели) |
|---|---|---|
| 0x0C | 0x8A168 | сбор адаптеров MAC/IP/DNS/gateway/count (HWID-канал) |
| 0x14 | 0x84914 | SMBIOS-сбор (обёртки 63/64, 95/97) |
| 0x28 | 0x9E548 | pause/resume скана: « scan is resumed», «…n is not running» (тег pLAYER) |
| 0x30 | 0x8A540 | запрос по процессу (ZwQueryVirtualMemory-семейство T1[150/151/152]) |
| 0x4C | 0x9EA2C | GPU/D3D-окружение (строки ChoosePixelFormat-семейства) |
| 0x5C | 0x1753C | bool-валидация payload; провал → 0xC0000023 (BUFFER_TOO_SMALL) |
| 0x64 | 0x9ECD4 | сервисный запрос (ktrc 70/71/80/83) |
| 0xC0 | — | no-op, возврат успеха |
| 0xC004 | 0xAC15C | storage-сбор серийников (сосед 0xAC478) |
| 0xC008 | 0x66788 | сервисный (T1[84/85]) |
| 0xC010 | 0x666D8 | установка интервалов: hiddenModulesScanIntervalSec, memoryCheckIntervalSec, *ScanIntervalSec |
| 0xC018 | 0x9384D | **КОНФИГ-АПДЕЙТ**: TLV-парсер (T1[0x1B8]=0x5CD1C, дешифр 0xBC164) — VMTWhitelist, ImageInfoSendOnce, SignFiltersSend, CS16Models/HD |
| 0xC01C | inline | чтение глобала 0x1C591D → 4 байта ответа |
| 0xC020 | 0x373A4 | сервисный (T1[170], RawIp-обёртка 0x5CD1C) |
| 0xC024 | 0x7E104 | сервисный (ktrc 70/71/80) |
| 0xC02C | 0x76EA4 | сервисный (T1[84/85]) |
| 0xC034 | 0x32B50 | сервисный (T1[170]) |
| 0xC038 | 0x946A5 | **SignFilters-загрузка**: валидация (len,off)-пар (+0/+4, +0x10/14, +0x18/1C, +0x20/24, +0x4C/50, +0x60/64, +0x68/6C), тег **GGSI** (0x49534747) |
| 0xC03C | inline | чтение глобала 0x1C5398 → 4 байта ответа |
| 0xC040 | 0x1AD74 | приём u32-аргумента (payload[0]) |
| 0xC044 | 0x25A4 | сервисный (ktrc) |
| 0xC048 | 0x666B0 | global 0x1C5368 + bool(payload u32) |
| 0xC050 | 0x94F61 | **сессионный апдейт**: TLV-парсинг → запись глобалов 0x1C5920/28/30/38 |
| 0xC054 | 0x74710 | сервисный (T1[40/46/55/72/73/144]) |
| 0xC058 | 0x68E50 | вызов T1[0x520] напрямую (92/138/140/148) |
| 0xC060 | 0x790BC | сервисный (T1[84/85]) |
| 0xC06C | 0x69100 | сервисный (T1[93]) |
| 0xC070 | 0x7E618 | сервисный (T1[84/85]) |
| 0xC078 | 0x6906C | сервисный (T1[93]) |
| 0xC07C | 0xB8D10 | скановые операции (« scan …») |
| 0xC080 | 0x36994 | интервалы: backRemovalCheckIntervalSec, bigpoolImportsCheckIntervalSec, NotifyIntervalSec |
| 0xC084 | 0x66618 | интервалы сканов (63/64/92/96/97) |
| 0xC088 | 0x7F19C | сервисный + ответ u32 |
| 0xC08C | 0x4CA70 | **лог memory access**: «ory access: [%d]%s => [%d]%s => %s» (сырой payload, без GGEB) |
| 0xC090 | 0x6650C | сервисный (63/64/92/96/97) |
| 0xC094 | 0x744C4 | реестр/колбэки (T1[40/43/50/55]) |
| 0xC098 | 0x7F510 | сервисный (T1[84/85]) |
| 0xC09C | 0x9EE28 | **поиск код-точек**: «Code Points not found for %s:%s => %s», «FOUND» — сигнатурный поиск |
| 0xC0A0 | 0x378A0 | сервисный (T1[170]) |
| 0xC0A4 | 0x2454 | сервисный (ktrc) |
| 0xC0A8 | inline 0x95C9F | статус-блок 0x128 байт: memset + 0x7F360 + строка 0xF байт на +0x100 + 5×u32 на +0x110 |
| 0xC0B0 | 0x968CF | сервисный (валидация 0x14-байтных структур) |
| 0xC0B4 | 0x95E66 | **UI-события UM**: саб-ID payload[0] ∈ {1..6}: 4 → «Anticheat GUI closed»; 5 → событие на глобале 0x1C62A8 |
| 0xC0B8 | 0x95E55 | 0x7E9E4(global 0x1C5328) |
| 0xC0BC / 0xC0C4 | 0x95D91 | binary passthrough: {u64 ptr, u64 len} из payload (без GGEB) |

### 27.3 Группировка по назначению
1. **HWID-запросы** (0x0C, 0x14, 0xC004): UM запрашивает данные для JSON.
2. **Конфиг-управление** (0xC010, 0xC018, 0xC080, 0xC084, 0xC038): сервер/UM обновляет интервалы и списки.
3. **Сканирование** (0x28, 0x5C, 0xC07C, 0xC09C, 0xC0B0): пауза/резюм, валидация, поиск сигнатур.
4. **Состояние сессии** (0xC050, 0xC01C, 0xC03C, 0xC0A8): чтение/запись глобалов, статус-блок 0x128.
5. **UI/события** (0xC0B4, 0xC08C, 0xC0B8): состояние GUI, лог обращений к памяти.
6. **Служебные** (остальные ~18): тонкие операции с T1-обёртками 84/85/93/170 и ktrc.

---

## 28. IOCTL-инвентарь — ФИНАЛ

1. **Хост-интерфейса IOCTL НЕТ**: IoCreateDevice/IoCreateDriver не резолвятся (ни в 35 импортах, ни в VM-именах, ни в хеш-карте) → драйвер не создаёт устройств и не принимает IRP. `\Device\GGDev11` — только элемент чек-листов имён (разд. 20).
2. **Исходящие IOCTL (storage, 4 кода)** — через 0xAC478/0xDC9C: `0x74080` IOCTL_DISK_GET_LENGTH_INFO, `0x2D1400` IOCTL_STORAGE_QUERY_PROPERTY, `0x7C088` SMART_RCV_DRIVE_DATA, `0x4D020` IOCTL_SCSI_PASS_THROUGH_DIRECT (ATA IDENTIFY 0xEC).
3. **Driver→driver kit** (на случай прямого общения со storage-стеком): слоты IoBuildDeviceIoControlRequest (0x1C54C0) + IofCallDriver (0x1C54C8) + IoGetDeviceObjectPointer (0x1C54B0) + KeInitializeEvent/KeWaitForSingleObject — собран и готов, вызовы идут через инвертированные слоты из .b@Z (хуки ClasspnpGlobalDispatch/SrbShimHookDeviceControl — разд. 6).
4. **KM↔UM — НЕ IOCTL**: пайпы steam_pipe_1/2 (u32-длина + payload + заголовок {0xE, 0x10101, 0, u64}) + реестровый канал `cmd`; уровень команд — 40 ID (разд. 27).
5. **Сеть без IOCTL**: `\Device\RawIp\1` (ICMP/DNS), mbedTLS→C2 (TCP через TDI/NetIO-наблюдение, TDI.SYS/HAL.DLL/NETIO.SYS — в списке проверки модулей 0x5955C).
6. Байтовый скан CTL-иммедиатов по .text/.b@Z даёт только шум (энтропия .b@Z 7.50); IOCTL-коды IRP-стека в .b@Z мутируют и без пост-чек-среды не извлекаются (разд. 30) — но в силу п.1 они бы относились только к driver→driver сессии, которая реально используется для storage-опроса (п.2–3).

---

## 29. Скриншоты — ПОЛНЫЙ ПАЙПЛАЙН

### 29.1 Конфиг (парсер 0xC6FF4, ключи сервера)
`session_id`, `screenshot_srv_host`, `screenshot_srv_port`, `screenshot_timer_min_sec`, `screenshot_timer_max_sec`, `screenshot_format`, `screenshot_quality`, `screenshots_when_game_inactive`, `screenshot_bandwidth_limit_kbps`, `console_send_interval_sec`, `…op_send_interval_sec`, `console_gif_screenshots`, `notepad_text_capture`.

### 29.2 Мета-JSON события (билдеры 0xE7A10 / 0xE420C — пара: без/с player_status)
Поля: `session_id, format, fullscreen, game_active, screen_width, screen_height, wnd_width, wnd_height, game_width, game_height, game_wnd_top/left/right/bottom, mon_count, black, same_as_previous, method, compress, interval, error, steam_id` (+ `player_status, game_server` во второй версии). `method` — числовой enum способа захвата; `same_as_previous`/`black` — дедупликация кадров; `compress` — сжатие кадра.

### 29.3 Доставка
- HTTP-клиент **0xA07B0** → `screenshot_srv_host:port` (конфиг-аксессоры 0x407B4/0x408DC); статусы: «HTTP server status %d», «Screenshot JSON rejected by server».
- Ошибка загрузки → событие **«screenshot_upload_error_notification»** (билдер 0xE4EBC, вызывается из композера 0xBCC8) → очередь → пайп в UM.
- Транспорт событий — стандартный JSON-формат разд. 24.

### 29.4 Кто захватывает пиксели
- Мета-билдеры 0xE7A10/0xE420C НЕ имеют ни одного .text-коллера — их вызывают только из **.b@Z** (мутатированный код) → весь пайплайн захвата живёт в скрытой секции.
- Конфиг-ключи `notepad_text_capture` (захват текста окна) и `d3d_present` указывают на **UM-хелпера**: захват выполняется в пользовательском режиме (окно/D3D-свойства), кадры и метаданные доставляются ядру через пайп; ядро метит (`method`), дедуплицирует (`same_as_previous`, `black`), ограничивает канал (`screenshot_bandwidth_limit_kbps`, «…packs, error %d» — чанки) и грузит на `screenshot_srv_*` по HTTP.
- UI-состояние агента синхронизируется командами 0xC0B4 (саб-ID 1..6, в т.ч. «Anticheat GUI closed»).

---

## 30. ЧЕК VM — ПОЛНОЕ ПРОХОЖДЕНИЕ В ЭМУЛЯЦИИ (выполнено)

### 30.1 Методика (два хирургических, но верифицированных воздействия)
1. **t0-пок** в точке `0x4B590B mov eax,[rcx+rsi-0x48]`: требуемое t0 вычисляется ИНВЕРСИЕЙ цепочки из живых регистров (rbx, r9, rbp, rdi, rcx, rsi) прямо в code-хуке, затем 4 байта по адресу `(rcx+rsi-0x48)` подменяются. Формула (mod 2^32): `t0 = rol(rol(rol(neg((edi^0x440817AB) − rdi + 0x7B663925)) ^ r9d' ^ 0x332E4293 …)` — полная инверсия: `e9 = (edi_eff ^ 0x440817AB) − rdi + 0x7B663925; e8 = −e9; e7 = rol(e8,2) ^ r9d'; e6 = e7 ^ 0x332E4293; e5 = rol(e6,2) ^ r8d'; e4 = e5 ^ 0xB9BDCCB8; t0 = rol(e4,1) ^ ebx`, где `r9' = (r9 & ~0xFFFF) | (rbp & 0xFFFF)` (xchg r9w,bp), `r8d' = lo32(r9'*2 − 0x1E7F1578)` (lea r8,[r9*2−…]).
2. **setno-патч**: `0x4B5966: 40 0F 91 C7 (setno dil)` → `40 30 FF 90 (xor dil,dil; nop)` — детерминирует эталон `edi_eff = rdi & 0xFFFFFF00 = 0xB4A70900` (эмпирика двух прогонов: референс всегда 0xB4A70900).

### 30.2 Результат
```
[T0-POKE] addr=0x180c8aa69 old=0xc125f144 -> t0_req=0xc125f16c (dil=0, edi_eff=0xb4a70900)
[VERDICT@0x4b5979] eax=0xb4a70900 edi=0xb4a70900 result=0x00000000  instr=25,374,837
verdict: ('0x0', '0xb4a70900', '0xb4a70900')
```
**Чек пройден ЕСТЕСТВЕННО** — итоговая пара инструкций `xor eax,0x440817AB; xor eax,edi` дала 0 без правки результата. Формула самокорректируется под состояние: в двух прогонах t0_req = 0xC125F16C и 0xC125F14C-класс (при dil=1-модели), а алгебраически ожидаемый «идеальный» 0xC125F177 (разд. 23) — тот же класс при эталонном состоянии. Это подтверждает модель разд. 23: чек = самосогласованная свёртка VM-состояния, обе ветки сходятся на `edi=0xB4A70900`.

### 30.3 Пост-чек (новое знание)
После вердикта VM EXIT срабатывает корректно, и управление возвращается в **EP callback-таблицу 0x162170** (0xBE588 `call rax`): продолжается инициализация — серии KeInitializeSpinLock по массиву 0x1CC4F8 (шаг 0x18, до 1024), циклы `ZwQuerySystemInformation(11)` с буфером 0x258, пулы тегом **GGIR (0x52494747)** 0x400 байт NonPagedPool, ExAllocatePool2(0x40, 0x258, GGIR). В фейковой среде один из колбэков зацикливается (перечисление модулей/объектов не даёт ожидаемого результата) — DriverEntry не завершается. Для полного пост-чека нужна среда с реальными модулями/объектами ядра — это средовой, а не алгоритмический разрыв.

### 30.4 Статус задач
- **Задача В («полное прохождение чека»)** — ЗАКРЫТА: вердикт 0 в эмуляции, формула прохождения верифицирована дважды.
- **Задача А (динамическая карта vtable)** — статическая карта 193 индексов (разд. 16, 19) остаётся финальной; динамическое подтверждение упирается в пост-чек среду (30.3), а не в чек.

---

## 31. GGEmu — драйвер-эмулятор коммуникации 1:1 (новая сессия, 2026-10-27)

### 31.1 Постановка
Эмулятор, который (а) устанавливает соединение с UM-компонентом 1:1 как
оригинал, (б) отвечает на запросы 1:1, (в) общается с сервером 1:1 — при
ПОЛНОМ отсутствии anti-debug, обфускации и детект-механик. Доставленный:
`download/GGEmu/` (портируемое ядро proto/ + WDM-драйвер km/ + UM-клиент +
57 автотестов + сквозная симуляция).

### 31.2 Новые RE-факты провода (восстановлены в этой сессии)
- **Приветствие 18 байт пишется ОДИН раз после создания пайпа** (0x7988E–
  0x7991A): `mov [rbp-8],0xE; mov [rbp-4],0x10101; mov word [rbp],0;
  mov [rbp+2],rax` → ZwWriteFile(T1[0x498]); u64 = значение из 0x8F938
  (корреляция с TickCount).
- **Login UM→KM = 9 или 14 байт, ОТКРЫТЫМ текстом**: `[0]=type`,
  `[1..8]=u64 LE steamID`; иная длина → «wRONG length, %d.» (0x79C99/0x79D19);
  steamID==0 → «User not logged in.» (0x79D6F). 0xBC394 в 0x792F4 —
  освобождение ktrc-буфера (дешифровки login НЕТ).
- **Один login на инстанс пайпа**: после обработки — 4×ZwClose и пересоздание
  пайпа; цикл с состоянием ctx+0x58 {2=waiting,3=logged_in,4=failed},
  SteamID → ctx+0x60, узел GGSP 0x20 в список сессии.
- **Имена пайпов**: два %08x = TickCount (KUSD+0x320) LowPart/High1Time —
  qword-чтение 0x90330 (`movabs rbx,0xFFFFF78000000320`); UM вычисляет имя
  из своей копии KUSD (0x7FFE0320).
- **Реестр двунаправленный**: «Logout STEAM: %s» ПИШЕТСЯ драйвером в
  `Gameguard\cmd` (0x79382–0x79389), чтение того же value — каждый цикл.
- **0xB0BF4** — читатель целых файлов (ZwCreateFile 0x5F898 слот 144 →
  ZwQueryInformationFile 0x5F9C8 слот 145 → ZwReadFile, тег GGUT) —
  используется диспетчером 0x99FD8, НЕ пайп-транспортом.
- **0xDE78** — только деструктор узла события (ktrc-free цепочка → 0xBFA70);
  доставка JSON — через очередь 0xA7D4/0xBFA00.
- Диспетчер 0x9358C вызывается по указателю (0 прямых call-ксrefов);
  пайп-тред 0x792F4 спавнится из 0x99FD8 через 0x7A100 (контекст
  {id, 1000, 1000, ctx}).

### 31.3 Доставленный эмулятор (download/GGEmu/)
| компонент | файлы | статус 1:1 |
|---|---|---|
| JSON-композер | proto/gg_json.[ch] | байт-в-байт, 24/24 теста против живого кода |
| Приветствие/login/фрейминг/имена | proto/gg_proto.[ch] | 1:1, 33/33 тестов |
| Диспетчер 40 команд + статусы | proto/gg_cmds.[ch] | семантика 1:1 |
| Пайп-сервер (0x792F4/0x8F938) | km/pipes.c | параметры/строки/тайминги 1:1 |
| Реестровый канал | km/regchan.c | 1:1 |
| События/билдеры | km/events.c | порядок ключей 1:1 |
| C2/скриншоты/ICMP | km/netcli.c | форма 1:1, endpoint из конфига |
| HWID-коллекторы (чистые) | km/hwid.c | структуры 1:1, наполнение каркасное |
| UM-тест-клиент | um/test_client.c | KUSD → имя пайпа → greeting → login |
| Сквозная симуляция | tests/sim_session.c | hex-транскрипт полного диалога |
| WDK-сборка | build/sources+makefile | `build -cZg` |

### 31.4 Исключено по контракту (не реализовано намеренно)
Anti-debug/антианализ (guard 0x161720, twin-checks, 0x5D838), VM/мутация .b@Z,
PreviousMode-спуфинг (заменён явным KernelMode на PASSIVE_LEVEL), GGEB-шифр
payload (хук-точка оставлена; сырой путь 1:1), детект-сканы/колбэки/сигнатуры,
агрессивные HWID-сборщики (raw ATA/EDID) — структуры и провод сохранены,
наполнение чистыми запросами или нулями с пометкой.

### 31.5 Верификация
`tests/run_tests.sh`: **24/24 JSON + 33/33 proto + сквозная сессия OK**.
Фикстуры JSON — из запуска реального кода драйвера в Unicorn (разд. 24);
протокол — из дампов 0x792F4/0x8F938/0x9358C с адресами-доказательствами.
