# GGEmu — протокол KM↔UM/C2 (побайтовая спецификация)

Восстановлено из acdrv.sys (GameGuard, CS-серия), SHA-256 `01035f86…5a45fc8`.
Каждый размер/константа ниже — с адресом-доказательством из оригинала.

---

## 0. Топология каналов

| Канал | Направление | Транспорт |
|---|---|---|
| A. Login-пайпы | UM → KM | `\??\pipe\steam_pipe_{1,2}_%08x%08x`, KM = сервер |
| B. Команды | UM → KM | тот же пайп (фреймы) + реестр `HKLM\Software\Gameguard` value `cmd` |
| C. События | KM → UM | JSON по пайпу, фрейм `u32 len + payload` |
| D. C2 | KM → server | mbedTLS HTTPS (serverHost:Port/Path), скриншоты — отдельный HTTP-клиент |

ВНИМАНИЕ: драйвер **не создаёт** IOCTL-интерфейс (`IoCreateDevice` не резолвится
ни в импортах, ни в хеш-карте — разд. 28 базы находок). Вся KM↔UM связь —
именованные пайпы + реестр.

---

## 1. Канал A: login-пайпы

### 1.1 Имя пайпа
```
\??\pipe\steam_pipe_<variant>_<tick_low:08x><tick_high:08x>
```
- формат: rva `0x1ABEE0` (v1) / `0x1ABB10` (v2), функции 0x8F938→0x8F680;
- `<tick_low>`/`<tick_high>` = `TickCount.LowPart` / `TickCount.High1Time`
  (KUSER_SHARED_DATA+0x320, чтение qword: `0x90330 movabs rbx,0xFFFFF78000000320`).
  UM вычисляет имя из своей копии KUSD (usermode 0x7FFE0320).

### 1.2 Параметры ZwCreateNamedPipeFile (0x8F938, эмпирически подтверждены)
| параметр | значение |
|---|---|
| ObjectAttributes | Length=0x30, Root=NULL, **OBJ_KERNEL_HANDLE(0x200)\|OBJ_CASE_INSENSITIVE(0x40)** |
| DesiredAccess | **0x80100100** (GENERIC_READ\|SYNCHRONIZE\|0x100) |
| CreateOptions | **0x20** FILE_SYNCHRONOUS_IO_NONALERT |
| PipeType / ReadMode / Completion | **BYTE_STREAM / BYTE_STREAM / QUEUE_OPERATION** |
| MaximumInstances | **1** |
| Inbound/OutboundQuota | **0x2000 / 0x2000** |
| DefaultTimeout | **−0x4788C00 ×100ns ≈ −11.99 с** |

### 1.3 Приветствие KM→UM (18 байт, пишется один раз после создания, 0x7988E–0x7991A)
```
+0x00 u32 0x0000000E    ; magic
+0x04 u32 0x00010101    ; сигнатура сессии
+0x08 u16 0x0000        ; резерв
+0x0A u64 session       ; корреляционное значение (TickCount при создании)
```
Ассемблерный след: `mov dword [rbp-8],0xE; mov dword [rbp-4],0x10101;
mov word [rbp],0; mov [rbp+2],rax` → ZwWriteFile (T1[0x498]=0x5FC28).

### 1.4 Login UM→KM
```
u32 LE len  ∈ {9, 14}            ; иная длина → "wRONG length, %d." (0x79C99/0x79D19)
payload[0]  u8   type            ; тип логина
payload[1..8] u64 LE steamID     ; 0 → "User not logged in." (0x79D6F)
payload[9..13]   extra           ; только при len==14
```
Сообщение идёт в ОТКРЫТЫМ виде (дешифровка в этом потоке не вызывается; вызовы
0xBC394 в 0x792F4 — освобождение ktrc-буфера).

### 1.5 Цикл (тред 0x792F4)
1. `cmpxchg [ctx+0x84],1` — захват слота; неудача → ждём −1.59 с (0x5CF8C).
2. Реестровый канал: `\Registry\Machine\Software\Gameguard`, value **`cmd`** —
   читается каждый цикл (запасной канал команд UM→KM).
3. Ожидание события: `KeResetEvent` (0x61E70) → `ZwWaitForSingleObject`
   (0x61D60) c таймаутом **−0x23C34600×100ns ≈ −59.9 с**;
   STATUS_TIMEOUT → «Timeout while waiting for response from steam.»
4. Чтение u32-длины (ровно 4 байта, T1[0x490]=0x5FAE8) → `[ctx+0x370]`.
   - `len==0` → «Failed to exchange data with steam.»
   - ошибка чтения → «fAILED …ata length from pipe, status %.8x»
5. Аллокация `max(len,0x100)`, тег **GGSK (0x534B4747)** через ktrc 0xBC298;
   чтение payload; ошибка → «fAILED …ata from pipe, status %.8x».
6. Валидация 1.4; успех → регистрация пользователя:
   узел **0x20 байт, тег GGSP (0x50534747)**: {+0x10 steamID, +0x18 флаг, +0x1C type},
   вставка в список сессии; состояние `ctx+0x58`: 2=WAITING, 3=LOGGED_IN, 4=FAILED;
   `ctx+0x60 = steamID`.
7. Хендлы закрываются (4×ZwClose), пайп пересоздаётся — **один login на инстанс**.

### 1.6 Выход из сессии
При logout KM пишет в реестр `Gameguard\cmd` строку **«Logout STEAM: %s»**
(0x79382–0x79389: rcx=ключ, rdx=W"cmd").

---

## 2. Канал B: команды UM→KM

### 2.1 Фрейм
```
u32 LE payload_len
0x20-байтный заголовок: {+0x08 u32 flags; +0x10 u32 payload_size; +0x18 u32 cmd_id}
payload (payload_size байт)
```
Заголовок — блок `[ctx+0xB8]` оригинала (смещения +8/+0x10/+0x18 установлены RE).
Буфер сообщения аллоцируется `max(size,0x100)`, тег **GGEB (0x42454747)**.

### 2.2 Правила исполнителя 0x9358C
- `id ∈ {0xC0C4, 0xC08C}` или `size==0` → сырой путь (без GGEB-конверта);
- иначе payload идёт через дешифратор 0xBC164 (в оригинале — обфусцированный;
  эмулятор оставляет хук-точку, см. DIFF);
- неизвестный ID → **0xC0000010** (STATUS_INVALID_DEVICE_REQUEST);
- маленький payload → **0xC0000023** (STATUS_BUFFER_TOO_SMALL);
- ответ пишется in-place, длина ответа — в io_len; завершение — T1[0x3B0]=0x5EBD4.

### 2.3 Карта 40 команд (полная — разд. 27 базы находок)
HWID-запросы: `0x0C` адаптеры (0x8A168), `0x14` SMBIOS (0x84914), `0xC004`
storage (0xAC15C), `0x4C` GPU (0x9EA2C), `0x30` процесс-запрос (0x8A540).
Конфиг: `0xC010/0xC080/0xC084` интервалы, `0xC018` TLV-конфиг, `0xC038` SignFilters.
Сессия: `0xC050` TLV→глобалы, `0xC01C/0xC03C` чтение глобалов (ответ 4 байта),
`0xC0A8` статус-блок **0x128** байт (строка 0xF на +0x100, 5×u32 на +0x110).
UI: `0xC0B4` саб-ID 1..6. Лог памяти: `0xC08C` (сырой). Passthrough: `0xC0BC/0xC0C4`.

---

## 3. Канал C: события KM→UM (JSON)

### 3.1 Фрейм
`u32 LE len + JSON-текст`. Транспорт очереди: производители 0xDC9C/0x77724/
0x866F0/0x8A7B0 → enqueue 0xA7D4 → композер 0xBCC8 → доставка.

### 3.2 Композер (байт-в-байт, все 256 байт проверены эмуляцией живого кода)
| примитив | адрес | байты |
|---|---|---|
| META | 0x15B4A0 | `{`, флаг first=1 |
| SEP | 0x15BC80 | [`,`] + `"key"` + `:` |
| QSTR | 0xBF860 | `"` + ESC + `"` |
| NUM | 0xC0CD0 | unsigned itoa base10 (0xBE268) |
| CLOSE | 0xC0930 | `}` |

Экранирование (0xBF230):
- `0x22`→`\"`, `0x5C`→`\\`;
- `≤0x1F`, `==0x7F` → `\u00XX` (hex ВЕРХНЕГО регистра);
- `≥0x80` → `\uFFXX` — **один юнит на сырой байт** (UTF-8 не конвертируется);
- `0x20–0x7E` — как есть; `0x00` — терминатор; коротких форм `\n\r\t` НЕТ.

Пример (фикстура из живого кода):
`{"cmd":"hwid_confirm","dlen":1234` →
`7b22636d64223a22687769645f636f6e6669726d222c22646c656e223a31323334`

### 3.3 Порядок ключей главных событий
- **hwid_confirm (0xD3D8C):** cmd, confirm, hash, dhash, dlen, dhash0, dlen0,
  serials{serial%d, serial%d_len}
- **ping_results (0xE11E0):** cmd, type, …results, timeout_ms, results{name,status,trip_time_ms}
- **measure_speed (0xDDB44):** cmd, measure_speed_result, download_time, upload_time, download_size, upload_size
- **screenshot (0xE7A10):** session_id, format, fullscreen, game_active, screen_width/height,
  wnd_width/height, game_width/height, game_wnd_top/left/right/bottom, mon_count, black,
  same_as_previous, method, compress, interval, error, steam_id, status
- create_suspended (0xD4344), process_protection (0xD3248), big_pool_import (0xD370C),
  gpa_notification (0xD54A8), game_resources (0xD5930), hidden_module/mmi (0xD5CF0),
  pci_device_info (0xE8D98) — полные последовательности в разд. 17.3 базы находок.

---

## 4. Канал D: C2

- **mbedTLS** встроен в оригинал; endpoint = конфиг `serverHost:Port/Path`;
  политика сертификатов: `sslPerformBasicCertChecks`, `sslCertComparison`,
  `sslVerifyCertChain`; шифрование канала: `encryptServerChannel`.
- **Скриншоты:** HTTP-клиент 0xA07B0 → `screenshot_srv_host:port`,
  POST `Content-Type: application/json` (мета-JSON разд. 3.3);
  статусы: «HTTP server status %d», «Screenshot JSON rejected by server»;
  ошибка загрузки → событие «screenshot_upload_error_notification» (0xE4EBC).
- **ICMP:** `\Device\RawIp\1` (plaintext-имя, 0xBED10 через 0xC3E40), echo-id =
  младшие 16 бит TickCountMultiplier, seq = `[ctx+0x14]`, поле 0 = запрос,
  приём/отправка — ZwWriteFile/ZwReadFile с APC 0xBEB80.
- **DNS-пробы:** 0x48868 (`dnsAddresses`, `dnsQueryTimeoutSec`).

Конфиг в оригинале — зашифрованный блоб (0x866F0/0x8E644, шифр GGEB).
Эмулятор читает те же ключи из `HKLM\Software\Gameguard\config` в открытом виде.

---

## 5. Статусы NTSTATUS исполнителя команд
| код | когда |
|---|---|
| 0x00000000 | успех |
| 0xC0000001 | неуспех валидации (bool=false) |
| 0xC0000010 | неизвестный ID команды |
| 0xC0000023 | payload/буфер меньше требуемого |
