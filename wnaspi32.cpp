/*
 * ============================================================================
 *  ASPI-to-SPTI Shim  v2.7  for UJ870BJ Research
 *  - Added: In-Memory Whitelist Bypass Patch (sub_401395 -> Force Target OK)
 *  - Added: Automatic 0xEA Payload Capture -> firmware_dump_raw.bin
 *  - Fixed: Two-stage Door Spoofing for GET_EVENT_STATUS (0x4A)
 * ============================================================================
 *  Build (WSL):
 *    i686-w64-mingw32-gcc -shared -o wnaspi32.dll wnaspi32.cpp \
 *        -static -static-libgcc -static-libstdc++ \
 *        -Wl,--kill-at -Wl,--enable-stdcall-fixup \
 *        -O2 -Wall
 * ============================================================================
 */
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// ============================================================
// SCSI_PASS_THROUGH_DIRECT — NATURAL ALIGNMENT (no pragma pack!)
// ============================================================
#ifndef IOCTL_SCSI_PASS_THROUGH_DIRECT
  #define IOCTL_SCSI_PASS_THROUGH_DIRECT 0x4D014
#endif
#ifndef SCSI_IOCTL_DATA_OUT
  #define SCSI_IOCTL_DATA_OUT          0
  #define SCSI_IOCTL_DATA_IN           1
  #define SCSI_IOCTL_DATA_UNSPECIFIED  2
#endif

typedef struct _SCSI_PASS_THROUGH_DIRECT_LOCAL {
    USHORT Length;
    UCHAR  ScsiStatus;
    UCHAR  PathId;
    UCHAR  TargetId;
    UCHAR  Lun;
    UCHAR  CdbLength;
    UCHAR  SenseInfoLength;
    UCHAR  DataIn;
    ULONG  DataTransferLength;
    ULONG  TimeOutValue;
    PVOID  DataBuffer;
    ULONG  SenseInfoOffset;
    UCHAR  Cdb[16];
} SCSI_PASS_THROUGH_DIRECT_LOCAL, *PSCSI_PASS_THROUGH_DIRECT_LOCAL;

// ============================================================
// ASPI constants
// ============================================================
#define SS_PENDING        0x00
#define SS_COMP           0x01
#define SS_ABORTED        0x02
#define SS_ABORT_FAIL     0x03
#define SS_ERR            0x04
#define SS_INVALID_CMD    0x80
#define SS_INVALID_HA     0x81
#define SS_NO_DEVICE      0x82
#define SS_INVALID_SRB    0xE0
#define SS_BUFFER_TOO_BIG 0x85

#define SRB_HAInquiry      0x00
#define SRB_GDEVBlock      0x01
#define SRB_ExecSCSICmd    0x02
#define SRB_Abort          0x03
#define SRB_BusDeviceReset 0x04

#define DTYPE_DASD    0x00
#define DTYPE_CDROM   0x05
#define DTYPE_OPTICAL 0x07
#define DTYPE_UNKNOWN 0x1F

// Correct ASPI 4.x direction flags
#define SRB_DIR_IN    0x08
#define SRB_DIR_OUT   0x10

#pragma pack(push, 1)
typedef struct {
    BYTE  SRB_Cmd;
    BYTE  SRB_Status;
    BYTE  SRB_HaId;
    BYTE  SRB_Flags;
    DWORD SRB_Hdr_Rsvd;
} SRB_Header;

typedef struct {
    BYTE  SRB_Cmd;
    BYTE  SRB_Status;
    BYTE  SRB_HaId;
    BYTE  SRB_Flags;
    DWORD SRB_Hdr_Rsvd;
    BYTE  SRB_HA_Count;
    BYTE  SRB_HA_SCSI_ID;
    BYTE  SRB_HA_LUN;
    BYTE  SRB_HA_MgrId[16];
    BYTE  SRB_HA_Identifier[16];
} SRB_HAInquiry_t;

typedef struct {
    BYTE  SRB_Cmd;
    BYTE  SRB_Status;
    BYTE  SRB_HaId;
    BYTE  SRB_Flags;
    DWORD SRB_Hdr_Rsvd;
    BYTE  SRB_Target;
    BYTE  SRB_Lun;
    BYTE  SRB_DeviceType;
    BYTE  SRB_Rsvd1;
} SRB_GDEVBlock_t;

typedef struct {
    BYTE  SRB_Cmd;
    BYTE  SRB_Status;
    BYTE  SRB_HaId;
    BYTE  SRB_Flags;
    DWORD SRB_Hdr_Rsvd;
    BYTE  SRB_Target;
    BYTE  SRB_Lun;
    WORD  SRB_Rsvd1;
    DWORD SRB_BufLen;
    PVOID SRB_BufPointer;
    BYTE  SRB_SenseLen;
    BYTE  SRB_CDBLen;
    BYTE  SRB_HaStat;
    BYTE  SRB_TargStat;
    PVOID SRB_PostProc;
    BYTE  SRB_Rsvd2[20];
    BYTE  CDBByte[16];
    BYTE  SenseArea[32];
} SRB_ExecSCSICmd_t;
#pragma pack(pop)

// ============================================================
// Globals
// ============================================================
static HANDLE           g_hDevice = INVALID_HANDLE_VALUE;
static FILE*            g_logFile = NULL;
static CRITICAL_SECTION g_csLog;
static CRITICAL_SECTION g_csStats;
static char             g_devicePath[MAX_PATH] = {0};
static BOOL             g_initialized = FALSE;
static HANDLE           g_hConsole = NULL;
static BOOL             g_consoleColors = FALSE;

// GET_EVENT_STATUS durum sayacı
static int              g_event_4a_calls = 0;

static struct {
    DWORD exec_count;
    DWORD comp_count;
    DWORD err_count;
    DWORD vendor_count;
    DWORD erase_count;
    DWORD write_count;
    DWORD unlock_count;
    DWORD data_in_bytes;
    DWORD data_out_bytes;
    DWORD first_ts;
    DWORD last_ts;
    BYTE  opcode_hits[256];
} g_stats;

// ============================================================
// Console colors
// ============================================================
#define CLR_RESET   7
#define CLR_RED     12
#define CLR_GREEN   10
#define CLR_YELLOW  14
#define CLR_CYAN    11
#define CLR_MAGENTA 13
#define CLR_GREY    8
#define CLR_WHITE   15

static void set_color(int c) {
    if (g_consoleColors && g_hConsole)
        SetConsoleTextAttribute(g_hConsole, (WORD)c);
}
static void reset_color(void) {
    if (g_consoleColors && g_hConsole)
        SetConsoleTextAttribute(g_hConsole,
            FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

static void log_raw(int color, const char* fmt, ...);

// ============================================================
// IN-MEMORY PATCH: Flasher Whitelist Bypass (sub_401395)
// ============================================================
static void patch_flasher_whitelist(void)
{
    static BOOL patched = FALSE;
    if (patched) return;
    patched = TRUE;

    uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
    if (!base) return;

    void* target_func = (void*)(base + 0x1395);
    uintptr_t target_var = base + 0x115C7E;

    DWORD oldProtect = 0;
    if (VirtualProtect(target_func, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        BYTE patch[] = {
            0xC6, 0x05, 0, 0, 0, 0, 0x06,  // mov byte ptr [byte_515C7E], 6
            0xB0, 0x07,                    // mov al, 7
            0xC3                           // ret
        };
        uint32_t target_var_u32 = (uint32_t)target_var;
        memcpy(&patch[2], &target_var_u32, sizeof(uint32_t));

        memcpy(target_func, patch, sizeof(patch));
        VirtualProtect(target_func, 16, oldProtect, &oldProtect);

        log_raw(CLR_GREEN, "[PATCH] Whitelist bypass devrede! sub_401395 zorla hedef secildi (0x%p)", target_func);
    } else {
        log_raw(CLR_RED, "[PATCH] VirtualProtect basarisiz oldu!");
    }
}

// ============================================================
// Init
// ============================================================
static void log_init(void)
{
    InitializeCriticalSection(&g_csLog);
    InitializeCriticalSection(&g_csStats);

    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (g_hConsole && g_hConsole != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(g_hConsole, &mode)) {
            g_consoleColors = TRUE;
            SetConsoleOutputCP(CP_UTF8);
        }
    }

    SYSTEMTIME st;
    GetLocalTime(&st);

    g_logFile = fopen("aspi_shim_log.txt", "w");
    if (g_logFile) {
        fprintf(g_logFile,
            "================================================================\n"
            "  ASPI-SPTI Shim v2.7  -  UJ870BJ Research Log\n"
            "================================================================\n"
            "  Session started: %04d-%02d-%02d %02d:%02d:%02d\n"
            "  Compiled: %s %s\n"
            "  NOTE: Full hex dump of every command is written below.\n"
            "----------------------------------------------------------------\n\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            __DATE__, __TIME__);
        fflush(g_logFile);
    }

    set_color(CLR_CYAN);
    printf("\n");
    printf("============================================================\n");
    printf("  ASPI-SPTI Shim v2.7  -  UJ870BJ Research\n");
    printf("============================================================\n");
    reset_color();
    printf("  Log file: aspi_shim_log.txt  (FULL data dump)\n");
    printf("  Started : %04d-%02d-%02d %02d:%02d:%02d\n",
           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    printf("  sizeof(SPTD_LOCAL) = %d (must be 44 on x86)\n\n",
           (int)sizeof(SCSI_PASS_THROUGH_DIRECT_LOCAL));

    GetSystemTimeAsFileTime((FILETIME*)&g_stats.first_ts);

    patch_flasher_whitelist();
}

// ============================================================
// Logging
// ============================================================
static void log_raw(int color, const char* fmt, ...)
{
    if (!g_initialized) return;

    SYSTEMTIME st;
    GetLocalTime(&st);

    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    set_color(color);
    printf("[%02d:%02d:%02d.%03d] %s\n",
           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
    reset_color();

    if (g_logFile) {
        EnterCriticalSection(&g_csLog);
        fprintf(g_logFile, "[%02d:%02d:%02d.%03d] %s\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
        fflush(g_logFile);
        LeaveCriticalSection(&g_csLog);
    }
}

// ============================================================
// FULL hex block dump -> LOG FILE ONLY (multi-line, no truncation)
// ============================================================
static void log_hex_block_file(const char* tag, const BYTE* data, DWORD len)
{
    if (!g_logFile) return;
    if (!data || len == 0) return;

    EnterCriticalSection(&g_csLog);
    fprintf(g_logFile, "        ----- %s [%lu bytes] -----\n",
            tag, (unsigned long)len);

    for (DWORD i = 0; i < len; i += 16) {
        fprintf(g_logFile, "        %04lX: ", (unsigned long)i);
        for (DWORD j = 0; j < 16; j++) {
            if (i + j < len)
                fprintf(g_logFile, "%02X ", data[i + j]);
            else
                fprintf(g_logFile, "   ");
        }
        fprintf(g_logFile, " |");
        for (DWORD j = 0; j < 16 && i + j < len; j++) {
            BYTE b = data[i + j];
            fprintf(g_logFile, "%c", (b >= 0x20 && b < 0x7F) ? b : '.');
        }
        fprintf(g_logFile, "|\n");
    }
    fprintf(g_logFile, "        ------------------------------\n");
    fflush(g_logFile);
    LeaveCriticalSection(&g_csLog);
}

// ============================================================
// Opcode metadata
// ============================================================
typedef struct {
    const char* name;
    int         danger;
    int         color;
} OpcodeInfo;

static OpcodeInfo get_opcode_info(BYTE op)
{
    switch (op) {
        case 0x00: return {"TEST_UNIT_READY",       0, CLR_GREY};
        case 0x03: return {"REQUEST_SENSE",         0, CLR_GREY};
        case 0x12: return {"INQUIRY",               0, CLR_GREEN};
        case 0x1A: return {"MODE_SENSE_6",          0, CLR_GREY};
        case 0x1B: return {"START_STOP_UNIT",       1, CLR_YELLOW};
        case 0x1E: return {"PREVENT_ALLOW",         0, CLR_GREY};
        case 0x23: return {"READ_FORMAT_CAPS",      0, CLR_GREY};
        case 0x25: return {"READ_CAPACITY_10",      0, CLR_GREEN};
        case 0x28: return {"READ_10",               0, CLR_GREEN};
        case 0x2A: return {"WRITE_10",              1, CLR_YELLOW};
        case 0x2B: return {"SEEK_10",               0, CLR_GREY};
        case 0x2D: return {"VENDOR_2D",             1, CLR_YELLOW};
        case 0x2E: return {"WRITE_VERIFY_10",       1, CLR_YELLOW};
        case 0x35: return {"SYNC_CACHE_10",         0, CLR_GREY};
        case 0x3B: return {"WRITE_BUFFER",          1, CLR_YELLOW};
        case 0x3C: return {"READ_BUFFER",           0, CLR_GREEN};
        case 0x42: return {"READ_SUBCHANNEL",       0, CLR_GREY};
        case 0x43: return {"READ_TOC",              0, CLR_GREEN};
        case 0x46: return {"GET_CONFIGURATION",     0, CLR_GREEN};
        case 0x4A: return {"GET_EVENT_STATUS",      0, CLR_GREEN};
        case 0x4B: return {"PAUSE_RESUME",          0, CLR_GREY};
        case 0x4D: return {"LOG_SENSE",             0, CLR_GREEN};
        case 0x51: return {"READ_DISC_INFO",        0, CLR_GREEN};
        case 0x52: return {"READ_TRACK_INFO",       0, CLR_GREEN};
        case 0x5A: return {"MODE_SENSE_10",         0, CLR_GREY};
        case 0xAD: return {"READ_DVD_STRUCT",       0, CLR_GREEN};
        case 0xBB: return {"SET_CD_SPEED",          0, CLR_GREY};
        case 0xBE: return {"READ_CD",               0, CLR_GREEN};

        case 0xE8: return {"VENDOR_E8_READ_RAM",    1, CLR_CYAN};
        case 0xEA: return {"VENDOR_EA_WRITE_RAM",   1, CLR_CYAN};
        case 0xED: return {"VENDOR_ED_UNLOCK",      0, CLR_MAGENTA};
        case 0xF4: return {"VENDOR_F4_FLASH?",      2, CLR_RED};
        case 0xF5: return {"VENDOR_F5_FLASH_WRITE", 2, CLR_RED};
        case 0xF6: return {"VENDOR_F6_FLASH?",      2, CLR_RED};
        case 0xFA: return {"VENDOR_FA_ERASE !!!",   2, CLR_RED};

        default:
            if (op >= 0xC0) return {"VENDOR_UNKNOWN", 1, CLR_MAGENTA};
            return {"UNKNOWN", 0, CLR_GREY};
    }
}

// ============================================================
// Hex dump helper (console preview, truncates)
// ============================================================
static void hex_dump_line(char* out, const BYTE* data, DWORD len)
{
    char* p = out;
    for (DWORD i = 0; i < len && i < 64; i++) {
        p += sprintf(p, "%02X ", data[i]);
    }
    if (len > 64) sprintf(p, "...");
}

// ============================================================
// Device detection
// ============================================================
static HANDLE try_open_cdrom(int idx)
{
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "\\\\.\\CdRom%d", idx);
    HANDLE h = CreateFileA(path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        strncpy(g_devicePath, path, sizeof(g_devicePath) - 1);
        return h;
    }
    return INVALID_HANDLE_VALUE;
}

static BOOL detect_cdrom(void)
{
    log_raw(CLR_CYAN, "[INIT] Scanning for CDROM devices...");
    log_raw(CLR_CYAN, "[INIT] sizeof(SPTD_LOCAL)=%d  sizeof(SRB_Exec)=%d",
            (int)sizeof(SCSI_PASS_THROUGH_DIRECT_LOCAL),
            (int)sizeof(SRB_ExecSCSICmd_t));

    for (int i = 0; i < 10; i++) {
        HANDLE h = try_open_cdrom(i);
        if (h == INVALID_HANDLE_VALUE) continue;

        DWORD alloc = sizeof(SCSI_PASS_THROUGH_DIRECT_LOCAL) + 24 + 36;
        PSCSI_PASS_THROUGH_DIRECT_LOCAL sptd =
            (PSCSI_PASS_THROUGH_DIRECT_LOCAL)LocalAlloc(LPTR, alloc);
        if (!sptd) { CloseHandle(h); continue; }

        sptd->Length = sizeof(SCSI_PASS_THROUGH_DIRECT_LOCAL);
        sptd->CdbLength = 12;
        sptd->SenseInfoLength = 24;
        sptd->DataIn = SCSI_IOCTL_DATA_IN;
        sptd->DataTransferLength = 36;
        sptd->TimeOutValue = 5;
        sptd->DataBuffer = (PVOID)((BYTE*)sptd + sptd->Length + 24);
        sptd->SenseInfoOffset = sptd->Length;
        sptd->Cdb[0] = 0x12;
        sptd->Cdb[4] = 36;

        DWORD br = 0;
        SetLastError(0);
        BOOL ok = DeviceIoControl(h, IOCTL_SCSI_PASS_THROUGH_DIRECT,
                                  sptd, alloc, sptd, alloc, &br, NULL);
        DWORD err = GetLastError();

        log_raw(CLR_YELLOW,
                "[INIT] CdRom%d: ioctl=%d  scsi_st=0x%02X  err=%lu  br=%lu",
                i, (int)ok, (int)sptd->ScsiStatus, (unsigned long)err,
                (unsigned long)br);

        if (ok && sptd->ScsiStatus == 0) {
            BYTE* data = (BYTE*)sptd->DataBuffer;
            log_raw(CLR_GREEN, "[INIT] Found device at %s", g_devicePath);
            log_raw(CLR_GREEN, "        Vendor : %.8s", data + 8);
            log_raw(CLR_GREEN, "        Product: %.16s", data + 16);
            log_raw(CLR_GREEN, "        Rev    : %.4s", data + 32);
            log_hex_block_file("INIT_INQUIRY_IN", data, 36);
            LocalFree(sptd);
            g_hDevice = h;
            return TRUE;
        }
        LocalFree(sptd);
        CloseHandle(h);
    }

    log_raw(CLR_RED, "[INIT] NO CDROM DEVICE FOUND");
    return FALSE;
}

// ============================================================
// SPTI forward
// ============================================================
static BOOL forward_to_spti(SRB_ExecSCSICmd_t* srb)
{
    if (g_hDevice == INVALID_HANDLE_VALUE) return FALSE;

    BYTE flags = srb->SRB_Flags;
    BOOL is_in  = (flags & SRB_DIR_IN)  != 0;
    BOOL is_out = (flags & SRB_DIR_OUT) != 0;
    BOOL has_data = is_in || is_out;
    DWORD buf_len = has_data ? srb->SRB_BufLen : 0;
    PVOID buf_ptr = has_data ? srb->SRB_BufPointer : NULL;

    DWORD alloc = sizeof(SCSI_PASS_THROUGH_DIRECT_LOCAL) + 24 + buf_len;
    PSCSI_PASS_THROUGH_DIRECT_LOCAL sptd =
        (PSCSI_PASS_THROUGH_DIRECT_LOCAL)LocalAlloc(LPTR, alloc);
    if (!sptd) return FALSE;

    sptd->Length = sizeof(SCSI_PASS_THROUGH_DIRECT_LOCAL);
    sptd->CdbLength = srb->SRB_CDBLen;
    if (sptd->CdbLength > 16) sptd->CdbLength = 16;
    sptd->SenseInfoLength = 24;
    sptd->DataIn = is_in ? SCSI_IOCTL_DATA_IN :
                   is_out ? SCSI_IOCTL_DATA_OUT :
                            SCSI_IOCTL_DATA_UNSPECIFIED;
    sptd->DataTransferLength = buf_len;
    sptd->TimeOutValue = 30;
    sptd->SenseInfoOffset = sptd->Length;

    PVOID payload = (BYTE*)sptd + sptd->Length + 24;
    sptd->DataBuffer = has_data ? payload : NULL;

    if (is_out && buf_ptr && buf_len) {
        memcpy(payload, buf_ptr, buf_len);
    }

    memcpy(sptd->Cdb, srb->CDBByte, sptd->CdbLength);

    DWORD br = 0;
    BOOL ioctl_ok = DeviceIoControl(g_hDevice, IOCTL_SCSI_PASS_THROUGH_DIRECT,
                                    sptd, alloc, sptd, alloc, &br, NULL);

    srb->SRB_TargStat = sptd->ScsiStatus;
    srb->SRB_HaStat   = 0;

    if (ioctl_ok && is_in && buf_ptr && buf_len) {
        memcpy(buf_ptr, payload, buf_len);
    }

    if (srb->SRB_SenseLen > 0) {
        BYTE* sense = (BYTE*)sptd + sptd->Length;
        DWORD sl = srb->SRB_SenseLen > 24 ? 24 : srb->SRB_SenseLen;
        memcpy(srb->SenseArea, sense, sl);
    }

    LocalFree(sptd);
    return ioctl_ok;
}

// ============================================================
// Statistics
// ============================================================
static void stats_update_exec(BYTE op, BOOL success, DWORD len, BYTE flags)
{
    EnterCriticalSection(&g_csStats);
    g_stats.exec_count++;
    g_stats.opcode_hits[op]++;
    if (success) g_stats.comp_count++; else g_stats.err_count++;
    if (op >= 0xC0) g_stats.vendor_count++;
    if (op == 0xFA) g_stats.erase_count++;
    if (op == 0xF5 || op == 0xEA) g_stats.write_count++;
    if (op == 0xED) g_stats.unlock_count++;
    if (flags & SRB_DIR_IN)  g_stats.data_in_bytes  += len;
    if (flags & SRB_DIR_OUT) g_stats.data_out_bytes += len;
    GetSystemTimeAsFileTime((FILETIME*)&g_stats.last_ts);
    LeaveCriticalSection(&g_csStats);
}

static void print_summary(void)
{
    DWORD elapsed = (g_stats.last_ts - g_stats.first_ts) / 10000;

    set_color(CLR_CYAN);
    printf("\n============================================================\n");
    printf("  SESSION SUMMARY\n");
    printf("============================================================\n");
    reset_color();

    printf("  Duration      : %lu.%03lu s\n", elapsed / 1000, elapsed % 1000);
    printf("  SCSI commands : %lu\n", g_stats.exec_count);
    printf("  Success       : %lu\n", g_stats.comp_count);
    printf("  Errors        : %lu\n", g_stats.err_count);
    printf("  Vendor ops    : %lu\n", g_stats.vendor_count);
    printf("  Data IN       : %lu bytes\n", g_stats.data_in_bytes);
    printf("  Data OUT      : %lu bytes\n", g_stats.data_out_bytes);

    printf("\n  Critical ops:\n");
    set_color(g_stats.unlock_count ? CLR_MAGENTA : CLR_GREY);
    printf("    Unlock (0xED) : %lu\n", g_stats.unlock_count);
    set_color(g_stats.write_count ? CLR_YELLOW : CLR_GREY);
    printf("    Write (EA/F5): %lu\n", g_stats.write_count);
    set_color(g_stats.erase_count ? CLR_RED : CLR_GREY);
    printf("    Erase (0xFA)  : %lu\n", g_stats.erase_count);
    reset_color();

    printf("\n  Opcode frequency (top 15):\n");
    typedef struct { BYTE op; DWORD hits; } Entry;
    Entry top[256];
    int n = 0;
    for (int i = 0; i < 256; i++) {
        if (g_stats.opcode_hits[i] > 0) {
            top[n].op = (BYTE)i;
            top[n].hits = g_stats.opcode_hits[i];
            n++;
        }
    }
    for (int i = 0; i < n - 1; i++)
        for (int j = i + 1; j < n; j++)
            if (top[j].hits > top[i].hits) {
                Entry t = top[i]; top[i] = top[j]; top[j] = t;
            }

    int shown = n < 15 ? n : 15;
    for (int i = 0; i < shown; i++) {
        OpcodeInfo oi = get_opcode_info(top[i].op);
        set_color(oi.color);
        printf("    0x%02X  %-28s  %lu\n", top[i].op, oi.name, top[i].hits);
        reset_color();
    }

    printf("\n  Full log saved to: aspi_shim_log.txt\n");
    printf("============================================================\n\n");

    if (g_logFile) {
        fprintf(g_logFile, "\n\n=== SESSION SUMMARY ===\n");
        fprintf(g_logFile, "Duration: %lu ms\n", elapsed);
        fprintf(g_logFile, "Commands: %lu  Success: %lu  Errors: %lu\n",
                g_stats.exec_count, g_stats.comp_count, g_stats.err_count);
        fprintf(g_logFile, "Vendor: %lu  Unlock: %lu  Write: %lu  ERASE: %lu\n",
                g_stats.vendor_count, g_stats.unlock_count,
                g_stats.write_count, g_stats.erase_count);
        fprintf(g_logFile, "Data IN: %lu  Data OUT: %lu\n",
                g_stats.data_in_bytes, g_stats.data_out_bytes);
        fflush(g_logFile);
    }
}

// ============================================================
// SRB logging — console summary + FULL file dump
// ============================================================
static void log_exec_full(SRB_ExecSCSICmd_t* srb, BOOL success)
{
    BYTE op = srb->SRB_CDBLen > 0 ? srb->CDBByte[0] : 0;
    OpcodeInfo oi = get_opcode_info(op);
    BYTE flags = srb->SRB_Flags;

    log_raw(oi.color, "[EXEC] 0x%02X  %s", op, oi.name);

    char cdb_hex[128] = {0};
    hex_dump_line(cdb_hex, srb->CDBByte, srb->SRB_CDBLen);
    log_raw(CLR_GREY, "        CDB[%d] = %s", srb->SRB_CDBLen, cdb_hex);

    const char* dir = (flags & SRB_DIR_IN)  ? "IN " :
                      (flags & SRB_DIR_OUT) ? "OUT" : "---";
    log_raw(CLR_GREY, "        Dir=%s Len=%u Ha=%d Tgt=%d Lun=%d",
            dir, srb->SRB_BufLen, srb->SRB_HaId, srb->SRB_Target, srb->SRB_Lun);

    if ((flags & SRB_DIR_OUT) && srb->SRB_BufPointer && srb->SRB_BufLen > 0) {
        DWORD show = srb->SRB_BufLen > 32 ? 32 : srb->SRB_BufLen;
        char data_hex[200] = {0};
        hex_dump_line(data_hex, (BYTE*)srb->SRB_BufPointer, show);
        log_raw(CLR_YELLOW, "        OUT[%u] = %s%s",
                show, data_hex, srb->SRB_BufLen > 32 ? " ..." : "");
    }

    if (success) {
        if ((flags & SRB_DIR_IN) && srb->SRB_BufPointer && srb->SRB_BufLen > 0) {
            DWORD show = srb->SRB_BufLen > 32 ? 32 : srb->SRB_BufLen;
            char data_hex[200] = {0};
            hex_dump_line(data_hex, (BYTE*)srb->SRB_BufPointer, show);
            log_raw(CLR_GREEN, "        IN [%u] = %s%s",
                    show, data_hex, srb->SRB_BufLen > 32 ? " ..." : "");

            BYTE* d = (BYTE*)srb->SRB_BufPointer;
            int printable = 0;
            for (DWORD i = 0; i < show; i++)
                if (d[i] >= 0x20 && d[i] < 0x7F) printable++;
            if (printable > (int)(show * 0.7)) {
                char ascii[80] = {0};
                for (DWORD i = 0; i < show && i < 60; i++)
                    ascii[i] = (d[i] >= 0x20 && d[i] < 0x7F) ? d[i] : '.';
                log_raw(CLR_CYAN, "        ASCII  = \"%s\"", ascii);
            }
        }
        log_raw(CLR_GREEN, "        -> SS_COMP");
    } else {
        BYTE sk   = srb->SenseArea[2] & 0x0F;
        BYTE asc  = srb->SenseArea[12];
        BYTE ascq = srb->SenseArea[13];
        log_raw(CLR_RED, "        -> SS_ERR  sk=0x%02X asc=0x%02X ascq=0x%02X",
                sk, asc, ascq);
    }

    if (oi.danger == 2) {
        set_color(CLR_RED);
        printf("        *** DANGER: %s ***\n", oi.name);
        reset_color();
        if (g_logFile) {
            EnterCriticalSection(&g_csLog);
            fprintf(g_logFile, "        *** DANGER: %s ***\n", oi.name);
            fflush(g_logFile);
            LeaveCriticalSection(&g_csLog);
        }
    }

    log_hex_block_file("CDB", srb->CDBByte, srb->SRB_CDBLen);

    if ((flags & SRB_DIR_OUT) && srb->SRB_BufPointer && srb->SRB_BufLen > 0) {
        log_hex_block_file("DATA_OUT", (BYTE*)srb->SRB_BufPointer,
                           srb->SRB_BufLen);
    }

    if ((flags & SRB_DIR_IN) && srb->SRB_BufPointer && srb->SRB_BufLen > 0) {
        log_hex_block_file("DATA_IN", (BYTE*)srb->SRB_BufPointer,
                           srb->SRB_BufLen);
    }

    if (srb->SRB_SenseLen > 0) {
        log_hex_block_file("SENSE", srb->SenseArea, srb->SRB_SenseLen);
    }

    if (g_logFile) {
        EnterCriticalSection(&g_csLog);
        fprintf(g_logFile,
                "        SRB: TargStat=0x%02X HaStat=0x%02X SenseLen=%u "
                "CDBLen=%u BufLen=%lu Flags=0x%02X\n\n",
                srb->SRB_TargStat, srb->SRB_HaStat, srb->SRB_SenseLen,
                srb->SRB_CDBLen, (unsigned long)srb->SRB_BufLen,
                srb->SRB_Flags);
        fflush(g_logFile);
        LeaveCriticalSection(&g_csLog);
    }
}

// ============================================================
// Exported ASPI functions
// ============================================================
extern "C" __declspec(dllexport)
DWORD WINAPI GetASPI32SupportInfo(void)
{
    if (!g_initialized) {
        log_init();
        g_initialized = TRUE;
        detect_cdrom();
    }
    patch_flasher_whitelist();
    if (g_hDevice == INVALID_HANDLE_VALUE) {
        log_raw(CLR_RED, "[ASPI] GetASPI32SupportInfo -> NO HBA (ret 0x00000000)");
        return 0x00000000;
    }
    log_raw(CLR_GREEN, "[ASPI] GetASPI32SupportInfo -> 1 HBA (ret 0x00000101)");
    return 0x00000101;
}

extern "C" __declspec(dllexport)
DWORD WINAPI SendASPI32Command(LPVOID lpSRB)
{
    if (!lpSRB) return SS_ERR;

    SRB_Header* hdr = (SRB_Header*)lpSRB;
    BYTE cmd = hdr->SRB_Cmd;

    if (!g_initialized) {
        log_init();
        g_initialized = TRUE;
        detect_cdrom();
    }

    switch (cmd) {
    case SRB_HAInquiry: {
        SRB_HAInquiry_t* s = (SRB_HAInquiry_t*)lpSRB;
        if (s->SRB_HaId != 0) {
            s->SRB_Status = SS_INVALID_HA;
            return SS_INVALID_HA;
        }
        s->SRB_HA_Count = 1;
        s->SRB_HA_SCSI_ID = 7;
        s->SRB_HA_LUN = 0;
        memset(s->SRB_HA_MgrId, 0, 16);
        memset(s->SRB_HA_Identifier, 0, 16);
        memcpy(s->SRB_HA_MgrId, "SPTI-ASPI-SHIM", 14);
        memcpy(s->SRB_HA_Identifier, "UJ870-Shim", 10);
        s->SRB_Status = SS_COMP;
        log_raw(CLR_GREEN, "[ASPI] HA_INQUIRY -> SS_COMP");
        return SS_COMP;
    }

    case SRB_GDEVBlock: {
        SRB_GDEVBlock_t* s = (SRB_GDEVBlock_t*)lpSRB;
        if (s->SRB_HaId != 0) {
            s->SRB_Status = SS_INVALID_HA;
            return SS_INVALID_HA;
        }
        if (s->SRB_Target == 0 && s->SRB_Lun == 0) {
            s->SRB_DeviceType = DTYPE_CDROM;
            s->SRB_Status = SS_COMP;
            log_raw(CLR_GREEN, "[ASPI] GDEVBlock Ha=%d Tgt=%d Lun=%d -> CDROM",
                    s->SRB_HaId, s->SRB_Target, s->SRB_Lun);
            return SS_COMP;
        }
        s->SRB_Status = SS_NO_DEVICE;
        s->SRB_DeviceType = DTYPE_UNKNOWN;
        log_raw(CLR_YELLOW, "[ASPI] GDEVBlock Ha=%d Tgt=%d Lun=%d -> NO_DEVICE",
                s->SRB_HaId, s->SRB_Target, s->SRB_Lun);
        return SS_NO_DEVICE;
    }

    case SRB_ExecSCSICmd: {
        SRB_ExecSCSICmd_t* s = (SRB_ExecSCSICmd_t*)lpSRB;

        if (s->SRB_HaId != 0 || s->SRB_Target != 0 || s->SRB_Lun != 0) {
            s->SRB_Status   = SS_NO_DEVICE;
            s->SRB_HaStat   = 0x00;
            s->SRB_TargStat = 0x02;
            log_raw(CLR_GREY, "[SKIP] Ha=%d Tgt=%d Lun=%d -> SS_NO_DEVICE",
                    s->SRB_HaId, s->SRB_Target, s->SRB_Lun);
            if (s->SRB_PostProc) SetEvent((HANDLE)s->SRB_PostProc);
            return SS_NO_DEVICE;
        }

        BYTE op = s->SRB_CDBLen > 0 ? s->CDBByte[0] : 0;

        // ============================================================
        // DUMP: Sürücüye gönderilen tüm 0xEA bloklarını diske kaydet
        // ============================================================
        if (op == 0xEA && (s->SRB_Flags & SRB_DIR_OUT) && s->SRB_BufPointer && s->SRB_BufLen > 48) {
            static bool first_chunk = true;
            FILE* fDump = fopen("firmware_dump_raw.bin", first_chunk ? "wb" : "ab");
            if (fDump) {
                if (first_chunk) {
                    first_chunk = false;
                    log_raw(CLR_CYAN, "[DUMP] Firmware bloklari kaydediliyor -> firmware_dump_raw.bin");
                }
                // İlk 48 bayt başlık, kalanı firmware kodudur
                BYTE* payload = (BYTE*)s->SRB_BufPointer + 48;
                DWORD payload_len = s->SRB_BufLen - 48;
                fwrite(payload, 1, payload_len, fDump);
                fclose(fDump);
            }
        }

        BOOL ioctl_ok = forward_to_spti(s);

        if (ioctl_ok) {
            s->SRB_Status = SS_COMP;
        } else {
            s->SRB_Status = SS_ERR;
            s->SRB_HaStat = 0;
            s->SRB_TargStat = 0;
        }

        // ============================================================
        // SPOOF: GET_EVENT_STATUS (0x4A) İki Aşamalı Kapak Durumu
        // ============================================================
        if (op == 0x4A && ioctl_ok && s->SRB_BufPointer && s->SRB_BufLen >= 8) {
            BYTE* buf = (BYTE*)s->SRB_BufPointer;
            g_event_4a_calls++;

            if (g_event_4a_calls <= 2) {
                buf[5] &= ~0x01;
                log_raw(CLR_YELLOW, "[SPOOF] 0x4A #%d: Kapak KAPALI yapildi (Cihaz tanima).", g_event_4a_calls);
            } else {
                buf[5] |= 0x01;
                log_raw(CLR_GREEN, "[SPOOF] 0x4A #%d: Kapak ACIK yapildi (Flasher onay).", g_event_4a_calls);
            }
        }

        BOOL real_success = ioctl_ok && (s->SRB_TargStat == 0);
        stats_update_exec(op, real_success, s->SRB_BufLen, s->SRB_Flags);
        log_exec_full(s, real_success);

        if (s->SRB_PostProc)
            SetEvent((HANDLE)s->SRB_PostProc);
        return s->SRB_Status;
    }

    case SRB_Abort:
    case SRB_BusDeviceReset: {
        SRB_Header* h = (SRB_Header*)lpSRB;
        h->SRB_Status = SS_COMP;
        log_raw(CLR_YELLOW, "[ASPI] SRB_%s -> SS_COMP",
                cmd == SRB_Abort ? "ABORT" : "BUS_RESET");
        return SS_COMP;
    }

    default:
        hdr->SRB_Status = SS_INVALID_CMD;
        log_raw(CLR_RED, "[ASPI] SRB_Cmd=0x%02X -> SS_INVALID_CMD", cmd);
        return SS_INVALID_CMD;
    }
}

extern "C" __declspec(dllexport)
DWORD WINAPI GetASPI32DLLVersion(void)
{
    return 0x00040001;
}

// ============================================================
// DllMain
// ============================================================
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL; (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_initialized) {
            print_summary();
            if (g_logFile) {
                log_raw(CLR_CYAN, "[SHIM] Unloaded");
                fclose(g_logFile);
                g_logFile = NULL;
            }
            if (g_hDevice != INVALID_HANDLE_VALUE) {
                CloseHandle(g_hDevice);
                g_hDevice = INVALID_HANDLE_VALUE;
            }
            DeleteCriticalSection(&g_csLog);
            DeleteCriticalSection(&g_csStats);
        }
    }
    return TRUE;
}