#pragma once
/*
 * driver_loader.h — Charge astral_drv.sys depuis le user-mode
 * Méthode : création de la clé service temporaire + NtLoadDriver
 * Compatible GCC / w64devkit C++17
 *
 * FIXES APPLIQUÉS :
 *   1. SE_LOAD_DRIVER_NAME   → L"SeLoadDriverPrivilege" (wide literal direct)
 *   2. ExtractDriverToTemp   → CreateFileW/WriteFile/CloseHandle (zero stdlib stream)
 */

#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

// ── IOCTL codes (miroir driver) ─────────────────────────────────────────────
#define ASTRAL_DEVICE_NAME  L"\\\\.\\AstralSpoofer"

#define CTL_CODE_ASTRAL(fn) \
    (0x00000022 << 16 | 0 << 14 | (fn) << 2 | 0)

#define IOCTL_ASTRAL_SPOOF_SMBIOS   CTL_CODE_ASTRAL(0x800)
#define IOCTL_ASTRAL_UNLOAD         CTL_CODE_ASTRAL(0x802)

#pragma pack(push, 1)
struct AstralSpoofParams {
    char DiskSerial[24];
    char BoardSerial[20];
    uint8_t UUID[16];
};
#pragma pack(pop)

// ── NtLoadDriver / NtUnloadDriver via ntdll ──────────────────────────────────
typedef NTSTATUS (WINAPI *PFN_NtLoadDriver)(PUNICODE_STRING);
typedef NTSTATUS (WINAPI *PFN_NtUnloadDriver)(PUNICODE_STRING);

// Init UNICODE_STRING from wstring
static inline void InitUStr(UNICODE_STRING* us, const std::wstring& s) {
    us->Buffer        = const_cast<PWSTR>(s.c_str());
    us->Length        = static_cast<USHORT>(s.size() * 2);
    us->MaximumLength = us->Length + 2;
}

// ── FIX 1 : SE_LOAD_DRIVER_PRIVILEGE helper ─────────────────────────────────
// SE_LOAD_DRIVER_NAME est défini comme "SeLoadDriverPrivilege" (ANSI const char*)
// dans winnt.h — LookupPrivilegeValueW attend un LPCWSTR.
// Solution : on passe directement le wide literal, aucune conversion nécessaire.
static bool EnableLoadDriverPrivilege() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    LUID luid;
    // FIX : wide literal direct — évite l'erreur cannot convert const char* → LPCWSTR
    if (!LookupPrivilegeValueW(nullptr, L"SeLoadDriverPrivilege", &luid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr)
           && GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

// ── Registry service key management ─────────────────────────────────────────
static const std::wstring SERVICE_REG_PATH =
    L"SYSTEM\\CurrentControlSet\\Services\\AstralDrv";

static bool CreateServiceKey(const std::wstring& driverAbsPath) {
    HKEY hKey;
    DWORD disp;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        SERVICE_REG_PATH.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr,
        &hKey, &disp) != ERROR_SUCCESS)
        return false;

    std::wstring imgPath = L"\\??\\" + driverAbsPath;
    RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ,
        reinterpret_cast<const BYTE*>(imgPath.c_str()),
        static_cast<DWORD>((imgPath.size() + 1) * 2));

    DWORD type = 1;
    RegSetValueExW(hKey, L"Type", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&type), sizeof(DWORD));

    DWORD start = 3;
    RegSetValueExW(hKey, L"Start", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&start), sizeof(DWORD));

    DWORD err = 1;
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&err), sizeof(DWORD));

    RegCloseKey(hKey);
    return true;
}

static void DeleteServiceKey() {
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, SERVICE_REG_PATH.c_str());
}

// ── DriverLoader class ───────────────────────────────────────────────────────
class DriverLoader {
public:
    explicit DriverLoader(const std::wstring& sysPath)
        : m_sysPath(sysPath), m_loaded(false)
    {
        m_ntdll = GetModuleHandleW(L"ntdll.dll");
        m_NtLoadDriver   = reinterpret_cast<PFN_NtLoadDriver>(
            GetProcAddress(m_ntdll, "NtLoadDriver"));
        m_NtUnloadDriver = reinterpret_cast<PFN_NtUnloadDriver>(
            GetProcAddress(m_ntdll, "NtUnloadDriver"));
    }

    bool Load() {
        if (!m_NtLoadDriver || !m_NtUnloadDriver) {
            std::wcout << L"  [!] NtLoadDriver introuvable dans ntdll\n";
            return false;
        }

        if (!EnableLoadDriverPrivilege()) {
            std::wcout << L"  [!] SeLoadDriverPrivilege refusé (admin requis)\n";
            return false;
        }

        wchar_t abs[MAX_PATH];
        GetFullPathNameW(m_sysPath.c_str(), MAX_PATH, abs, nullptr);
        m_absPath = abs;

        if (!CreateServiceKey(m_absPath)) {
            std::wcout << L"  [!] Impossible de créer la clé service\n";
            return false;
        }

        std::wstring regPath =
            L"\\Registry\\Machine\\" + SERVICE_REG_PATH;
        UNICODE_STRING ustr;
        InitUStr(&ustr, regPath);

        NTSTATUS status = m_NtLoadDriver(&ustr);
        if (status != 0 && status != (NTSTATUS)0xC0000010 /* already loaded */) {
            std::wcout << L"  [!] NtLoadDriver failed: 0x"
                       << std::hex << status << std::dec << L"\n";
            DeleteServiceKey();
            return false;
        }

        m_loaded = true;
        return true;
    }

    HANDLE OpenDevice() {
        return CreateFileW(ASTRAL_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    bool SendSpoofParams(const AstralSpoofParams& params) {
        HANDLE dev = OpenDevice();
        if (dev == INVALID_HANDLE_VALUE) {
            std::wcout << L"  [!] Impossible d'ouvrir le device driver\n";
            return false;
        }

        DWORD returned = 0;
        bool ok = DeviceIoControl(dev,
            IOCTL_ASTRAL_SPOOF_SMBIOS,
            const_cast<AstralSpoofParams*>(&params),
            sizeof(params),
            nullptr, 0,
            &returned, nullptr) != 0;

        CloseHandle(dev);
        return ok;
    }

    void Unload() {
        if (!m_loaded || !m_NtUnloadDriver) return;

        HANDLE dev = OpenDevice();
        if (dev != INVALID_HANDLE_VALUE) {
            DWORD ret = 0;
            DeviceIoControl(dev, IOCTL_ASTRAL_UNLOAD,
                nullptr, 0, nullptr, 0, &ret, nullptr);
            CloseHandle(dev);
        }

        std::wstring regPath =
            L"\\Registry\\Machine\\" + SERVICE_REG_PATH;
        UNICODE_STRING ustr;
        InitUStr(&ustr, regPath);
        m_NtUnloadDriver(&ustr);

        DeleteServiceKey();
        m_loaded = false;
    }

    ~DriverLoader() { Unload(); }
    bool IsLoaded() const { return m_loaded; }

private:
    std::wstring         m_sysPath;
    std::wstring         m_absPath;
    bool                 m_loaded;
    HMODULE              m_ntdll;
    PFN_NtLoadDriver     m_NtLoadDriver;
    PFN_NtUnloadDriver   m_NtUnloadDriver;
};

// ── FIX 2 : Embedded driver extractor ───────────────────────────────────────
// Remplacement complet de std::ofstream par les API Win32 brutes.
// std::ofstream + std::wstring sous MinGW = crash garanti sur les chemins
// avec caractères non-ASCII ou les wstring → narrow conversions foireuses.
//
// CreateFileW accepte un LPCWSTR natif — zéro conversion, zéro plantage.
static std::wstring ExtractDriverToTemp(const uint8_t* data, size_t size,
                                         const std::wstring& filename) {
    // Récupère %TEMP% en wide natif
    wchar_t tmpDir[MAX_PATH];
    DWORD len = GetTempPathW(MAX_PATH, tmpDir);
    if (len == 0 || len > MAX_PATH)
        return L"";

    // Construit le chemin complet : %TEMP%\filename
    std::wstring outPath = std::wstring(tmpDir) + filename;

    // Ouvre / crée le fichier via Win32 — LPCWSTR direct, aucune conversion
    HANDLE hFile = CreateFileW(
        outPath.c_str(),
        GENERIC_WRITE,
        0,                          // pas de partage pendant l'écriture
        nullptr,
        CREATE_ALWAYS,              // écrase si existant
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE)
        return L"";

    // Écrit les données en une passe
    DWORD written = 0;
    BOOL ok = WriteFile(
        hFile,
        data,
        static_cast<DWORD>(size),
        &written,
        nullptr
    );

    CloseHandle(hFile);

    // Vérifie que tout a bien été écrit
    if (!ok || written != static_cast<DWORD>(size)) {
        DeleteFileW(outPath.c_str()); // nettoie le fichier corrompu
        return L"";
    }

    return outPath;
}
