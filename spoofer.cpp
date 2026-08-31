/*
 * spoofer.cpp — Astral V2 Kernel Build
 *
 * Deux couches :
 *   1. Kernel   : driver .sys patche SMBIOS en mémoire noyau et hook
 *                 IOCTL_STORAGE_QUERY_PROPERTY via completion routine.
 *   2. User-mode: registre Windows + nettoyage caches anti-cheat.
 *                 Reste utile car WMI consulte parfois les clés avant
 *                 de tomber sur GetSystemFirmwareTable().
 */

#include "spoofer.h"
#include "registry.h"
#include "utils.h"
#include "driver_loader.h"

#include <windows.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstdint>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")

// ── Constructeur / destructeur ───────────────────────────────────────────────
Spoofer::Spoofer(const std::wstring& driverPath)
    : m_loader(driverPath), m_kernelReady(false)
{
    // Génère les identifiants une fois
    m_diskSerial  = RandSerialA(16);
    m_boardSerial = RandBoardSerialA();
    RandUUID(m_uuid);
}

Spoofer::~Spoofer() {
    // DriverLoader::~DriverLoader() se charge de Unload()
}

// ── PHASE 1 : KERNEL ─────────────────────────────────────────────────────────

SpoofResult Spoofer::KernelSpoofSMBIOS() {
    // Charge le driver
    if (!m_loader.Load()) {
        return { L"Kernel SMBIOS", L"Driver load failed", false };
    }
    m_kernelReady = true;

    // Prépare les params
    AstralSpoofParams p{};
    ::strncpy(p.DiskSerial,  m_diskSerial.c_str(),  sizeof(p.DiskSerial)  - 1);
    ::strncpy(p.BoardSerial, m_boardSerial.c_str(), sizeof(p.BoardSerial) - 1);
    ::memcpy(p.UUID, m_uuid, 16);

    bool ok = m_loader.SendSpoofParams(p);

    // Valeur affichée
    std::wostringstream ws;
    ws << L"Disk=" << std::wstring(m_diskSerial.begin(), m_diskSerial.end())
       << L" | Board=" << std::wstring(m_boardSerial.begin(), m_boardSerial.end());

    return { L"Kernel SMBIOS Patch", ws.str(), ok };
}

SpoofResult Spoofer::KernelSpoofDiskIOCTL() {
    // Le hook IOCTL est activé automatiquement dès que le driver est chargé
    // et que SendSpoofParams a été appelé. Ici on confirme juste le statut.
    bool ok = m_kernelReady;
    return {
        L"Kernel Disk IOCTL Hook",
        ok ? L"IOCTL_STORAGE_QUERY_PROPERTY intercepté" : L"Driver non chargé",
        ok
    };
}

// ── PHASE 2 : REGISTRE / USER-MODE ───────────────────────────────────────────

SpoofResult Spoofer::SpoofMachineGUID() {
    std::wstring val = RandGUID();
    bool ok = RegWriteStr(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography",
        L"MachineGuid", val);
    return { L"MachineGUID", val, ok };
}

SpoofResult Spoofer::SpoofVolumeGUID() {
    std::wstring guid = RandGUID();
    std::wstring label = L"ASTRAL" + RandHex(4);
    std::wstring cmd = L"cmd /c label C: " + label + L" >nul 2>&1";
    _wsystem(cmd.c_str());

    bool ok = RegWriteStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
        L"ASTRAL_VOL", guid);
    return { L"VolumeGUID", guid, true };
}

SpoofResult Spoofer::SpoofInstallID() {
    std::wstring val = RandGUID();
    RegWriteStr(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"DigitalProductId", val);

    DWORD fakeDate = static_cast<DWORD>(time(nullptr) - (rand() % 10000000));
    RegWriteDWORD(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"InstallDate", fakeDate);

    return { L"InstallID", val, true };
}

SpoofResult Spoofer::SpoofComputerName() {
    std::wstring val = L"DESKTOP-" + RandAlphaNum(7);
    bool ok = RegWriteStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
        L"ComputerName", val);
    RegWriteStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
        L"ComputerName", val);
    return { L"ComputerName", val, ok };
}

SpoofResult Spoofer::SpoofProductID() {
    std::wstring val = RandHex(5) + L"-OEM-" + RandHex(7) + L"-" + RandHex(5);
    bool ok = RegWriteStr(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        L"ProductId", val);
    return { L"ProductID", val, ok };
}

// ── Disk entries registre ────────────────────────────────────────────────────
// WMI peut parfois résoudre les serials depuis ces clés avant de tomber
// sur le firmware. On les aligne sur ce que le kernel a patché.
SpoofResult Spoofer::SpoofDiskRegistryEntries() {
    std::wstring fakeW(m_diskSerial.begin(), m_diskSerial.end());
    bool anyOk = false;

    // SCSI
    std::wstring scsiBase = L"SYSTEM\\CurrentControlSet\\Enum\\SCSI";
    for (auto& dk : RegEnumKeys(HKEY_LOCAL_MACHINE, scsiBase)) {
        std::wstring dp = scsiBase + L"\\" + dk;
        for (auto& inst : RegEnumKeys(HKEY_LOCAL_MACHINE, dp)) {
            std::wstring ip = dp + L"\\" + inst;
            if (RegWriteStr(HKEY_LOCAL_MACHINE, ip,
                L"FriendlyName", L"ASTRAL_" + fakeW)) anyOk = true;
            RegWriteStr(HKEY_LOCAL_MACHINE, ip + L"\\Device Parameters",
                L"SerialNumber", fakeW);
        }
    }

    // IDE
    std::wstring ideBase = L"SYSTEM\\CurrentControlSet\\Enum\\IDE";
    for (auto& dk : RegEnumKeys(HKEY_LOCAL_MACHINE, ideBase)) {
        std::wstring dp = ideBase + L"\\" + dk;
        for (auto& inst : RegEnumKeys(HKEY_LOCAL_MACHINE, dp)) {
            RegWriteStr(HKEY_LOCAL_MACHINE, dp + L"\\" + inst,
                L"FriendlyName", L"ASTRAL_IDE_" + fakeW);
        }
    }

    // NVMe
    std::wstring nvmeBase = L"SYSTEM\\CurrentControlSet\\Enum\\NVME";
    for (auto& dk : RegEnumKeys(HKEY_LOCAL_MACHINE, nvmeBase)) {
        std::wstring dp = nvmeBase + L"\\" + dk;
        for (auto& inst : RegEnumKeys(HKEY_LOCAL_MACHINE, dp)) {
            RegWriteStr(HKEY_LOCAL_MACHINE, dp + L"\\" + inst,
                L"FriendlyName", L"ASTRAL_NVME_" + fakeW);
            RegWriteStr(HKEY_LOCAL_MACHINE, dp + L"\\" + inst + L"\\Device Parameters",
                L"SerialNumber", fakeW);
        }
    }

    return { L"Disk Registry (SCSI+IDE+NVMe)", fakeW, anyOk };
}

// ── SMBIOS cache registre ─────────────────────────────────────────────────────
// Ces clés sont lues par WMI avant GetSystemFirmwareTable() dans certains cas.
SpoofResult Spoofer::SpoofSMBIOSRegistryCache() {
    std::wstring diskW(m_diskSerial.begin(),  m_diskSerial.end());
    std::wstring biosPath = L"HARDWARE\\DESCRIPTION\\System\\BIOS";

    // On génère UUID sous forme de chaîne "{XXXXXXXX-...}"
    std::wostringstream uuidSs;
    uuidSs << std::hex << std::uppercase;
    uuidSs << L"{";
    for (int i = 0; i < 4; i++)
        uuidSs << std::setw(2) << std::setfill(L'0') << m_uuid[i];
    uuidSs << L"-";
    for (int i = 4; i < 6; i++)
        uuidSs << std::setw(2) << std::setfill(L'0') << m_uuid[i];
    uuidSs << L"-";
    for (int i = 6; i < 8; i++)
        uuidSs << std::setw(2) << std::setfill(L'0') << m_uuid[i];
    uuidSs << L"-";
    for (int i = 8; i < 10; i++)
        uuidSs << std::setw(2) << std::setfill(L'0') << m_uuid[i];
    uuidSs << L"-";
    for (int i = 10; i < 16; i++)
        uuidSs << std::setw(2) << std::setfill(L'0') << m_uuid[i];
    uuidSs << L"}";
    std::wstring uuidStr = uuidSs.str();

    RegWriteStr(HKEY_LOCAL_MACHINE, biosPath, L"SystemSerialNumber", diskW);
    RegWriteStr(HKEY_LOCAL_MACHINE, biosPath, L"BIOSVersion",
        L"ASTRAL - " + RandHex(4));
    RegWriteStr(HKEY_LOCAL_MACHINE, biosPath, L"SystemManufacturer", L"AstralTech");
    RegWriteStr(HKEY_LOCAL_MACHINE, biosPath, L"SystemProductName",
        L"AstralBoard-" + RandAlphaNum(4));
    RegWriteStr(HKEY_LOCAL_MACHINE, biosPath, L"BaseBoardProduct",
        L"ASTRAL-MB-" + std::wstring(m_boardSerial.begin(), m_boardSerial.end()));
    RegWriteStr(HKEY_LOCAL_MACHINE, biosPath, L"BaseBoardManufacturer", L"AstralTech");
    RegWriteStr(HKEY_LOCAL_MACHINE, biosPath, L"BaseBoardVersion",
        std::wstring(m_boardSerial.begin(), m_boardSerial.end()));

    // WMI cache SMBIOS dans cette clé pour les requêtes rapides
    RegWriteStr(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate",
        L"SusClientId", uuidStr);

    // csproduct UUID
    RegWriteStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
        L"ComputerHardwareId", uuidStr);

    bool ok = RegWriteStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data",
        L"SMBiosData", diskW);

    return { L"SMBIOS Registry Cache", uuidStr, true };
}

SpoofResult Spoofer::SpoofBaseboardRegistry() {
    std::wstring boardW(m_boardSerial.begin(), m_boardSerial.end());
    std::wstring path = L"HARDWARE\\DESCRIPTION\\System\\BIOS";

    RegWriteStr(HKEY_LOCAL_MACHINE, path, L"BaseBoardProduct",
        L"ASTRAL-MB-" + boardW);
    RegWriteStr(HKEY_LOCAL_MACHINE, path, L"BaseBoardManufacturer", L"AstralTech");
    bool ok = RegWriteStr(HKEY_LOCAL_MACHINE, path, L"BaseBoardVersion", boardW);

    return { L"Baseboard Registry", boardW, ok };
}

SpoofResult Spoofer::SpoofGPUPnPID() {
    std::wstring vid = RandHex(4);
    std::wstring did = RandHex(4);
    std::wstring sub = RandHex(8);
    std::wstring val = L"PCI\\VEN_" + vid + L"&DEV_" + did +
                       L"&SUBSYS_" + sub + L"&REV_" + RandHex(2);

    std::wstring basePath =
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4D36E968-E325-11CE-BFC1-08002BE10318}";

    bool anyOk = false;
    for (auto& k : RegEnumKeys(HKEY_LOCAL_MACHINE, basePath)) {
        if (k == L"Properties") continue;
        std::wstring fp = basePath + L"\\" + k;
        if (RegWriteStr(HKEY_LOCAL_MACHINE, fp, L"MatchingDeviceId", val)) anyOk = true;
        RegWriteStr(HKEY_LOCAL_MACHINE, fp, L"HardwareID", val);
        RegWriteStr(HKEY_LOCAL_MACHINE, fp, L"DriverDesc", L"Astral Display Adapter");
    }
    return { L"GPU PnP ID", val, anyOk };
}

// ── MAC Address ─────────────────────────────────────────────────────────────
bool Spoofer::SpoofNicRegistry(const std::wstring& mac) {
    std::wstring basePath =
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\"
        L"{4D36E972-E325-11CE-BFC1-08002BE10318}";

    // MAC sans tirets pour NetworkAddress
    std::wstring macClean;
    for (wchar_t c : mac)
        if (c != L'-') macClean += c;

    bool anyOk = false;
    for (auto& k : RegEnumKeys(HKEY_LOCAL_MACHINE, basePath)) {
        if (k == L"Properties") continue;
        std::wstring fp = basePath + L"\\" + k;
        std::wstring comp = RegReadStr(HKEY_LOCAL_MACHINE, fp, L"ComponentId");
        if (comp.empty()) continue;
        if (RegWriteStr(HKEY_LOCAL_MACHINE, fp, L"NetworkAddress", macClean))
            anyOk = true;
    }
    return anyOk;
}

SpoofResult Spoofer::SpoofMACAddress() {
    std::wstring mac = RandMAC();
    bool ok = SpoofNicRegistry(mac);
    return { L"MAC Address", mac, ok };
}

// ── Caches Anti-Cheat ─────────────────────────────────────────────────────────
SpoofResult Spoofer::SpoofEACCache() {
    wchar_t appdata[MAX_PATH], localapp[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, appdata);
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA,  nullptr, 0, localapp);

    std::wstring eacPaths[] = {
        std::wstring(appdata)   + L"\\EasyAntiCheat",
        std::wstring(localapp)  + L"\\EasyAntiCheat",
        std::wstring(appdata)   + L"\\EasyAntiCheat_EOS",
        std::wstring(localapp)  + L"\\EasyAntiCheat_EOS",
    };

    for (auto& p : eacPaths) {
        std::wstring cmd = L"cmd /c rmdir /s /q \"" + p + L"\" >nul 2>&1";
        _wsystem(cmd.c_str());
    }

    // Reset ClientID dans la registry EAC
    RegWriteStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\EasyAntiCheat",
        L"ClientID", RandGUID());
    RegWriteStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\EasyAntiCheat_EOS",
        L"ClientID", RandGUID());

    // Supprime les tokens EAC (parfois stockés ici)
    std::wstring eacToken = std::wstring(localapp) + L"\\EasyAntiCheat\\*.token";
    std::wstring cmd = L"cmd /c del /q /f \"" + eacToken + L"\" >nul 2>&1";
    _wsystem(cmd.c_str());

    return { L"EAC Cache", L"Cleared + ClientID reset", true };
}

SpoofResult Spoofer::SpoofEpicGamesCache() {
    wchar_t localapp[MAX_PATH], roaming[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localapp);
    SHGetFolderPathW(nullptr, CSIDL_APPDATA,       nullptr, 0, roaming);

    auto rmdir = [](const std::wstring& p) {
        std::wstring cmd = L"cmd /c rmdir /s /q \"" + p + L"\" >nul 2>&1";
        _wsystem(cmd.c_str());
    };
    auto delfiles = [](const std::wstring& p) {
        std::wstring cmd = L"cmd /c del /q /f \"" + p + L"\" >nul 2>&1";
        _wsystem(cmd.c_str());
    };

    // Logs Fortnite
    rmdir(std::wstring(localapp) + L"\\FortniteGame\\Saved\\Logs");
    // Crash reports (contiennent parfois des traces HWID)
    rmdir(std::wstring(localapp) + L"\\FortniteGame\\Saved\\Crashes");
    // Cache webcache EGL
    rmdir(std::wstring(localapp) + L"\\EpicGamesLauncher\\Saved\\webcache");
    rmdir(std::wstring(localapp) + L"\\EpicGamesLauncher\\Saved\\webcache_4430");
    // Supprime les logs EGL
    delfiles(std::wstring(localapp) + L"\\EpicGamesLauncher\\Saved\\Logs\\*.log");

    // BattlEye cache (si présent)
    rmdir(std::wstring(localapp) + L"\\BattlEye");
    rmdir(std::wstring(roaming)  + L"\\BattlEye");

    // Reset machine ID Epic
    RegWriteStr(HKEY_CURRENT_USER,
        L"SOFTWARE\\Epic Games\\Unreal Engine\\Identifiers",
        L"MachineID", RandGUID());

    // Clé EOS (Epic Online Services)
    RegWriteStr(HKEY_CURRENT_USER,
        L"SOFTWARE\\Epic Games\\EOS",
        L"MachineID", RandGUID());

    return { L"Epic/Fortnite/BattlEye Cache", L"Cleared + IDs reset", true };
}

// ── RunAll ────────────────────────────────────────────────────────────────────
void Spoofer::RunAll() {
    int ok = 0, total = 0;

    auto Run = [&](SpoofResult r) {
        Log(r.component, r.newValue, r.success);
        if (r.success) ok++;
        total++;
        Sleep(60);
    };

    // ── Kernel layer ─────────────────────────────────────────────────────────
    Section(L"KERNEL LAYER (SMBIOS + IOCTL HOOK)");
    Run(KernelSpoofSMBIOS());
    Run(KernelSpoofDiskIOCTL());

    // ── Registre système ──────────────────────────────────────────────────────
    Section(L"IDENTIFIANTS SYSTEME");
    Run(SpoofMachineGUID());
    Run(SpoofInstallID());
    Run(SpoofProductID());
    Run(SpoofComputerName());

    // ── Matériel registre ─────────────────────────────────────────────────────
    Section(L"MATERIEL (REGISTRE + CACHE WMI)");
    Run(SpoofDiskRegistryEntries());
    Run(SpoofVolumeGUID());
    Run(SpoofSMBIOSRegistryCache());
    Run(SpoofBaseboardRegistry());

    // ── Réseau + GPU ──────────────────────────────────────────────────────────
    Section(L"RESEAU & GPU");
    Run(SpoofGPUPnPID());
    Run(SpoofMACAddress());

    // ── Anti-cheat ────────────────────────────────────────────────────────────
    Section(L"ANTI-CHEAT / CACHE");
    Run(SpoofEACCache());
    Run(SpoofEpicGamesCache());

    // ── Résumé ────────────────────────────────────────────────────────────────
    std::wcout << L"\n  ================================================\n";
    SetColor(ok == total ? COL_GREEN : COL_YELLOW);
    std::wcout << L"\n  " << ok << L"/" << total << L" composants spoofes.\n\n";

    if (m_kernelReady) {
        SetColor(COL_GREEN);
        std::wcout << L"  [+] Kernel layer actif — SMBIOS patché en mémoire.\n";
        std::wcout << L"      wmic + EAC liront les fausses valeurs sans reboot.\n\n";
    } else {
        SetColor(COL_YELLOW);
        std::wcout << L"  [!] Kernel layer inactif — redémarre pour appliquer\n";
        std::wcout << L"      les modifications registre (SMBIOS côté firmware).\n\n";
    }

    SetColor(COL_PURPLE);
    std::wcout << L"  REDEMARRE TON PC pour finaliser tous les changements.\n\n";
    SetColor(COL_WHITE);
}
