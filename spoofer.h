#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include "driver_loader.h"

// ── Résultat d'une opération de spoof ───────────────────────────────────────
struct SpoofResult {
    std::wstring component;
    std::wstring newValue;
    bool         success;
};

// ── Classe principale ─────────────────────────────────────────────────────────
class Spoofer {
public:
    // Constructeur : prend le chemin vers le .sys
    explicit Spoofer(const std::wstring& driverPath);
    ~Spoofer();

    // ── Phase 1 : Kernel (SMBIOS + IOCTL disk) ──────────────────────────────
    SpoofResult KernelSpoofSMBIOS();   // Envoie diskSerial, boardSerial, UUID au driver
    SpoofResult KernelSpoofDiskIOCTL();// Confirmation du hook IOCTL_STORAGE_QUERY_PROPERTY

    // ── Phase 2 : Registre / User-mode (toujours utile pour WMI cache) ───────
    SpoofResult SpoofMachineGUID();
    SpoofResult SpoofVolumeGUID();
    SpoofResult SpoofInstallID();
    SpoofResult SpoofComputerName();
    SpoofResult SpoofProductID();

    // Registre matériel (WMI lit parfois ces clés avant GetSystemFirmwareTable)
    SpoofResult SpoofDiskRegistryEntries();
    SpoofResult SpoofSMBIOSRegistryCache();
    SpoofResult SpoofBaseboardRegistry();
    SpoofResult SpoofGPUPnPID();

    // Réseau
    SpoofResult SpoofMACAddress();

    // Anti-cheat / caches
    SpoofResult SpoofEACCache();
    SpoofResult SpoofEpicGamesCache();

    // ── Runner complet ────────────────────────────────────────────────────────
    void RunAll();

    // ── Getters identifiants générés (utiles pour affichage) ─────────────────
    const std::string& GetDiskSerial()  const { return m_diskSerial; }
    const std::string& GetBoardSerial() const { return m_boardSerial; }

private:
    bool SpoofNicRegistry(const std::wstring& mac);

    // Identifiants générés une fois au démarrage
    std::string  m_diskSerial;   // 16 chars alphanum
    std::string  m_boardSerial;  // 12 chars alphanum
    uint8_t      m_uuid[16];

    // Loader driver
    DriverLoader m_loader;
    bool         m_kernelReady;
};
