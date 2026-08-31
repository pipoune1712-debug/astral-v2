#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <string>
#include <filesystem>
#include "utils.h"
#include "spoofer.h"
#include "keys.h"

// ── Chemin driver (.sys) ─────────────────────────────────────────────────────
// Le .sys doit se trouver dans le même dossier que l'exe.
// Si tu l'embarques en ressource, utilise ExtractDriverToTemp() depuis driver_loader.h.
static std::wstring GetDriverPath() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::filesystem::path p(exePath);
    return (p.parent_path() / L"astral_drv.sys").wstring();
}

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin),  _O_U16TEXT);

    SetConsoleTitleW(L"Astral V2 BY Zairis - HWID Spoofer [Kernel Build]");
    PrintBanner();

    // ── Admin check ──────────────────────────────────────────────────────────
    if (!IsAdmin()) {
        SetColor(COL_RED);
        std::wcout << L"  [!] Lance en tant qu'Administrateur !\n\n";
        SetColor(COL_WHITE);
        std::wcout << L"  Clic droit -> Executer en tant qu'administrateur\n\n";
        system("pause");
        return 1;
    }

    SetColor(COL_GREEN);
    std::wcout << L"  [+] Droits Admin OK\n";
    SetColor(COL_WHITE);

    // ── Driver check ─────────────────────────────────────────────────────────
    std::wstring drvPath = GetDriverPath();
    if (!std::filesystem::exists(drvPath)) {
        SetColor(COL_YELLOW);
        std::wcout << L"\n  [!] astral_drv.sys introuvable a cote de l'exe.\n";
        std::wcout << L"      Le spoof kernel sera desactive (registre seulement).\n\n";
        SetColor(COL_WHITE);
        // On continue sans kernel layer — fallback registre
    } else {
        SetColor(COL_GREEN);
        std::wcout << L"  [+] Driver astral_drv.sys trouve\n\n";
        SetColor(COL_WHITE);
    }

    // ── Validation key ───────────────────────────────────────────────────────
    std::wstring key;
    int tries = 0;

    while (tries < 3) {
        SetColor(COL_CYAN);
        std::wcout << L"  Entre ta key HWID : ";
        SetColor(COL_YELLOW);
        std::getline(std::wcin, key);
        SetColor(COL_WHITE);

        // Trim
        while (!key.empty() && key.front() == L' ') key.erase(key.begin());
        while (!key.empty() && key.back()  == L' ') key.pop_back();

        if (ValidateKey(key)) break;

        SetColor(COL_RED);
        std::wcout << L"\n  [!] Key invalide. (" << (++tries) << L"/3)\n\n";
        SetColor(COL_WHITE);

        if (tries == 3) {
            std::wcout << L"  Trop de tentatives. Fermeture.\n\n";
            system("pause");
            return 1;
        }
    }

    SetColor(COL_GREEN);
    std::wcout << L"\n  [+] Key validee. Lancement du spoof...\n";
    SetColor(COL_WHITE);
    Sleep(600);

    // ── Spoof ────────────────────────────────────────────────────────────────
    Spoofer spoofer(drvPath);
    spoofer.RunAll();

    system("pause");
    return 0;
}
