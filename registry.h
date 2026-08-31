#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
// Lecture REG_SZ
std::wstring RegReadStr(HKEY root, const std::wstring& path, const std::wstring& name);

// Écriture REG_SZ
bool RegWriteStr(HKEY root, const std::wstring& path,
                 const std::wstring& name, const std::wstring& value);

// Écriture REG_BINARY
bool RegWriteBin(HKEY root, const std::wstring& path,
                 const std::wstring& name, const std::vector<uint8_t>& data);

// Écriture REG_DWORD
bool RegWriteDWORD(HKEY root, const std::wstring& path,
                   const std::wstring& name, DWORD value);

// Suppression valeur
bool RegDeleteVal(HKEY root, const std::wstring& path, const std::wstring& name);

// Énumération sous-clés
std::vector<std::wstring> RegEnumKeys(HKEY root, const std::wstring& path);

// Énumération valeurs d'une clé
std::vector<std::wstring> RegEnumValues(HKEY root, const std::wstring& path);
