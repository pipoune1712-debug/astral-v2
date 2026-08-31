#include "registry.h"

#include <windows.h>
#include <string>
#include <vector>

std::wstring RegReadStr(HKEY root,
                        const std::wstring& path,
                        const std::wstring& name) {
    HKEY hKey;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return L"";

    wchar_t buf[1024] = {};
    DWORD   sz        = sizeof(buf);
    DWORD   type      = REG_SZ;
    RegQueryValueExW(hKey, name.c_str(), nullptr, &type,
                     reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(hKey);
    return std::wstring(buf);
}

bool RegWriteStr(HKEY root,
                 const std::wstring& path,
                 const std::wstring& name,
                 const std::wstring& value) {
    HKEY  hKey;
    DWORD disp;
    if (RegCreateKeyExW(root, path.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
        nullptr, &hKey, &disp) != ERROR_SUCCESS)
        return false;

    bool ok = RegSetValueExW(hKey, name.c_str(), 0, REG_SZ,
        reinterpret_cast<const BYTE*>(value.c_str()),
        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return ok;
}

bool RegWriteBin(HKEY root,
                 const std::wstring& path,
                 const std::wstring& name,
                 const std::vector<uint8_t>& data) {
    HKEY hKey;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;

    bool ok = RegSetValueExW(hKey, name.c_str(), 0, REG_BINARY,
        data.data(), static_cast<DWORD>(data.size())) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return ok;
}

bool RegWriteDWORD(HKEY root,
                   const std::wstring& path,
                   const std::wstring& name,
                   DWORD value) {
    HKEY hKey;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;

    bool ok = RegSetValueExW(hKey, name.c_str(), 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&value),
        sizeof(DWORD)) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return ok;
}

bool RegDeleteVal(HKEY root,
                  const std::wstring& path,
                  const std::wstring& name) {
    HKEY hKey;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;
    bool ok = RegDeleteValueW(hKey, name.c_str()) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return ok;
}

std::vector<std::wstring> RegEnumKeys(HKEY root, const std::wstring& path) {
    HKEY hKey;
    std::vector<std::wstring> result;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return result;

    wchar_t name[256];
    DWORD   idx = 0, sz;
    while (true) {
        sz = 256;
        if (RegEnumKeyExW(hKey, idx++, name, &sz,
            nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        result.emplace_back(name);
    }
    RegCloseKey(hKey);
    return result;
}

std::vector<std::wstring> RegEnumValues(HKEY root, const std::wstring& path) {
    HKEY hKey;
    std::vector<std::wstring> result;
    if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return result;

    wchar_t name[256];
    DWORD   idx = 0, nameSz;
    while (true) {
        nameSz = 256;
        if (RegEnumValueW(hKey, idx++, name, &nameSz,
            nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        result.emplace_back(name);
    }
    RegCloseKey(hKey);
    return result;
}
