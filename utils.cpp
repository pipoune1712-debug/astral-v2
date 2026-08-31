#include "utils.h"

// ── RNG global ───────────────────────────────────────────────────────────────
static std::mt19937 rng([]() -> std::mt19937::result_type {
    std::random_device rd;
    return rd();
}());

// ── Console ─────────────────────────────────────────────────────────────────
void SetColor(WORD color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void PrintBanner() {
    SetColor(COL_PURPLE);
    std::wcout << L"\n";
    std::wcout << L"  _____ _____ _____ _____ _____ _____   _   _ ___  \n";
    std::wcout << L" |  _  |   __|_   _| __  |  _  |     | | | | |_  |\n";
    std::wcout << L" |     |__   | | | |    -|     |  |  | | | | |_| |\n";
    std::wcout << L" |__|__|_____| |_| |__|__|__|__|_____| |_____|_____|\n";
    std::wcout << L"\n";
    SetColor(COL_CYAN);
    std::wcout << L"               HWID SPOOFER  --  BY ZAIRIS\n";
    std::wcout << L"             v2.0  KR Edition  [Kernel Build]\n\n";
    SetColor(COL_WHITE);
    std::wcout << L"  ================================================\n\n";
}

void Log(const std::wstring& component, const std::wstring& value, bool ok) {
    std::wcout << L"  ";
    SetColor(ok ? COL_GREEN : COL_RED);
    std::wcout << (ok ? L"[OK]  " : L"[ERR] ");
    SetColor(COL_CYAN);
    std::wcout << component;
    SetColor(COL_WHITE);
    std::wcout << L"  ->  ";
    SetColor(COL_YELLOW);
    std::wcout << value << L"\n";
    SetColor(COL_WHITE);
}

void Section(const std::wstring& title) {
    std::wcout << L"\n";
    SetColor(COL_PURPLE);
    std::wcout << L"  [ " << title << L" ]\n";
    SetColor(COL_WHITE);
    std::wcout << L"  ------------------------------------------------\n";
}

// ── Helpers hex ─────────────────────────────────────────────────────────────
static const wchar_t HEX_W[] = L"0123456789ABCDEF";
static const char    HEX_A[] =  "0123456789ABCDEF";

std::wstring RandHex(int len) {
    std::uniform_int_distribution<int> d(0, 15);
    std::wstring r;
    r.reserve(len);
    for (int i = 0; i < len; i++) r += HEX_W[d(rng)];
    return r;
}

std::string RandHexA(int len) {
    std::uniform_int_distribution<int> d(0, 15);
    std::string r;
    r.reserve(len);
    for (int i = 0; i < len; i++) r += HEX_A[d(rng)];
    return r;
}

std::wstring RandGUID() {
    return L"{" + RandHex(8) + L"-" + RandHex(4) + L"-" +
           RandHex(4) + L"-" + RandHex(4) + L"-" + RandHex(12) + L"}";
}

std::wstring RandMAC() {
    // Premier octet pair (unicast bit clear)
    std::uniform_int_distribution<int> d8(0, 255);
    std::wostringstream ss;
    ss << std::hex << std::uppercase
       << std::setw(2) << std::setfill(L'0') << ((d8(rng) & 0xFE) | 0x02);
    for (int i = 1; i < 6; i++)
        ss << L"-" << std::setw(2) << std::setfill(L'0') << d8(rng);
    return ss.str();
}

// ── Alphanum helpers ─────────────────────────────────────────────────────────
static const wchar_t ALPHA_W[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static const char    ALPHA_A[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

std::wstring RandAlphaNum(int len) {
    std::uniform_int_distribution<int> d(0,
        static_cast<int>(std::wcslen(ALPHA_W)) - 1);
    std::wstring r;
    r.reserve(len);
    for (int i = 0; i < len; i++) r += ALPHA_W[d(rng)];
    return r;
}

std::wstring RandSerial(int len) { return RandAlphaNum(len); }

// ── Narrow serial generators ─────────────────────────────────────────────────

// Disk serial — format typique WD/Seagate: WD-XXXXXXXX (mais on génère alphanum brut)
// La plupart des anti-cheat vérifient juste que ce n'est pas tous-zéros ou identique.
// On cible le format XXXXXXXXXXXXXXXX (16 chars, majuscules + chiffres).
std::string RandSerialA(int len) {
    std::uniform_int_distribution<int> d(0,
        static_cast<int>(strlen(ALPHA_A)) - 1);
    std::string r;
    r.reserve(len);
    for (int i = 0; i < len; i++) r += ALPHA_A[d(rng)];
    return r;
}

// Baseboard serial — format ASUS/MSI/Gigabyte : typiquement 12 chars
std::string RandBoardSerialA() {
    // Certains boards utilisent format : YYMMDDxxxxxxx
    // On simule : 2 chiffres mois/année + 8 alphanum
    std::uniform_int_distribution<int> dd(0, 9);
    std::uniform_int_distribution<int> dm(1, 12);
    std::uniform_int_distribution<int> da(23, 26); // "année" 23-26

    std::ostringstream ss;
    ss << da(rng)
       << std::setw(2) << std::setfill('0') << dm(rng)
       << RandSerialA(7);
    return ss.str().substr(0, 12);
}

// UUID v4 — 4 bits version = 0100, 2 bits variant = 10
void RandUUID(uint8_t out[16]) {
    std::uniform_int_distribution<int> d(0, 255);
    for (int i = 0; i < 16; i++) out[i] = static_cast<uint8_t>(d(rng));
    out[6] = (out[6] & 0x0F) | 0x40; // version 4
    out[8] = (out[8] & 0x3F) | 0x80; // variant 10xx
}

// ── Admin check ─────────────────────────────────────────────────────────────
bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID sid     = nullptr;
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&auth, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &sid)) {
        CheckTokenMembership(nullptr, sid, &isAdmin);
        FreeSid(sid);
    }
    return isAdmin == TRUE;
}
