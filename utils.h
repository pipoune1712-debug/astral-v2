#pragma once

#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <vector>
#include <random>
#include <algorithm>
#include <ctime>

// ── Couleurs console ────────────────────────────────────────────────────────
#define COL_PURPLE  (FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY)
#define COL_GREEN   (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define COL_RED     (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define COL_WHITE   (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
#define COL_CYAN    (FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define COL_YELLOW  (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)

// ── Fonctions console ────────────────────────────────────────────────────────
void SetColor(WORD color);
void PrintBanner();
void Log(const std::wstring& component, const std::wstring& value, bool ok);
void Section(const std::wstring& title);

// ── Génération aléatoire ────────────────────────────────────────────────────
std::wstring  RandHex(int len);
std::wstring  RandGUID();
std::wstring  RandMAC();
std::wstring  RandSerial(int len);
std::wstring  RandAlphaNum(int len);

// Versions narrow (pour les paramètres kernel)
std::string   RandHexA(int len);
std::string   RandSerialA(int len);     // disk serial style : 8+4+8 alphanum
std::string   RandBoardSerialA();       // baseboard style  : 12 alphanum
void          RandUUID(uint8_t out[16]);// UUID v4 raw bytes

// ── Admin check ─────────────────────────────────────────────────────────────
bool IsAdmin();
