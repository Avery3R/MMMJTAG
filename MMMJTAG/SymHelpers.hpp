#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <IpcApiAccess.hpp>

std::vector<uint8_t> GetDebugData(const uint64_t pageTableAddr, const uint64_t modueBase);
BOOL SymbolCallback(HANDLE hProcess, ULONG ActionCode, ULONG64 CallbackData, ULONG64 UserContext);
uint64_t GetAddrOfSymbol(HANDLE hSym, const std::string &symbolName);
ULONG GetTypeIdFromName(HANDLE hSym, const uint64_t moduleBase, const std::string &typeName);
ULONG GetTypeSizeFromName(HANDLE hSym, const uint64_t moduleBase, const std::string &typeName);
std::unordered_map<std::string, uint64_t> GetTypeChildren(HANDLE hSym, const uint64_t moduleBase, const ULONG typeId);