#include "SymHelpers.hpp"

#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

#include <iostream>

#include "CPUHelpers.hpp"
#include "MiscHelpers.hpp"

std::vector<uint8_t> GetDebugData(const OpenIPC::IPC_DeviceId threadId, const uint64_t modueBase)
{
	IMAGE_DOS_HEADER dosHeader;
	CPUMemRead(threadId, modueBase, &dosHeader, sizeof(dosHeader));

	IMAGE_NT_HEADERS64 ntHeaders;
	CPUMemRead(threadId, modueBase+dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders));

	std::vector<uint8_t> debugData;

	auto &dbgDataDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	const size_t numDebugDirs = dbgDataDir.Size/sizeof(IMAGE_DEBUG_DIRECTORY);
	for(size_t i = 0; i < numDebugDirs; ++i)
	{
		IMAGE_DEBUG_DIRECTORY dbgDir;
		CPUMemRead(threadId, modueBase+dbgDataDir.VirtualAddress+i*sizeof(IMAGE_DEBUG_DIRECTORY), &dbgDir, sizeof(dbgDir));

		debugData.insert(debugData.end(), (char*)&dbgDir, (char*)(&dbgDir)+sizeof(dbgDir));
	}

	for(size_t i = 0; i < numDebugDirs; ++i)
	{
		IMAGE_DEBUG_DIRECTORY *dbgDir = (IMAGE_DEBUG_DIRECTORY*)&debugData[i*sizeof(IMAGE_DEBUG_DIRECTORY)];

		if(dbgDir->SizeOfData == 0)
		{
			dbgDir->AddressOfRawData = 0;
			dbgDir->PointerToRawData = 0;
			continue;
		}

		std::vector<uint8_t> dataBuf(dbgDir->SizeOfData);
		CPUMemRead(threadId, modueBase+dbgDir->AddressOfRawData, &dataBuf[0], dataBuf.size());

		size_t dataOffset = debugData.size();

		debugData.insert(debugData.end(), dataBuf.begin(), dataBuf.end());

		dbgDir = (IMAGE_DEBUG_DIRECTORY*)&debugData[i*sizeof(IMAGE_DEBUG_DIRECTORY)];
		dbgDir->AddressOfRawData = 0;
		dbgDir->PointerToRawData = (DWORD)dataOffset;
	}

	return debugData;
}

BOOL SymbolCallback(HANDLE hProcess, ULONG ActionCode, ULONG64 CallbackData, ULONG64 UserContext)
{
	CBA_DEFERRED_SYMBOL_LOAD_PARTIAL;
	IMAGEHLP_DEFERRED_SYMBOL_LOAD64* data = (IMAGEHLP_DEFERRED_SYMBOL_LOAD64*)CallbackData;
	IMAGEHLP_CBA_READ_MEMORY* data2 = (IMAGEHLP_CBA_READ_MEMORY*)CallbackData;
	if(ActionCode == CBA_DEBUG_INFO || ActionCode == CBA_SRCSRV_INFO)
	{
		std::cout << (char*)CallbackData << std::flush;
	}
	ActionCode;
	return FALSE;
}

uint64_t GetAddrOfSymbol(HANDLE hSym, const std::string &symbolName)
{
	IMAGEHLP_SYMBOL64 symhlp = {0};
	symhlp.SizeOfStruct = sizeof(symhlp);
	BOOL winresult = SymGetSymFromName64(hSym, symbolName.c_str(), &symhlp);

	return symhlp.Address;
}

ULONG GetTypeIdFromName(HANDLE hSym, const uint64_t moduleBase, const std::string &typeName)
{
	SYMBOL_INFO info = {0};
	info.SizeOfStruct = sizeof(SYMBOL_INFO);
	BOOL winresult = SymGetTypeFromName(hSym, moduleBase, typeName.c_str(), &info);

	return info.TypeIndex;
}

ULONG GetTypeSizeFromName(HANDLE hSym, const uint64_t moduleBase, const std::string &typeName)
{
	SYMBOL_INFO info = {0};
	info.SizeOfStruct = sizeof(SYMBOL_INFO);
	BOOL winresult = SymGetTypeFromName(hSym, moduleBase, typeName.c_str(), &info);

	return info.Size;
}

std::unordered_map<std::string, uint64_t> GetTypeChildren(HANDLE hSym, const uint64_t moduleBase, const ULONG typeId)
{
	std::unordered_map<std::string, uint64_t> ret;

	DWORD typeChildCount = 0;
	BOOL winresult = SymGetTypeInfo(hSym, moduleBase, typeId, TI_GET_CHILDRENCOUNT, &typeChildCount);

	std::vector<ULONG> typeChildren(typeChildCount+2);
	typeChildren[0] = typeChildCount; //Count
	winresult = SymGetTypeInfo(hSym, moduleBase, typeId, TI_FINDCHILDREN, &typeChildren[0]);

	size_t imageFileNameOffset = 0;
	size_t activeProcessLinksOffset = 0;

	for(size_t i = 0; i < typeChildren[0]; ++i)
	{
		wchar_t *symName;
		DWORD symOffset;
		SymGetTypeInfo(hSym, moduleBase, typeChildren[i+2], TI_GET_SYMNAME, &symName);
		SymGetTypeInfo(hSym, moduleBase, typeChildren[i+2], TI_GET_OFFSET, &symOffset);

		ret[WideToString(symName)] = symOffset;

		LocalFree(symName);
	}

	return ret;
}