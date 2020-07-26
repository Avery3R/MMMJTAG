#include <MMMJTAG.h>

#include <cstdlib> //For getenv()
#include <cstdint>

#include <iostream>
#include <iomanip>
#include <functional>
#include <vector>
#include <string>
#include <thread>
#include <unordered_map>

#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")

#include <IpcApiAccess.hpp>
#include <IPC_Event.hpp>
#include <IPC_General.hpp>
#include <IPC_Device.hpp>
#include <IPC_Register.hpp>
#include <IPC_OperationReceipt.hpp>
#include <IPC_RunControl.hpp>
#include <IPC_Memory.hpp>

template<typename T, size_t WIDTH = 0>
class _hexout
{
	public:
	_hexout(const T val) :
		m_val(val)
	{
	}

	friend std::ostream& operator<<(std::ostream& os, const _hexout& ho)
	{
		os << std::hex << std::uppercase << std::setfill('0');
		if(WIDTH == 0)
		{
			os << std::setw(sizeof(T)*2);
		}
		else
		{
			os << std::setw(WIDTH);
		}
		os << ho.m_val;
		os << std::dec << std::nouppercase;
		return os;
	}

	friend std::wostream& operator<<(std::wostream& os, const _hexout& ho)
	{
		os << std::hex << std::uppercase << std::setfill(L'0');
		if(WIDTH == 0)
		{
			os << std::setw(sizeof(T)*2);
		}
		else
		{
			os << std::setw(WIDTH);
		}
		os << ho.m_val;
		os << std::dec << std::nouppercase;
		return os;
	}

	private:
	const T m_val;
};

template<typename T>
_hexout<T,0> hexout(const T val)
{
	return _hexout<T,0>(val);
}

template<size_t WIDTH, typename T>
_hexout<T,WIDTH> hexout(const T val)
{
	return _hexout<T,WIDTH>(val);
}

constexpr size_t DOT_WIDTH = 64;

bool CallIPCAndCheckErrors(std::function<OpenIPC::IPC_ErrorCode()> ipcFunc, const std::string &opText = "", bool onlyPrintOnError = false)
{
	size_t numDots = opText.length() > DOT_WIDTH-3 ? 3 : DOT_WIDTH-opText.length();
	if(!onlyPrintOnError)
	{
		std::cout << opText;
		for(size_t i = 0; i < numDots; ++i)
		{
			std::cout << '.';
		}

		std::cout << std::flush;
	}

	OpenIPC::IPC_ErrorCode ipcresult = ipcFunc();
	if(ipcresult != OpenIPC::No_Error)
	{
		if(onlyPrintOnError)
		{
			std::cout << opText;
			for(size_t i = 0; i < numDots; ++i)
			{
				std::cout << '.';
			}
		}
		std::cout << std::hex << std::uppercase << std::setfill('0');
		std::cout << "Error: " << std::setw(8) << ipcresult << std::endl;
		return false;
	}
	else
	{
		if(!onlyPrintOnError)
		{
			std::cout << "Ok" << std::endl;
		}
	}

	return true;
}

void MessageHandler(OpenIPC::IPC_MessageEventArgs *args, OpenIPC::IPC_UINT64 userData)
{
	std::cout << "[MessageEvent] " << args->eventType << " " << args->pMessage << std::endl;
}

uint64_t CPURegRead64(const OpenIPC::IPC_DeviceId dev, const std::string &regName)
{
	OpenIPC::Service_Register *regsvc = nullptr;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_Register, (void**)&regsvc);
	if(!regsvc)
	{
		std::cout << "Could not get the register service" << std::endl;
		return 0;
	}
	OpenIPC::Service_OperationReceipt *opsvc = nullptr;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_OperationReceipt, (void**)&opsvc);
	if(!opsvc)
	{
		std::cout << "Could not get the operation receipt service" << std::endl;
		return 0;
	}

	OpenIPC::IPC_Handle operation;
	if(!CallIPCAndCheckErrors([regsvc, &operation, dev, regName]{return regsvc->ReadRegister(dev, regName.c_str(), &operation);}, "Reading register", true))
	{
		return 0;
	}

	uint64_t reg;
	if(!CallIPCAndCheckErrors([opsvc, &operation]{return opsvc->Flush(operation);}, "Flushing operation", true))
	{
		return 0;
	}
	if(!CallIPCAndCheckErrors([opsvc, &reg, operation]{return opsvc->GetValueAsUInt64(operation, &reg);}, "Getting data from operaton", true))
	{
		return 0;
	}
	if(!CallIPCAndCheckErrors([opsvc, operation]{return opsvc->Destroy(operation);}, "Freeing operation", true))
	{
		return 0;
	}

	return reg;
}

bool CPUMemRead(const OpenIPC::IPC_DeviceId dev, const uint64_t addr, void* data, const size_t dataSize)
{
	OpenIPC::IPC_Address ipcaddr = {0};
	ipcaddr.structureSize = sizeof(ipcaddr);
	ipcaddr.offset = addr;
	ipcaddr._addressType = OpenIPC::Linear;

	OpenIPC::Service_Memory *memsvc;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_Memory, (void**)&memsvc);
	if(!memsvc)
	{
		std::cout << "Could not get the memory service" << std::endl;
		return false;
	}

	OpenIPC::Service_OperationReceipt *opsvc = nullptr;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_OperationReceipt, (void**)&opsvc);
	if(!opsvc)
	{
		std::cout << "Could not get the operation receipt service" << std::endl;
		return false;
	}

	OpenIPC::IPC_Handle operation;
	if(!CallIPCAndCheckErrors([memsvc, dev, &ipcaddr, dataSize, &operation]{return memsvc->ReadMemory(dev, &ipcaddr, (OpenIPC::IPC_INT32)dataSize, &operation);}, "Reading memory", true))
	{
		return false;
	}
	if(!CallIPCAndCheckErrors([opsvc, &operation]{return opsvc->Flush(operation);}, "Flushing operation", true))
	{
		return false;
	}
	OpenIPC::IPC_UINT32 actualReadSize = (OpenIPC::IPC_UINT32)dataSize;
	if(!CallIPCAndCheckErrors([opsvc, dev, data, operation, &actualReadSize]{return opsvc->GetValueAsRawBytes(operation, (uint8_t*)data, actualReadSize, &actualReadSize);}, "Getting read memory data", true))
	{
		return false;
	}
	if(!CallIPCAndCheckErrors([opsvc, operation]{return opsvc->Destroy(operation);}, "Freeing operation", true))
	{
		return false;
	}

	return true;
}

namespace MSR
{
	using addr_t = uint32_t;

	constexpr addr_t IA32_LSTAR_MSR = 0xC0000082;
};

uint64_t CPUMSRRead64(const OpenIPC::IPC_DeviceId dev, MSR::addr_t msr)
{
	OpenIPC::Service_Register *regsvc = nullptr;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_Register, (void**)&regsvc);
	if(!regsvc)
	{
		std::cout << "Could not get the register service" << std::endl;
		return 0;
	}
	OpenIPC::Service_OperationReceipt *opsvc = nullptr;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_OperationReceipt, (void**)&opsvc);
	if(!regsvc)
	{
		std::cout << "Could not get the operation receipt service" << std::endl;
		return 0;
	}

	OpenIPC::IPC_Handle operation;
	if(!CallIPCAndCheckErrors([regsvc, &operation, dev, msr]{return regsvc->ReadMsr(dev, msr, &operation);}, "Reading MSR", true))
	{
		return 0;
	}

	uint64_t reg;
	if(!CallIPCAndCheckErrors([opsvc, &operation]{return opsvc->Flush(operation);}, "Flushing operation", true))
	{
		return 0;
	}
	if(!CallIPCAndCheckErrors([opsvc, &reg, operation]{return opsvc->GetValueAsUInt64(operation, &reg);}, "Getting data from operaton", true))
	{
		return 0;
	}
	if(!CallIPCAndCheckErrors([opsvc, operation]{return opsvc->Destroy(operation);}, "Freeing operation", true))
	{
		return 0;
	}

	return reg;
}

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

std::string WideToString(wchar_t *widestr)
{
	std::string ret;

	for(size_t i = 0; i < wcslen(widestr); ++i)
	{
		ret += char(widestr[i]&0xFF);
	}

	return ret;
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

/// <summary>
/// Initialized by JTAGConnect, is a list of all cpu cores effectively.
/// </summary>
std::vector<OpenIPC::IPC_DeviceId> gThreads;

JTAGIMP BOOL WINAPI JTAGConnect()
{
	if(!CallIPCAndCheckErrors([]{return OpenIPC::IPC_ConnectSingleton("IntelJtagCredBypass", OpenIPC::Out_of_Process);}, "Connecting to OpenIPC"))
	{
		return FALSE;
	}

	OpenIPC::Service_Event *eventsvc = nullptr;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_Event, (void**)&eventsvc);

	if(!eventsvc)
	{
		std::cout << "Could not get the event service" << std::endl;
		return FALSE;
	}

	if(!CallIPCAndCheckErrors([eventsvc]{return eventsvc->SubscribeMessageEvents(&MessageHandler, 0);}, "Registering IPC message handler"))
	{
		return FALSE;
	}

	if(!CallIPCAndCheckErrors([]{return OpenIPC::IPC_FinishInitialization();}, "Finishing OpenIPC Initialization"))
	{
		return FALSE;
	}

	OpenIPC::Service_General *gensvc = nullptr;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_General, (void**)&gensvc);

	if(!gensvc)
	{
		std::cout << "Could not get the general service" << std::endl;
		return FALSE;
	}

	OpenIPC::IPC_Version ver;
	ver.structureSize = sizeof(ver);
	char ident[OpenIPC::IPC_IMPLEMENTATION_IDENTIFIER_MAX_LENGTH];

	if(!CallIPCAndCheckErrors([gensvc, &ver]{return gensvc->GetImplementationVersion(&ver);}, "Getting IPC implementation version"))
	{
		return FALSE;
	}

	if(!CallIPCAndCheckErrors([gensvc, &ident]{return gensvc->GetImplementationIdentifier(ident);}, "Getting IPC implementation ident"))
	{
		return FALSE;
	}

	std::cout << "OpenIPC ver: " << ver.major << '.' << ver.minor << '.' << ver.build << '.' << ver.classification << " ident: " << ident << std::endl;

	OpenIPC::Service_Device *devsvc = nullptr;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_Device, (void**)&devsvc);

	if(!gensvc)
	{
		std::cout << "Could not get the device service" << std::endl;
		return FALSE;
	}

	OpenIPC::IPC_DeviceId targetDomain;

	if(!CallIPCAndCheckErrors([devsvc, &targetDomain]{return devsvc->GetTargetDomainDeviceIds(1, &targetDomain);}, "Getting the target domain device ID"))
	{
		return FALSE;
	}

	OpenIPC::IPC_UINT32 numThreads = 0;
	if(!CallIPCAndCheckErrors([devsvc, targetDomain, &numThreads]{return devsvc->GetNumDescendantIdsForType(targetDomain, OpenIPC::LogicalThread, 1, &numThreads);}, "Getting # of cores"))
	{
		return FALSE;
	}


	gThreads.resize(numThreads);
	OpenIPC::IPC_DeviceId *pThreadsData = &gThreads[0];
	if(!CallIPCAndCheckErrors([devsvc, targetDomain, numThreads, pThreadsData]{return devsvc->GetDescendantIdsForType(targetDomain, OpenIPC::LogicalThread, 1, numThreads, pThreadsData);}, "Getting core device IDs"))
	{
		return FALSE;
	}

	for(const auto &threadId : gThreads)
	{
		std::cout << "Core ID: " << hexout(threadId) << std::endl;
	}

	return TRUE;
}

JTAGIMP BOOL WINAPI JTAGHaltExecution()
{
	OpenIPC::Service_RunControl *runsvc;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_RunControl, (void**)&runsvc);

	if(!runsvc)
	{
		std::cout << "Could not get the run control service" << std::endl;
		return FALSE;
	}

	OpenIPC::Service_OperationReceipt *opsvc = nullptr;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_OperationReceipt, (void**)&opsvc);
	if(!opsvc)
	{
		std::cout << "Could not get the operation receipt service" << std::endl;
		return 0;
	}

	OpenIPC::IPC_Handle operation;

	if(!CallIPCAndCheckErrors([runsvc, &operation]{return runsvc->HaltAll(&operation);}, "Halting execution on target target"))
	{
		return FALSE;
	}

	if(!CallIPCAndCheckErrors([opsvc, &operation]{return opsvc->Flush(operation);}, "Flushing operation", true))
	{
		return FALSE;
	}
	if(!CallIPCAndCheckErrors([opsvc, operation]{return opsvc->Destroy(operation);}, "Freeing operation", true))
	{
		return FALSE;
	}

	return TRUE;
}

JTAGIMP BOOL WINAPI JTAGRun()
{
	OpenIPC::Service_RunControl *runsvc;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_RunControl, (void**)&runsvc);

	if(!runsvc)
	{
		std::cout << "Could not get the run control service" << std::endl;
		return FALSE;
	}

	OpenIPC::Service_OperationReceipt *opsvc = nullptr;
	OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_OperationReceipt, (void**)&opsvc);
	if(!opsvc)
	{
		std::cout << "Could not get the operation receipt service" << std::endl;
		return 0;
	}

	OpenIPC::IPC_Handle operation;

	if(!CallIPCAndCheckErrors([runsvc, &operation]{return runsvc->GoAll(&operation);}, "Resuming execution on target target"))
	{
		return FALSE;
	}

	if(!CallIPCAndCheckErrors([opsvc, &operation]{return opsvc->Flush(operation);}, "Flushing operation", true))
	{
		return FALSE;
	}
	if(!CallIPCAndCheckErrors([opsvc, operation]{return opsvc->Destroy(operation);}, "Freeing operation", true))
	{
		return FALSE;
	}

	return TRUE;
}

std::string gSymbolPath = std::string(getenv("TEMP"))+"\\JTAGSymbols";

JTAGIMP VOID WINAPI JTAGSetSymbolCachePath(LPCSTR symPath)
{
	gSymbolPath = symPath;
}

JTAGIMP HKERNEL WINAPI JTAGOpenKernel()
{
	if(!JTAGHaltExecution())
	{
		return INVALID_HANDLE_VALUE;
	}

	uint64_t kernelAddr = 0;
	for(const auto &threadId : gThreads)
	{
		uint64_t lstar;
		lstar = CPUMSRRead64(threadId, MSR::IA32_LSTAR_MSR);

		std::cout << "thread: " << hexout(threadId) << " IA32_LSTAR_MSR: " << hexout(lstar) << std::endl;

		uint64_t kernelSyscallAddr = 0;

		if(lstar != 0)
		{
			kernelSyscallAddr = lstar;
		}
		else
		{
			continue;
		}

		const uint64_t CS = CPURegRead64(threadId, "cs");

		std::cout << "thread: " << hexout(threadId) << " CS: " << hexout(CS) << std::endl;

		if((CS&3) == 0) //CPL = Ring-0
		{
			constexpr size_t PAGE_SIZE = 0x1000ll;
			constexpr size_t PAGE_MASK = ~(PAGE_SIZE-1);

			const size_t searchBase = kernelSyscallAddr&PAGE_MASK;
			constexpr size_t MEMBUF_SIZE = 2;
			std::vector<uint8_t> membuf(MEMBUF_SIZE);
			//FIXME: Reset this to PAGE_SIZE*1
			for(size_t lookback = PAGE_SIZE*0x1C0; lookback < 32*1024*1024; lookback += PAGE_SIZE)
			{
				std::cout << "Searching for kernel base " << hexout<16>(lookback/PAGE_SIZE) << '/' << hexout<16>(32*1024*1024/PAGE_SIZE) << std::endl;

				if(!CPUMemRead(threadId, searchBase-lookback, &membuf[0], membuf.size()))
				{
					//Something is messed up with this thread
					std::cout << "Memory read error... Continuing onto the next thread" << std::endl;
					break;
				}

				for(size_t offset = 0; offset < MEMBUF_SIZE; offset += PAGE_SIZE)
				{
					if(membuf[offset] == 'M' && membuf[offset+1] == 'Z')
					{
						kernelAddr = searchBase-lookback+offset;
						break;
					}
				}

				if(kernelAddr != 0)
				{
					break;
				}
			}

			HKERNEL hKernel = (HKERNEL)kernelAddr;

			if(kernelAddr != 0)
			{
				std::cout << "Found kernel at " << hexout(kernelAddr) << std::endl;
				std::cout << "Walking through kernel DOS/PE header to find debug directories" << std::endl;

				auto debugData = GetDebugData(threadId, kernelAddr);

				BOOL winresult = SymInitialize(hKernel, (std::string("srv*")+gSymbolPath+"*https://msdl.microsoft.com/download/symbols").c_str(), FALSE);
				//DWORD winresult32 = SymSetOptions(
				DWORD symOptions = SymGetOptions();
				symOptions &= ~SYMOPT_DEFERRED_LOADS;
				//symOptions |= SYMOPT_DEBUG;
				symOptions = SymSetOptions(symOptions);
				winresult = SymRegisterCallback64(hKernel, &SymbolCallback, 0);
				DWORD gla = GetLastError();
				MODLOAD_DATA modData;
				modData.ssize = sizeof(modData);
				modData.ssig = DBHHEADER_DEBUGDIRS;
				modData.data = &debugData[0];
				modData.size = (DWORD)debugData.size();
				modData.flags = 0;

				std::cout << "Loading kernel symbols" << std::endl;
				DWORD64 winresult64 = SymLoadModuleEx(hKernel, nullptr, "nt", "nt", kernelAddr, 0, &modData, 0);
				gla = GetLastError();

				std::cout << "Symbols loaded winresult64: " << hexout(winresult64) << " GLE(): " << gla << std::endl;

				std::cout << "PsActiveProcessHead at: " << hexout(GetAddrOfSymbol(hKernel, "nt!PsActiveProcessHead")) << std::endl;

				JTAGRun();
				return hKernel;
			}
		}
	}

	return INVALID_HANDLE_VALUE;
}