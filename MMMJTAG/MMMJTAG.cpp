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

#include <IpcApiAccess.hpp>
#include <IPC_Event.hpp>
#include <IPC_General.hpp>
#include <IPC_Device.hpp>
#include <IPC_Register.hpp>
#include <IPC_OperationReceipt.hpp>
#include <IPC_RunControl.hpp>
#include <IPC_Memory.hpp>

#include "HexOut.hpp"
#include "CPUHelpers.hpp"
#include "MiscHelpers.hpp"
#include "SymHelpers.hpp"

void MessageHandler(OpenIPC::IPC_MessageEventArgs *args, OpenIPC::IPC_UINT64 userData)
{
	std::cout << "[MessageEvent] " << args->eventType << " " << args->pMessage << std::endl;
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

JTAGIMP VOID WINAPI JTAGSetSymbolCachePath(LPCSTR _In_ symPath)
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