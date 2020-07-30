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
#include <thread>
#include <chrono>
#include <mutex>
#include <utility>

using namespace std::chrono_literals;

#include <DbgHelp.h>

#include <IpcApiAccess.hpp>
#include <IPC_Event.hpp>
#include <IPC_General.hpp>
#include <IPC_Device.hpp>
#include <IPC_Register.hpp>
#include <IPC_OperationReceipt.hpp>
#include <IPC_RunControl.hpp>
#include <IPC_Memory.hpp>
#include <IPC_Breakpoint.hpp>

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

/// <summary>
/// CPU Cores for JTAG_DMA_DEDICATED_CORE mode
/// </summary>
std::vector<OpenIPC::IPC_DeviceId> dmaThreads;

std::mutex gDMAThreadsMutex;

BYTE gDMAMode = JTAG_DMA_HALT_ALL_CORES;

//Things get unstable if the DMA cores are halted for too long, so we run them every 2.5s
void DMACoreRefreshThread()
{
	while(true)
	{
		gDMAThreadsMutex.lock();
		for(const auto &dmaCoreId : dmaThreads)
		{
			CPURunSingleCore(dmaCoreId);
		}
		std::this_thread::sleep_for(250ms);
		gDMAThreadsMutex.unlock();
		std::this_thread::sleep_for(2250ms);
	}
}

JTAGIMP BOOL WINAPI JTAGConnect(BYTE _In_ dmaMode)
{
	gDMAMode = dmaMode;

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

	if(gDMAMode == JTAG_DMA_DEDICATED_CORE)
	{
		//TODO: HACK: Make this configurable, currently assumes hyperthreading
		dmaThreads.push_back(gThreads[gThreads.size()-2]);
		dmaThreads.push_back(gThreads[gThreads.size()-1]);
		gThreads.resize(gThreads.size()-2);

		OpenIPC::Service_Breakpoint *bpsvc;
		OpenIPC::IPC_GetService(OpenIPC::IPC_ServiceId_Breakpoint, (void**)&bpsvc);

		if(!bpsvc)
		{
			std::cout << "Could not get the breakpoint service" << std::endl;
			return FALSE;
		}

		if(!CallIPCAndCheckErrors([bpsvc, targetDomain]{return bpsvc->SetBreakAllSetting(targetDomain, OpenIPC::IPC_BreakAll_Disabled);}, "Setting BreakAll setting"))
		{
			return FALSE;
		}

		std::thread *dmaCoreRefresh = new std::thread(&DMACoreRefreshThread); //It's ok that we don't keep track of this thread, because there's no JTAGDisconnect() XD
	}

	for(const auto &threadId : gThreads)
	{
		std::cout << "Core ID: " << hexout(threadId) << std::endl;
	}

	for(const auto &threadId : dmaThreads)
	{
		std::cout << "DMA Core ID: " << hexout(threadId) << std::endl;
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

JTAGIMP BYTE WINAPI JTAGGetNumCores()
{
	return (BYTE)gThreads.size();
}


JTAGIMP BOOL WINAPI JTAGIsCoreRunning(BYTE _In_ coreNumber)
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

	OpenIPC::IPC_DeviceId coreId = gThreads[coreNumber];
	OpenIPC::IPC_RunStates runStatus;

	if(!CallIPCAndCheckErrors([runsvc, coreId, &runStatus]{return runsvc->GetRunStatus(coreId, &runStatus);}, "Getting execution status of core", true))
	{
		return FALSE;
	}

	return runStatus == OpenIPC::Running;
}

std::string gSymbolPath = std::string(getenv("TEMP"))+"\\JTAGSymbols";

JTAGIMP VOID WINAPI JTAGSetSymbolCachePath(LPCSTR _In_ symPath)
{
	gSymbolPath = symPath;
}

JTAGIMP HKERNEL WINAPI JTAGOpenKernel(DWORD64 _In_ pageTableAddrOverride)
{
	// pair<lstar, cr3>
	std::vector<std::pair<uint64_t, uint64_t>> kernelSearchParams;

	if(!JTAGHaltExecution())
	{
		return INVALID_HANDLE_VALUE;
	}

	for(const auto &threadId : gThreads)
	{
		uint64_t lstar;
		lstar = CPUMSRRead64(threadId, MSR::IA32_LSTAR_MSR);

		std::cout << "thread: " << hexout(threadId) << " IA32_LSTAR_MSR: " << hexout(lstar) << std::endl;

		const uint64_t CS = CPURegRead64(threadId, "cs");

		std::cout << "thread: " << hexout(threadId) << " CS: " << hexout(CS) << std::endl;

		if((CS&3) == 0) //CPL = Ring-0
		{
			uint64_t cr3 = CPURegRead64(threadId, "cr3");

			std::cout << "thread: " << hexout(threadId) << " CR3: " << hexout(cr3) << std::endl;

			if(pageTableAddrOverride != 0)
			{
				cr3 = pageTableAddrOverride;
			}

			kernelSearchParams.push_back(std::make_pair(lstar, cr3));
		}
	}

	std::this_thread::sleep_for(std::chrono::seconds(1)); //Stability, rapid starts and stops are bad for windows/hyper-v

	if(!JTAGRun())
	{
		return INVALID_HANDLE_VALUE;
	}

	for(const auto &searchPair : kernelSearchParams)
	{
		uint64_t lstarPhysicalAddress = JTAGTranslateAddress(searchPair.second, searchPair.first);
		if(lstarPhysicalAddress)
		{
			std::cout << "found an LSTAR at: " << hexout(lstarPhysicalAddress) << std::endl;

			constexpr size_t PAGE_SIZE = 0x1000ll;
			constexpr size_t PAGE_MASK = ~(PAGE_SIZE-1);

			const size_t searchBase = searchPair.first&PAGE_MASK;
			constexpr size_t MEMBUF_SIZE = 2;
			std::vector<uint8_t> membuf(MEMBUF_SIZE);
			//FIXME: Reset this to PAGE_SIZE*1

			uint64_t kernelAddr = 0;

			for(size_t lookback = PAGE_SIZE*0x1C0; lookback < 32*1024*1024; lookback += PAGE_SIZE)
			{
				std::cout << "Searching for kernel base " << hexout<16>(lookback/PAGE_SIZE) << '/' << hexout<16>(32*1024*1024/PAGE_SIZE) << std::endl;

				uint64_t searchPhysicalAddr = JTAGTranslateAddress(searchPair.second,  searchBase-lookback);
				if(!searchPhysicalAddr)
				{
					std::cout << "Page not mapped... continuing onto the next search pair." << std::endl;
					break;
				}

				if(!JTAGDMA(searchPhysicalAddr, &membuf[0], MEMBUF_SIZE))
				{
					//Something is messed up with this thread
					std::cout << "Memory read error... Continuing onto the next search pair" << std::endl;
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

				auto debugData = GetDebugData(searchPair.second, kernelAddr);

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

				return hKernel;
			}
		}
	}

	return INVALID_HANDLE_VALUE;
}

JTAGIMP BOOL WINAPI JTAGDMA(DWORD64 _In_ physicalAddress, PVOID _In_ buffer, DWORD64 _In_ bufferSize)
{
	BOOL result = FALSE;

	switch(gDMAMode)
	{
		case JTAG_DMA_DCI:
		{
			std::cout << "JTAG_DMA_DCI not yet implemented" << std::endl;
			return FALSE;
		};
		break;
		case JTAG_DMA_HALT_ALL_CORES:
		{
			bool wasAnyCoreRunning = JTAGIsCoreRunning(gThreads[0]);
			JTAGHaltExecution();

			result = CPUMemRead(gThreads[0], physicalAddress, buffer, bufferSize, true) ? TRUE : FALSE;

			if(wasAnyCoreRunning)
			{
				JTAGRun();
				//For stability we need to sleep here
				Sleep(100);
			}
		};
		break;
		case JTAG_DMA_DEDICATED_CORE:
		{
			gDMAThreadsMutex.lock();
			for(const auto &dmaCore : dmaThreads)
			{
				if(!CPUHaltSingleCore(dmaCore))
				{
					gDMAThreadsMutex.unlock();
					return FALSE;
				}
			}

			result = CPUMemRead(dmaThreads[0], physicalAddress, buffer, bufferSize, true) ? TRUE : FALSE;
			gDMAThreadsMutex.unlock();
		}
		break;
	}

	return result;
}

JTAGIMP DWORD64 WINAPI JTAGTranslateAddress(DWORD64 _In_ pageTableAddress, DWORD64 _In_ virtualAddress)
{
	virtualAddress &= (1LL<<48)-1;
	uint64_t pml4Index = virtualAddress >> 39;

	uint64_t pml4Entry = 0;

	if(!JTAGDMA(pageTableAddress+(pml4Index*8), &pml4Entry, 8))
	{
		return 0;
	}

	if(!(pml4Entry&1))
	{
		return 0; // Page not present
	}

	virtualAddress &= (1LL<<39)-1;

	uint64_t pdpteAddress = pml4Entry&(~(0xFFF));

	uint64_t pdpteIndex = virtualAddress>>30;

	uint64_t pdpteEntry = 0;

	if(!JTAGDMA(pdpteAddress+(uint64_t(pdpteIndex)*8), &pdpteEntry, 8))
	{
		return 0;
	}

	if(!(pdpteEntry&1))
	{
		return 0; // Page not present
	}

	virtualAddress &= (1LL<<30)-1;

	uint64_t pdeAddress = pdpteEntry&(~(0xFFF));

	uint64_t pdeIndex = virtualAddress>>21;

	uint64_t pdeEntry = 0;

	if(!JTAGDMA(pdeAddress+(uint64_t(pdeIndex)*8), &pdeEntry, 8))
	{
		return 0;
	}

	if(!(pdeEntry&1))
	{
		return 0; // Page not present
	}

	virtualAddress &= (1LL<<21)-1;

	uint64_t ptAddress = pdeEntry&(~(0xFFF));

	uint64_t ptIndex = virtualAddress>>12;

	uint64_t ptEntry = 0;

	if(!JTAGDMA(ptAddress+(uint64_t(ptIndex)*8), &ptEntry, 8))
	{
		return 0;
	}

	if(!(pdeEntry&1))
	{
		return 0; // Page not present or not 4kb paging mode
	}

	ptEntry &= (1ll<<52)-1;

	uint64_t retVal = (ptEntry&(~(0xFFF)))|(virtualAddress&0xFFF);

	return retVal;
}