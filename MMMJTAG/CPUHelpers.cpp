#include "CPUHelpers.hpp"

#include <iostream>

#include <IPC_Register.hpp>
#include <IPC_OperationReceipt.hpp>
#include <IPC_Memory.hpp>

#include "HexOut.hpp"
#include "MiscHelpers.hpp"

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

bool CPUMemRead(const OpenIPC::IPC_DeviceId dev, const uint64_t addr, void* data, const size_t dataSize, bool dma)
{
	OpenIPC::IPC_Address ipcaddr = {0};
	ipcaddr.structureSize = sizeof(ipcaddr);
	ipcaddr.offset = addr;
	ipcaddr._addressType = dma ? OpenIPC::Physical : OpenIPC::Linear;

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