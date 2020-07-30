#pragma once

#include <string>

#include <IpcApiAccess.hpp>

namespace MSR
{
	using addr_t = uint32_t;
	constexpr addr_t IA32_LSTAR_MSR = 0xC0000082;
};

uint64_t CPURegRead64(const OpenIPC::IPC_DeviceId dev, const std::string &regName);
bool CPUMemRead(const OpenIPC::IPC_DeviceId dev, const uint64_t addr, void* data, const size_t dataSize, bool dma = false);
uint64_t CPUMSRRead64(const OpenIPC::IPC_DeviceId dev, MSR::addr_t msr);
bool CPURunSingleCore(OpenIPC::IPC_DeviceId coreId);
bool CPUHaltSingleCore(OpenIPC::IPC_DeviceId coreId);