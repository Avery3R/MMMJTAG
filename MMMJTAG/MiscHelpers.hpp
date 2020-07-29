#pragma once

#include <functional>
#include <string>

#include <IpcApiAccess.hpp>

bool CallIPCAndCheckErrors(std::function<OpenIPC::IPC_ErrorCode()> ipcFunc, const std::string &opText = "", bool onlyPrintOnError = false);

std::string WideToString(wchar_t *widestr);