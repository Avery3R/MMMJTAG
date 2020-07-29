#include "MiscHelpers.hpp"

#include <iostream>
#include <iomanip>

constexpr size_t DOT_WIDTH = 64;

bool CallIPCAndCheckErrors(std::function<OpenIPC::IPC_ErrorCode()> ipcFunc, const std::string &opText, bool onlyPrintOnError)
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

std::string WideToString(wchar_t *widestr)
{
	std::string ret;

	for(size_t i = 0; i < wcslen(widestr); ++i)
	{
		ret += char(widestr[i]&0xFF);
	}

	return ret;
}