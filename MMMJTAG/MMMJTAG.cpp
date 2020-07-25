#include <MMMJTAG.h>

#include <iostream>
#include <iomanip>
#include <functional>

#include <IpcApiAccess.hpp>
#include <IPC_Event.hpp>
#include <IPC_General.hpp>

constexpr size_t DOT_WIDTH = 64;

bool CallIPCAndCheckErrors(std::function<OpenIPC::IPC_ErrorCode()> ipcFunc, const std::string &opText = "")
{
	std::cout << opText;
	size_t numDots = opText.length() > DOT_WIDTH-3 ? 3 : DOT_WIDTH-opText.length();
	for(size_t i = 0; i < numDots; ++i)
	{
		std::cout << '.';
	}

	std::cout << std::flush;
	OpenIPC::IPC_ErrorCode ipcresult = ipcFunc();
	if(ipcresult != OpenIPC::No_Error)
	{
		std::cout << std::hex << std::uppercase << std::setfill('0');
		std::cout << "Error: " << std::setw(8) << ipcresult << std::endl;
		return false;
	}
	else
	{
		std::cout << "Ok" << std::endl;
	}

	return true;
}

void MessageHandler(OpenIPC::IPC_MessageEventArgs *args, OpenIPC::IPC_UINT64 userData)
{
	std::cout << "[MessageEvent] " << args->eventType << " " << args->pMessage << std::endl;
}

JTAGIMP BOOL JTAGConnect()
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

	return TRUE;
}