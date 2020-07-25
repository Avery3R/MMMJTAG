#ifndef MMMJTAG_INC
#define MMMJTAG_INC

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#ifdef BUILDING_MMMJTAG
#define JTAGIMP __declspec(dllexport)
#else
#define JTAGIMP __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C"
{
#endif

	/// <summary>
	/// Initializes JTAG and attemps to connect to the target
	/// </summary>
	/// <returns>
	/// TRUE if successful, FALSE otherwise.
	/// </returns>
	JTAGIMP BOOL WINAPI JTAGConnect();

#ifdef __cplusplus
}
#endif
#endif