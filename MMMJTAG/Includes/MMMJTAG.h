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

	/// <summary>
	/// Attempts to halt execution on the target.
	/// </summary>
	/// <returns>
	/// TRUE if successful, FALSE otherwise.
	/// </returns>
	JTAGIMP BOOL WINAPI JTAGHaltExecution();

	/// <summary>
	/// Attempts to resume exeuction on the target.
	/// </summary>
	/// <returns>
	/// TRUE if successful, FALSE otherwise.
	/// </returns>
	JTAGIMP BOOL WINAPI JTAGRun();

	/// <summary>
	/// Sets the path where downloaded symbols will be cached.
	/// </summary>
	JTAGIMP VOID WINAPI JTAGSetSymbolCachePath(LPCSTR symPath);

	typedef HANDLE HKERNEL;

	/// <summary>
	/// Attempts to get the base address of the NT kernel by pausing execution and reading the value of the IA32_LSTAR MSR.
	/// It then repeatedly pauses and unpauses the machine until execution is stopped in kernel space, then it loads debug symbols
	/// </summary>
	/// <remarks>
	/// Debug symbols are downloaded from https://msdl.microsoft.com/download/symbols, and placed in the location specified by
	/// JTAGSetSymbolCachePath(), or in %TEMP%/JTAGSymbols if it is never set explicity.
	///
	/// The HANDLE retuned by this function is the same one that is passed to Sym*() functions, so if you'd like to use them yourself,
	/// you can.
	///
	/// It's possible that if this function returns INVALID_HANDLE_VALUE, the target will be left in a halted state.
	/// So if you need to ensure the target will continue to run in the case of an error, call JTAGRun().
	/// </remarks>
	/// <returns>
	/// INVALID_HANDLE_VALUE if unsucessful, otherwise a HANDLE value that can be used in functions requiring a HKERNEL parameter.
	/// </returns>
	JTAGIMP HKERNEL WINAPI JTAGOpenKernel();

#ifdef __cplusplus
}
#endif
#endif