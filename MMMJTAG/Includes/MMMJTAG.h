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

#define JTAG_DMA_DCI 0 // For systems where the Dma service actually works
#define JTAG_DMA_HALT_ALL_CORES 1 // Halts all CPUs then uses one at random to do DMA
#define JTAG_DMA_DEDICATED_CORE 2 // Halts the last core and uses one of its threads to do DMA. IMPORTANT: Currently hyperthreading is assumed to be enabled. So if it's not things will mess up.

	/// <summary>
	/// Initializes JTAG and attemps to connect to the target
	/// </summary>
	/// <param name="dmaMode">See JTAG_DMA_* constants</param>
	/// <returns>
	/// TRUE if successful, FALSE otherwise.
	/// </returns>
	JTAGIMP BOOL WINAPI JTAGConnect(BYTE _In_ dmaMode = JTAG_DMA_HALT_ALL_CORES);

	/// <summary>
	/// Attempts to halt execution on the target.
	/// </summary>
	/// <returns>
	/// TRUE if successful, FALSE otherwise.
	/// </returns>
	JTAGIMP BOOL WINAPI JTAGHaltExecution();

	/// <summary>
	/// Gets number of CPU Cores
	/// </summary>
	/// <returns>
	/// number of CPU Cores.
	/// </returns>
	JTAGIMP BYTE WINAPI JTAGGetNumCores();

	/// <summary>
	/// Gets run status of a core
	/// </summary>
	/// <returns>
	/// TRUE if that core is running, FALSE if it is not, or if there was an error.
	/// </returns>
	JTAGIMP BOOL WINAPI JTAGIsCoreRunning(BYTE _In_ coreNumber);

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
	JTAGIMP VOID WINAPI JTAGSetSymbolCachePath(LPCSTR _In_ symPath);

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
	JTAGIMP HKERNEL WINAPI JTAGOpenKernel(DWORD64 _In_ pageTableAddrOverride = 0);

	/// <summary>
	/// Reads physical memory into buffer
	/// </summary>
	/// <returns>
	/// TRUE if successful, FALSE otherwise.
	/// </returns>
	JTAGIMP BOOL WINAPI JTAGDMA(DWORD64 _In_ physicalAddress, PVOID _In_ buffer, DWORD64 _In_ bufferSize);

	/// <summary>
	/// Translates a virtual address into a physical one
	/// </summary>
	/// <returns>
	/// Physical address, 0 if the page isn't present or if there was an error
	/// </returns>
	JTAGIMP DWORD64 WINAPI JTAGTranslateAddress(DWORD64 _In_ pageTableAddress, DWORD64 _In_ virtualAddress);

#ifdef __cplusplus
}
#endif
#endif