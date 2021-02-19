#include <Windows.h>

/// <summary>
/// Position independent shellcode that loads the DLL after it was written to the remote process memory.
/// <para>This is the main entry point for reflective DLL injection.</para>
/// </summary>
/// <param name="dllBase">A pointer to the beginning of the DLL file.</param>
/// <returns>
/// If this function succeeds, the return value of DllMain;
/// otherwise, FALSE.
/// </returns>
__declspec(dllexport) BOOL WINAPI ReflectiveDllMain(LPBYTE dllBase);