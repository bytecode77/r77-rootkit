#include "ReflectiveDll.h"

#define NTDLLDLL_HASH					0x3cfa685d
#define KERNEL32DLL_HASH				0x6a4abc5b
#define NTFLUSHINSTRUCTIONCACHE_HASH	0x534c0ab8
#define LOADLIBRARYA_HASH				0xec0e4e8e
#define GETPROCADDRESS_HASH				0x7c0dfcaa
#define VIRTUALALLOC_HASH				0x91afca54

#define COMPUTEHASH(value) ((DWORD)(value) >> 13 | (DWORD)(value) << (32 - 13))

namespace nt
{
	typedef struct _UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		SHORT LoadCount;
		SHORT TlsIndex;
		LIST_ENTRY HashTableEntry;
		ULONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

	typedef struct _PEB_LDR_DATA
	{
		DWORD Length;
		DWORD Initialized;
		LPVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		LPVOID EntryInProgress;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _PEB
	{
		BYTE InheritedAddressSpace;
		BYTE ReadImageFileExecOptions;
		BYTE BeingDebugged;
		BYTE SpareBool;
		LPVOID Mutant;
		LPVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		LPVOID ProcessParameters;
		LPVOID SubSystemData;
		LPVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
		LPVOID FastPebLockRoutine;
		LPVOID FastPebUnlockRoutine;
		DWORD EnvironmentUpdateCount;
		LPVOID KernelCallbackTable;
		DWORD SystemReserved;
		DWORD AtlThunkSListPtr32;
		PVOID FreeList;
		DWORD TlsExpansionCounter;
		LPVOID TlsBitmap;
		DWORD TlsBitmapBits[2];
		LPVOID ReadOnlySharedMemoryBase;
		LPVOID ReadOnlySharedMemoryHeap;
		LPVOID ReadOnlyStaticServerData;
		LPVOID AnsiCodePageData;
		LPVOID OemCodePageData;
		LPVOID UnicodeCaseTableData;
		DWORD NumberOfProcessors;
		DWORD NtGlobalFlag;
		LARGE_INTEGER CriticalSectionTimeout;
		DWORD HeapSegmentReserve;
		DWORD HeapSegmentCommit;
		DWORD HeapDeCommitTotalFreeThreshold;
		DWORD HeapDeCommitFreeBlockThreshold;
		DWORD NumberOfHeaps;
		DWORD MaximumNumberOfHeaps;
		LPVOID ProcessHeaps;
		LPVOID GdiSharedHandleTable;
		LPVOID ProcessStarterHelper;
		DWORD GdiDCAttributeList;
		LPVOID LoaderLock;
		DWORD OSMajorVersion;
		DWORD OSMinorVersion;
		WORD OSBuildNumber;
		WORD OSCSDVersion;
		DWORD OSPlatformId;
		DWORD ImageSubsystem;
		DWORD ImageSubsystemMajorVersion;
		DWORD ImageSubsystemMinorVersion;
		DWORD ImageProcessAffinityMask;
		DWORD GdiHandleBuffer[34];
		LPVOID PostProcessInitRoutine;
		LPVOID TlsExpansionBitmap;
		DWORD TlsExpansionBitmapBits[32];
		DWORD SessionId;
		ULARGE_INTEGER AppCompatFlags;
		ULARGE_INTEGER AppCompatFlagsUser;
		LPVOID ShimData;
		LPVOID AppCompatInfo;
		UNICODE_STRING CSDVersion;
		LPVOID ActivationContextData;
		LPVOID ProcessAssemblyStorageMap;
		LPVOID SystemDefaultActivationContextData;
		LPVOID SystemAssemblyStorageMap;
		DWORD MinimumStackCommit;
	} PEB, *PPEB;

	typedef struct _IMAGE_RELOC
	{
		WORD Offset : 12;
		WORD Type : 4;
	} IMAGE_RELOC, *PIMAGE_RELOC;

	typedef BOOL(WINAPI *DLLMAIN)(HINSTANCE module, DWORD reason, LPVOID reserved);
	typedef DWORD(NTAPI *NTFLUSHINSTRUCTIONCACHE)(HANDLE process, LPVOID baseAddress, ULONG size);
	typedef HMODULE(WINAPI *LOADLIBRARYA)(LPCSTR fileName);
	typedef FARPROC(WINAPI *GETPROCADDRESS)(HMODULE module, LPCSTR function);
	typedef LPVOID(WINAPI *VIRTUALALLOC)(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect);
}

namespace api
{
	// Even standard functions cannot be used before DLL's are loaded and the IAT is patched.
	VOID memcpy(LPBYTE dest, LPBYTE src, DWORD size)
	{
		for (DWORD i = 0; i < size; i++)
		{
			*dest++ = *src++;
		}
	}

	// Because string comparisons require a data section, the string is compared by calculating a hash.
	DWORD strhash(LPCSTR str)
	{
		DWORD hash = 0;

		while (*str)
		{
			hash = COMPUTEHASH(hash) + *str++;
		}

		return hash;
	}

	DWORD strhashi(LPCSTR str, USHORT length)
	{
		DWORD hash = 0;

		for (USHORT i = 0; i < length; i++)
		{
			hash = COMPUTEHASH(hash) + (str[i] >= 'a' ? str[i] - 0x20 : str[i]);
		}

		return hash;
	}
}

__declspec(dllexport) BOOL WINAPI ReflectiveDllMain(LPBYTE dllBase)
{
#ifdef _WIN64
	nt::PPEB_LDR_DATA peb = (nt::PPEB_LDR_DATA)((nt::PPEB)__readgsqword(0x60))->Ldr;
#else
	nt::PPEB_LDR_DATA peb = (nt::PPEB_LDR_DATA)((nt::PPEB)__readfsdword(0x30))->Ldr;
#endif

	// All functions that are used here must be found by searching the PEB.
	// Functions, such as memcpy need to be handwritten, because no functions are imported, yet.
	// Switch statements cannot be used, because a jump table would be created and the shellcode would not be position independent anymore.

	nt::NTFLUSHINSTRUCTIONCACHE ntFlushInstructionCache = NULL;
	nt::LOADLIBRARYA loadLibraryA = NULL;
	nt::GETPROCADDRESS getProcAddress = NULL;
	nt::VIRTUALALLOC virtualAlloc = NULL;

	nt::PLDR_DATA_TABLE_ENTRY firstPebEntry = (nt::PLDR_DATA_TABLE_ENTRY)peb->InMemoryOrderModuleList.Flink;
	nt::PLDR_DATA_TABLE_ENTRY pebEntry = firstPebEntry;
	do
	{
		DWORD moduleHash = api::strhashi((LPCSTR)pebEntry->BaseDllName.Buffer, pebEntry->BaseDllName.Length);

		// Search functions in ntdll.dll and kernel32.dll
		if (moduleHash == NTDLLDLL_HASH || moduleHash == KERNEL32DLL_HASH)
		{
			LPBYTE pebModuleBase = (LPBYTE)pebEntry->DllBase;
			PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pebModuleBase + ((PIMAGE_DOS_HEADER)pebModuleBase)->e_lfanew);
			PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pebModuleBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			LPDWORD nameDirectory = (LPDWORD)(pebModuleBase + exportDirectory->AddressOfNames);
			LPWORD nameOrdinalDirectory = (LPWORD)(pebModuleBase + exportDirectory->AddressOfNameOrdinals);

			for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++, nameDirectory++, nameOrdinalDirectory++)
			{
				DWORD functionHash = api::strhash((LPCSTR)(pebModuleBase + *nameDirectory));
				LPBYTE functionAddress = pebModuleBase + exportDirectory->AddressOfFunctions + *nameOrdinalDirectory * sizeof(DWORD);

				if (functionHash == NTFLUSHINSTRUCTIONCACHE_HASH) ntFlushInstructionCache = (nt::NTFLUSHINSTRUCTIONCACHE)(pebModuleBase + *(LPDWORD)functionAddress);
				else if (functionHash == LOADLIBRARYA_HASH) loadLibraryA = (nt::LOADLIBRARYA)(pebModuleBase + *(LPDWORD)functionAddress);
				else if (functionHash == GETPROCADDRESS_HASH) getProcAddress = (nt::GETPROCADDRESS)(pebModuleBase + *(LPDWORD)functionAddress);
				else if (functionHash == VIRTUALALLOC_HASH) virtualAlloc = (nt::VIRTUALALLOC)(pebModuleBase + *(LPDWORD)functionAddress);

				if (loadLibraryA && getProcAddress && virtualAlloc && ntFlushInstructionCache) break;
			}
		}

		if (loadLibraryA && getProcAddress && virtualAlloc && ntFlushInstructionCache) break;
	}
	while ((pebEntry = (nt::PLDR_DATA_TABLE_ENTRY)pebEntry->InMemoryOrderModuleList.Flink) != firstPebEntry);

	// Safety check: Continue only, if all functions were found.
	if (loadLibraryA && getProcAddress && virtualAlloc && ntFlushInstructionCache)
	{
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllBase + ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew);

		// Allocate memory for the DLL.
		LPBYTE allocatedMemory = (LPBYTE)virtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (allocatedMemory)
		{
			// Copy optional header to new memory.
			api::memcpy(allocatedMemory, dllBase, ntHeaders->OptionalHeader.SizeOfHeaders);

			// Copy sections to new memory.
			PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((LPBYTE)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
			for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
			{
				api::memcpy(allocatedMemory + sections[i].VirtualAddress, dllBase + sections[i].PointerToRawData, sections[i].SizeOfRawData);
			}

			// Read the import directory, call LoadLibraryA to import dependencies and patch the IAT.
			PIMAGE_DATA_DIRECTORY importDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			if (importDirectory->Size)
			{
				for (PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(allocatedMemory + importDirectory->VirtualAddress); importDescriptor->Name; importDescriptor++)
				{
					LPBYTE module = (LPBYTE)loadLibraryA((LPCSTR)(allocatedMemory + importDescriptor->Name));
					if (module)
					{
						PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(allocatedMemory + importDescriptor->OriginalFirstThunk);
						PUINT_PTR importAddressTable = (PUINT_PTR)(allocatedMemory + importDescriptor->FirstThunk);

						while (*importAddressTable)
						{
							if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
							{
								PIMAGE_NT_HEADERS moduleNtHeaders = (PIMAGE_NT_HEADERS)(module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
								PIMAGE_EXPORT_DIRECTORY moduleExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(module + moduleNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
								*importAddressTable = (UINT_PTR)(module + *(LPDWORD)(module + moduleExportDirectory->AddressOfFunctions + (IMAGE_ORDINAL(thunk->u1.Ordinal) - moduleExportDirectory->Base) * sizeof(DWORD)));
							}
							else
							{
								importDirectory = (PIMAGE_DATA_DIRECTORY)(allocatedMemory + *importAddressTable);
								*importAddressTable = (UINT_PTR)getProcAddress((HMODULE)module, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)importDirectory)->Name);
							}

							thunk = (PIMAGE_THUNK_DATA)((LPBYTE)thunk + sizeof(UINT_PTR));
							importAddressTable = (PUINT_PTR)((LPBYTE)importAddressTable + sizeof(UINT_PTR));
						}
					}
				}
			}

			// Patch relocations.
			PIMAGE_DATA_DIRECTORY relocationDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			if (relocationDirectory->Size)
			{
				UINT_PTR imageBase = (UINT_PTR)(allocatedMemory - ntHeaders->OptionalHeader.ImageBase);

				for (PIMAGE_BASE_RELOCATION baseRelocation = (PIMAGE_BASE_RELOCATION)(allocatedMemory + relocationDirectory->VirtualAddress); baseRelocation->SizeOfBlock; baseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)baseRelocation + baseRelocation->SizeOfBlock))
				{
					LPBYTE relocationAddress = allocatedMemory + baseRelocation->VirtualAddress;
					nt::PIMAGE_RELOC relocations = (nt::PIMAGE_RELOC)((LPBYTE)baseRelocation + sizeof(IMAGE_BASE_RELOCATION));

					for (UINT_PTR i = 0; i < (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(nt::IMAGE_RELOC); i++)
					{
						if (relocations[i].Type == IMAGE_REL_BASED_DIR64) *(PUINT_PTR)(relocationAddress + relocations[i].Offset) += imageBase;
						else if (relocations[i].Type == IMAGE_REL_BASED_HIGHLOW) *(LPDWORD)(relocationAddress + relocations[i].Offset) += (DWORD)imageBase;
						else if (relocations[i].Type == IMAGE_REL_BASED_HIGH) *(LPWORD)(relocationAddress + relocations[i].Offset) += HIWORD(imageBase);
						else if (relocations[i].Type == IMAGE_REL_BASED_LOW) *(LPWORD)(relocationAddress + relocations[i].Offset) += LOWORD(imageBase);
					}
				}
			}

			// Get actual main entry point.
			nt::DLLMAIN dllMain = (nt::DLLMAIN)(allocatedMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint);

			// Flush instruction cache to avoid stale instructions on modified code to be executed.
			ntFlushInstructionCache(INVALID_HANDLE_VALUE, NULL, 0);

			// Call actual DllMain.
			return dllMain((HINSTANCE)allocatedMemory, DLL_PROCESS_ATTACH, NULL);
		}
	}

	// If loading failed, DllMain was not executed either. Return FALSE.
	return FALSE;
}