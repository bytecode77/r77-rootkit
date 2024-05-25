#include "ReflectiveDllMain.h"
#include "ntdll.h"
#include "peb.h"

BOOL WINAPI ReflectiveDllMain(LPBYTE dllBase)
{
	// All functions that are used in the reflective loader must be found by searching the PEB, because no functions are imported, yet.
	// Switch statements must not be used, because a jump table would be created and the shellcode would not be position independent anymore.

	NT_NTFLUSHINSTRUCTIONCACHE ntFlushInstructionCache = (NT_NTFLUSHINSTRUCTIONCACHE)PebGetProcAddress(0x3cfa685d, 0x534c0ab8);
	NT_LOADLIBRARYA loadLibraryA = (NT_LOADLIBRARYA)PebGetProcAddress(0x6a4abc5b, 0xec0e4e8e);
	NT_GETPROCADDRESS getProcAddress = (NT_GETPROCADDRESS)PebGetProcAddress(0x6a4abc5b, 0x7c0dfcaa);
	NT_VIRTUALALLOC virtualAlloc = (NT_VIRTUALALLOC)PebGetProcAddress(0x6a4abc5b, 0x91afca54);
	NT_VIRTUALPROTECT virtualProtect = (NT_VIRTUALPROTECT)PebGetProcAddress(0x6a4abc5b, 0x7946c61b);

	// Safety check: Continue only, if all functions were found.
	if (ntFlushInstructionCache && loadLibraryA && getProcAddress && virtualAlloc && virtualProtect)
	{
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllBase + ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew);

		// Allocate memory for the DLL.
		LPBYTE allocatedMemory = (LPBYTE)virtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (allocatedMemory)
		{
			// Copy optional header to new memory.
			i_memcpy(allocatedMemory, dllBase, ntHeaders->OptionalHeader.SizeOfHeaders);

			// Set memory protection on header.
			DWORD oldProtect;
			if (!virtualProtect(allocatedMemory, ntHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect)) return FALSE;

			// Copy sections to new memory.
			PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((LPBYTE)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
			for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
			{
				i_memcpy(allocatedMemory + sections[i].VirtualAddress, dllBase + sections[i].PointerToRawData, sections[i].SizeOfRawData);
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
					PNT_IMAGE_RELOC relocations = (PNT_IMAGE_RELOC)((LPBYTE)baseRelocation + sizeof(IMAGE_BASE_RELOCATION));

					for (UINT_PTR i = 0; i < (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(NT_IMAGE_RELOC); i++)
					{
						if (relocations[i].Type == IMAGE_REL_BASED_DIR64) *(PUINT_PTR)(relocationAddress + relocations[i].Offset) += imageBase;
						else if (relocations[i].Type == IMAGE_REL_BASED_HIGHLOW) *(LPDWORD)(relocationAddress + relocations[i].Offset) += (DWORD)imageBase;
						else if (relocations[i].Type == IMAGE_REL_BASED_HIGH) *(LPWORD)(relocationAddress + relocations[i].Offset) += HIWORD(imageBase);
						else if (relocations[i].Type == IMAGE_REL_BASED_LOW) *(LPWORD)(relocationAddress + relocations[i].Offset) += LOWORD(imageBase);
					}
				}
			}

			// Set memory protection on sections.
			for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
			{
				if (!virtualProtect(
					allocatedMemory + sections[i].VirtualAddress,
					i == ntHeaders->FileHeader.NumberOfSections - 1 ? ntHeaders->OptionalHeader.SizeOfImage - sections[i].VirtualAddress : sections[i + 1].VirtualAddress - sections[i].VirtualAddress,
					SectionCharacteristicsToProtection(sections[i].Characteristics),
					&oldProtect
				))
				{
					return FALSE;
				}
			}

			// Get actual main entry point.
			NT_DLLMAIN dllMain = (NT_DLLMAIN)(allocatedMemory + ntHeaders->OptionalHeader.AddressOfEntryPoint);

			// Flush instruction cache to avoid stale instructions on modified code to be executed.
			ntFlushInstructionCache(INVALID_HANDLE_VALUE, NULL, 0);

			// Call actual DllMain.
			return dllMain((HINSTANCE)allocatedMemory, DLL_PROCESS_ATTACH, NULL);
		}
	}

	// If loading failed, DllMain was not executed either. Return FALSE.
	return FALSE;
}