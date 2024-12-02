#include "peb.h"
#include "ntdll.h"

LPVOID PebGetModuleHandle(DWORD moduleHash)
{
#ifdef _WIN64
	PNT_PEB_LDR_DATA peb = (PNT_PEB_LDR_DATA)((PNT_PEB)__readgsqword(0x60))->Ldr;
#else
	PNT_PEB_LDR_DATA peb = (PNT_PEB_LDR_DATA)((PNT_PEB)__readfsdword(0x30))->Ldr;
#endif

	PNT_LDR_DATA_TABLE_ENTRY firstPebEntry = (PNT_LDR_DATA_TABLE_ENTRY)peb->InMemoryOrderModuleList.Flink;
	PNT_LDR_DATA_TABLE_ENTRY pebEntry = firstPebEntry;
	do
	{
		DWORD entryHash = 0;
		if (pebEntry->BaseDllName.Buffer)
		{
			for (USHORT i = 0; i < pebEntry->BaseDllName.Length; i++)
			{
				CHAR c = ((LPCSTR)pebEntry->BaseDllName.Buffer)[i];
				entryHash = _rotr(entryHash, 13) + (c >= 'a' ? c - 0x20 : c);
			}
		}

		if (entryHash == moduleHash)
		{
			return pebEntry->DllBase;
		}
	}
	while ((pebEntry = (PNT_LDR_DATA_TABLE_ENTRY)pebEntry->InMemoryOrderModuleList.Flink) != firstPebEntry);

	return NULL;
}
LPVOID PebGetProcAddress(DWORD moduleHash, DWORD functionHash)
{
	LPBYTE dllBase = PebGetModuleHandle(moduleHash);
	if (dllBase)
	{
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllBase + ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		LPDWORD nameDirectory = (LPDWORD)(dllBase + exportDirectory->AddressOfNames);
		LPWORD nameOrdinalDirectory = (LPWORD)(dllBase + exportDirectory->AddressOfNameOrdinals);

		// Find function by hash
		for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++, nameDirectory++, nameOrdinalDirectory++)
		{
			DWORD hash = 0;
			for (LPCSTR currentFunctionName = (LPCSTR)(dllBase + *nameDirectory); *currentFunctionName; currentFunctionName++)
			{
				hash = _rotr(hash, 13) + *currentFunctionName;
			}

			if (hash == functionHash)
			{
				return dllBase + *(LPDWORD)(dllBase + exportDirectory->AddressOfFunctions + *nameOrdinalDirectory * sizeof(DWORD));
			}
		}
	}

	return NULL;
}