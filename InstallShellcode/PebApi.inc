; Module hashes
PEB_NtdllDll							= 0x3cfa685d
PEB_Kernel32Dll							= 0x6a4abc5b

; Function hashes (ntdll.dll)
PEB_RtlAllocateHeap						= 0x3e192526
PEB_NtUnmapViewOfSection				= 0xf21037d0

; Function hashes (kernel32.dll)
PEB_GetProcessHeap						= 0xa80eecae
PEB_GetModuleFileNameW					= 0x45b06d8c
PEB_CreateProcessW						= 0x16b3fe88
PEB_TerminateProcess					= 0x78b5b983
PEB_VirtualAllocEx						= 0x6e1a959c
PEB_WriteProcessMemory					= 0xd83d6aa1
PEB_GetThreadContext					= 0x68a7c7d2
PEB_SetThreadContext					= 0xe8a7c7d3
PEB_ResumeThread						= 0x9e4a3f88

macro pebcall modulehash, functionhash, [arg]
{
	common
	if ~ arg eq
		reverse
		pushd arg
		common
	end if

	stdcall	PebGetProcAddress, modulehash, functionhash
	call	eax
}