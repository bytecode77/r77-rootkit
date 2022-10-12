proc PebGetProcAddress ModuleHash:DWORD, FunctionHash:DWORD
	local	FirstEntry:DWORD
	local	CurrentEntry:DWORD
	local	ModuleBase:DWORD
	local	ExportDirectory:DWORD
	local	NameDirectory:DWORD
	local	NameOrdinalDirectory:DWORD
	local	FunctionCounter:DWORD

	; Get InMemoryOrderModuleList from PEB
	mov		eax, 3
	shl		eax, 4
	mov		eax, [fs:eax] ; fs:0x30
	mov		eax, [eax + PEB.Ldr]
	mov		eax, [eax + PEB_LDR_DATA.InMemoryOrderModuleList.Flink]
	mov		[FirstEntry], eax
	mov		[CurrentEntry], eax

	; Find module by hash
.L_module:

	; Compute hash of case insensitive module name
	xor		edx, edx
	mov		eax, [CurrentEntry]
	movzx	ecx, word[eax + LDR_DATA_TABLE_ENTRY.BaseDllName.Length]
	test	ecx, ecx
	jz		.C_module
	mov		esi, [eax + LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer]
	xor		eax, eax
	cld
.L_module_hash:
	lodsb
	ror		edx, 13
	add		edx, eax
	cmp		al, 'a'
	jl		@f
	sub		edx, 0x20 ; Convert lower case letters to upper case
@@:	dec		ecx
	test	ecx, ecx
	jnz		.L_module_hash

	; Check, if module is found by hash
	cmp		edx, [ModuleHash]
	jne		.C_module

	; Get module base
	mov		eax, [CurrentEntry]
	mov		eax, [eax + LDR_DATA_TABLE_ENTRY.DllBase]
	mov		[ModuleBase], eax

	; Get export directory
	mov		eax, [ModuleBase]
	add		eax, [eax + IMAGE_DOS_HEADER.e_lfanew]
	mov		eax, [eax + IMAGE_NT_HEADERS32.OptionalHeader.DataDirectoryExport.VirtualAddress]
	add		eax, [ModuleBase]
	mov		[ExportDirectory], eax

	; Get name table
	mov		eax, [ExportDirectory]
	mov		eax, [eax + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
	add		eax, [ModuleBase]
	mov		[NameDirectory], eax

	; Get name ordinal table
	mov		eax, [ExportDirectory]
	mov		eax, [eax + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
	add		eax, [ModuleBase]
	mov		[NameOrdinalDirectory], eax

	; Find function in export directory by hash
	mov		[FunctionCounter], 0
.L_functions:
	mov		eax, [ExportDirectory]
	mov		eax, [eax + IMAGE_EXPORT_DIRECTORY.NumberOfNames]
	cmp		eax, [FunctionCounter]
	je		.E_functions

	; Compute hash of function name
	xor		edx, edx
	mov		esi, [NameDirectory]
	mov		esi, [esi]
	add		esi, [ModuleBase]
	xor		eax, eax
	cld
.L_function_hash:
	lodsb
	test	al, al
	jz		.E_function_hash
	ror		edx, 13
	add		edx, eax
	jmp		.L_function_hash
.E_function_hash:

	; Check, if function is found by hash
	cmp		edx, [FunctionHash]
	jne		.C_functions

	; Return function address
	mov		eax, [ExportDirectory]
	mov		eax, [eax + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
	add		eax, [ModuleBase]
	mov		ebx, [NameOrdinalDirectory]
	movzx	ebx, word[ebx]
	lea		eax, [eax + ebx * 4]
	mov		eax, [eax]
	add		eax, [ModuleBase]
	ret

.C_functions:
	add		[NameDirectory], 4
	add		[NameOrdinalDirectory], 2
	inc		[FunctionCounter]
	jmp		.L_functions
.E_functions:

	; Function not found in module's export table
	xor		eax, eax
	ret

.C_module:
	; Move to next module, exit loop if CurrentEntry == FirstEntry
	mov		eax, [CurrentEntry]
	mov		eax, [eax + LIST_ENTRY.Flink]
	mov		[CurrentEntry], eax
	cmp		eax, [FirstEntry]
	jne		.L_module

	; Module not found
	xor		eax, eax
	ret
endp