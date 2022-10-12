WOW64_CONTEXT_i386						= 0x00010000
WOW64_CONTEXT_INTEGER					= 0x00000002

struct UNICODE_STRING
	Length			dw ?
	MaximumLength	dw ?
	Buffer			dd ?
ends

struct IMAGE_DOS_HEADER
	e_magic		dw ?
	e_cblp		dw ?
	e_cp		dw ?
	e_crlc		dw ?
	e_cparhdr	dw ?
	e_minalloc	dw ?
	e_maxalloc	dw ?
	e_ss		dw ?
	e_sp		dw ?
	e_csum		dw ?
	e_ip		dw ?
	e_cs		dw ?
	e_lfarl		dw ?
	e_ovno		dw ?
	e_res		rw 4
	e_oemid		dw ?
	e_oeminfo	dw ?
	e_res2		rw 10
	e_lfanew	dd ?
ends

struct IMAGE_FILE_HEADER
	Machine					dw ?
	NumberOfSections		dw ?
	TimeDateStamp			dd ?
	PointerToSymbolTable	dd ?
	NumberOfSymbols			dd ?
	SizeOfOptionalHeader	dw ?
	Characteristics			dw ?
ends

struct IMAGE_DATA_DIRECTORY
	VirtualAddress	dd ?
	Size			dd ?
ends

struct IMAGE_OPTIONAL_HEADER32
	Magic						dw ?
	MajorLinkerVersion			db ?
	MinorLinkerVersion			db ?
	SizeOfCode					dd ?
	SizeOfInitializedData		dd ?
	SizeOfUninitializedData		dd ?
	AddressOfEntryPoint			dd ?
	BaseOfCode					dd ?
	BaseOfData					dd ?
	ImageBase					dd ?
	SectionAlignment			dd ?
	FileAlignment				dd ?
	MajorOperatingSystemVersion	dw ?
	MinorOperatingSystemVersion	dw ?
	MajorImageVersion			dw ?
	MinorImageVersion			dw ?
	MajorSubsystemVersion		dw ?
	MinorSubsystemVersion		dw ?
	Win32VersionValue			dd ?
	SizeOfImage					dd ?
	SizeOfHeaders				dd ?
	CheckSum					dd ?
	Subsystem					dw ?
	DllCharacteristics			dw ?
	SizeOfStackReserve			dd ?
	SizeOfStackCommit			dd ?
	SizeOfHeapReserve			dd ?
	SizeOfHeapCommit			dd ?
	LoaderFlags					dd ?
	NumberOfRvaAndSizes			dd ?
	DataDirectoryExport			IMAGE_DATA_DIRECTORY
	DataDirectoryImport			IMAGE_DATA_DIRECTORY
	DataDirectoryResource		IMAGE_DATA_DIRECTORY
	DataDirectoryException		IMAGE_DATA_DIRECTORY
	DataDirectorySecurity		IMAGE_DATA_DIRECTORY
	DataDirectoryBaseReloc		IMAGE_DATA_DIRECTORY
	DataDirectoryDebug			IMAGE_DATA_DIRECTORY
	DataDirectoryArchitecture	IMAGE_DATA_DIRECTORY
	DataDirectoryGlobalPtr		IMAGE_DATA_DIRECTORY
	DataDirectoryTls			IMAGE_DATA_DIRECTORY
	DataDirectoryLoadConfig		IMAGE_DATA_DIRECTORY
	DataDirectoryBoundImport	IMAGE_DATA_DIRECTORY
	DataDirectoryIat			IMAGE_DATA_DIRECTORY
	DataDirectoryDelayImport	IMAGE_DATA_DIRECTORY
	DataDirectoryComDescriptor	IMAGE_DATA_DIRECTORY
	DataDirectory16				IMAGE_DATA_DIRECTORY
ends

struct IMAGE_EXPORT_DIRECTORY
	Characteristics			dd ?
	TimeDateStamp			dd ?
	MajorVersion			dw ?
	MinorVersion			dw ?
	Name					dd ?
	Base					dd ?
	NumberOfFunctions		dd ?
	NumberOfNames			dd ?
	AddressOfFunctions		dd ?
	AddressOfNames			dd ?
	AddressOfNameOrdinals	dd ?
ends

struct IMAGE_NT_HEADERS32
	Signature		dd ?
	FileHeader		IMAGE_FILE_HEADER
	OptionalHeader	IMAGE_OPTIONAL_HEADER32
ends

struct IMAGE_SECTION_HEADER 
	Name					rb 8
	union
		PhysicalAddress		dd ?
		VirtualSize			dd ?
	ends
	VirtualAddress			dd ?
	SizeOfRawData			dd ?
	PointerToRawData		dd ?
	PointerToRelocations	dd ?
	PointerToLinenumbers	dd ?
	NumberOfRelocations		dw ?
	NumberOfLinenumbers		dw ?
	Characteristics			dd ?
ends

struct FLOATING_SAVE_AREA
	ControlWord		dd ?
	StatusWord		dd ?
	TagWord			dd ?
	ErrorOffset		dd ?
	ErrorSelector	dd ?
	DataOffset		dd ?
	DataSelector	dd ?
	RegisterArea	rb 80
	Cr0NpxState		dd ?
ends

struct CONTEXT32
	ContextFlags		dd ?
	Dr0					dd ?
	Dr1					dd ?
	Dr2					dd ?
	Dr3					dd ?
	Dr6					dd ?
	Dr7					dd ?
	FloatSave			FLOATING_SAVE_AREA
	SegGs				dd ?
	SegFs				dd ?
	SegEs				dd ?
	SegDs				dd ?
	Edi					dd ?
	Esi					dd ?
	Ebx					dd ?
	Edx					dd ?
	Ecx					dd ?
	Eax					dd ?
	Ebp					dd ?
	Eip					dd ?
	SegCs				dd ?
	EFlags				dd ?
	Esp					dd ?
	SegSs				dd ?
	ExtendedRegisters	rb 512
ends

struct LIST_ENTRY
	Flink	dd ?
	Blink	dd ?
ends

struct LDR_DATA_TABLE_ENTRY
	InMemoryOrderModuleList			LIST_ENTRY
	InInitializationOrderModuleList	LIST_ENTRY
	DllBase							dd ?
	EntryPoint						dd ?
	SizeOfImage						dd ?
	FullDllName						UNICODE_STRING
	BaseDllName						UNICODE_STRING
	Flags							dd ?
	LoadCount						dw ?
	TlsIndex						dw ?
	HashTableEntry					LIST_ENTRY
	TimeDateStamp					dd ?
ends

struct PEB_LDR_DATA
	Reserved1				rb 8
	Reserved2				rd 3
	InMemoryOrderModuleList	LIST_ENTRY
ends

struct PEB
	Reserved1				rb 2
	BeingDebugged			db ?
	Reserved2				db ?
	Reserved3				rd 2
	Ldr						dd ?
	ProcessParameters		dd ?
	Reserved4				rd 3
	AtlThunkSListPtr		dd ?
	Reserved5				dd ?
	Reserved6				dd ?
	Reserved7				dd ?
	Reserved8				dd ?
	AtlThunkSListPtr32		dd ?
	Reserved9				rd 45
	Reserved10				rb 96
	PostProcessInitRoutine	dd ?
	Reserved11				rb 128
	Reserved12				dd ?
	SessionId				dd ?
ends