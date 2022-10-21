#include "r77mindef.h"
#ifndef _NTDLL_H
#define _NTDLL_H

#define STATUS_NO_MORE_FILES			((NTSTATUS)0x80000006L)

#define SL_RESTART_SCAN					0x01
#define SL_RETURN_SINGLE_ENTRY			0x02
#define SL_INDEX_SPECIFIED				0x04
#define SL_RETURN_ON_DISK_ENTRIES_ONLY	0x08
#define SL_NO_CURSOR_UPDATE				0x10

#define DEVICE_NSI						L"\\Device\\Nsi"
#define IOCTL_NSI_GETALLPARAM			0x12001b

typedef enum _NT_SYSTEM_INFORMATION_CLASS
{
	SystemProcessorInformation = 1,
	SystemPathInformation = 4,
	SystemCallCountInformation = 6,
	SystemDeviceInformation,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformationObsolete,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	SystemThreadPriorityClientIdInformation,
	SystemProcessorIdleCycleTimeInformation,
	SystemVerifierCancellationInformation,
	SystemProcessorPowerInformationEx,
	SystemRefTraceInformation,
	SystemSpecialPoolInformation,
	SystemProcessIdInformation,
	SystemErrorPortInformation,
	SystemBootEnvironmentInformation,
	SystemHypervisorInformation,
	SystemVerifierInformationEx,
	SystemTimeZoneInformation,
	SystemImageFileExecutionOptionsInformation,
	SystemCoverageInformation,
	SystemPrefetchPatchInformation,
	SystemVerifierFaultsInformation,
	SystemSystemPartitionInformation,
	SystemSystemDiskInformation,
	SystemProcessorPerformanceDistribution,
	SystemNumaProximityNodeInformation,
	SystemDynamicTimeZoneInformation,
	SystemProcessorMicrocodeUpdateInformation = 104,
	SystemProcessorBrandString,
	SystemVirtualAddressInformation,
	SystemLogicalProcessorAndGroupInformation,
	SystemProcessorCycleTimeInformation,
	SystemStoreInformation,
	SystemRegistryAppendString,
	SystemAitSamplingValue,
	SystemVhdBootInformation,
	SystemCpuQuotaInformation,
	SystemNativeBasicInformation,
	SystemErrorPortTimeouts,
	SystemLowPriorityIoInformation,
	SystemTpmBootEntropyInformation,
	SystemVerifierCountersInformation,
	SystemPagedPoolInformationEx,
	SystemSystemPtesInformationEx,
	SystemNodeDistanceInformation,
	SystemAcpiAuditInformation,
	SystemBasicPerformanceInformation,
	SystemQueryPerformanceCounterInformation,
	SystemSessionBigPoolInformation,
	SystemBootGraphicsInformation,
	SystemScrubPhysicalMemoryInformation,
	SystemBadPageInformation,
	SystemProcessorProfileControlArea,
	SystemCombinePhysicalMemoryInformation,
	SystemEntropyInterruptTimingInformation,
	SystemConsoleInformation,
	SystemPlatformBinaryInformation,
	SystemHypervisorProcessorCountInformation = 135,
	SystemDeviceDataInformation,
	SystemDeviceDataEnumerationInformation,
	SystemMemoryTopologyInformation,
	SystemMemoryChannelInformation,
	SystemBootLogoInformation,
	SystemProcessorPerformanceInformationEx,
	SystemCriticalProcessErrorLogInformation,
	SystemSecureBootPolicyInformation,
	SystemPageFileInformationEx,
	SystemSecureBootInformation,
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation,
	SystemFullProcessInformation,
	SystemKernelDebuggerInformationEx,
	SystemBootMetadataInformation,
	SystemSoftRebootInformation,
	SystemElamCertificateInformation,
	SystemOfflineDumpConfigInformation,
	SystemProcessorFeaturesInformation,
	SystemRegistryReconciliationInformation,
	SystemEdidInformation,
	SystemManufacturingInformation,
	SystemEnergyEstimationConfigInformation,
	SystemHypervisorDetailInformation,
	SystemProcessorCycleStatsInformation,
	SystemVmGenerationCountInformation,
	SystemTrustedPlatformModuleInformation,
	SystemKernelDebuggerFlags,
	SystemCodeIntegrityPolicyInformation,
	SystemIsolatedUserModeInformation,
	SystemHardwareSecurityTestInterfaceResultsInformation,
	SystemSingleModuleInformation,
	SystemAllowedCpuSetsInformation,
	SystemVsmProtectionInformation,
	SystemInterruptCpuSetsInformation,
	SystemSecureBootPolicyFullInformation,
	SystemCodeIntegrityPolicyFullInformation,
	SystemAffinitizedInterruptProcessorInformation,
	SystemRootSiloInformation,
	SystemCpuSetInformation,
	SystemCpuSetTagInformation,
	SystemWin32WerStartCallout,
	SystemSecureKernelProfileInformation,
	SystemCodeIntegrityPlatformManifestInformation,
	SystemInterruptSteeringInformation,
	SystemSupportedProcessorArchitectures,
	SystemMemoryUsageInformation,
	SystemCodeIntegrityCertificateInformation,
	SystemPhysicalMemoryInformation,
	SystemControlFlowTransition,
	SystemKernelDebuggingAllowed,
	SystemActivityModerationExeState,
	SystemActivityModerationUserSettings,
	SystemCodeIntegrityPoliciesFullInformation,
	SystemCodeIntegrityUnlockInformation,
	SystemIntegrityQuotaInformation,
	SystemFlushInformation,
	SystemProcessorIdleMaskInformation,
	SystemSecureDumpEncryptionInformation,
	SystemWriteConstraintInformation,
	SystemKernelVaShadowInformation,
	SystemHypervisorSharedPageInformation,
	SystemFirmwareBootPerformanceInformation,
	SystemCodeIntegrityVerificationInformation,
	SystemFirmwarePartitionInformation,
	SystemSpeculationControlInformation,
	SystemDmaGuardPolicyInformation,
	SystemEnclaveLaunchControlInformation,
	SystemWorkloadAllowedCpuSetsInformation,
	SystemCodeIntegrityUnlockModeInformation,
	SystemLeapSecondInformation,
	SystemFlags2Information,
	SystemSecurityModelInformation,
	SystemCodeIntegritySyntheticCacheInformation,
	SystemFeatureConfigurationInformation,
	SystemFeatureConfigurationSectionInformation,
	SystemFeatureUsageSubscriptionInformation,
	SystemSecureSpeculationControlInformation
} NT_SYSTEM_INFORMATION_CLASS;

typedef struct _NT_SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} NT_SYSTEM_PROCESS_INFORMATION, *PNT_SYSTEM_PROCESS_INFORMATION;

typedef struct _NT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER DpcTime;
	LARGE_INTEGER InterruptTime;
	ULONG InterruptCount;
} NT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PNT_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef enum _NT_FILE_INFORMATION_CLASS
{
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileIoCompletionNotificationInformation,
	FileIoStatusBlockRangeInformation,
	FileIoPriorityHintInformation,
	FileSfioReserveInformation,
	FileSfioVolumeInformation,
	FileHardLinkInformation,
	FileProcessIdsUsingFileInformation,
	FileNormalizedNameInformation,
	FileNetworkPhysicalNameInformation,
	FileIdGlobalTxDirectoryInformation,
	FileIsRemoteDeviceInformation,
	FileUnusedInformation,
	FileNumaNodeInformation,
	FileStandardLinkInformation,
	FileRemoteProtocolInformation,
	FileRenameInformationBypassAccessCheck,
	FileLinkInformationBypassAccessCheck,
	FileVolumeNameInformation,
	FileIdInformation,
	FileIdExtdDirectoryInformation,
	FileReplaceCompletionInformation,
	FileHardLinkFullIdInformation,
	FileIdExtdBothDirectoryInformation,
	FileMaximumInformation
} NT_FILE_INFORMATION_CLASS;

typedef struct _NT_FILE_BOTH_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	WCHAR FileName[1];
} NT_FILE_BOTH_DIR_INFORMATION, *PNT_FILE_BOTH_DIR_INFORMATION;

typedef struct _NT_FILE_DIRECTORY_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	WCHAR FileName[1];
} NT_FILE_DIRECTORY_INFORMATION, *PNT_FILE_DIRECTORY_INFORMATION;

typedef struct _NT_FILE_FULL_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	WCHAR FileName[1];
} NT_FILE_FULL_DIR_INFORMATION, *PNT_FILE_FULL_DIR_INFORMATION;

typedef struct _NT_FILE_ID_BOTH_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	CCHAR ShortNameLength;
	WCHAR ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR FileName[1];
} NT_FILE_ID_BOTH_DIR_INFORMATION, *PNT_FILE_ID_BOTH_DIR_INFORMATION;

typedef struct _NT_FILE_ID_FULL_DIR_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	LARGE_INTEGER FileId;
	WCHAR FileName[1];
} NT_FILE_ID_FULL_DIR_INFORMATION, *PNT_FILE_ID_FULL_DIR_INFORMATION;

typedef struct _NT_FILE_NAMES_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG FileIndex;
	ULONG FileNameLength;
	WCHAR FileName[1];
} NT_FILE_NAMES_INFORMATION, *PNT_FILE_NAMES_INFORMATION;

typedef enum _NT_KEY_INFORMATION_CLASS
{
	KeyBasicInformation,
	KeyNodeInformation,
	KeyFullInformation,
	KeyNameInformation
} NT_KEY_INFORMATION_CLASS;

typedef enum _NT_KEY_VALUE_INFORMATION_CLASS
{
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation
} NT_KEY_VALUE_INFORMATION_CLASS;

typedef struct _NT_KEY_BASIC_INFORMATION
{
	LARGE_INTEGER LastWriteTime;
	ULONG TitleIndex;
	ULONG NameLength;
	WCHAR Name[1];
} NT_KEY_BASIC_INFORMATION, *PNT_KEY_BASIC_INFORMATION;

typedef struct _NT_KEY_NAME_INFORMATION
{
	ULONG NameLength;
	WCHAR Name[1];
} NT_KEY_NAME_INFORMATION, *PNT_KEY_NAME_INFORMATION;

typedef struct _NT_KEY_VALUE_BASIC_INFORMATION
{
	ULONG TitleIndex;
	ULONG Type;
	ULONG NameLength;
	WCHAR Name[1];
} NT_KEY_VALUE_BASIC_INFORMATION, *PNT_KEY_VALUE_BASIC_INFORMATION;

typedef struct _NT_KEY_VALUE_FULL_INFORMATION
{
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataOffset;
	ULONG DataLength;
	ULONG NameLength;
	WCHAR Name[1];
} NT_KEY_VALUE_FULL_INFORMATION, *PNT_KEY_VALUE_FULL_INFORMATION;

typedef enum _NT_NSI_PARAM_TYPE
{
	NsiUdp = 1,
	NsiTcp = 3
} NT_NSI_PARAM_TYPE;

typedef struct _NT_NSI_TCP_SUBENTRY
{
	BYTE Reserved1[2];
	USHORT Port;
	ULONG IpAddress;
	BYTE IpAddress6[16];
	BYTE Reserved2[4];
} NT_NSI_TCP_SUBENTRY, *PNT_NSI_TCP_SUBENTRY;

typedef struct _NT_NSI_TCP_ENTRY
{
	NT_NSI_TCP_SUBENTRY Local;
	NT_NSI_TCP_SUBENTRY Remote;
} NT_NSI_TCP_ENTRY, *PNT_NSI_TCP_ENTRY;

typedef struct _NT_NSI_UDP_ENTRY
{
	BYTE Reserved1[2];
	USHORT Port;
	ULONG IpAddress;
	BYTE IpAddress6[16];
	BYTE Reserved2[4];
} NT_NSI_UDP_ENTRY, *PNT_NSI_UDP_ENTRY;

typedef struct _NT_NSI_STATUS_ENTRY
{
	ULONG State;
	BYTE Reserved[8];
} NT_NSI_STATUS_ENTRY, *PNT_NSI_STATUS_ENTRY;

typedef struct _NT_NSI_PROCESS_ENTRY
{
	ULONG UdpProcessId;
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG TcpProcessId;
	ULONG Reserved3;
	ULONG Reserved4;
	ULONG Reserved5;
	ULONG Reserved6;
} NT_NSI_PROCESS_ENTRY, *PNT_NSI_PROCESS_ENTRY;

typedef struct _NT_NSI_PARAM
{
	// It was really daunting to figure out the contents of this struct...
	// There are lots of examples online with "LPVOID Unknown1, Unknown2" and so on.
	// However, this should be as close to the actual structure as it gets:

	SIZE_T Reserved1;
	SIZE_T Reserved2;
	LPVOID ModuleId;
	NT_NSI_PARAM_TYPE Type;
	ULONG Reserved3;
	ULONG Reserved4;
	LPVOID Entries;
	SIZE_T EntrySize;
	LPVOID Reserved5;
	SIZE_T Reserved6;
	LPVOID StatusEntries;
	SIZE_T StatusEntrySize;
	LPVOID ProcessEntries;
	SIZE_T ProcessEntrySize;
	SIZE_T Count;
} NT_NSI_PARAM, *PNT_NSI_PARAM;

typedef enum _NT_OBJECT_INFORMATION_CLASS
{
	ObjectNameInformation = 1,
	ObjectAllInformation = 3,
	ObjectDataInformation
} NT_OBJECT_INFORMATION_CLASS, *PNT_OBJECT_INFORMATION_CLASS;

typedef struct _NT_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID DllBase;
	LPVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} NT_LDR_DATA_TABLE_ENTRY, *PNT_LDR_DATA_TABLE_ENTRY;

typedef struct _NT_PEB_LDR_DATA
{
	DWORD Length;
	DWORD Initialized;
	LPVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID EntryInProgress;
} NT_PEB_LDR_DATA, *PNT_PEB_LDR_DATA;

typedef struct _NT_PEB
{
	BYTE InheritedAddressSpace;
	BYTE ReadImageFileExecOptions;
	BYTE BeingDebugged;
	BYTE SpareBool;
	LPVOID Mutant;
	LPVOID ImageBaseAddress;
	PNT_PEB_LDR_DATA Ldr;
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
	LPVOID FreeList;
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
} NT_PEB, *PNT_PEB;

typedef struct _NT_IMAGE_RELOC
{
	WORD Offset : 12;
	WORD Type : 4;
} NT_IMAGE_RELOC, *PNT_IMAGE_RELOC;

typedef NTSTATUS(NTAPI *NT_NTQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS systemInformationClass, LPVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
typedef NTSTATUS(NTAPI *NT_NTRESUMETHREAD)(HANDLE thread, PULONG suspendCount);
typedef NTSTATUS(NTAPI *NT_NTQUERYDIRECTORYFILE)(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, FILE_INFORMATION_CLASS fileInformationClass, BOOLEAN returnSingleEntry, PUNICODE_STRING fileName, BOOLEAN restartScan);
typedef NTSTATUS(NTAPI *NT_NTQUERYDIRECTORYFILEEX)(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, FILE_INFORMATION_CLASS fileInformationClass, ULONG queryFlags, PUNICODE_STRING fileName);
typedef NTSTATUS(NTAPI *NT_NTENUMERATEKEY)(HANDLE key, ULONG index, NT_KEY_INFORMATION_CLASS keyInformationClass, LPVOID keyInformation, ULONG keyInformationLength, PULONG resultLength);
typedef NTSTATUS(NTAPI *NT_NTENUMERATEVALUEKEY)(HANDLE key, ULONG index, NT_KEY_VALUE_INFORMATION_CLASS keyValueInformationClass, LPVOID keyValueInformation, ULONG keyValueInformationLength, PULONG resultLength);
typedef BOOL(WINAPI *NT_ENUMSERVICEGROUPW)(SC_HANDLE serviceManager, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPVOID reserved);
typedef BOOL(WINAPI *NT_ENUMSERVICESSTATUSEXW)(SC_HANDLE serviceManager, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPCWSTR groupName);
typedef NTSTATUS(NTAPI *NT_NTDEVICEIOCONTROLFILE)(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, ULONG ioControlCode, LPVOID inputBuffer, ULONG inputBufferLength, LPVOID outputBuffer, ULONG outputBufferLength);
typedef NTSTATUS(NTAPI *NT_NTQUERYOBJECT)(HANDLE handle, OBJECT_INFORMATION_CLASS objectInformationClass, LPVOID objectInformation, ULONG objectInformationLength, PULONG returnLength);
typedef NTSTATUS(NTAPI *NT_NTCREATETHREADEX)(PHANDLE thread, ACCESS_MASK desiredAccess, LPVOID objectAttributes, HANDLE processHandle, LPVOID startAddress, LPVOID parameter, ULONG flags, SIZE_T stackZeroBits, SIZE_T sizeOfStackCommit, SIZE_T sizeOfStackReserve, LPVOID bytesBuffer);
typedef NTSTATUS(NTAPI *NT_RTLADJUSTPRIVILEGE)(ULONG privilege, BOOLEAN enablePrivilege, BOOLEAN isThreadPrivilege, PBOOLEAN previousValue);
typedef NTSTATUS(NTAPI *NT_RTLSETPROCESSISCRITICAL)(BOOLEAN newIsCritical, PBOOLEAN oldIsCritical, BOOLEAN needScb);
typedef DWORD(NTAPI *NT_NTFLUSHINSTRUCTIONCACHE)(HANDLE process, LPVOID baseAddress, ULONG size);
typedef HMODULE(WINAPI *NT_LOADLIBRARYA)(LPCSTR fileName);
typedef FARPROC(WINAPI *NT_GETPROCADDRESS)(HMODULE module, LPCSTR function);
typedef LPVOID(WINAPI *NT_VIRTUALALLOC)(LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect);
typedef BOOL(WINAPI *NT_DLLMAIN)(HINSTANCE module, DWORD reason, LPVOID reserved);

#endif