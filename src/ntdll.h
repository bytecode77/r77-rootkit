#define STATUS_NO_MORE_FILES			((NTSTATUS)0x80000006L)

#define SL_RESTART_SCAN					0x01
#define SL_RETURN_SINGLE_ENTRY			0x02
#define SL_INDEX_SPECIFIED				0x04
#define SL_RETURN_ON_DISK_ENTRIES_ONLY	0x08
#define SL_NO_CURSOR_UPDATE				0x10

#define DEVICE_NSI						L"\\Device\\Nsi"
#define IOCTL_NSI_GETALLPARAM			0x12001b

namespace nt
{
	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation,
		SystemProcessorInformation,
		SystemPerformanceInformation,
		SystemTimeOfDayInformation,
		SystemPathInformation,
		SystemProcessInformation,
		SystemCallCountInformation,
		SystemDeviceInformation,
		SystemProcessorPerformanceInformation,
		SystemFlagsInformation,
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
		SystemInterruptInformation,
		SystemDpcBehaviorInformation,
		SystemFullMemoryInformation,
		SystemLoadGdiDriverInformation,
		SystemUnloadGdiDriverInformation,
		SystemTimeAdjustmentInformation,
		SystemSummaryMemoryInformation,
		SystemMirrorMemoryInformation,
		SystemPerformanceTraceInformation,
		SystemObsolete0,
		SystemExceptionInformation,
		SystemCrashDumpStateInformation,
		SystemKernelDebuggerInformation,
		SystemContextSwitchInformation,
		SystemRegistryQuotaInformation,
		SystemExtendServiceTableInformation,
		SystemPrioritySeperation,
		SystemVerifierAddDriverInformation,
		SystemVerifierRemoveDriverInformation,
		SystemProcessorIdleInformation,
		SystemLegacyDriverInformation,
		SystemCurrentTimeZoneInformation,
		SystemLookasideInformation,
		SystemTimeSlipNotification,
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
		SystemCodeIntegrityInformation,
		SystemProcessorMicrocodeUpdateInformation,
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
		SystemPolicyInformation,
		SystemHypervisorProcessorCountInformation,
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
	} SYSTEM_INFORMATION_CLASS;

	typedef struct _SYSTEM_PROCESS_INFORMATION
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
	} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

	typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	{
		LARGE_INTEGER IdleTime;
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER DpcTime;
		LARGE_INTEGER InterruptTime;
		ULONG InterruptCount;
	} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

	typedef enum _FILE_INFORMATION_CLASS
	{
		FileDirectoryInformation = 1,
		FileFullDirectoryInformation,
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
	} FILE_INFORMATION_CLASS;

	typedef struct _FILE_BOTH_DIR_INFORMATION
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
	} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

	typedef struct _FILE_DIRECTORY_INFORMATION
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
	} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

	typedef struct _FILE_FULL_DIR_INFORMATION
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
	} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

	typedef struct _FILE_ID_BOTH_DIR_INFORMATION
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
	} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

	typedef struct _FILE_ID_FULL_DIR_INFORMATION
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
	} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

	typedef struct _FILE_NAMES_INFORMATION
	{
		ULONG NextEntryOffset;
		ULONG FileIndex;
		ULONG FileNameLength;
		WCHAR FileName[1];
	} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

	typedef enum _KEY_INFORMATION_CLASS
	{
		KeyBasicInformation,
		KeyNodeInformation,
		KeyFullInformation,
		KeyNameInformation
	} KEY_INFORMATION_CLASS;

	typedef enum _KEY_VALUE_INFORMATION_CLASS
	{
		KeyValueBasicInformation,
		KeyValueFullInformation,
		KeyValuePartialInformation
	} KEY_VALUE_INFORMATION_CLASS;

	typedef struct _KEY_BASIC_INFORMATION
	{
		LARGE_INTEGER LastWriteTime;
		ULONG TitleIndex;
		ULONG NameLength;
		WCHAR Name[1];
	} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

	typedef struct _KEY_NAME_INFORMATION
	{
		ULONG NameLength;
		WCHAR Name[1];
	} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

	typedef struct _KEY_VALUE_BASIC_INFORMATION
	{
		ULONG TitleIndex;
		ULONG Type;
		ULONG NameLength;
		WCHAR Name[1];
	} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

	typedef struct _KEY_VALUE_FULL_INFORMATION
	{
		ULONG TitleIndex;
		ULONG Type;
		ULONG DataOffset;
		ULONG DataLength;
		ULONG NameLength;
		WCHAR Name[1];
	} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

	typedef enum _NSI_PARAM_TYPE
	{
		Udp = 1,
		Tcp = 3
	} NSI_PARAM_TYPE;

	typedef struct _NSI_TCP_SUBENTRY
	{
		BYTE Reserved1[2];
		USHORT Port;
		ULONG IpAddress;
		BYTE IpAddress6[16];
		BYTE Reserved2[4];
	} NSI_TCP_SUBENTRY, *PNSI_TCP_SUBENTRY;

	typedef struct _NSI_TCP_ENTRY
	{
		NSI_TCP_SUBENTRY Local;
		NSI_TCP_SUBENTRY Remote;
	} NSI_TCP_ENTRY, *PNSI_TCP_ENTRY;

	typedef struct _NSI_UDP_ENTRY
	{
		BYTE Reserved1[2];
		USHORT Port;
		ULONG IpAddress;
		BYTE IpAddress6[16];
		BYTE Reserved2[4];
	} NSI_UDP_ENTRY, *PNSI_UDP_ENTRY;

	typedef struct _NSI_STATUS_ENTRY
	{
		ULONG State;
		BYTE Reserved[8];
	} NSI_STATUS_ENTRY, *PNSI_STATUS_ENTRY;

	typedef struct _NSI_PROCESS_ENTRY
	{
		ULONG UdpProcessId;
		ULONG Reserved1;
		ULONG Reserved2;
		ULONG TcpProcessId;
		ULONG Reserved3;
		ULONG Reserved4;
		ULONG Reserved5;
		ULONG Reserved6;
	} NSI_PROCESS_ENTRY, *PNSI_PROCESS_ENTRY;

	typedef struct _NSI_PARAM
	{
		SIZE_T Reserved1;
		SIZE_T Reserved2;
		LPVOID ModuleId;
		NSI_PARAM_TYPE Type;
		ULONG Reserved3;
		ULONG Reserved4;
		LPVOID Entries;
		SIZE_T EntrySize;
		LPVOID Reserved5;
		SIZE_T Reserved6;
		PNSI_STATUS_ENTRY StatusEntries;
		SIZE_T Reserved7;
		PNSI_PROCESS_ENTRY ProcessEntries;
		SIZE_T ProcessEntrySize;
		SIZE_T Count;
	} NSI_PARAM, *PNSI_PARAM;

	typedef enum _OBJECT_INFORMATION_CLASS
	{
		ObjectBasicInformation,
		ObjectNameInformation,
		ObjectTypeInformation,
		ObjectAllInformation,
		ObjectDataInformation
	} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

	typedef NTSTATUS(NTAPI *NTQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS systemInformationClass, LPVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
	typedef NTSTATUS(NTAPI *NTRESUMETHREAD)(HANDLE thread, PULONG suspendCount);
	typedef NTSTATUS(NTAPI *NTQUERYDIRECTORYFILE)(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, FILE_INFORMATION_CLASS fileInformationClass, BOOLEAN returnSingleEntry, PUNICODE_STRING fileName, BOOLEAN restartScan);
	typedef NTSTATUS(NTAPI *NTQUERYDIRECTORYFILEEX)(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, FILE_INFORMATION_CLASS fileInformationClass, ULONG queryFlags, PUNICODE_STRING fileName);
	typedef NTSTATUS(NTAPI *NTENUMERATEKEY)(HANDLE key, ULONG index, KEY_INFORMATION_CLASS keyInformationClass, LPVOID keyInformation, ULONG keyInformationLength, PULONG resultLength);
	typedef NTSTATUS(NTAPI *NTENUMERATEVALUEKEY)(HANDLE key, ULONG index, KEY_VALUE_INFORMATION_CLASS keyValueInformationClass, LPVOID keyValueInformation, ULONG keyValueInformationLength, PULONG resultLength);
	typedef BOOL(WINAPI *ENUMSERVICEGROUPW)(SC_HANDLE serviceManager, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPVOID reserved);
	typedef BOOL(WINAPI *ENUMSERVICESSTATUSEXW)(SC_HANDLE serviceManager, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPCWSTR groupName);
	typedef NTSTATUS(NTAPI *NTDEVICEIOCONTROLFILE)(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, ULONG ioControlCode, LPVOID inputBuffer, ULONG inputBufferLength, LPVOID outputBuffer, ULONG outputBufferLength);
	typedef NTSTATUS(NTAPI *NTQUERYOBJECT)(HANDLE handle, OBJECT_INFORMATION_CLASS objectInformationClass, LPVOID objectInformation, ULONG objectInformationLength, PULONG returnLength);
	typedef NTSTATUS(NTAPI *NTCREATETHREADEX)(PHANDLE thread, ACCESS_MASK desiredAccess, LPVOID objectAttributes, HANDLE processHandle, LPVOID startAddress, LPVOID parameter, ULONG flags, SIZE_T stackZeroBits, SIZE_T sizeOfStackCommit, SIZE_T sizeOfStackReserve, LPVOID bytesBuffer);
	typedef NTSTATUS(NTAPI *RTLADJUSTPRIVILEGE)(ULONG privilege, BOOLEAN enablePrivilege, BOOLEAN isThreadPrivilege, PBOOLEAN previousValue);
	typedef NTSTATUS(NTAPI *RTLSETPROCESSISCRITICAL)(BOOLEAN newIsCritical, PBOOLEAN oldIsCritical, BOOLEAN needScb);
}