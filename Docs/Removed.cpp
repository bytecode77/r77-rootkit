// Backup of removed code & work in progress tests that may be implemented later on



NTSTATUS NTAPI Hooks::HookedNtQuerySystemInformationEx(nt::SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID inputBuffer, ULONG inputBufferLength, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength)
{
	ULONG newReturnLength;
	NTSTATUS status = OriginalNtQuerySystemInformationEx(systemInformationClass, inputBuffer, inputBufferLength, systemInformation, systemInformationLength, &newReturnLength);
	if (returnLength) *returnLength = newReturnLength;

	if (NT_SUCCESS(status))
	{
		if (systemInformationClass == nt::SYSTEM_INFORMATION_CLASS::SystemProcessorCycleTimeInformation)
		{
			//TODO: TaskMgr (systemInformationLength = 512, inputBufferLength = 2, returnLength = 64)
			//for (ULONG i = 0; i < newReturnLength / sizeof(SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION); i++)
			//{
			//	PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION cycleTime = &((PSYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION)systemInformation)[i];
			//	cycleTime->CycleTime = 0;
			//}
		}
	}

	return status;
}

NTSTATUS NTAPI Hooks::HookedNtQueryInformationProcess(HANDLE process, nt::PROCESS_INFORMATION_CLASS processInformationClass, PVOID processInformation, ULONG processInformationLength, PULONG returnLength)
{
	NTSTATUS status = OriginalNtQueryInformationProcess(process, processInformationClass, processInformation, processInformationLength, returnLength);

	if (NT_SUCCESS(status))
	{
		if (processInformationClass == nt::PROCESS_INFORMATION_CLASS::ProcessCycleTime)
		{
		}
		else if (processInformationClass == nt::PROCESS_INFORMATION_CLASS::ProcessTimes)
		{
			//TODO: TaskMgr
			///ARGE_INTEGER hiddenKernelTime = { 0 };
			//LARGE_INTEGER hiddenUserTime = { 0 };
			//if (GetProcessHiddenTimes(&hiddenKernelTime, &hiddenUserTime, NULL))
			//{
			//	nt::PKERNEL_USER_TIMES times = (nt::PKERNEL_USER_TIMES)processInformation;
			//	times->KernelTime.QuadPart -= hiddenKernelTime.QuadPart;
			//	times->UserTime.QuadPart -= hiddenUserTime.QuadPart;
			//}
		}
	}

	return status;
}

typedef enum _PROCESS_INFORMATION_CLASS
{
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessResourceManagement,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
	ProcessHandleInformation,
	ProcessMitigationPolicy,
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,
	ProcessKeepAliveCount,
	ProcessRevokeFileHandles,
	ProcessWorkingSetControl,
	ProcessHandleTable,
	ProcessCheckStackExtentsMode,
	ProcessCommandLineInformation,
	ProcessProtectionInformation,
	ProcessMemoryExhaustion,
	ProcessFaultInformation,
	ProcessTelemetryIdInformation,
	ProcessCommitReleaseInformation,
	ProcessDefaultCpuSetsInformation,
	ProcessAllowedCpuSetsInformation,
	ProcessSubsystemProcess,
	ProcessJobMemoryInformation,
	ProcessInPrivate,
	ProcessRaiseUMExceptionOnInvalidHandleClose,
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation,
	ProcessHighGraphicsPriorityInformation,
	ProcessSubsystemInformation,
	ProcessEnergyValues,
	ProcessActivityThrottleState,
	ProcessActivityThrottlePolicy,
	ProcessWin32kSyscallFilterInformation,
	ProcessDisableSystemAllowedCpuSets,
	ProcessWakeInformation,
	ProcessEnergyTrackingState,
	ProcessManageWritesToExecutableMemory,
	ProcessCaptureTrustletLiveDump,
	ProcessTelemetryCoverage,
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging,
	ProcessUptimeInformation,
	ProcessImageSection,
	ProcessDebugAuthInformation,
	ProcessSystemResourceManagement,
	ProcessSequenceNumber,
	ProcessLoaderDetour,
	ProcessSecurityDomainInformation,
	ProcessCombineSecurityDomainsInformation,
	ProcessEnableLogging,
	ProcessLeapSecondInformation,
	ProcessFiberShadowStackAllocation,
	ProcessFreeFiberShadowStackAllocation,
	ProcessAltSystemCallInformation,
	ProcessDynamicEHContinuationTargets,
} PROCESS_INFORMATION_CLASS;

typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
	ULONG SessionId;
	ULONG SizeOfBuf;
	LPVOID Buffer;
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

typedef struct _KERNEL_USER_TIMES
{
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER ExitTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES, *PKERNEL_USER_TIMES;

typedef NTSTATUS(NTAPI *NTQUERYSYSTEMINFORMATIONEX)(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID inputBuffer, ULONG inputBufferLength, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);