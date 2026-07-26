#include "CpuUsage.h"

static DWORD Quota;
static DWORD CpuUsageThreadCount;
static HANDLE *CpuUsageThreads;

VOID InitializeCpuUsage()
{
	Quota = 0;

	SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);

	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);

	CpuUsageThreadCount = systemInfo.dwNumberOfProcessors;
	CpuUsageThreads = NEW_ARRAY(HANDLE, CpuUsageThreadCount);

	for (DWORD i = 0; i < CpuUsageThreadCount; i++)
	{
		CpuUsageThreads[i] = CreateThread(NULL, 0, CpuUsageThreadFunc, NULL, 0, NULL);
		SetThreadPriority(CpuUsageThreads[i], THREAD_PRIORITY_IDLE);
	}
}
VOID UninitializeCpuUsage()
{
	for (DWORD i = 0; i < CpuUsageThreadCount; i++)
	{
		TerminateThread(CpuUsageThreads[i], 0);
		CloseHandle(CpuUsageThreads[i]);
	}

	FREE(CpuUsageThreads);
}
static DWORD WINAPI CpuUsageThreadFunc(LPVOID parameter)
{
	while (TRUE)
	{
		DWORD busyTime = Quota;
		DWORD idleTime = 100 - Quota;

		for (ULONGLONG startTime = GetTickCount64(); GetTickCount64() - startTime < busyTime;)
		{
		}

		if (idleTime > 0)
		{
			Sleep(idleTime);
		}
	}

	return 0;
}
VOID SetCpuUsage(DWORD quota)
{
	Quota = quota;
}