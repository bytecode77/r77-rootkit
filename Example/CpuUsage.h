#include "r77mindef.h"
#ifndef _CPUUSAGE_H
#define _CPUUSAGE_H

VOID InitializeCpuUsage();
VOID UninitializeCpuUsage();
static DWORD WINAPI CpuUsageThreadFunc(LPVOID parameter);
VOID SetCpuUsage(DWORD quota);

#endif