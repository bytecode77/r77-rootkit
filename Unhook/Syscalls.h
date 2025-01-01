#include "r77mindef.h"
#ifndef _SYSCALLS_H
#define _SYSCALLS_H

LPVOID SyscallGadget;
DWORD NtCreateFileSyscallNumber;
DWORD NtQueryInformationFileSyscallNumber;
DWORD NtReadFileSyscallNumber;
DWORD NtProtectVirtualMemorySyscallNumber;

extern NTSTATUS SyscallNtCreateFile(LPHANDLE fileHandle, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, PIO_STATUS_BLOCK ioStatusBlock, PLARGE_INTEGER allocationSize, ULONG fileAttributes, ULONG shareAccess, ULONG createDisposition, ULONG createOptions, LPVOID eaBuffer, ULONG eaLength);
extern NTSTATUS SyscallNtQueryInformationFile(HANDLE fileHandle, PIO_STATUS_BLOCK ioStatusBlock, LPVOID fileInformation, ULONG length, FILE_INFORMATION_CLASS fileInformationClass);
extern NTSTATUS SyscallNtReadFile(HANDLE fileHandle, HANDLE event, PIO_APC_ROUTINE apcRoutine, LPVOID apcContext, PIO_STATUS_BLOCK ioStatusBlock, LPVOID buffer, ULONG length, PLARGE_INTEGER byteOffset, PULONG key);
extern NTSTATUS SyscallNtProtectVirtualMemory(HANDLE processHandle, LPVOID *baseAddress, PSIZE_T numberOfBytesToProtect, ULONGLONG newAccessProtection, PULONGLONG oldAccessProtection);

#endif