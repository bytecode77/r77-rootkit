# r77 Rootkit

## Ring 3 rootkit

r77 is a ring 3 Rootkit that hides following entities from all processes:

 - Files, directories, junctions, named pipes, scheduled tasks
 - Processes
 - CPU usage
 - Registry keys & values
 - Services
 - TCP & UDP connections

It is compatible with Windows 7 and Windows 10 in both x64 and x86 editions.

## Hiding by prefix

All entities where the name starts with `"$77"` are hidden.

![](https://bytecode77.com/images/pages/r77-rootkit/hiding.png)

## Configuration System

The dynamic configuration system allows to hide processes by **PID** and by **name**, file system items by **full path**, TCP & UDP connections of specific ports, etc.

![](https://bytecode77.com/images/pages/r77-rootkit/config.png)

The configuration is stored in `HKEY_LOCAL_MACHINE\SOFTWARE\$77config` and is writable by any process without elevated privileges. The DACL of this key is set to grant full access to any user.

The `$77config` key is hidden when RegEdit is injected with the rootkit.

## Installer

r77 is deployable using a single file `"Install.exe"`. It installs the r77 service that starts before the first user is logged on. This background process injects all currently running processes, as well as processes that spawn later. Two processes are needed to inject both 32-bit and 64-bit processes. Both processes are hidden by ID using the configuration system.

`Uninstall.exe` removes r77 from the system and gracefully detaches the rootkit from all processes.

## Child process hooking

When a process creates a child process, the new process is injected before it can run any of its own instructions. The function `NtResumeThread` is always called when a new process is created. Therefore, it's a suitable target to hook. Because a 32-bit process can spawn a 64-bit child process and vice versa, the r77 service provides a named pipe to handle child process injection requests.

In addition, there is a periodic check every 100ms for new processes that might have been missed by child process hooking. This is necessary because some processes are protected and cannot be injected, such as services.exe.

## In-memory injection

The rootkit DLL (`r77-x86.dll` and `r77-x64.dll`) can be injected into a process from memory and doesn't need to be stored on the disk. **Reflective DLL injection** is used to achieve this. The DLL provides an exported function that when called, loads all sections of the DLL, handles dependency loading and relocations, and finally calls `DllMain`.

## Fileless persistence

The rootkit resides in the system memory and does not write any files to the disk. This is achieved in multiple stages.

**Stage 1:** The installer creates two scheduled tasks for the 32-bit and the 64-bit r77 service. The scheduled tasks start `powershell.exe` with following command line:

```
[Reflection.Assembly]::Load([Microsoft.Win32.Registry]::LocalMachine.OpenSubkey('SOFTWARE').GetValue('$77stager')).EntryPoint.Invoke($Null,$Null)
```

The command is inline and does not require a .ps1 script. Here, the .NET Framework capabilities of PowerShell are utilized in order to load a C# executable from the registry and execute it in memory. For this, `Assembly.Load().EntryPoint.Invoke()` is used.

![](https://bytecode77.com/images/pages/r77-rootkit/scheduled-task.png)
![](https://bytecode77.com/images/pages/r77-rootkit/stager.png)

**Stage 2:** The executed C# binary is the stager. It will create the r77 service processes using process hollowing. The r77 service is a native executable compiled in both 32-bit and 64-bit separately. The parent process is spoofed and set to winlogon.exe for additional obscurity. In addition, the two processes are hidden by ID and are not visible in the task manager.

![](https://bytecode77.com/images/pages/r77-rootkit/service.png)

No executables or DLL's are ever stored on the disk. The stager is stored in the registry and loads the r77 service executable from its resources.

The PowerShell and .NET dependencies are present in a fresh installation of Windows 7 and Windows 10. Please review the [documentation](https://bytecode77.com/downloads/r77%20Rootkit%20Technical%20Documentation.pdf) for a complete description of the fileless initialization.

## Hooking

Detours is used to hook several functions from `ntdll.dll`. These low-level syscall wrappers are called by **any** WinAPI or framework implementation.

 - NtQuerySystemInformation
 - NtResumeThread
 - NtQueryDirectoryFile
 - NtQueryDirectoryFileEx
 - NtEnumerateKey
 - NtEnumerateValueKey
 - EnumServiceGroupW
 - EnumServicesStatusExW
 - NtDeviceIoControlFile

The only exception is `advapi32.dll` and `sechost.dll`. These functions are hooked to hide services. This is because the actual service enumeration happens in services.exe, which cannot be injected.

## AV/EDR evasion

Several AV and EDR evasion techniques are in use:

- **AMSI bypass:** The PowerShell inline script disables AMSI by patching `amsi.dll!AmsiScanBuffer` to always return `AMSI_RESULT_CLEAN`.
- **DLL unhooking:** Since EDR solutions monitor API calls by hooking `ntdll.dll`, these hooks need to be removed by loading a fresh copy of `ntdll.dll` from disk and restoring the original section. Otherwise, process hollowing would be detected.

## Test environment

The Test Console can be used to inject r77 to or detach r77 from individual processes.

![](https://bytecode77.com/images/pages/r77-rootkit/testconsole.png)

## Technical Documentation

Please read the [technical documentation](https://bytecode77.com/downloads/r77%20Rootkit%20Technical%20Documentation.pdf) to get a comprehensive and full overview of r77 and its internals, and how to deploy and integrate it.

## Downloads

[![](https://bytecode77.com/public/fileicons/zip.png) r77 Rootkit 1.3.0.zip](https://bytecode77.com/downloads/r77Rootkit%201.3.0.zip)
(**ZIP Password:** bytecode77)<br />
[![](https://bytecode77.com/public/fileicons/pdf.png) Technical Documentation](https://bytecode77.com/downloads/r77%20Rootkit%20Technical%20Documentation.pdf)

## Project Page

[![](https://bytecode77.com/public/favicon16.png) bytecode77.com/r77-rootkit](https://bytecode77.com/r77-rootkit)