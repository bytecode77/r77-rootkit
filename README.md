# r77 Rootkit

## Ring 3 rootkit

This *work in progress* ring 3 rootkit hides processes, files and directories from applications in user mode. Future implementation on modules, registry, services and possibly other entities is planned.

## Visualization

Before/after the rootkit is running. Items with the "**$77**" prefix are hidden. This applies to processes, files and directories:

![](https://bytecode77.com/images/pages/r77-rootkit/taskmanager.gif)
![](https://bytecode77.com/images/pages/r77-rootkit/explorer.gif)

## Implementation

r77 uses MinHook, a hooking library that enables redirection of API calls from their original function to a custom one. This provides the opportunity to choose what, for instance, process enumerations should return and what should be hidden. In order to hook WinAPI functions globally, the rootkit DLL must be loaded as a thread into every running process. This can be done using AppInit_DLLs, DLL injection, or by combining multiple routes. Install.exe drops the DLL to %TEMP%\$77_{random}.dll and registers it in AppInit_DLLs. The drop in the example is required in order to avoid file locking while testing. However, the utilizing application can use whatever route fits best, because once the DLL is loaded into the process, its payload is running.

### AppInit_DLLs

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
```

A DLL registered in AppInit_DLLs is loaded into every process that is executed after this value was written. This also requires enabling it by setting LoadAppInit_DLLs to 1 and additionally, RequireSignedAppInit_DLLs to 0.

Setting the registry value under HKEY_LOCAL_MACHINE requires elevated privileges. After installation, the rootkit runs in user mode, however, does not require any startup logic to re-install on reboot.

Also, because the AppInit_DLLs method is commonly used by malware, security software will likely block access to this registry value. r77 is not guaranteed to work while anti-virus software is running.

## Legitimacy

Rootkits are not malicious per se. However, their reputation is considered low, because rootkits are primarily used to hide malware.

However, the same hooking techniques are used by security software in order to shield itself off from user mode processes. Such rootkits are always implemented in kernel mode to make it impossible for malware to subvert installed security software. Maximum persistence can be achieved with bios or hardware rootkits. When done correctly, they are impossible to detect or remove.

## ToDo List

This is a **work in progress / beta** state and not ready-made to be used. Following tasks are on the agenda, prior to final release:

- **Installation:** The exemplary installation app should also consider injection into running processes.
- **Deinstallation:** The installation app should detach running threads and successively delete locked DLL files.
- **Other entities:** Hiding and obscuring modules, registry keys & values, services and other entities are also primary goals.
- File hiding is disabled in x86 processes, because it is not currently stable.

## Downloads

[![](http://bytecode77.com/public/fileicons/zip.png) r77 Rootkit 0.6.0.zip](https://bytecode77.com/downloads/r77Rootkit%200.6.0.zip)

## Project Page

[![](https://bytecode77.com/public/favicon16.png) bytecode77.com/r77-rootkit](https://bytecode77.com/r77-rootkit)