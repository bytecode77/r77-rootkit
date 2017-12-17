# r77 Rootkit

This *work in progress* ring 3 rootkit hides processes, files and directories
from applications in user mode. Future implementation on modules, registry,
services and possibly other entities is planned.

## A quick visualization

Before/after rootkit is running. Items with the "**$77**" prefix are hidden.

![](https://bytecode77.com/images/sites/hacking/payloads/r77-rootkit/taskmanager.gif)
![](https://bytecode77.com/images/sites/hacking/payloads/r77-rootkit/explorer.gif)

## How it works

r77 uses MinHook, a hooking library that enables redirection of API calls from
their original function to a custom one. This provides the opportunity to choose
what, for instance, process enumerations should return and what should be
hidden. In order to hook WinAPI functions globally, the rootkit DLL must be
loaded as a thread in every running process. This can be done through
AppInit_DLLs as well as DLL injection or using multiple routes. Install.exe
drops the DLL to `%TEMP%\$77_{GUID}.dll` and registers it in AppInit_DLLs. The
drop is required in the example in order to avoid file locking while testing.
However, the utilizing application can use whatever route fits best, because
once the DLL is loaded into the process, its payload is running.

## AppInit_DLLs

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
```

A DLL registered in `AppInit_DLLs` is loaded into every process that is executed
from this point. This also requires enabling it by setting `LoadAppInit_DLLs` to
1 and additionally, `RequireSignedAppInit_DLLs` to 0, because the rootkit is not
signed.

Setting the registry value under `HKEY_LOCAL_MACHINE` requires elevated
privileges. After installation, the rootkit runs in user mode, however does not
require any startup logic to re-install on reboot. A ring 0 rootkit in this
instance would be a kernel mode driver (*.sys file) that also requires
administrator privileges when installing.

Also, because the AppInit_DLLs method is commonly used by malware, security
software will likely block access to this registry value. r77 is not guaranteed
to work while anti-virus software is running.

## Legitimacy

Rootkits are not illegal software. However, their reputation is considered low,
because rootkits are primarily used to hide malware. So, at this point, I would
like to point out that this is for educational / PoC purposes and I'm not
responsible for developers misusing it.

However, high quality rootkits *are* used by security software in order to
protect them from malware. Such rootkits are always implemented in kernel mode
to make it impossible for malware to subvert installed security software.
Maximum persistence can be achieved with ring -3 rootkits that are implemented
in hardware itself. When done correctly, they cannot be removed in any way.
These usually are BIOS firmware rootkits that add persistance by blocking
installation attempts of the BIOS firmware.

## ToDo

This is a **work in progress / beta** state and is not complete. Following tasks
are on the agenda, prior to final release:

1. **Installation:** The exemplary installation app should also consider injection into running processes.
2. **Deinstallation:** The installation app should detach running threads and successively delete locked DLL files.
3. **Other entities:** Hiding and obscuring modules, registry keys & values, services and other entities are also primary goals.
4. File hiding is disabled in x86 processes, because it is currently unstable.

## Downloads

[![](https://bytecode77.com/images/shared/fileicons/zip.png) r77 Rootkit 0.6.0 Binaries.zip](https://bytecode77.com/downloads/hacking/payloads/r77%20Rootkit%200.6.0%20Binaries.zip)

## Project Page

[![](https://bytecode77.com/images/shared/favicon16.png) bytecode77.com/hacking/payloads/r77-rootkit](https://bytecode77.com/hacking/payloads/r77-rootkit)