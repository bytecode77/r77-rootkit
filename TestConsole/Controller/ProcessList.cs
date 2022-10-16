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
		/// <para>Helper32.exe and Helper64.exe need to be invoked to retrieve the process list, because some information can only be accessed by a process of matching bitness.</para>
		/// </summary>
		/// <returns>
		/// A new <see cref="ProcessView" />[] with all running processes.
		/// </returns>
		public static ProcessView[] GetProcesses()
		{
			// Invoke Helper32.exe and Helper64.exe to retrieve the process list.
			// Because the process list contains r77 specific information, the bitness of the enumerating process needs to match
			// that of the enumerated process to retrieve this information.

			string helper32Path = App.GetFilePath("Helper32.exe", out _);
			string helper64Path = App.GetFilePath("Helper64.exe", out _);
			if (helper32Path == null || helper64Path == null) return new ProcessView[0];

			string[] helperExecutables = Environment.Is64BitOperatingSystem ?
				new[] { helper32Path, helper64Path } :
				new[] { helper32Path };

			return helperExecutables
				.Select(fileName => Path.Combine(ApplicationBase.Path, fileName))
				.Where(path => File.Exists(path))
				.Select(path => CSharp.Try(() => ProcessEx.ReadProcessOutput(path, "-list", false, true))) // Execute and read console output
				.ToArray()
				.Select(str => str?.SplitToLines())
				.ExceptNull()
				.SelectMany()
				.Where(line => !line.IsNullOrWhiteSpace())
				.Select(line => line.Split('|').ToArray())
				.Select(line =>
				{
					// Split console output to lines, then by '|' and parse content.
					ProcessView process = new ProcessView
					{
						Id = line[0].ToInt32OrDefault(),
						Name = line[1],
						Is64Bit = line[3] == "32" ? false : line[3] == "64" ? true : (bool?)null,
						IntegrityLevel = line[4].ToInt32OrNull() is int integrityLevel && integrityLevel != -1 ? (ProcessIntegrityLevel?)integrityLevel : null,
						User = line[5],
						Icon = GetIcon(line[1], line[2]),
						IsInjected = line[6] == "1",
						IsR77Service = line[7] == "1",
						IsHelper = line[8] == "1",
						IsHiddenById = line[9] == "1"
					};

					process.CanInject =
						process.Is64Bit != null &&
						process.IntegrityLevel != null &&
						(ApplicationBase.Process.IsElevated || process.IntegrityLevel <= ProcessIntegrityLevel.Medium);

					return process;
				})
				.Where(process => CSharp.EqualsNone(process.Id, 0, 4)) // Exclude "System" and "System Idle Process"
				.GroupBy(process => process.Id)
				.Where(group => group.Count() == helperExecutables.Length)
				.Select(group => group.OrderByDescending(p => p.IsInjected || p.IsR77Service || p.IsHelper).First())
				.OrderBy(process => process.Name, StringComparer.OrdinalIgnoreCase)
				.ThenBy(process => process.Id)
				.ToArray();

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
		/// <para>Helper32.exe or Helper64.exe is invoked to perform injection.</para>
		/// </summary>
		/// <param name="process">The process to inject.</param>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> Inject(ProcessView process)
		{
			string helperPath = App.GetFilePath(process.Is64Bit == true ? "Helper64.exe" : "Helper32.exe", out LogMessage helperPathLogMessage);
			if (helperPath == null)
			{
				yield return helperPathLogMessage;
				yield break;
			}

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

			if (ProcessEx.Execute(helperPath, $"-inject {process.Id} \"{dllPath}\"") == 0)
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
				if (process.Name.StartsWith(Config.HidePrefix)) reason = $"The filename starts with '{Config.HidePrefix}'.";
				else if (process.IsR77Service) reason = "The process is the r77 service process.";
				else if (process.IsHelper) reason = "The process is a helper process.";
				else if (process.IntegrityLevel < ProcessIntegrityLevel.Medium) reason = "Sandboxes are not supported";
				else reason = Path.GetFileName(helperPath) + " returned an error code.";

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
		/// <para>Helper32.exe or Helper64.exe is invoked to call the detach function pointer found in the r77 header.</para>
		/// </summary>
		/// <param name="process">The process to detach.</param>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> Detach(ProcessView process)
		{
			string helperPath = App.GetFilePath(process.Is64Bit == true ? "Helper64.exe" : "Helper32.exe", out LogMessage helperPathLogMessage);
			if (helperPath == null)
			{
				yield return helperPathLogMessage;
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

			if (ProcessEx.Execute(helperPath, $"-detach {process.Id}") == 0)
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
		/// <para>Both Helper32.exe and Helper64.exe are invoked using the "-inject -all" commandline.</para>
		/// </summary>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> InjectAll()
		{
			int injectedCount = GetInjectedCount();

			string helper32Path = App.GetFilePath("Helper32.exe", out LogMessage helper32PathLogMessage);
			if (helper32Path == null)
			{
				yield return helper32PathLogMessage;
				yield break;
			}

			string helper64Path = null;
			if (Environment.Is64BitOperatingSystem)
			{
				helper64Path = App.GetFilePath("Helper64.exe", out LogMessage helper64PathLogMessage);
				if (helper64Path == null)
				{
					yield return helper64PathLogMessage;
					yield break;
				}
			}

			string dll32Path = App.GetFilePath("r77-x86.dll", out LogMessage dll32PathLogMessage);
			if (dll32Path == null)
			{
				yield return dll32PathLogMessage;
				yield break;
			}

			string dll64Path = null;
			if (Environment.Is64BitOperatingSystem)
			{
				dll64Path = App.GetFilePath("r77-x64.dll", out LogMessage dll64PathLogMessage);
				if (dll64Path == null)
				{
					yield return dll64PathLogMessage;
					yield break;
				}
			}

			if (ProcessEx.Execute(helper32Path, $"-inject -all \"{dll32Path}\"") != 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Error,
					new LogFileItem(Path.GetFileName(helper32Path)),
					new LogTextItem("returned an error code.")
				);
			}

			if (Environment.Is64BitOperatingSystem && ProcessEx.Execute(helper64Path, $"-inject -all \"{dll64Path}\"") != 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Error,
					new LogFileItem(Path.GetFileName(helper64Path)),
					new LogTextItem("returned an error code.")
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
		/// <para>Both Helper32.exe and Helper64.exe are invoked using the "-detach -all" commandline.</para>
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

			string helper32Path = App.GetFilePath("Helper32.exe", out LogMessage helper32PathLogMessage);
			if (helper32Path == null)
			{
				yield return helper32PathLogMessage;
				yield break;
			}

			string helper64Path = null;
			if (Environment.Is64BitOperatingSystem)
			{
				helper64Path = App.GetFilePath("Helper64.exe", out LogMessage helper64PathLogMessage);
				if (helper64Path == null)
				{
					yield return helper64PathLogMessage;
					yield break;
				}
			}

			if (ProcessEx.Execute(helper32Path, "-detach -all") != 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Error,
					new LogFileItem(Path.GetFileName(helper32Path)),
					new LogTextItem("returned an error code.")
				);
			}

			if (Environment.Is64BitOperatingSystem && ProcessEx.Execute(helper64Path, "-detach -all") != 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Error,
					new LogFileItem(Path.GetFileName(helper64Path)),
					new LogTextItem("returned an error code.")
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

					if (process.Name.StartsWith(Config.HidePrefix))
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