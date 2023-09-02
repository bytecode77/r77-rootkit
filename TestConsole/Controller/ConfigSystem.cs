using BytecodeApi.Comparers;
using BytecodeApi.Extensions;
using Global;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Linq;

namespace TestConsole
{
	/// <summary>
	/// Interface to read from and write to the r77 configuration system.
	/// </summary>
	public static class ConfigSystem
	{
		private static readonly Dictionary<string, RegistryValueKind> Directories = new Dictionary<string, RegistryValueKind>()
		{
			["startup"] = RegistryValueKind.String,
			["pid"] = RegistryValueKind.DWord,
			["process_names"] = RegistryValueKind.String,
			["paths"] = RegistryValueKind.String,
			["service_names"] = RegistryValueKind.String,
			["tcp_local"] = RegistryValueKind.DWord,
			["tcp_remote"] = RegistryValueKind.DWord,
			["udp"] = RegistryValueKind.DWord
		};

		/// <summary>
		/// Creates the registry key HKLM\SOFTWARE\$77config, if it does not exist.
		/// This key will already be present, when r77 is installed.
		/// Otherwise, creation of the key requires elevated privileges (only once).
		/// </summary>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> EnsureConfigSystem()
		{
			using (RegistryKey key = GetConfigSystemKey())
			{
				if (key == null)
				{
					if (HelperDll.CreateConfigSystem())
					{
						yield return new LogMessage
						(
							LogMessageType.Information,
							new LogTextItem("Registry key"),
							new LogFileItem($@"HKEY_LOCAL_MACHINE\SOFTWARE\{R77Const.HidePrefix}config"),
							new LogTextItem("created.")
						);
					}
					else
					{
						yield return new LogMessage
						(
							LogMessageType.Error,
							new LogTextItem("Failed to create registry key"),
							new LogFileItem($@"HKEY_LOCAL_MACHINE\SOFTWARE\{R77Const.HidePrefix}config"),
							new LogTextItem("Try to"),
							new LogLinkItem("run as administrator", () => MainWindowViewModel.Singleton.ElevateCommand.Execute())
						);
					}
				}
			}
		}
		/// <summary>
		/// Returns the registry key that represents the configuration system.
		/// Call <see cref="EnsureConfigSystem" /> to ensure that this key exists.
		/// </summary>
		/// <returns>
		/// The registry key that represents the configuration system.
		/// </returns>
		public static RegistryKey GetConfigSystemKey()
		{
			return Registry.LocalMachine.OpenSubKey($@"SOFTWARE\{R77Const.HidePrefix}config", true);
		}
		/// <summary>
		/// Retrieves the r77 configuration system.
		/// </summary>
		/// <returns>
		/// A new <see cref="ConfigSystemDirectory" />[] with all configuration system entries.
		/// </returns>
		public static ConfigSystemDirectory[] GetConfigSystem()
		{
			return Directories
				.Select(kvp =>
				{
					ConfigSystemDirectory directory = new ConfigSystemDirectory(kvp.Key);

					using (RegistryKey configKey = GetConfigSystemKey())
					using (RegistryKey key = configKey?.OpenSubKey(kvp.Key))
					{
						if (key != null)
						{
							directory.Entries.AddRange
							(
								key
									.GetValueNames()
									.OrderBy(value => value, new NaturalStringComparer())
									.Where(valueName => key.GetValueKind(valueName) == kvp.Value)
									.Select(valueName => new ConfigSystemEntry(valueName, key.GetValue(valueName).ToString()))
							);
						}
					}

					return directory;
				})
				.ToArray();
		}
		/// <summary>
		/// Creates an entry in the configuration system.
		/// </summary>
		/// <param name="directoryName">The name of the config directory.</param>
		/// <param name="entryName">The name of the config entry.</param>
		/// <param name="value">The value of the entry.</param>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> CreateEntry(string directoryName, string entryName, object value)
		{
			foreach (LogMessage logMessage in EnsureConfigSystem())
			{
				yield return logMessage;
			}

			using (RegistryKey configKey = GetConfigSystemKey())
			using (RegistryKey key = configKey?.CreateSubKey(directoryName))
			{
				if (key != null)
				{
					switch (Directories[directoryName])
					{
						case RegistryValueKind.String:
							if (value?.ToString() is string stringValue && !stringValue.IsNullOrEmpty())
							{
								key.SetStringValue(entryName, stringValue);

								yield return new LogMessage
								(
									LogMessageType.Information,
									new LogTextItem("Created config system entry"),
									new LogFileItem($"{directoryName}/{entryName}"),
									new LogTextItem("="),
									new LogFileItem($"{stringValue}")
								);
							}
							else
							{
								yield return new LogMessage
								(
									LogMessageType.Error,
									new LogTextItem("Created config system entry failed."),
									new LogDetailsItem("Value must not be empty.")
								);
							}
							yield break;
						case RegistryValueKind.DWord:
							if (value?.ToString().ToInt32OrNull() is int intValue)
							{
								key.SetInt32Value(entryName, intValue);

								yield return new LogMessage
								(
									LogMessageType.Information,
									new LogTextItem("Created config system entry"),
									new LogFileItem($"{directoryName}/{entryName}"),
									new LogTextItem("="),
									new LogFileItem($"{intValue}")
								);
								yield break;
							}
							else
							{
								yield return new LogMessage
								(
									LogMessageType.Error,
									new LogTextItem("Created config system entry failed."),
									new LogDetailsItem("Value must be a valid integer.")
								);
							}
							yield break;
					}

					yield return new LogMessage
					(
						LogMessageType.Error,
						new LogTextItem("Failed to create config system entry"),
						new LogFileItem($"{directoryName}/{entryName}")
					);
				}
			}
		}
		/// <summary>
		/// Deletes an entry from the configuration system.
		/// </summary>
		/// <param name="directoryName">The name of the config directory.</param>
		/// <param name="entryName">The name of the config entry.</param>
		/// <returns>
		/// An enumerable of <see cref="LogMessage" /> entries to be displayed in the log view.
		/// </returns>
		public static IEnumerable<LogMessage> DeleteEntry(string directoryName, string entryName)
		{
			using (RegistryKey configKey = GetConfigSystemKey())
			using (RegistryKey key = configKey?.OpenSubKey(directoryName, true))
			{
				if (key != null && key.GetValueNames().Contains(entryName))
				{
					key.DeleteValue(entryName);
					yield return new LogMessage
					(
						LogMessageType.Information,
						new LogTextItem("Deleted config system entry"),
						new LogFileItem($"{directoryName}/{entryName}")
					);
				}
				else
				{
					yield return new LogMessage
					(
						LogMessageType.Error,
						new LogTextItem("Failed to delete config system entry"),
						new LogFileItem($"{directoryName}/{entryName}")
					);
				}
			}
		}
	}
}