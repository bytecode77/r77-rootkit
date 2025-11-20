using BytecodeApi.Comparers;
using BytecodeApi.Extensions;
using Global;
using Microsoft.Win32;
using TestConsole.Model;

namespace TestConsole.Helper;

/// <summary>
/// Interface to read from and write to the r77 configuration system.
/// </summary>
public static class ConfigSystem
{
	private static readonly Dictionary<string, RegistryValueKind> Directories = new()
	{
		["startup"] = RegistryValueKind.String,
		["pid"] = RegistryValueKind.DWord,
		["process_names"] = RegistryValueKind.String,
		["paths"] = RegistryValueKind.String,
		["registry_paths"] = RegistryValueKind.String,
		["service_names"] = RegistryValueKind.String,
		["tcp_local"] = RegistryValueKind.DWord,
		["tcp_remote"] = RegistryValueKind.DWord,
		["udp"] = RegistryValueKind.DWord
	};
	/// <summary>
	/// A <see cref="bool" /> value, indicating whether the configuration system registry key exists.
	/// </summary>
	public static bool IsConfigSystemCreated
	{
		get
		{
			using RegistryKey? configKey = GetConfigSystemKey();
			return configKey != null;
		}
	}

	/// <summary>
	/// Creates the registry key HKLM\SOFTWARE\$77config, if it does not exist.
	/// This key will already be present, when r77 is installed.
	/// Otherwise, creation of the key requires elevated privileges (only once).
	/// </summary>
	/// <returns>
	/// <see langword="true" />, if the configuration system exists or was created successfully;
	/// otherwise, <see langword="false" />.
	/// </returns>
	public static bool EnsureConfigSystem()
	{
		if (IsConfigSystemCreated)
		{
			return true;
		}
		else
		{
			if (HelperDll.CreateConfigSystem())
			{
				Log.Information(
					new LogTextItem("Registry key"),
					new LogFileItem($@"HKEY_LOCAL_MACHINE\SOFTWARE\{R77Const.HidePrefix}config"),
					new LogTextItem("created.")
				);

				return true;
			}
			else
			{
				Log.Error(
					new LogTextItem("Failed to create registry key"),
					new LogFileItem($@"HKEY_LOCAL_MACHINE\SOFTWARE\{R77Const.HidePrefix}config"),
					new LogTextItem("Try to"),
					new LogLinkItem("run as administrator", () => MainWindowViewModel.Singleton?.ElevateCommand.Execute())
				);

				return false;
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
	public static RegistryKey? GetConfigSystemKey()
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
		using RegistryKey? configKey = GetConfigSystemKey();

		return Directories
			.Select(dir =>
			{
				ConfigSystemDirectory directory = new(dir.Key);

				using RegistryKey? key = configKey?.OpenSubKey(dir.Key);

				if (key != null)
				{
					directory.Entries.AddRange(
						key
							.GetValueNames()
							.OrderBy(value => value, new NaturalStringComparer())
							.Where(valueName => key.GetValueKind(valueName) == dir.Value)
							.Select(valueName => new ConfigSystemEntry(directory, dir.Value, valueName, key.GetValue(valueName)?.ToString() ?? ""))
					);
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
	public static void CreateEntry(string directoryName, string entryName, object value)
	{
		if (!EnsureConfigSystem())
		{
			return;
		}

		using RegistryKey? configKey = GetConfigSystemKey();
		using RegistryKey? key = configKey?.CreateSubKey(directoryName);

		if (key != null)
		{
			switch (Directories[directoryName])
			{
				case RegistryValueKind.String:
					if (value?.ToString() is string stringValue && !stringValue.IsNullOrWhiteSpace())
					{
						key.SetStringValue(entryName, stringValue);

						Log.Information(
							new LogTextItem("Created config system entry"),
							new LogFileItem($"{directoryName}/{entryName}"),
							new LogTextItem("="),
							new LogFileItem($"{stringValue}")
						);
					}
					return;
				case RegistryValueKind.DWord:
					if (value?.ToString().ToInt32OrNull() is int intValue)
					{
						key.SetInt32Value(entryName, intValue);

						Log.Information(
							new LogTextItem("Created config system entry"),
							new LogFileItem($"{directoryName}/{entryName}"),
							new LogTextItem("="),
							new LogFileItem($"{intValue}")
						);
					}
					else
					{
						Log.Error(
							new LogTextItem("Failed to create config system entry."),
							new LogDetailsItem("Value must be an integer.")
						);
					}
					return;
			}
		}

		Log.Error(
			new LogTextItem("Failed to create config system entry"),
			new LogFileItem($"{directoryName}/{entryName}")
		);
	}
	/// <summary>
	/// Deletes an entry from the configuration system.
	/// </summary>
	/// <param name="directoryName">The name of the config directory.</param>
	/// <param name="entryName">The name of the config entry.</param>
	public static void DeleteEntry(string directoryName, string entryName)
	{
		using RegistryKey? configKey = GetConfigSystemKey();
		using RegistryKey? key = configKey?.OpenSubKey(directoryName, true);

		if (key != null && key.GetValueNames().Contains(entryName))
		{
			key.DeleteValue(entryName);

			Log.Information(
				new LogTextItem("Deleted config system entry"),
				new LogFileItem($"{directoryName}/{entryName}")
			);
		}
		else
		{
			Log.Error(
				new LogTextItem("Failed to delete config system entry"),
				new LogFileItem($"{directoryName}/{entryName}")
			);
		}
	}
}