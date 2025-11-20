using Microsoft.Win32;

namespace TestConsole.Model;

/// <summary>
/// Represents an entry in the configuration system.
/// </summary>
public sealed class ConfigSystemEntry
{
	/// <summary>
	/// Gets the parent <see cref="ConfigSystemDirectory" /> of this entry.
	/// </summary>
	public ConfigSystemDirectory Directory { get; private set; }
	/// <summary>
	/// Gets the <see cref="RegistryValueKind" /> of the registry value that represents this entry.
	/// </summary>
	public RegistryValueKind Type { get; private set; }
	/// <summary>
	/// Gets or sets the name of the registry value that represents this entry.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Gets or sets the contents of the registry value that represents this entry.
	/// </summary>
	public string Value { get; set; }

	/// <summary>
	/// Initializes a new instance of the <see cref="ConfigSystemEntry" /> class.
	/// </summary>
	/// <param name="directory">The parent <see cref="ConfigSystemDirectory" /> of this entry.</param>
	/// <param name="type">The <see cref="RegistryValueKind" /> of the registry value that represents this entry.</param>
	/// <param name="name">The name of the registry value that represents this entry.</param>
	/// <param name="value">The contents of the registry value that represents this entry.</param>
	public ConfigSystemEntry(ConfigSystemDirectory directory, RegistryValueKind type, string name, string value)
	{
		Directory = directory;
		Type = type;
		Name = name;
		Value = value;
	}
}