using System.Collections.ObjectModel;

namespace TestConsole.Model;

/// <summary>
/// Represents a directory in the configuration system (e.g. "pid" or "paths").
/// </summary>
public sealed class ConfigSystemDirectory
{
	/// <summary>
	/// Gets or sets the name of the registry key that represents this directory.
	/// </summary>
	public string Name { get; set; }
	/// <summary>
	/// Gets or sets a collection of entries in this directory.
	/// </summary>
	public ObservableCollection<ConfigSystemEntry> Entries { get; set; }

	/// <summary>
	/// Initializes a new instance of the <see cref="ConfigSystemDirectory" /> class.
	/// </summary>
	/// <param name="name">The name of the registry key that represents this directory.</param>
	public ConfigSystemDirectory(string name)
	{
		Name = name;
		Entries = [];
	}
}