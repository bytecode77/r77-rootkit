using BytecodeApi.UI.Data;
using System.Collections.ObjectModel;

namespace TestConsole
{
	/// <summary>
	/// Represents a directory in the configuration system (e.g. "pid" or "paths").
	/// </summary>
	public sealed class ConfigSystemDirectory : ObservableObject
	{
		private string _Name;
		private ObservableCollection<ConfigSystemEntry> _Entries;
		/// <summary>
		/// Gets or sets the name of the registry key that represents this directory.
		/// </summary>
		public string Name
		{
			get => _Name;
			set => Set(ref _Name, value);
		}
		/// <summary>
		/// Gets or sets a collection of entries in this directory.
		/// </summary>
		public ObservableCollection<ConfigSystemEntry> Entries
		{
			get => _Entries;
			set => Set(ref _Entries, value);
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="ConfigSystemDirectory" /> class.
		/// </summary>
		/// <param name="name">The name of the registry key that represents this directory.</param>
		public ConfigSystemDirectory(string name)
		{
			Name = name;
			Entries = new ObservableCollection<ConfigSystemEntry>();
		}
	}
}