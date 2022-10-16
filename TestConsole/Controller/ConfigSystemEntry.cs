using BytecodeApi.UI.Data;

namespace TestConsole
{
	/// <summary>
	/// Represents an entry in the configuration system.
	/// </summary>
	public sealed class ConfigSystemEntry : ObservableObject
	{
		private string _Name;
		private string _Value;
		/// <summary>
		/// Gets or sets the name of the registry value that represents this entry.
		/// </summary>
		public string Name
		{
			get => _Name;
			set => Set(ref _Name, value);
		}
		/// <summary>
		/// Gets or sets the contents of the registry value that represents this entry.
		/// </summary>
		public string Value
		{
			get => _Value;
			set => Set(ref _Value, value);
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="ConfigSystemEntry" /> class.
		/// </summary>
		/// <param name="name">The name of the registry value that represents this entry.</param>
		/// <param name="value">The contents of the registry value that represents this entry.</param>
		public ConfigSystemEntry(string name, string value)
		{
			Name = name;
			Value = value;
		}
	}
}