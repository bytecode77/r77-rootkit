using BytecodeApi.UI;
using BytecodeApi.UI.Data;

namespace TestConsole
{
	public sealed class ConfigSystemValueWindowViewModel : ObservableObject
	{
		public ConfigSystemValueWindow View { get; set; }

		private DelegateCommand _CreateCommand;
		public DelegateCommand CreateCommand => _CreateCommand ?? (_CreateCommand = new DelegateCommand(CreateCommand_Execute));

		private bool _IsCreate;
		private string _DirectoryName;
		private string _Name;
		private string _Value;
		public bool IsCreate
		{
			get => _IsCreate;
			set => Set(ref _IsCreate, value);
		}
		public string DirectoryName
		{
			get => _DirectoryName;
			set => Set(ref _DirectoryName, value);
		}
		public string Name
		{
			get => _Name;
			set => Set(ref _Name, value);
		}
		public string Value
		{
			get => _Value;
			set => Set(ref _Value, value);
		}

		public ConfigSystemValueWindowViewModel(ConfigSystemValueWindow view)
		{
			View = view;
		}

		private void CreateCommand_Execute()
		{
			View.DialogResult = true;
		}
	}
}