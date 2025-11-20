using BytecodeApi.Wpf;
using TestConsole.Model;

namespace TestConsole;

public sealed class ConfigSystemEntryDialogViewModel : ViewModel
{
	public ConfigSystemEntryDialog View { get; set; }

	private DelegateCommand? _SaveCommand;
	public DelegateCommand SaveCommand => _SaveCommand ??= new(SaveCommand_Execute);

	private bool _IsCreate;
	private string? _Name;
	private string? _Value;
	public bool IsCreate
	{
		get => _IsCreate;
		set => Set(ref _IsCreate, value);
	}
	public string? Name
	{
		get => _Name;
		set => Set(ref _Name, value);
	}
	public string? Value
	{
		get => _Value;
		set => Set(ref _Value, value);
	}

	public ConfigSystemEntryDialogViewModel(ConfigSystemEntryDialog view)
	{
		View = view;
	}

	private void SaveCommand_Execute()
	{
		View.DialogResult = true;
	}
}