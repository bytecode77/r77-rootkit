using TestConsole.Model;

namespace TestConsole;

public sealed class AboutDialogViewModel : ViewModel
{
	public AboutDialog View { get; set; }

	public AboutDialogViewModel(AboutDialog view)
	{
		View = view;
	}
}