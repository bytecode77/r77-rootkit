using BytecodeApi.Wpf;
using BytecodeApi.Wpf.Extensions;
using System.Windows;
using System.Windows.Controls;

namespace TestConsole.Controls;

public class LoadingOverlay : ContentControl
{
	public static readonly DependencyProperty ShowBusyIndicatorProperty = DependencyPropertyEx.Register(nameof(ShowBusyIndicator));
	public bool ShowBusyIndicator
	{
		get => this.GetValue<bool>(ShowBusyIndicatorProperty);
		set => SetValue(ShowBusyIndicatorProperty, value);
	}
}