using BytecodeApi.UI;
using BytecodeApi.UI.Extensions;
using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace TestConsole
{
	public static class AppResources
	{
		public static Image Image(string name, int width, int height, Thickness margin, bool noDisabledEffect)
		{
			BitmapImage imageSource = new BitmapImage();
			imageSource.BeginInit();
			imageSource.UriSource = new Uri(Packs.Application + "/TestConsole;component/Resources/" + name + ".png");
			imageSource.EndInit();

			Image image = new Image
			{
				Source = imageSource,
				Width = width,
				Height = height,
				Margin = margin,
				Stretch = Stretch.Uniform
			};

			if (noDisabledEffect)
			{
				image.Style = Application.Current.FindResource<Style>("ImageNoDisabledEffect");
			}

			return image;
		}
	}
}