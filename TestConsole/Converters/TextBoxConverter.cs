using BytecodeApi.Extensions;
using BytecodeApi.Wpf;
using System.ComponentModel;

namespace TestConsole.Converters;

public sealed class TextBoxConverter : TwoWayConverterBase<object>
{
	public TextBoxConverterMethod Method { get; set; }
	public object? DefaultValue { get; set; }

	public TextBoxConverter(TextBoxConverterMethod method)
	{
		Method = method;
	}

	public override object? Convert(object? value)
	{
		if (value == null)
		{
			return null;
		}
		else
		{
			return Method switch
			{
				TextBoxConverterMethod.Int32 => (value as int?)?.ToString(),
				_ => throw new InvalidEnumArgumentException()
			};
		}
	}
	public override object? ConvertBack(object? value)
	{
		if (value is not string str)
		{
			return null;
		}
		else
		{
			str = str.Trim();

			return Method switch
			{
				TextBoxConverterMethod.Int32 => (object?)(str.ToInt32OrNull() ?? (int?)DefaultValue),
				_ => throw new InvalidEnumArgumentException()
			};
		}
	}
}