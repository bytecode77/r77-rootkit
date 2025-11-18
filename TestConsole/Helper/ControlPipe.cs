using BytecodeApi;
using BytecodeApi.Extensions;
using Global;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using TestConsole.Model;

namespace TestConsole.Helper;

/// <summary>
/// Communication interface to the r77 control pipe.
/// </summary>
public static class ControlPipe
{
	/// <summary>
	/// A <see cref="bool" /> value, indicating whether the control pipe is available.
	/// </summary>
	public static bool IsAvailable
	{
		get
		{
			using NamedPipeClientStream pipe = new(".", R77Const.ControlPipeName, PipeDirection.InOut, PipeOptions.None, TokenImpersonationLevel.Impersonation);

			try
			{
				pipe.Connect(500);
				return true;
			}
			catch
			{
				return false;
			}
		}
	}

	/// <summary>
	/// Writes a control code to the control pipe.
	/// </summary>
	/// <param name="controlCode">The <see cref="ControlCode" /> to write.</param>
	public static void Write(ControlCode controlCode)
	{
		Write(controlCode, null, null);
	}
	/// <summary>
	/// Writes a control code to the control pipe.
	/// </summary>
	/// <param name="controlCode">The <see cref="ControlCode" /> to write.</param>
	/// <param name="data">A <see cref="byte" />[] with data to be sent in addition to the control code.</param>
	/// <param name="dataString">A <see cref="string" /> representation of <paramref name="data" /> to be displayed in the UI.</param>
	public static void Write(ControlCode controlCode, byte[]? data, string? dataString)
	{
		// Use this as an example in your own implementation when connecting to the control pipe

		using NamedPipeClientStream pipe = new(".", R77Const.ControlPipeName, PipeDirection.InOut, PipeOptions.None, TokenImpersonationLevel.Impersonation);

		if (CSharp.Try(() => pipe.Connect(1000)))
		{
			using (BinaryWriter writer = new(pipe))
			{
				writer.Write((int)controlCode);
				if (data?.Length > 0) writer.Write(data);
			}

			Log.Information(
				new LogTextItem("Sent"),
				new LogFileItem(controlCode.GetDescription() ?? ""),
				new LogTextItem("to control pipe" + (dataString == null ? null : " (Parameter: " + dataString + ")") + ".")
			);
		}
		else
		{
			Log.Error(
				new LogTextItem("Sending command to control pipe failed."),
				new LogDetailsItem("Is the r77 service running?")
			);
		}
	}
}