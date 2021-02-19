using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

/// <summary>
/// This class implements features that are not available in .NET 3.5.
/// </summary>
public static class Helper
{
	/// <summary>
	/// Determines whether the operating system is a 64-bit operating system.
	/// </summary>
	/// <returns>
	/// <see langword="true" />, if the operating system is a 64-bit operating system;
	/// otherwise, <see langword="false" />.
	/// </returns>
	public static bool Is64BitOperatingSystem()
	{
		if (IntPtr.Size == 8)
		{
			return true;
		}
		else
		{
			using (Process process = Process.GetCurrentProcess())
			{
				bool wow64;
				if (IsWow64Process(process.Handle, out wow64))
				{
					return wow64;
				}
				else
				{
					throw new Exception();
				}
			}
		}
	}
	/// <summary>
	/// Reads the bytes from a stream and writes them to another stream.
	/// </summary>
	/// <param name="stream">The stream from which to read the contents from.</param>
	/// <param name="destination">The stream to which the contents will be copied.</param>
	public static void CopyStream(Stream stream, Stream destination)
	{
		byte[] buffer = new byte[16 * 1024];
		int bytesRead;

		while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
		{
			destination.Write(buffer, 0, bytesRead);
		}
	}

	[DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool wow64Process);
}