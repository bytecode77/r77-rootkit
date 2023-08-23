using System.IO;

/// <summary>
/// This class implements features that are not available in .NET 3.5.
/// </summary>
public static class Helper
{
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
}