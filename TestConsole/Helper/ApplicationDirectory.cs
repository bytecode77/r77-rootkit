using BytecodeApi;
using BytecodeApi.Extensions;
using System.IO;
using TestConsole.Model;

namespace TestConsole.Helper;

/// <summary>
/// Helper class that works on the application directory.
/// </summary>
public static class ApplicationDirectory
{
	private static readonly string[] Paths = new[]
	{
		// Probe for multiple paths to support deployment of TestConsole.exe in a sub directory.
		ApplicationBase.Path,
		new DirectoryInfo(ApplicationBase.Path).Parent?.Parent?.FullName
	}.ExceptNull().ToArray();

	/// <summary>
	/// Checks, whether a collection of files exist in the application directory.
	/// </summary>
	/// <param name="fileNames">A <see cref="string" />[] of filenames to check.</param>
	/// <param name="notFoundFileNames">When this method returns, a <see cref="string" />[] with the missing filenames.</param>
	/// <returns>
	/// <see langword="true" />, if all files were found in the application directory;
	/// otherwise, <see langword="false" />.
	/// </returns>
	public static bool FilesExist(string[] fileNames, out string[] notFoundFileNames)
	{
		notFoundFileNames = fileNames
			.Where(fileName => Paths.None(path => File.Exists(Path.Combine(path, fileName))))
			.ToArray();

		return notFoundFileNames.None();
	}
	/// <summary>
	/// Gets the full file path of a file in the application directory.
	/// </summary>
	/// <param name="fileName">The filename of the file that is located in the application directory.</param>
	/// <returns>
	/// The full path of the file, if it exists;
	/// otherwise, <see langword="null" />.
	/// </returns>
	public static string? GetFilePath(string fileName)
	{
		if (Paths.Select(path => Path.Combine(path, fileName)).FirstOrDefault(File.Exists) is string path)
		{
			return path;
		}
		else
		{
			Log.Error(
				new LogTextItem("File"),
				new LogFileItem(fileName),
				new LogTextItem("not found."),
				new LogDetailsItem("It might have been removed by antivirus software.")
			);

			return null;
		}
	}
}