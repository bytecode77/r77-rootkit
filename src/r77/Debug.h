/// <summary>
/// Helper class for quick debugging in the development process.
/// </summary>
class Debug
{
public:
	/// <summary>
	/// Displays a MessageBox. This will pause the caling thread.
	/// </summary>
	/// <param name="title">The title to display in the MessageBox.</param>
	/// <param name="str">The text to display in the MessageBox.</param>
	static void Message(LPCWSTR title, LPCWSTR str);
	/// <summary>
	/// Displays a MessageBox. This will pause the caling thread.
	/// </summary>
	/// <param name="title">The title to display in the MessageBox.</param>
	/// <param name="str">The text to display in the MessageBox.</param>
	static void Message(LPCWSTR title, UNICODE_STRING str);
	/// <summary>
	/// Displays a MessageBox. This will pause the caling thread.
	/// </summary>
	/// <param name="title">The title to display in the MessageBox.</param>
	/// <param name="number">The 32-bit number to display in the MessageBox.</param>
	static void Message(LPCWSTR title, ULONG number);
	/// <summary>
	/// Displays a MessageBox. This will pause the caling thread.
	/// </summary>
	/// <param name="title">The title to display in the MessageBox.</param>
	/// <param name="number">The 64-bit number to display in the MessageBox.</param>
	static void Message(LPCWSTR title, ULONGLONG number);
	/// <summary>
	/// Appends text to a logfile.
	/// </summary>
	/// <param name="path">The path to a file to write to. The file is created, if it doesn't exist.</param>
	/// <param name="text">The text to write to the file.</param>
	static void Log(LPCSTR path, LPCSTR text);
};