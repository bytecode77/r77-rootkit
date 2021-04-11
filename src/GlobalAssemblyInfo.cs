using System.Reflection;

[assembly: AssemblyVersion("1.1.0")]
[assembly: AssemblyFileVersion("1.1.0")]
[assembly: AssemblyCopyright("© bytecode77, 2021.")]

namespace Global
{
	// These constants must match the preprocessor definitions in r77api.h
	public static class Config
	{
		public const string HidePrefix = "$77";
		public const ushort R77ServiceSignature = 0x7273;
		public const ushort R77HelperSignature = 0x7268;
	}
}