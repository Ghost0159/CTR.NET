using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CTR.NET
{
    public static class Tools
    {
        public static string GetVersion(byte[] versionBytes, out int versionInt)
        {
            if (versionBytes.Length != 2)
            {
                throw new ArgumentException("Input byte array was not 2 bytes long.");
            }

            Array.Reverse(versionBytes);

            versionInt = ((versionBytes[1] & 0xff) << 8) + (versionBytes[0] & 0xff);

            return $"{(versionInt >> 10) & 0x3F}.{(versionInt >> 4) & 0x3F}.{versionInt & 0xF}";
        }

        public static byte[] ReadBytes(string pathToFile, int startOffset, int endOffset)
        {
            if (!File.Exists(pathToFile))
            {
                throw new FileNotFoundException($"File at {pathToFile} was not found.");
            }

            List<byte> bytes = new List<byte>();

            using (FileStream fs = File.OpenRead(pathToFile))
            {
                fs.Position = startOffset;

                while (fs.Position < endOffset)
                {
                    bytes.Add((byte)fs.ReadByte());
                }
            }

            return bytes.ToArray();
        }

        public static int RoundUp(int offset, int alignment)
        {
            return (int)Math.Ceiling((double)offset / alignment) * alignment;
        }

        public static int RoundUp(long offset, int alignment)
        {
            return (int)Math.Ceiling((double)offset / alignment) * alignment;
        }

        

        

        public static byte[] HashSHA256(byte[] inputData)
        {
            byte[] hash = Array.Empty<byte>();

            using (var sha256 = SHA256.Create())
            {
                hash = sha256.ComputeHash(inputData);
            }
            return hash;
        }

        public static byte[] HexToBytes(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];

            for (int i = 0; i < NumberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }

        public static void ExtractFromFile(Stream input, FileStream output, long offset, long size, int bufferSize = 20000000)
        {
            using (input)
            {
                input.Seek(offset, 0);

                byte[] buffer = new byte[bufferSize];

                while (input.Position < offset + size)
                {
                    int remaining = bufferSize, bytesRead;
                    while (remaining > 0 && (bytesRead = input.Read(buffer, 0, Math.Min(remaining, bufferSize))) > 0)
                    {
                        remaining -= bytesRead;
                        output.Write(buffer);
                    }
                }
                output.Close();
            }
        }

        public static byte[] HashSHA256Region(Stream input, long offset, long size, int bufferSize = 20000000)
        {
            using (input)
            {
                using (var sha256 = SHA256.Create())
                {
                    input.Seek(offset, 0);

                    byte[] buffer = new byte[bufferSize];

                    while (input.Position < offset + size)
                    {
                        int remaining = bufferSize, bytesRead;
                        while (remaining > 0 && (bytesRead = input.Read(buffer, 0, Math.Min(remaining, bufferSize))) > 0)
                        {
                            remaining -= bytesRead;
                            sha256.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                        }
                    }

                    sha256.TransformFinalBlock(buffer, 0, 0);
                    return sha256.Hash;
                }
            }
        }
    }

    public static class ExtensionMethods
    {
        public static int IntLE(this byte[] data, int startIndex = 0) => (data[startIndex + 3] << 24) | (data[startIndex + 2] << 16) | (data[startIndex + 1] << 8) | data[startIndex];

        public static int IntBE(this byte[] data, int startIndex = 0)
        {
            if (data.Length < 4)
            {
                return (data[0] << 8) | data[1];
            }
            else
            {
                return (data[startIndex] << 24) | (data[startIndex + 1] << 16) | (data[startIndex + 2] << 8) | data[startIndex + 3];
            }
        }

        public static byte[] ReadBytes(this Stream s, long length)
        {
            List<byte> output = new List<byte>();
            long alength = s.Position + length;

            for (long i = s.Position; i < alength; i++)
            {
                output.Add((byte)s.ReadByte());
            }

            return output.ToArray();
        }

        public static string Decode(this byte[] bytes, Encoding encoding)
        {
            string output = encoding.GetString(bytes);

            return encoding == Encoding.Unicode ? output.Replace("\u0000", "").Replace("\n", "") : output;
        }

        public static string YesNo(this bool value) => value ? "yes" : "no";

        public static string PrettifyHex(this string s, int partLength)
        {
            string output = "";
            for (var i = 0; i < s.Length; i += partLength)
            {
                output += $"{s.Substring(i, Math.Min(partLength, s.Length - i))}\n";
            }

            return output;
        }

        public static string Hex(this byte[] bytes, bool littleEndian = false)
        {
            string output = "";

            if (littleEndian)
            {
                Array.Reverse(bytes);
            }

            foreach (byte b in bytes)
            {
                output += b.ToString("X2");
            }

            return output;
        }

        public static byte[] TakeBytes(this byte[] bytes, int startOffset, int endOffset)
        {
            int count = endOffset - startOffset;
            byte[] output = new byte[count];

            Buffer.BlockCopy(bytes, startOffset, output, 0, count);
            return output;
        }

        public static byte[] Combine(this byte[] a, byte[] b) => a.Concat(b).ToArray();

        public static Stream Encrypt(this Aes cipher, byte[] data)
        {
            ICryptoTransform encryptor = cipher.CreateEncryptor(cipher.Key, cipher.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();

                    return ms;
                }
            }
        }

        public static Stream Decrypt(this Aes cipher, byte[] data)
        {
            ICryptoTransform decryptor = cipher.CreateDecryptor(cipher.Key, cipher.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();

                    return ms;
                }
            }
        }
    }
}