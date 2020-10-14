using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CTR.NET
{
    internal static class Tools
    {
        public static string BytesToString(byte[] bytes, bool isUnicode)
        {
            string result = "";

            if (isUnicode)
            {
                for (int i = 0; i < bytes.Length - 1; i += 2)
                {
                    if (bytes[i] == 0 && bytes[i + 1] == 0)
                    {
                        break;
                    }
                    result += BitConverter.ToChar(bytes, i);
                }
                return result;
            }
            else
            {
                return Encoding.Default.GetString(bytes);
            }
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

        public static byte[] ReadFromStream(Stream s, int length)
        {
            List<byte> output = new List<byte>();
            int alength = (int)s.Position + length;

            for (int i = (int)s.Position; i < alength; i++)
            {
                output.Add((byte)s.ReadByte());
            }

            return output.ToArray();
        }

        public static byte[] ReadFromStream(Stream s, long length)
        {
            List<byte> output = new List<byte>();
            long alength = s.Position + length;

            for (long i = s.Position; i < alength; i++)
            {
                output.Add((byte)s.ReadByte());
            }

            return output.ToArray();
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

        public static void ExtractFromFile(FileStream input, FileStream output, long offset, long size, int bufferSize = 20000000)
        {
            using (input)
            {
                input.Seek(offset, 0);

                byte[] buffer = new byte[bufferSize];

                while (input.Position < size)
                {
                    int remaining = 15000000, bytesRead;
                    while (remaining > 0 && (bytesRead = input.Read(buffer, 0, Math.Min(remaining, bufferSize))) > 0)
                    {
                        remaining -= bytesRead;
                        output.Write(buffer);
                    }
                }
                output.Close();
            }
        }
    }

    public static class ExtensionMethods
    {
        public static int IntLE(this byte[] data, int startIndex = 0) => (data[startIndex + 3] << 24) | (data[startIndex + 2] << 16) | (data[startIndex + 1] << 8) | data[startIndex];

        public static int IntBE(this byte[] data, int startIndex = 0)
        {
            return data.Length < 4
                ? (data[0] << 8) | data[1]
                : (data[startIndex] << 24) | (data[startIndex + 1] << 16) | (data[startIndex + 2] << 8) | data[startIndex + 3];
        }

        public static string Hex(this byte[] bytes)
        {
            string output = "";

            foreach (byte b in bytes)
            {
                output += b.ToString("X2");
            }

            return output;
        }

        public static byte[] Copy(this byte[] bytes, int startOffset, int endOffset)
        {
            int count = endOffset - startOffset;
            byte[] output = new byte[count];

            Buffer.BlockCopy(bytes, startOffset, output, 0, count);
            return output;
        }

        public static byte[] Combine(this byte[] a, byte[] b) => a.Concat(b).ToArray();
    }
}