using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Linq;
using System.Text;

namespace CTR.NET
{
    public static class Tools
    {
        public static string GetVersion(byte[] versionBytes, out short versionInt)
        {
            if (versionBytes.Length != 2)
            {
                throw new ArgumentException("Input byte array was not 2 bytes long.");
            }

            versionInt = versionBytes.ToInt16();

            return $"{(versionInt >> 10) & 0x3F}.{(versionInt >> 4) & 0x3F}.{versionInt & 0xF}";
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

        public static void ExtractFromStreamBuffered(Stream input, Stream output, long offset, long size, int bufferSize = 4000000)
        {
            using (output)
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

                if (output.Length > size)
                {
                    output.SetLength(size);
                }
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
        public static Int64 ToInt64(this byte[] bytes, bool isBigEndian = false)
        {
            if (isBigEndian)
            {
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(bytes);
                }
            }

            return BitConverter.ToInt64(bytes, 0);
        }

        public static Int32 ToInt32(this byte[] bytes, bool isBigEndian = false)
        {
            if (isBigEndian)
            {
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(bytes);
                }
            }

            return BitConverter.ToInt32(bytes, 0);
        }

        public static Int16 ToInt16(this byte[] bytes, bool isBigEndian = false)
        {
            if (isBigEndian)
            {
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(bytes);
                }
            }

            return BitConverter.ToInt16(bytes, 0);
        }

        public static UInt64 ToUInt64(this byte[] bytes, bool isBigEndian = false)
        {
            if (isBigEndian)
            {
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(bytes);
                }
            }

            return BitConverter.ToUInt64(bytes, 0);
        }
        
        public static UInt32 ToUInt32(this byte[] bytes, bool isBigEndian = false)
        {
            if (isBigEndian)
            {
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(bytes);
                }
            }

            return BitConverter.ToUInt32(bytes, 0);
        }

        public static UInt16 ToUInt16(this byte[] bytes, bool isBigEndian = false)
        {
            if (isBigEndian)
            {
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(bytes);
                }
            }

            return BitConverter.ToUInt16(bytes, 0);
        }

        public static float ToFloat(this byte[] bytes, bool isBigEndian = false)
        {
            if (isBigEndian)
            {
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(bytes);
                }
            }

            return BitConverter.ToSingle(bytes, 0);
        }

        public static byte[] PadRight(this byte[] input, byte padValue, int len)
        {
            var temp = Enumerable.Repeat(padValue, len).ToArray();
            for (var i = 0; i < input.Length; i++)
                temp[i] = input[i];

            return temp.ToArray();
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

        //Linq is slow, imma use this instead because yes
        public static T[] FReverse<T>(this T[] input)
        {
            T[] output = new T[input.Length];
            int index = 0;

            for (int i = input.Length - 1; i >= 0; i--)
            {
                output[index] = input[i];
                index++;
            }

            return output;
        }

        public static List<T> TakeItems<T>(this List<T> input, int startIndex, int endIndex)
        {
            List<T> output = new List<T>();

            if (startIndex > input.Count || endIndex > input.Count)
            {
                throw new ArgumentException("Start Index and End Index must refer to a location within the input list.");
            }

            for (int i = startIndex; i < endIndex; i++)
            {
                output.Add(input[i]);
            }

            return output;
        }

        public static T[] TakeItems<T>(this T[] input, int startIndex, int endIndex)
        {
            if (startIndex > input.Length || endIndex > input.Length)
            {
                throw new ArgumentException("Start Index and End Index must refer to a location within the input array.");
            }

            T[] output = new T[endIndex - startIndex];

            int index = 0;

            for (int i = startIndex; i < endIndex; i++)
            {
                output[index] = input[i];
                index++;
            }

            return output;
        }

        public static List<T> MergeWith<T>(this List<T> input, List<T> listToMergeWith)
        {
            List<T> outputList = input;

            for (int i = 0; i < listToMergeWith.Count; i++)
            {
                outputList.Add(listToMergeWith[i]);
            }

            return outputList;
        }

        public static T[] MergeWith<T>(this T[] input, T[] arrayToMergeWith)
        {
            T[] outputArray = new T[input.Length + arrayToMergeWith.Length];

            Array.Copy(input, 0, outputArray, 0, input.Length);
            Array.Copy(arrayToMergeWith, 0, outputArray, input.Length, arrayToMergeWith.Length);

            return outputArray;
        }

        public static byte[] HexToByteArray(this string hex)
        {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        public static int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }

        public static byte[] HashSHA256(this byte[] bytes)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(bytes);
            }
        }

        public static BigInteger ToUnsignedBigInt(this byte[] bigIntBytes)
        {
            return BitConverter.IsLittleEndian
                ? new BigInteger(bigIntBytes.FReverse().MergeWith(new byte[] { 0 }))
                : new BigInteger(bigIntBytes.MergeWith(new byte[] { 0 }));
        }

        public static bool IsEmpty(this DirectoryInfo dir)
        {
            if (!((dir.GetFiles().Length == 0) && (dir.GetDirectories().Length == 0)))
            {
                return false;
            }
            
            return true;
        }
    }
}   