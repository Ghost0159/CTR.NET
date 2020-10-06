using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace CTR_LIB
{
  static class Tools
  {
    public static string BytesToString(byte[] bytes, bool decode, bool isUnicode) 
    {
      string result = "";
      
      if (decode)
      {
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
        }
        else 
        {
          result = Encoding.Default.GetString(bytes);
        }
      }
      else
      {
        foreach (byte b in bytes)
        {
          result += b.ToString("X2");
        }
      }
      
      return result;
    }
    
    public static byte[] ReadBytes(string pathToFile, Int32 startOffset, Int32 endOffset) 
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
      return (int)Math.Ceiling((double)offset / (double)alignment) * alignment;
    }
    
    public static byte[] ReadFromStream(Stream s, Int32 length)
    {
      List<byte> output = new List<byte>();
      Int32 alength = (Int32)s.Position + length;
      
      for (int i = (int)s.Position; i < alength; i++)
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
    
    public static byte[] HexToBytes(String hex)
    {
      int NumberChars = hex.Length;
      byte[] bytes = new byte[NumberChars / 2];
      
      for (int i = 0; i < NumberChars; i += 2)
      {
        bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
      }
      
      return bytes;
    }
  }
  
  static class ExtensionMethods
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
    
    public static string Hex(this byte[] bytes)
    {
      string output = "";
      
      foreach (byte b in bytes)
      {
        output += b.ToString("X2");
      }
      
      return output;
    }
    
    public static byte[] Copy(this byte[] bytes, Int32 startOffset, Int32 endOffset)
    {
      int count = endOffset - startOffset;
      byte[] output = new byte[count];
      
      Buffer.BlockCopy(bytes, startOffset, output, 0, count);
      return output;
    }
    
    public static byte[] Combine(this byte[] a, byte[] b) => a.Concat(b).ToArray();
  }
}