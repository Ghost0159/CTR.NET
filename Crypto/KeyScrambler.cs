using System;
using System.Collections.Generic;
using System.Numerics;

namespace CTR.NET.Crypto
{
    public static class KeyScrambler
    {
        public enum ArrayRotationDirection
        {
            Left = 0,
            Right = 1
        }

        //3DS (CTR) Constant
        public static readonly BigInteger C1 = "1FF9E9AAC5FE0408024591DC5D52768A".HexToByteArray().ToUnsignedBigInt();

        public static byte[] XORBytes(byte[] firstArray, byte[] secondArray)
        {
            if (firstArray.Length != secondArray.Length)
            {
                throw new ArgumentException($"The specified Arrays do not have the same length. {nameof(firstArray)} has length {firstArray.Length}, and {nameof(secondArray)} has length {secondArray.Length}.");
            }

            //definition of output byte array which has the same size as the input byte array
            byte[] outputBytes = new byte[firstArray.Length];

            for (int i = 0; i < firstArray.Length; i++)
            {
                //taking bytes from both arrays, XORing, and filling the output array at current index with the result
                outputBytes[i] = (byte)(firstArray[i] ^ secondArray[i]);
            }

            return outputBytes;
        }

        public static byte[] RotateByteArray(byte[] input, ArrayRotationDirection direction, int amount)
        {
            int shift = (direction == ArrayRotationDirection.Left) ? (input.Length * 8) - (amount % (input.Length * 8)) : amount % (input.Length * 8);
            byte[] outputBytes = new byte[input.Length];
            List<int> byteBits = new List<int>(input.Length * 8);

            byte[] reversedBytes = input.FReverse();

            for (int i = 0; i < reversedBytes.Length; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    byteBits.Add((reversedBytes[i] >> j) & 1);
                }
            }

            byteBits = byteBits.TakeItems(shift, byteBits.Count).MergeWith(byteBits.TakeItems(0, shift));

            for (int i = 0; i < outputBytes.Length; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    outputBytes[i] |= (byte)(byteBits[i * 8 + j] << j);
                }
            }

            return outputBytes.FReverse();
        }

        public static BigInteger GenerateCTRNormalKey(BigInteger keyX, BigInteger keyY)
        {
            BigInteger key = BigInteger.Add(XORBytes(RotateByteArray(keyX.ToBytes(), ArrayRotationDirection.Left, 2), keyY.ToBytes()).ToUnsignedBigInt(), C1);

            return RotateByteArray(key.ToBytes(), ArrayRotationDirection.Right, 41).ToUnsignedBigInt();
        }
    }
}