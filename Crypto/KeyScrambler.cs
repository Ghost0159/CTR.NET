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

        public static byte[] GenerateCTRNormalKey(BigInteger keyX, BigInteger keyY)
        {
            return RotateLeft((RotateLeft(keyX, 2, 128) ^ keyY) + C1, 87, 128).ToBytes();
        }

        public static BigInteger RotateLeft(BigInteger value, int rotateBits, int maxBits)
        {
            return (value << rotateBits % maxBits) & (BigInteger.Pow(2, maxBits) - 1) | ((value & (BigInteger.Pow(2, maxBits) - 1)) >> (maxBits - (rotateBits % maxBits)));
        }
    }
}