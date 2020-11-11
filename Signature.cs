using System;

namespace CTR.NET
{
    public class Signature
    {
        public string Name { get; private set; }
        public int PaddingSize { get; private set; }
        public int Size { get; private set; }

        public Signature(string name, int paddingSize, int size)
        {
            this.Name = name;
            this.PaddingSize = paddingSize;
            this.Size = size;
        }

        public static Signature Parse(byte[] sigTypeBytes)
        {
            Signature output;

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(sigTypeBytes);
            }
            
            switch (BitConverter.ToInt32(sigTypeBytes))
            {
                case 0x00010000:
                    output = new Signature("RSA_4096_SHA1", 0x200, 0x3C);
                    break;

                case 0x00010001:
                    output = new Signature("RSA_2048_SHA1", 0x100, 0x3C);
                    break;

                case 0x00010002:
                    output = new Signature("ECDSA_SHA1", 0x3C, 0x40);
                    break;

                case 0x00010003:
                    output = new Signature("RSA_4096_SHA256", 0x200, 0x3C);
                    break;

                case 0x00010004:
                    output = new Signature("RSA_2048_SHA256", 0x100, 0x3C);
                    break;

                case 0x00010005:
                    output = new Signature("ECDSA_SHA256", 0x200, 0x3C);
                    break;

                default:
                    throw new ArgumentException("Invalid Signature Data.");
            }
            return output;
        }
    }
}