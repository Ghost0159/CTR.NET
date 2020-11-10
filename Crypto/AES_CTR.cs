using SecurityDriven.Inferno.Cipher;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CTR.NET.Crypto
{
    public class AES_CTR
    {
        private byte[] Key { get; set; }
        private byte[] CTR { get; set; }
        private AesCtrCryptoTransform Transform { get; set; }

        public AES_CTR(byte[] key, byte[] ctr)
        {
            this.Key = key;
            this.CTR = ctr;
            this.Transform = new AesCtrCryptoTransform(this.Key, new ArraySegment<byte>(this.CTR));
        }

        public byte[] Decrypt(byte[] data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, this.Transform, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                }

                return ms.ToArray();
            }
        }

        public byte[] Encrypt(byte[] data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, this.Transform, CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                }

                return ms.ToArray();
            }
        }
    }
}