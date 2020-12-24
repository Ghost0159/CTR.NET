using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace CTR.NET.Crypto
{
    public enum Keyslot
    {

        //Extra NCCH Keyslot for Titles exclusive to the New Nintendo 3DS, released after firmware version 9.3.0-21
        NCCH93 = 0x18,

        //Extra NCCH Keyslot for Titles exclusive to the New Nintendo 3DS, released after firmware version 9.6.0-24
        NCCH96 = 0x1B,

        //Extra NCCH Keyslot for Titles released after Firmware Version 7.0.0-13
        NCCH70 = 0x25,

        //Original NCCH Keyslot
        NCCH = 0x2C,

        //Common key for title key decryption
        CommonKey = 0x3D,

        //Non-Official

        //For decrypting CIA/CDN contents
        DecryptedTitleKey = 0x40,

        //For NCCH that uses fixed crypto
        ZeroKey = 0x41,

        //Special Key for NCCH that used fixed crypto
        FixedSystemKey = 0x42,

        //Sector 0x96 (New Nintendo 3DS only)
        New3DSKeySector = 0x43
    }

    public class CryptoEngine
    {
        public static readonly byte[] Boot9ProtHash = { 0x73, 0x31, 0xF7, 0xED, 0xEC, 0xE3, 0xDD, 0x33, 0xF2, 0xAB, 0x4B, 0xD0, 0xB3, 0xA5, 0xD6, 0x07, 0x22, 0x9F, 0xD1, 0x92, 0x12, 0xC1, 0x0B, 0x73, 0x4C, 0xED, 0xCA, 0xF7, 0x8C, 0x1A, 0x7B, 0x98 };
        public static readonly byte[] DevCommonKeyZero = { 0x55, 0xA3, 0xF8, 0x72, 0xBD, 0xC8, 0x0C, 0x55, 0x5A, 0x65, 0x43, 0x81, 0x13, 0x9E, 0x15, 0x3B };
        public static readonly BigInteger[] CommonKeyYs = new BigInteger[6]
        {
            //eShop
            new byte[] { 0xD0, 0x7B, 0x33, 0x7F, 0x9C, 0xA4, 0x38, 0x59, 0x32, 0xA2, 0xE2, 0x57, 0x23, 0x23, 0x2E, 0xB9 }.ToUnsignedBigInt(),
            //System
            new byte[] { 0x0C, 0x76, 0x72, 0x30, 0xF0, 0x99, 0x8F, 0x1C, 0x46, 0x82, 0x82, 0x02, 0xFA, 0xAC, 0xBE, 0x4C }.ToUnsignedBigInt(),
            //Unknown
            new byte[] { 0xC4, 0x75, 0xCB, 0x3A, 0xB8, 0xC7, 0x88, 0xBB, 0x57, 0x5E, 0x12, 0xA1, 0x09, 0x07, 0xB8, 0xA4 }.ToUnsignedBigInt(),
            new byte[] { 0xE4, 0x86, 0xEE, 0xE3, 0xD0, 0xC0, 0x9C, 0x90, 0x2F, 0x66, 0x86, 0xD4, 0xC0, 0x6F, 0x64, 0x9F }.ToUnsignedBigInt(),
            new byte[] { 0xED, 0x31, 0xBA, 0x9C, 0x04, 0xB0, 0x67, 0x50, 0x6C, 0x44, 0x97, 0xA3, 0x5B, 0x78, 0x04, 0xFC }.ToUnsignedBigInt(),
            new byte[] { 0x5E, 0x66, 0x99, 0x8A, 0xB4, 0xE8, 0x93, 0x16, 0x06, 0x85, 0x0F, 0xD7, 0xA1, 0x6D, 0xD7, 0x55 }.ToUnsignedBigInt()
        };

        public static readonly Dictionary<int, Tuple<BigInteger, BigInteger>> BaseKeyXs = new Dictionary<int, Tuple<BigInteger, BigInteger>>()
        {
            // New Nintendo 3DS Firmware Version 9.3 NCCH
            { 0x18, Tuple.Create(BigInteger.Parse("82E9C9BEBFB8BDB875ECC0A07D474374", NumberStyles.HexNumber), BigInteger.Parse("304BF1468372EE64115EBD4093D84276", NumberStyles.HexNumber)) },
            // New Nintendo 3DS Firmware Version 9.6 NCCH
            { 0x1B, Tuple.Create(BigInteger.Parse("45AD04953992C7C893724A9A7BCE6182", NumberStyles.HexNumber), BigInteger.Parse("6C8B2944A0726035F941DFC018524FB6", NumberStyles.HexNumber)) },
            // Nintendo 3DS Firmware Version 7.X NCCH
            { 0x25, Tuple.Create(BigInteger.Parse("CEE7D8AB30C00DAE850EF5E382AC5AF3", NumberStyles.HexNumber), BigInteger.Parse("81907A4B6F1B47323A677974CE4AD71B", NumberStyles.HexNumber)) }
        };

        public Dictionary<int, BigInteger> KeyX { get; set; }
        public Dictionary<int, BigInteger> KeyY { get; set; }
        public Dictionary<int, byte[]> NormalKey { get; set; }
        public bool IsDev { get; set; }
        public bool Boot9KeysAreSet { get; set; }

        public CryptoEngine(byte[] boot9, bool isDev, bool setupBoot9Keys = true)
        {
            this.KeyX = new Dictionary<int, BigInteger>();
            this.KeyY = new Dictionary<int, BigInteger>();

            this.NormalKey = new Dictionary<int, byte[]>()
            {
                { (int)Keyslot.ZeroKey, new byte[16] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
                { (int)Keyslot.FixedSystemKey, new byte[16] { 52, 0x7C, 0xE6, 0x30, 0xA9, 0xCA, 0x30, 0x5F, 0x36, 0x96, 0xF3, 0xCD, 0xE9, 0x54, 0x19, 0x4B } }
            };

            this.IsDev = isDev;
            this.Boot9KeysAreSet = false;

            foreach (KeyValuePair<int, Tuple<BigInteger, BigInteger>> pair in BaseKeyXs)
            {
                this.KeyX[pair.Key] = (isDev) ? pair.Value.Item2 : pair.Value.Item1;
            }

            if (setupBoot9Keys)
            {
                SetupKeysFromBoot9(boot9);
            }
        }
        public void SetupKeysFromBoot9(byte[] boot9Bytes)
        {
            byte[] usedPartOfBoot9 = boot9Bytes.TakeItems(0x8000, 0x10000);

            if (usedPartOfBoot9.Length != 0x8000)
            {
                throw new ArgumentException($"Expected Boot9 length 0x8000 ({0x8000})");
            }

            byte[] hash = usedPartOfBoot9.HashSHA256();

            if (!Enumerable.SequenceEqual(hash, Boot9ProtHash))
            {
                throw new ArgumentException($"Invalid Boot9. Expected Hash: {Boot9ProtHash.Hex()}, but got {hash.Hex()}.");
            }

            int keyblobOffset = 0x5860;

            if (this.IsDev)
            {
                keyblobOffset += 0x400;
            }

            byte[] keyblob = usedPartOfBoot9.TakeItems(keyblobOffset, keyblobOffset + 0x400);

            KeyX[0x2C] = KeyX[0x2D] = KeyX[0x2E] = KeyX[0x2F] = keyblob.TakeItems(0x170, 0x180).ToUnsignedBigInt();
            KeyX[0x30] = KeyX[0x31] = KeyX[0x32] = KeyX[0x33] = keyblob.TakeItems(0x180, 0x190).ToUnsignedBigInt();
            KeyX[0x34] = KeyX[0x35] = KeyX[0x36] = KeyX[0x37] = keyblob.TakeItems(0x190, 0x1A0).ToUnsignedBigInt();
            KeyX[0x38] = KeyX[0x39] = KeyX[0x3A] = KeyX[0x3B] = keyblob.TakeItems(0x1A0, 0x1B0).ToUnsignedBigInt();
            KeyX[0x3C] = keyblob.TakeItems(0x1B0, 0x1C0).ToUnsignedBigInt();
            KeyX[0x3D] = keyblob.TakeItems(0x1C0, 0x1D0).ToUnsignedBigInt();
            KeyX[0x3E] = keyblob.TakeItems(0x1D0, 0x1E0).ToUnsignedBigInt();
            KeyY[0x04] = keyblob.TakeItems(0x1F0, 0x200).ToUnsignedBigInt();
            KeyY[0x06] = keyblob.TakeItems(0x210, 0x220).ToUnsignedBigInt();
            KeyY[0x07] = keyblob.TakeItems(0x220, 0x230).ToUnsignedBigInt();
            KeyY[0x08] = keyblob.TakeItems(0x230, 0x240).ToUnsignedBigInt();
            KeyY[0x09] = keyblob.TakeItems(0x240, 0x250).ToUnsignedBigInt();
            KeyY[0x0A] = keyblob.TakeItems(0x250, 0x260).ToUnsignedBigInt();
            KeyY[0x0B] = keyblob.TakeItems(0x260, 0x270).ToUnsignedBigInt();

            NormalKey[0x0D] = keyblob.TakeItems(0x270, 0x280);
        }

        public void SetKeyslot(string slot, int keyslot, BigInteger key)
        {
            if (!(slot.Equals("x", StringComparison.CurrentCultureIgnoreCase) || slot.Equals("y", StringComparison.CurrentCultureIgnoreCase)))
            {
                throw new ArgumentException("Invalid Keyslot. Accepted Values: \"x\" and \"y\" (both cases x/X, y/Y are supported)");
            }

            if (slot.Equals("x", StringComparison.CurrentCultureIgnoreCase))
            {
                KeyX[keyslot] = key;
            }
            else if (slot.Equals("y", StringComparison.CurrentCultureIgnoreCase))
            {
                KeyY[keyslot] = key;
            }

            try
            {
                byte[] generatedKey = KeyScrambler.GenerateCTRNormalKey(this.KeyX[keyslot], this.KeyY[keyslot]).ToByteArray(false, true);
                this.NormalKey[keyslot] = (generatedKey.Length > 0x10) ? generatedKey.TakeItems(0x1, generatedKey.Length) : generatedKey;
            }
            catch (Exception)
            {
                throw;
            }
        }

        public void SetNormalKey(int keyslot, byte[] key)
        {
            if (key.Length != 16)
            {
                throw new ArgumentException($"The specified key \"{key.Hex()}\" (length: {key.Length}) is not 16 bytes long.");
            }

            this.NormalKey[keyslot] = key;
        }

        public void LoadTitleKeyFromTicket(byte[] ticket)
        {
            if (ticket.Length < 0x2AC)
            {
                throw new ArgumentException($"Specified ticket was expected to be at least 684 (0x2AC) bytes long, but instead, was {ticket.Length} ({ticket.Length:X}) bytes long");
            }

            DecryptTitlekey(ticket.TakeItems(0x1BF, 0x1CF), ticket[0x1F1], ticket.TakeItems(0x1DC, 0x1E4));
        }

        public void DecryptTitlekey(byte[] titlekey, int commonKeyIndex, byte[] titleId)
        {
            if (this.IsDev && commonKeyIndex == 0)
            {
                SetNormalKey(0x3D, DevCommonKeyZero);
            }
            else
            {
                this.SetKeyslot("y", 0x3D, CommonKeyYs[commonKeyIndex]);
            }

            using (Aes cbcCipher = Aes.Create())
            {
                cbcCipher.Key = this.NormalKey[(int)Keyslot.CommonKey];
                cbcCipher.Mode = CipherMode.CBC;
                cbcCipher.IV = titleId.PadRight(0x00, 16);
                cbcCipher.Padding = PaddingMode.Zeros;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, cbcCipher.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(titlekey, 0, titlekey.Length);
                        cs.FlushFinalBlock();
                    }

                    SetNormalKey((int)Keyslot.DecryptedTitleKey, ms.ToArray().TakeItems(0, 16));
                }
            }
        }
    }
}