using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using CTR.NET.Crypto;

namespace CTR.NET
{
    public class CDNContents
    {
        public DirectoryInfo ContentDir { get; private set; }
        public TMD TMD { get; private set; }
        private CryptoEngine Cryptor { get; set; }
        private SeedDatabase SeedDb { get; set; }

        private void Load(DirectoryInfo contents, CryptoEngine ce, SeedDatabase seedDb, bool verifyHashes, bool ignoreMissingContents)
        {
            if (!contents.Exists)
            {
                throw new DirectoryNotFoundException("The specified directory was not found.");
            }

            this.ContentDir = contents;
            this.Cryptor = ce;
            this.SeedDb = seedDb;
            this.TMD = new TMD(File.ReadAllBytes($"{this.ContentDir.FullName}/tmd"), verifyHashes);

            if (!ignoreMissingContents && !this.TMD.ContentChunkRecords.All(ccr => File.Exists($"{this.ContentDir.FullName}/{ccr.ID.ToString("x8")}")))
            {
                throw new ArgumentException("CDN Content folder is missing one or more contents that are defined in the TMD.");
            }
        }

        public CDNContents(DirectoryInfo contentDir, CryptoEngine ce, SeedDatabase seedDb, Ticket ticket, bool verifyTmdHashes = true, bool ignoreMissingContents = false)
        {
            Load(contentDir, ce, seedDb, verifyTmdHashes, ignoreMissingContents);

            this.Cryptor.LoadTitleKeyFromTicket(ticket);
        }

        public CDNContents(DirectoryInfo contentDir, CryptoEngine ce, SeedDatabase seedDb, byte[] titleKey, bool verifyTmdHashes = true, bool ignoreMissingContents = false)
        {
            Load(contentDir, ce, seedDb, verifyTmdHashes, ignoreMissingContents);

            this.Cryptor.SetNormalKey((int)Keyslot.DecryptedTitleKey, titleKey);
        }

        public void Decrypt(DirectoryInfo outputDirectory, bool fullyDecryptNcchContents)
        {
            foreach (ContentChunkRecord ccr in this.TMD.ContentChunkRecords)
            {
                using (FileStream inputFs = File.OpenRead($"{this.ContentDir.FullName}/{ccr.ID.ToString("x8")}"))
                {
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = this.Cryptor.NormalKey[(int)Keyslot.DecryptedTitleKey];
                        byte[] cindex = BitConverter.GetBytes(ccr.ContentIndex);
                        aes.IV = (BitConverter.IsLittleEndian ? cindex.FReverse() : cindex).PadRight(0x00, 0x10);
                        aes.Padding = PaddingMode.Zeros;
                        aes.Mode = CipherMode.CBC;


                        using (CryptoStream cs = new CryptoStream(File.Create($"{outputDirectory.FullName}/{ccr.ID.ToString("x8")}"), aes.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            inputFs.CopyTo(cs);
                            cs.FlushFinalBlock();
                        }
                    }
                }

                if (fullyDecryptNcchContents)
                {
                    FileStream decryptedLayer1Fs = File.Open($"{outputDirectory.FullName}/{ccr.ID.ToString("x8")}", FileMode.Open, FileAccess.ReadWrite);

                    using (NCCH ncch = new NCCH(decryptedLayer1Fs, this.Cryptor, this.SeedDb))
                    {
                        using (FileStream decryptedLayer2Fs = File.Create($"{outputDirectory.FullName}/{ccr.ID.ToString("x8")}_decrypted.{(ncch.Info.Flags.IsExecutable ? "cxi" : "cfa")}"))
                        {
                            ncch.Decrypt(decryptedLayer2Fs);
                        }
                    }
                }
            }

            File.Copy($"{this.ContentDir.FullName}/tmd", $"{outputDirectory.FullName}/tmd");
        }
    }
}