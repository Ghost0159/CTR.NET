using System;
using System.Numerics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using SecurityDriven.Inferno.Cipher;
using CTR.NET.Crypto;
using CTR.NET.FS;

namespace CTR.NET
{
    public class NCCH : IDisposable
    {
        private long DataStart { get; set; } = 0;
        public NCCHInfo Info { get; private set; }
        public List<NCCHRegion> Regions = new List<NCCHRegion>();
        private MemoryMappedFile NCCHMemoryMappedFile { get; set; }
        private CryptoEngine Cryptor { get; set; }
        private SeedDatabase SeedDB { get; set; }
        private static readonly string[] NormalCryptoExeFSFiles = new string[] { "icon", "banner" };

        private static readonly Dictionary<int, Keyslot> ExtraCryptoKeyslots = new Dictionary<int, Keyslot>()
        {
            { 0x00, Keyslot.NCCH   },
            { 0x01, Keyslot.NCCH70 },
            { 0x0A, Keyslot.NCCH93 },
            { 0x0B, Keyslot.NCCH96 }
        };

        public static readonly List<NCCHSection> NoCryptoSections = new List<NCCHSection>()
        {
            NCCHSection.Header,
            NCCHSection.Logo,
            NCCHSection.PlainRegion
        };

        public NCCH(FileStream ncchStream, CryptoEngine ce = null, SeedDatabase seedDb = null)
        {
            this.NCCHMemoryMappedFile = Tools.LoadFileMapped(ncchStream);

            Load(ce, seedDb);
        }

        public NCCH(string pathToNcch, CryptoEngine ce = null, SeedDatabase seedDb = null)
        {
            if (!File.Exists(pathToNcch))
            {
                throw new FileNotFoundException($"File at {pathToNcch} does not exist.");
            }

            this.NCCHMemoryMappedFile = Tools.LoadFileMapped(File.Open(pathToNcch, FileMode.Open, FileAccess.ReadWrite));

            Load(ce, seedDb);
        }

        public NCCH(MemoryMappedFile ncch, long dataStart, CryptoEngine ce = null, SeedDatabase seedDb = null)
        {
            this.DataStart = dataStart;
            this.NCCHMemoryMappedFile = ncch;

            Load(ce, seedDb);
        }

        private void Load(CryptoEngine ce = null, SeedDatabase seedDb = null)
        {
            using (MemoryMappedViewStream viewStream = this.NCCHMemoryMappedFile.CreateViewStream(this.DataStart, 0x200))
            {
                this.Info = new NCCHInfo(viewStream.ReadBytes(0x200));
            }

            this.Regions = new List<NCCHRegion>();
            this.Cryptor = ce;
            this.SeedDB = seedDb;

            LoadRegions(this.Info.TitleID);
        }



        private void LoadRegions(long tid)
        {
            // ExHeader, ExeFS, RomFS - use crypto

            if (this.Info.Flags.IsExecutable)
            {
                this.Regions.AddIfExists(new NCCHRegion(NCCHSection.ExHeader, this.DataStart + 0x200, 0x800, tid));
            }

            this.Regions.AddIfExists(new NCCHRegion(NCCHSection.ExeFS, this.DataStart + this.Info.ExeFSOffset, this.Info.ExeFSSize, tid));
            this.Regions.AddIfExists(new NCCHRegion(NCCHSection.RomFS, this.DataStart + this.Info.RomFSOffset, this.Info.RomFSSize, tid));

            // Header, Logo, Plain - no crypto

            this.Regions.AddIfExists(new NCCHRegion(NCCHSection.Header, this.DataStart, 0x200));
            this.Regions.AddIfExists(new NCCHRegion(NCCHSection.Logo, this.DataStart + this.Info.LogoRegionOffset, this.Info.LogoRegionSize));
            this.Regions.AddIfExists(new NCCHRegion(NCCHSection.PlainRegion, this.DataStart + this.Info.PlainRegionOffset, this.Info.PlainRegionSize));
        }

        public void ExtractSection(NCCHSection section, Stream outputStream, bool decrypt = true, bool close = true)
        {
            if (this.Info.Flags.UsesEncryption && this.Cryptor == null && decrypt == true)
            {
                throw new ArgumentException("This NCCH is encrypted, and no Crypto Engine was provided to perform decryption.");
            }

            if (!this.Regions.Any(region => region.Type == section))
            {
                throw new ArgumentException($"The requested section ({Enum.GetName(typeof(NCCHSection), section)}) was not found inside this NCCH.");
            }

            NCCHRegion region = this.Regions.Find(region => region.Type == section);

            if (this.Info.Flags.UsesEncryption && decrypt && !NoCryptoSections.Contains(region.Type)) //if encrypted, user wants to decrypt, and the selected region is known to use encryption
            {
                Keyslot primaryKeyslot;
                Keyslot secondaryKeyslot;

                byte[] secondaryKeyY = new byte[16];

                if (this.Info.Flags.UsesFixedKey)
                {
                    primaryKeyslot = ((this.Info.TitleID & (0x10 << 32)) > 0) ? Keyslot.FixedSystemKey : Keyslot.ZeroKey;
                    secondaryKeyslot = primaryKeyslot;
                }
                else
                {
                    primaryKeyslot = Keyslot.NCCH;
                    secondaryKeyslot = secondaryKeyslot = this.Info.Flags.CryptoMethod switch
                    {
                        0x00 => Keyslot.NCCH,
                        0x01 => Keyslot.NCCH70,
                        0x0A => Keyslot.NCCH93,
                        0x0B => Keyslot.NCCH96,
                        _ => throw new Exception("Could not determine crypto type. This should NOT happen.")
                    };

                    if (this.Info.Flags.UsesSeed)
                    {
                        this.Info.LoadSeed(this.SeedDB);

                        secondaryKeyY = this.Info.SeededKeyY;
                    }
                    else
                    {
                        secondaryKeyY = this.Info.KeyY;
                    }
                }

                this.Cryptor.SetKeyslot("y", (int)primaryKeyslot, this.Info.KeyY.ToUnsignedBigInt()); //load primary key into keyslot
                this.Cryptor.SetKeyslot("y", (int)secondaryKeyslot, secondaryKeyY.ToUnsignedBigInt()); //load secondary key into keyslot

                //decrypts based on section
                switch (region.Type)
                {
                    case NCCHSection.ExHeader:
                        Tools.CryptFileStreamPart(this.NCCHMemoryMappedFile, outputStream, new AesCtrCryptoTransform(this.Cryptor.NormalKey[(int)primaryKeyslot], region.CTR), region.Offset, region.Size, close);
                        break;
                    case NCCHSection.RomFS:
                        //uses secondary keyslot for it's entirety
                        Tools.CryptFileStreamPart(this.NCCHMemoryMappedFile, outputStream, new AesCtrCryptoTransform(this.Cryptor.NormalKey[(int)secondaryKeyslot], region.CTR), region.Offset, region.Size, close);
                        break;
                    case NCCHSection.ExeFS:
                        //can use two keyslots. because of this, I separated the ExeFS decryption into another method
                        ExtractExeFS(outputStream, region, secondaryKeyslot, close);
                        break;
                }
            }
            else //just extract the raw section, because no crypto is used or the user did not request decryption
            {
                Tools.ExtractFileStreamPart(this.NCCHMemoryMappedFile, outputStream, region.Offset, region.Size, close);
            }
        }

        private void ExtractExeFS(Stream output, NCCHRegion region, Keyslot secondaryKeyslot, bool close = true)
        {
            if (secondaryKeyslot == Keyslot.NCCH)
            {
                //if the secondary keyslot is also the original 0x2C NCCH Keyslot, don't bother decrypting anything in parts, and just shove the entire ExeFS through a CryptoStream
                Tools.CryptFileStreamPart(this.NCCHMemoryMappedFile, output, new AesCtrCryptoTransform(this.Cryptor.NormalKey[(int)Keyslot.NCCH], region.CTR), region.Offset, region.Size, close);
                return;
            }

            //here we go, i don't like this part

            byte[] header = new byte[0x200];

            using (MemoryMappedViewStream headerViewStream = this.NCCHMemoryMappedFile.CreateViewStream(region.Offset, 0x200))
            {
                header = Tools.CryptBytes(headerViewStream.ReadBytes(0x200), new AesCtrCryptoTransform(this.Cryptor.NormalKey[0x2C], region.CTR));
            }

            output.Write(header);

            //create dummy ExeFS class instance to figure out the locations of each file in the ExeFS
            ExeFS exefs = new ExeFS(header);

            //write decrypted header to output file
            foreach (ExeFSEntry entry in exefs.Entries)
            {
                byte[] CTR = (region.CTRInt + (entry.Offset / 16)).ToCTRBytes();

                AesCtrCryptoTransform transform = (NormalCryptoExeFSFiles.Contains(entry.Name)) ? new AesCtrCryptoTransform(this.Cryptor.NormalKey[(int)Keyslot.NCCH], CTR) : new AesCtrCryptoTransform(this.Cryptor.NormalKey[(int)secondaryKeyslot], CTR);

                using (MemoryMappedViewStream fileViewStream = this.NCCHMemoryMappedFile.CreateViewStream(region.Offset + entry.Offset, entry.Size))
                {
                    CryptoStream cs = new CryptoStream(output, transform, CryptoStreamMode.Write);

                    output.Seek(entry.Offset, SeekOrigin.Begin);

                    fileViewStream.CopyTo(cs);

                    cs.FlushFinalBlock();
                }
            }

            //sneaky way to make it gm9-like

            if (!(output.GetType() == typeof(MemoryMappedViewStream)))
            {
                output.SetLength(Tools.RoundUp(output.Length, 0x200));
            }

            if (close)
            {
                output.Dispose();
            }
        }
        public void Decrypt(MemoryMappedFile outputFile)
        {
            foreach (NCCHRegion region in this.Regions)
            {
                using (MemoryMappedViewStream destRegionViewStream = outputFile.CreateViewStream(region.Offset, region.Size))
                {
                    if (region.Type == NCCHSection.Header)
                    {
                        this.ExtractSection(region.Type, destRegionViewStream, true, false);

                        destRegionViewStream.Seek(0x188, SeekOrigin.Begin);

                        byte[] flags = destRegionViewStream.ReadBytes(0x8);

                        flags[3] = 0x0;
                        flags[7] |= (0x1 << 0x2);

                        destRegionViewStream.Seek(0x188, SeekOrigin.Begin);
                        destRegionViewStream.Write(flags);
                        destRegionViewStream.Dispose();
                    }
                    else
                    {
                        this.ExtractSection(region.Type, destRegionViewStream);
                    }
                }
            }
        }

        public void Decrypt(FileStream fs)
        {
            fs.SetLength(this.Info.ContentSize);
            fs.Seek(0, SeekOrigin.Begin);

            Decrypt(Tools.LoadFileMapped(fs));
        }

        public void Dispose()
        {
            this.NCCHMemoryMappedFile.Dispose();
        }
    }
    public class NCCHInfo
    {
        private long Size { get; set; }
        public byte[] RawHeader { get; private set; }
        public byte[] KeyY { get; private set; }
        public byte[] SeededKeyY { get; private set; }
        public byte[] Signature { get; private set; } //hex
        public string Magic { get; private set; } //UTF-8 plaintext
        public long ContentSize { get; private set; } //in media units
        public long TitleID { get; private set; } //LE
        public string MakerCode { get; private set; } //UTF-8 plaintext
        public short VersionNumber { get; private set; } //LE
        public string Version { get; private set; }
        public byte[] SeedVerifyHashPart { get; private set; } //bytes
        public long ProgramID { get; private set; } //LE
        public byte[] LogoRegionHash { get; private set; } //hex
        public ProductCodeInfo ProductCode { get; private set; } //utf-8 string
        public byte[] ExHeaderHash { get; private set; } //hex
        public long ExHeaderSize { get; private set; } //bytes
        public NCCHFlags Flags { get; private set; } //bytes
        public long PlainRegionOffset { get; private set; } //in media units
        public long PlainRegionSize { get; private set; } //in media units
        public long LogoRegionOffset { get; private set; } //in media units
        public long LogoRegionSize { get; private set; } //in media units
        public long ExeFSOffset { get; private set; } //in media units
        public long ExeFSSize { get; private set; } // in media units
        public long ExeFSHashRegionSize { get; private set; } //in media units
        public long RomFSOffset { get; private set; } //in media units
        public long RomFSSize { get; private set; } // in media units
        public long RomFSHashRegionSize { get; private set; } //in media units
        public byte[] ExeFSSuperBlockHash { get; private set; } //hex
        public byte[] RomFSSuperBlockHash { get; private set; } //hex
        public NCCHInfo(byte[] ncchHeader)
        {
            this.RawHeader = ncchHeader;
            this.KeyY = ncchHeader.TakeItems(0x0, 0x10);
            this.Signature = ncchHeader.TakeItems(0x0, 0x100);
            this.Magic = ncchHeader.TakeItems(0x100, 0x104).Decode(Encoding.UTF8);
            this.ContentSize = ncchHeader.TakeItems(0x104, 0x108).ToInt32() * 0x200;
            this.TitleID = ncchHeader.TakeItems(0x108, 0x110).ToInt64();
            this.MakerCode = $"{ncchHeader.TakeItems(0x110, 0x112).Hex()} (\"{ncchHeader.TakeItems(0x110, 0x112).Decode(Encoding.UTF8)}\")";
            this.Version = Tools.GetVersion(ncchHeader.TakeItems(0x112, 0x114), out short versionNumber);
            this.SeedVerifyHashPart = ncchHeader.TakeItems(0x114, 0x118);
            this.VersionNumber = versionNumber;
            this.ProgramID = ncchHeader.TakeItems(0x118, 0x120).ToInt64();
            this.LogoRegionHash = ncchHeader.TakeItems(0x130, 0x150);
            this.ProductCode = new ProductCodeInfo(ncchHeader.TakeItems(0x150, 0x160).Decode(Encoding.UTF8).Trim());
            this.ExHeaderHash = ncchHeader.TakeItems(0x160, 0x180);
            this.ExHeaderSize = ncchHeader.TakeItems(0x180, 0x184).ToInt32();
            this.Flags = new NCCHFlags(ncchHeader.TakeItems(0x188, 0x190));
            this.PlainRegionOffset = ncchHeader.TakeItems(0x190, 0x194).ToInt32() * 0x200;
            this.PlainRegionSize = ncchHeader.TakeItems(0x194, 0x198).ToInt32() * 0x200;
            this.LogoRegionOffset = ncchHeader.TakeItems(0x198, 0x19C).ToInt32() * 0x200;
            this.LogoRegionSize = ncchHeader.TakeItems(0x19C, 0x1A0).ToInt32() * 0x200;
            this.ExeFSOffset = ncchHeader.TakeItems(0x1A0, 0x1A4).ToInt32() * 0x200;
            this.ExeFSSize = ncchHeader.TakeItems(0x1A4, 0x1A8).ToInt32() * 0x200;
            this.ExeFSHashRegionSize = ncchHeader.TakeItems(0x1A8, 0x1AC).ToInt32() * 0x200;
            this.RomFSOffset = ncchHeader.TakeItems(0x1B0, 0x1B4).ToInt32() * 0x200;
            this.RomFSSize = ncchHeader.TakeItems(0x1B4, 0x1B8).ToInt32() * 0x200;
            this.RomFSHashRegionSize = ncchHeader.TakeItems(0x1B8, 0x1BC).ToInt32() * 0x200;
            this.ExeFSSuperBlockHash = ncchHeader.TakeItems(0x1C0, 0x1E0);
            this.RomFSSuperBlockHash = ncchHeader.TakeItems(0x1E0, 0x200);
        }

        public void LoadSeed(SeedDatabase seedDb)
        {
            if (seedDb == null)
            {
                throw new ArgumentException("NCCH uses seed crypto, no seed database is loaded");
            }

            byte[] tid = (BitConverter.IsLittleEndian) ? BitConverter.GetBytes(this.ProgramID) : BitConverter.GetBytes(this.ProgramID).FReverse();
            byte[] seed = new byte[16];

            try
            {
                seed = seedDb.Seeds[this.ProgramID];
            }
            catch (KeyNotFoundException)
            {
                throw new ArgumentException($"The specified seed database does not contain an entry for Title ID {tid.Hex()}.");
            }

            byte[] seedVerifyHash = Tools.HashSHA256(seed.MergeWith(tid));

            if (!Enumerable.SequenceEqual(seedVerifyHash.TakeItems(0x0, 0x4), this.SeedVerifyHashPart))
            {
                throw new ArgumentException($"The specified seed database contains an invalid seed for title id {tid.Hex()}");
            }

            this.SeededKeyY = Tools.HashSHA256(this.KeyY.MergeWith(seed)).TakeItems(0x0, 0x10);
        }

        public override string ToString()
        {
            return $"NCCH INFO:\n\n" +
                $"Magic: {this.Magic}\n" +
                $"Content Size: {this.ContentSize} (0x{this.ContentSize:X}) bytes - {this.ContentSize / (long)1024 / (long)128} blocks\n" +
                $"Title ID: {this.TitleID:X16}\n" +
                $"Maker Code: {this.MakerCode}\n" +
                $"Version: {this.Version} ({this.VersionNumber})\n" +
                $"Program ID: {this.ProgramID:X16}\n" +
                $"Logo Region Hash: {this.LogoRegionHash.Hex()}\n\n" +
                $"{this.ProductCode}\n\n" +
                $"Extended Header Hash: {this.ExHeaderHash.Hex()}\n" +
                $"Extended Header Size: {ExHeaderSize} (0x{ExHeaderSize:X})\n\n" +
                $"{this.Flags}\n\n" +
                $"Plain Region Offset: {this.PlainRegionOffset} (0x{this.PlainRegionOffset:X})\n" +
                $"Plain Region Size: {this.PlainRegionSize} (0x{this.PlainRegionSize:X}) bytes\n\n" +
                $"Logo Region Offset: {this.LogoRegionOffset} (0x{this.LogoRegionOffset:X})\n" +
                $"Logo Region Size: {this.LogoRegionSize} (0x{this.LogoRegionSize:X}) bytes\n\n" +
                $"ExeFS Offset: {this.ExeFSOffset} (0x{this.ExeFSOffset:X})\n" +
                $"ExeFS Size: {this.ExeFSSize} (0x{this.ExeFSSize:X}) bytes\n" +
                $"ExeFS Hash Region Size: {this.ExeFSHashRegionSize} (0x{this.ExeFSHashRegionSize:X}) bytes\n\n" +
                $"RomFS Offset: {this.RomFSOffset} (0x{this.RomFSOffset:X})\n" +
                $"RomFS Size: {this.RomFSSize} (0x{this.RomFSSize:X}) bytes\n" +
                $"RomFS Hash Region Size: {this.RomFSHashRegionSize} (0x{this.RomFSHashRegionSize:X}) bytes\n\n" +
                $"ExeFS Superblock Hash: {this.ExeFSSuperBlockHash.Hex()}\n" +
                $"RomFS Superblock Hash: { this.RomFSSuperBlockHash.Hex()}";
        }
    }

    public class ProductCodeInfo
    {
        public string ProductCode { get; private set; }
        public string Console { get; private set; }
        public string ContentType { get; private set; }
        public string Region { get; private set; }

        public ProductCodeInfo(string productCode)
        {
            this.ProductCode = productCode;

            if (productCode.Split("-").Length < 3)
            {
                this.Console = "Unrecognized Product Code.";
                this.ContentType = "Unrecognized Product Code.";
                this.Region = "Unrecognized Product Code.";
            }
            else
            {
                this.Console = productCode.Split("-")[0] switch
                {
                    "KTR" => "New Nintendo 3DS (KTR)",
                    "CTR" => "Original (Old) Nintendo 3DS (CTR)",
                    _ => $"Unknown, \"{productCode.Split("-")[0]}\""
                };

                this.ContentType = productCode.Split("-")[1] switch
                {
                    "P" => "Game Data",
                    "N" => "Game Data",
                    "U" => "Update Data",
                    "M" => "DLC",
                    "H" => "Demo",
                    "B" => "Demo",
                    _ => $"Unknown, \"{productCode.Split("-")[1]}\""
                };

                this.Region = productCode.Split("-")[2][3] switch
                {
                    'P' => "Europe (E)",
                    'Z' => "Europe (Z)",
                    'X' => "Europe (X)",
                    'V' => "Europe (V)",
                    'Y' => "Europe (Y)",
                    'D' => "Europe (D)",
                    'S' => "Europe (S)",
                    'F' => "Europe (F)",
                    'E' => "USA (U)",
                    'J' => "Japan (J)",
                    'K' => "Korea (K)",
                    'W' => "China (CN)",
                    'A' => "RegionFree (A)",
                    _ => $"Unknown, \"{productCode.Split("-")[2][3]}\"",
                };
            }
        }

        public override string ToString()
        {
            return $"Product Code: {this.ProductCode}\n\n" +
                $"Product Code Information:\n\n" +
                $"Console: {this.Console}\n" +
                $"Content Type: {this.ContentType}\n" +
                $"Region: {this.Region}";
        }
    }

    public enum ContentPlatform
    {
        CTR_Old3DS = 1,
        SNAKE_New3DS = 2
    }

    public enum NCCHSection
    {
        ExHeader = 1,
        ExeFS = 2,
        RomFS = 3,

        Header = 4,
        Logo = 5,
        PlainRegion = 6
    }

    public class NCCHRegion
    {
        public NCCHSection Type { get; private set; }
        public long Offset { get; private set; }
        public long Size { get; private set; }
        public byte[] CTR { get; private set; }
        public BigInteger CTRInt { get; private set; }

        public NCCHRegion(NCCHSection type, long offset, long size, long tid = 0)
        {
            this.Type = type;
            this.Offset = offset;
            this.Size = size;

            if ((int)type < 4 && tid != 0)
            {
                BigInteger ctrAsBigInt = ((BigInteger)tid << 64 | (BigInteger)(int)type << 56);

                this.CTRInt = ctrAsBigInt;
                this.CTR = ctrAsBigInt.ToCTRBytes();
            }
        }
    }
    public class NCCHFlags
    {
        public int CryptoMethod { get; private set; }
        public ContentPlatform Platform { get; private set; }
        public bool IsExecutable { get; private set; }
        public bool UsesFixedKey { get; private set; }
        public bool HasRomFS { get; private set; }
        public bool UsesEncryption { get; private set; }
        public uint ContentUnitSize { get; private set; }
        public bool UsesSeed { get; private set; }
        public string ContentType { get; private set; }

        public NCCHFlags(byte[] ncchFlags)
        {
            this.CryptoMethod = ncchFlags[3];
            this.Platform = (ContentPlatform)ncchFlags[4];
            this.IsExecutable = (ncchFlags[5] & 0x2) > 0;
            this.UsesFixedKey = (ncchFlags[7] & 0x1) > 0;
            this.HasRomFS = !((ncchFlags[7] & 0x2) > 0);
            this.UsesEncryption = !((ncchFlags[7] & 0x4) > 0);
            this.UsesSeed = (ncchFlags[7] & 0x20) > 0;
            this.ContentUnitSize = (uint)0x200 * 2 ^ ncchFlags[6];
            this.CryptoMethod = ncchFlags[3];
            this.Platform = (ContentPlatform)ncchFlags[4];

            if ((ncchFlags[5] & 0x1) != 0 && (ncchFlags[5] & 0x2) != 0)
            {
                this.ContentType = "Data + Excecutable, CTR Executable Image (CXI) NCCH";
            }
            else if ((ncchFlags[5] & 0x1) != 0 && (ncchFlags[5] & 0x2) == 0)
            {
                this.ContentType = "Data, CTR File Archive (CFA) NCCH";
            }
            else if ((ncchFlags[5] & 0x4) != 0)
            {
                this.ContentType = "System Update";
            }
            else if ((ncchFlags[5] & 0x8) != 0)
            {
                this.ContentType = "Electronic User Manual (CFA) NCCH";
            }
            else if ((ncchFlags[5] & (0x4 | 0x8)) != 0)
            {
                this.ContentType = "Download Play Child (DLP) (CFA) NCCH";
            }
            else if ((ncchFlags[5] & 0x10) != 0)
            {
                this.ContentType = "Trial";
            }
        }

        public override string ToString()
        {
            return $"NCCH Flags:\n\n" +
                $"Crypto Method: {CryptoMethod:X}\n" +
                $"Content Platform: {Enum.GetName(typeof(ContentPlatform), this.Platform)}\n" +
                $"Content Unit Size: {this.ContentUnitSize} (0x{this.ContentUnitSize:X}) bytes\n" +
                $"Content Type: {this.ContentType}\n" +
                $"Encrypted: {this.UsesEncryption}\n" +
                $"Uses Seed: {this.UsesSeed}";
        }
    }
}
