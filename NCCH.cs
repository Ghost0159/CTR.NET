using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace CTR.NET
{
    public class NCCHInfo
    {
        public string Signature { get; private set; } //hex
        public string Magic { get; private set; } //UTF-8 string
        public long ContentSize { get; private set; } //in media units
        public string TitleID { get; private set; } //LE
        public string MakerCode { get; private set; } //parse as UTF-8
        public int VersionNumber { get; private set; }
        public string Version { get; private set; } //LE
        public string ProgramID { get; private set; }
        public string LogoRegionHash { get; private set; } //hex
        public ProductCodeInfo ProductCode { get; private set; } //utf-8 string
        public string ExHeaderHash { get; private set; } //hex
        public long ExHeaderSize { get; private set; } //bytes
        public NCCHFlags Flags { get; private set; } //bytes
        public long PlainRegionOffset { get; private set; } //in media units
        public long PlainRegionSize { get; private set; } //in media units
        public string PlainRegion { get; private set; }
        public long LogoRegionOffset { get; private set; } //in media units
        public long LogoRegionSize { get; private set; } //in media units
        public long ExeFSOffset { get; private set; } //in media units
        public long ExeFSSize { get; private set; } // in media units
        public long ExeFSHashRegionSize { get; private set; } //in media units
        public long RomFSOffset { get; private set; } //in media units
        public long RomFSSize { get; private set; } // in media units
        public long RomFSHashRegionSize { get; private set; } //in media units
        public string ExeFSSuperBlockHash { get; private set; } //hex
        public string RomFSSuperBlockHash { get; private set; } //hex

        public NCCHInfo(Stream ncch)
        {
            byte[] ncchHeader = ncch.ReadBytes(512);

            this.Signature = ncchHeader.TakeBytes(0x0, 0x100).Hex();
            this.Magic = ncchHeader.TakeBytes(0x100, 0x104).Decode(Encoding.UTF8);
            this.ContentSize = ncchHeader.TakeBytes(0x104, 0x108).IntLE() * 0x200;
            this.TitleID = ncchHeader.TakeBytes(0x108, 0x110).Hex(true);
            this.MakerCode = $"{ncchHeader.TakeBytes(0x110, 0x112).Hex()} (\"{ncchHeader.TakeBytes(0x110, 0x112).Decode(Encoding.UTF8)}\")";
            this.Version = Tools.GetVersion(ncchHeader.TakeBytes(0x112, 0x114), out int versionNumber);
            this.VersionNumber = versionNumber;
            this.ProgramID = ncchHeader.TakeBytes(0x118, 0x120).Hex(true);
            this.LogoRegionHash = ncchHeader.TakeBytes(0x130, 0x150).Hex();
            this.ProductCode = new ProductCodeInfo(ncchHeader.TakeBytes(0x150, 0x160).Decode(Encoding.UTF8));
            this.ExHeaderHash = ncchHeader.TakeBytes(0x160, 0x180).Hex();
            this.ExHeaderSize = ncchHeader.TakeBytes(0x180, 0x184).IntLE();
            this.Flags = new NCCHFlags(ncchHeader.TakeBytes(0x188, 0x190));
            this.PlainRegionOffset = ncchHeader.TakeBytes(0x190, 0x194).IntLE() * 0x200;
            this.PlainRegionSize = ncchHeader.TakeBytes(0x194, 0x198).IntLE() * 0x200;

            using (ncch)
            {
                ncch.Seek(PlainRegionOffset, 0);
                this.PlainRegion = ncch.ReadBytes(this.PlainRegionSize).Decode(Encoding.UTF8).Replace("\0", "\n").Trim();
            }

            this.LogoRegionOffset = ncchHeader.TakeBytes(0x198, 0x19C).IntLE() * 0x200;
            this.LogoRegionSize = ncchHeader.TakeBytes(0x19C, 0x1A0).IntLE() * 0x200;
            this.ExeFSOffset = ncchHeader.TakeBytes(0x1A0, 0x1A4).IntLE() * 0x200;
            this.ExeFSSize = ncchHeader.TakeBytes(0x1A4, 0x1A8).IntLE() * 0x200;
            this.ExeFSHashRegionSize = ncchHeader.TakeBytes(0x1A8, 0x1AC).IntLE() * 0x200;
            this.RomFSOffset = ncchHeader.TakeBytes(0x1B0, 0x1B4).IntLE() * 0x200;
            this.RomFSSize = ncchHeader.TakeBytes(0x1B4, 0x1B8).IntLE() * 0x200;
            this.RomFSHashRegionSize = ncchHeader.TakeBytes(0x1B8, 0x1BC).IntLE() * 0x200;
            this.ExeFSSuperBlockHash = ncchHeader.TakeBytes(0x1C0, 0x1E0).Hex();
            this.RomFSSuperBlockHash = ncchHeader.TakeBytes(0x1E0, 0x200).Hex();
        }

        public override string ToString()
        {
            return $"NCCH INFO:\n\n" +
                $"Magic: {this.Magic}\n" +
                $"Content Size: {this.ContentSize} (0x{this.ContentSize:X}) bytes - {this.ContentSize / (long)1024 / (long)128} blocks\n" +
                $"Title ID: {this.TitleID}\n" +
                $"Maker Code: {this.MakerCode}\n" +
                $"Version: {this.Version} ({this.VersionNumber})\n" +
                $"Program ID: {this.ProgramID}\n" +
                $"Logo Region Hash: {this.LogoRegionHash}\n\n" +
                $"{this.ProductCode}\n\n" +
                $"Extended Header Hash: {this.ExHeaderHash}\n" +
                $"Extended Header Size: {ExHeaderSize} (0x{ExHeaderSize:X})\n\n" +
                $"{this.Flags}\n\n" +
                $"Plain Region Offset: {this.PlainRegionOffset} (0x{this.PlainRegionOffset:X})\n" +
                $"Plain Region Size: {this.PlainRegionSize} (0x{this.PlainRegionSize:X}) bytes\n\n" +
                $"Plain Region: \n\n{(this.PlainRegion == "" ? "(Empty)" : this.PlainRegion)}\n\n" +
                $"Logo Region Offset: {this.LogoRegionOffset} (0x{this.LogoRegionOffset:X})\n" +
                $"Logo Region Size: {this.LogoRegionSize} (0x{this.LogoRegionSize:X}) bytes\n\n" +
                $"ExeFS Offset: {this.ExeFSOffset} (0x{this.ExeFSOffset:X})\n" +
                $"ExeFS Size: {this.ExeFSSize} (0x{this.ExeFSSize:X}) bytes\n" +
                $"ExeFS Hash Region Size: {this.ExeFSHashRegionSize} (0x{this.ExeFSHashRegionSize:X}) bytes\n\n" +
                $"RomFS Offset: {this.RomFSOffset} (0x{this.RomFSOffset:X})\n" +
                $"RomFS Size: {this.RomFSSize} (0x{this.RomFSSize:X}) bytes\n" +
                $"RomFS Hash Region Size: {this.RomFSHashRegionSize} (0x{this.RomFSHashRegionSize:X}) bytes\n\n" +
                $"ExeFS Superblock Hash: {this.ExeFSSuperBlockHash}\n" +
                $"RomFS Superblock Hash: { this.RomFSSuperBlockHash}";
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
            if (productCode.Split("-").Length < 3)
            {
                this.Console = "Unrecognized Product Code.";
                this.ContentType = "Unrecognized Product Code.";
                this.Region = "Unrecognized Product Code.";
            }
            else
            {
                this.ProductCode = productCode;
                this.Console = productCode.Split("-")[0] switch
                {
                    "KTR" => "New Nintendo 3DS (KTR)",
                    "CTR" => "Original (Old) Nintendo 3DS (CTR)",
                    "TWL" => "Nintendo DSiWare (TWL)",
                    _ => $"Unknown, \"{productCode.Split("-")[0]}\". report this on GitHub so it can be added."
                };

                this.ContentType = productCode.Split("-")[1] switch
                {
                    "P" => "Game Data",
                    "N" => "Game Data",
                    "U" => "Update Data",
                    "M" => "DLC",
                    "H" => "Demo",
                    "B" => "Demo",
                    _ => $"Unknown, \"{productCode.Split("-")[1]}\". Please report this on GitHub so it can be added."
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

    public class NCCHFlags
    {
        public enum ContentPlatform
        {
            CTR_Old3DS = 1,
            SNAKE_New3DS = 2
        }

        public int CryptoMethod { get; private set; }
        public ContentPlatform Platform { get; private set; }
        public string ContentType { get; private set; }
        public uint ContentUnitSize { get; private set; }
        public bool IsEncrypted { get; private set; }

        public NCCHFlags(byte[] ncchFlags)
        {
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

            this.ContentUnitSize = (uint)0x200 * 2 ^ ncchFlags[6];
            this.IsEncrypted = (ncchFlags[7] & 0x4) == 0 ? true : true;
        }

        public override string ToString()
        {
            return $"NCCH Flags:\n\n" +
                $"Crypto Method: {CryptoMethod:X}\n" +
                $"Content Platform: {Enum.GetName(typeof(ContentPlatform), this.Platform)}\n" +
                $"Content Unit Size: {this.ContentUnitSize} (0x{this.ContentUnitSize:X}) bytes\n" +
                $"Content Type: {this.ContentType}\n" +
                $"Encrypted: {this.IsEncrypted.YesNo()}";
        }
    }
}
