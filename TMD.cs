using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace CTR.NET
{
    public class TMDInfo
    {
        public static readonly int ChunkRecordSize = 0x30;

        public byte[] RawData { get; private set; }
        public Signature SignatureInfo { get; private set; }
        public byte[] SignatureData { get; private set; }
        public string SignatureIssuer { get; private set; }
        public byte[] Header { get; private set; }
        public byte[] TitleID { get; private set; }
        public int SaveDataSize { get; private set; }
        public int SrlSaveDataSize { get; private set; }
        public int RawTitleVersion { get; private set; }
        public string TitleVersion { get; private set; }
        public short ContentCount { get; private set; }
        public byte[] RawContentInfoRecords { get; private set; }
        public byte[] ContentInfoRecordsHash { get; private set; }
        public byte[] RawContentChunkRecords { get; private set; }
        public List<ContentChunkRecord> ContentChunkRecords { get; private set; }
        public List<ContentInfoRecord> ContentInfoRecords { get; private set; }
        public byte Version { get; private set; }
        public byte CaCrlVersion { get; private set; }
        public byte SignerCrlVersion { get; private set; }
        public long SystemVersion { get; private set; }
        public int TitleType { get; private set; }
        public byte[] GroupId { get; private set; }
        public byte SrlFlag { get; private set; }
        public byte[] AccessRights { get; private set; }
        public byte[] BootContent { get; private set; }

        public TMDInfo(byte[] tmdBytes, bool verifyHashes = true)
        {
            this.RawData = tmdBytes;

            using (MemoryStream tmdStream = new MemoryStream(tmdBytes))
            {
                this.SignatureInfo = Signature.Parse(tmdStream.ReadBytes(0x4));

                if (this.SignatureInfo.Size == 0)
                {
                    Console.WriteLine("Could not determine Signature Type of TMD.");
                }

                this.SignatureData = tmdStream.ReadBytes(this.SignatureInfo.Size);

                tmdStream.ReadBytes(this.SignatureInfo.PaddingSize);

                this.Header = tmdStream.ReadBytes(0xC4);

                if (this.Header.Length != 0xC4)
                {
                    throw new ArgumentException($"TMD Header size is wrong, expected 0xC4 but got {this.Header.Length:X4}");
                }

                this.TitleID = this.Header.TakeItems(0x4C, 0x54);
                this.SaveDataSize = this.Header.TakeItems(0x5A, 0x5E).ToInt32();
                this.SrlSaveDataSize = this.Header.TakeItems(0x5E, 0x62).ToInt32();
                this.RawTitleVersion = this.Header.TakeItems(0x9C, 0x9E).ToInt16(true);
                this.TitleVersion = $"{(this.RawTitleVersion >> 10) & 0x3F}.{(this.RawTitleVersion >> 4) & 0x3F}.{this.RawTitleVersion & 0xF}";
                this.ContentCount = this.Header.TakeItems(0x9E, 0xA0).ToInt16(true);
                this.ContentInfoRecordsHash = this.Header.TakeItems(0xA4, 0xC4);
                this.RawContentInfoRecords = tmdStream.ReadBytes(0x900);

                if (this.RawContentInfoRecords.Length != 0x900)
                {
                    throw new ArgumentException("TMD Content Info Records size is invalid.");
                }

                if (verifyHashes)
                {
                    if (Tools.HashSHA256(this.RawContentInfoRecords).Hex() != this.ContentInfoRecordsHash.Hex())
                    {
                        throw new ArgumentException("TMD Content Info Records Hash does not match.");
                    }
                }

                this.RawContentChunkRecords = tmdStream.ReadBytes(this.ContentCount * ChunkRecordSize);
                this.ContentChunkRecords = new List<ContentChunkRecord>();

                for (int i = 0; i < this.ContentCount * ChunkRecordSize; i += ChunkRecordSize)
                {
                    byte[] contentChunk = this.RawContentChunkRecords.TakeItems(i, i + ChunkRecordSize);

                    this.ContentChunkRecords.Add(new ContentChunkRecord(contentChunk));
                }

                this.ContentInfoRecords = new List<ContentInfoRecord>();

                for (int i = 0; i < 0x900; i += 0x24)
                {
                    byte[] infoRecord = this.RawContentInfoRecords.TakeItems(i, i + 0x24);

                    if (!infoRecord.All(b => b == 0x0))
                    {
                        this.ContentInfoRecords.Add(new ContentInfoRecord(infoRecord));
                    }
                }

                if (verifyHashes)
                {
                    List<ContentChunkRecord> hashedChunkRecords = new List<ContentChunkRecord>();

                    foreach (ContentInfoRecord infoRecord in this.ContentInfoRecords)
                    {
                        List<ContentChunkRecord> toHash = new List<ContentChunkRecord>();

                        foreach (ContentChunkRecord chunkRecord in this.ContentChunkRecords)
                        {
                            if (hashedChunkRecords.Contains(chunkRecord))
                            {
                                throw new ArgumentException("Invalid TMD - Got same chunk record twice");
                            }

                            hashedChunkRecords.Add(chunkRecord);
                            toHash.Add(chunkRecord);
                        }

                        byte[] dataToHash = new byte[] { };

                        foreach (ContentChunkRecord cr in toHash)
                        {
                            dataToHash = dataToHash.MergeWith(cr.Raw);
                        }

                        byte[] hash = Tools.HashSHA256(dataToHash);

                        if (hash.Hex() != infoRecord.Hash.Hex())
                        {
                            Console.WriteLine("\nGot: " + hash.Hex());
                            throw new ArgumentException($"Invalid Info Records Detected.\nExpected: {infoRecord.Hash.Hex()}\nGot: {hash.Hex()}");
                        }
                    }
                }

                this.SignatureIssuer = Encoding.ASCII.GetString(this.Header.TakeItems(0x0, 0x40)).Replace("\0", "");
                this.Version = this.Header[0x40];
                this.CaCrlVersion = this.Header[0x41];
                this.SignerCrlVersion = this.Header[0x42];
                this.SystemVersion = this.Header.TakeItems(0x44, 0x4C).ToInt64(true);
                this.TitleType = this.Header.TakeItems(0x54, 0x58).ToInt32(true);
                this.GroupId = this.Header.TakeItems(0x58, 0x5A);
                this.SrlFlag = this.Header[0x66];
                this.AccessRights = this.Header.TakeItems(0x98, 0x9C);
                this.BootContent = this.Header.TakeItems(0xA0, 0xA2);
            }
        }

        public override string ToString()
        {
            string output =
                $"Signature Name: {this.SignatureInfo.Name}\n" +
                $"Signature Size: {this.SignatureInfo.Size} (0x{this.SignatureInfo.Size:X}) bytes\n" +
                $"Signature Padding: {this.SignatureInfo.PaddingSize} (0x{this.SignatureInfo.PaddingSize:X}) bytes\n" +
                $"Title ID: {this.TitleID.Hex()}\n" +
                $"Title Type: {this.TitleType:X8}\n" +
                $"Save Data Size: {this.SaveDataSize} (0x{this.SaveDataSize:X}) bytes\n" +
                $"SRL Save Data Size: {this.SrlSaveDataSize} (0x{this.SrlSaveDataSize:X}) bytes\n" +
                $"Title Version: {this.TitleVersion} ({this.RawTitleVersion})\n" +
                $"Amount of contents defined in TMD: {this.ContentCount}\n" +
                $"Content Info Records Hash: {this.ContentInfoRecordsHash.Hex()}\n" +
                $"Issuer: { this.SignatureIssuer }\n" +
                $"CA CRL Version: { this.CaCrlVersion }\n" +
                $"Signer CRL Version: {this.SignerCrlVersion }\n" +
                $"System Version: { this.SystemVersion }\n" +
                $"Group ID: { this.GroupId.Hex() }\n" +
                $"SRL Flag: { this.SrlFlag }\n" +
                $"Access Rights: { this.AccessRights.Hex()}\n" +
                $"Boot Content: { this.BootContent.Hex()}\n";

            foreach (ContentChunkRecord ccr in this.ContentChunkRecords)
            {
                output += $"\n{ccr}\n";
            }

            foreach (ContentInfoRecord cir in this.ContentInfoRecords)
            {
                output += $"\n{cir}\n";
            }

            return output;
        }
    }

    public class ContentChunkRecord
    {
        public byte[] Raw { get; private set; }
        public long ID { get; private set; }
        public short ContentIndex { get; private set; }
        public ContentTypeFlags Flags { get; private set; }
        public long Size { get; private set; }
        public byte[] Hash { get; private set; }


        public ContentChunkRecord(byte[] contentChunk)
        {
            this.Raw = contentChunk;
            this.ID = contentChunk.TakeItems(0x0, 0x4).ToInt32(true);
            this.ContentIndex = contentChunk.TakeItems(0x4, 0x6).ToInt16(true);
            this.Flags = new ContentTypeFlags(contentChunk.TakeItems(0x6, 0x8).ToInt16(true));
            this.Size = contentChunk.TakeItems(0x8, 0x10).ToInt64(true);
            this.Hash = contentChunk.TakeItems(0x10, 0x30);
        }

        public override string ToString() =>
            $"--------------------------------\n" +
            $"Content Chunk Record - {this.GetContentName()}:\n\n" +
            $"ID: {this.ID:X8}\n" +
            $"Content Index: {this.ContentIndex} ({this.ContentIndex:X4})\n\n" +
            $"{this.Flags}\n\n" +
            $"Content Size: {this.Size} (0x{this.Size:X}) bytes\n" +
            $"Hash: {this.Hash.Hex()}\n" +
            $"--------------------------------";

        public string GetContentName()
        {
            return $"{this.ContentIndex:X4}.{this.ID:X8}";
        }
    }

    public class ContentInfoRecord
    {
        public byte[] Raw { get; private set; }
        public short IndexOffset { get; private set; }
        public short CommandCount { get; private set; }
        public byte[] Hash { get; private set; }

        public ContentInfoRecord(byte[] infoRecord)
        {
            this.Raw = infoRecord;
            this.IndexOffset = infoRecord.TakeItems(0x0, 0x2).ToInt16(true);
            this.CommandCount = infoRecord.TakeItems(0x2, 0x4).ToInt16(true);
            this.Hash = infoRecord.TakeItems(0x4, 0x24);
        }

        public override string ToString() => $"Content Info Record:\n\nIndex Offset: {this.IndexOffset}\nCommand Count: {this.CommandCount}\nHash: {this.Hash.Hex()}";
    }

    public class ContentTypeFlags
    {
        public short Raw { get; private set; }
        public bool Encrypted { get; private set; }
        public bool IsDisc { get; private set; }
        public bool Cfm { get; private set; }
        public bool Optional { get; private set; }
        public bool Shared { get; private set; }

        public ContentTypeFlags(short flags)
        {
            this.Raw = flags;
            this.Encrypted = (flags & 1) > 0;
            this.IsDisc = (flags & 2) > 0;
            this.Cfm = (flags & 4) > 0;
            this.Optional = (flags & 0x4000) > 0;
            this.Shared = (flags & 0x8000) > 0;
        }

        public override string ToString() =>
            $"================================\n" +
            $"Content Type Flags:\n\n" +
            $"Encrypted: {this.Encrypted}\n" +
            $"Is Disc: {this.IsDisc}\n" +
            $"CFM: {this.Cfm}\n" +
            $"Optional: {this.Optional}\n" +
            $"Shared: {this.Shared}\n" +
            $"================================";
    }
}