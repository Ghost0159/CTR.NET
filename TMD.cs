using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace CTR.NET
{
    public class TMDInfo
    {
        public byte[] RawData { get; private set; }
        public Signature SignatureInfo { get; private set; }
        public byte[] SignatureData { get; private set; }
        public byte[] Header { get; private set; }
        public byte[] TitleId { get; private set; }
        public int SaveDataSize { get; private set; }
        public int SrlSaveDataSize { get; private set; }
        public int RawTitleVersion { get; private set; }
        public string TitleVersion { get; private set; }
        public int ContentCount { get; private set; }
        public byte[] RawContentInfoRecords { get; private set; }
        public byte[] ContentInfoRecordsHash { get; private set; }
        public byte[] RawContentChunkRecords { get; private set; }
        public List<ContentChunkRecord> ContentChunkRecords { get; private set; }
        public List<ContentInfoRecord> ContentInfoRecords { get; private set; }
        public string Issuer { get; private set; }
        public byte[] CaCrlVersion { get; private set; }
        public byte[] SignerCrlVersion { get; private set; }
        public byte[] SystemVersion { get; private set; }
        public byte[] TitleType { get; private set; }
        public byte[] GroupId { get; private set; }
        public byte[] SrlFlag { get; private set; }
        public byte[] AccessRights { get; private set; }
        public byte[] BootCount { get; private set; }

        public TMDInfo(byte[] rawData, Signature signature, byte[] signatureData, byte[] header, byte[] titleId, int saveDataSize, int srlSaveDataSize, int rawTitleVersion, string titleVersion, int contentCount, byte[] rawContentInfoRecords, byte[] contentInfoRecordsHash, byte[] rawContentChunkRecords, List<ContentChunkRecord> contentChunkRecords, List<ContentInfoRecord> contentInfoRecords, string issuer, byte[] caCrlVersion, byte[] signerCrlVersion, byte[] systemVersion, byte[] titleType, byte[] groupId, byte[] srlFlag, byte[] accessRights, byte[] bootCount)
        {
            this.RawData = rawData;
            this.SignatureInfo = signature;
            this.SignatureData = signatureData;
            this.Header = header;
            this.TitleId = titleId;
            this.SaveDataSize = saveDataSize;
            this.SrlSaveDataSize = srlSaveDataSize;
            this.RawTitleVersion = rawTitleVersion;
            this.TitleVersion = titleVersion;
            this.ContentCount = contentCount;
            this.RawContentInfoRecords = rawContentInfoRecords;
            this.ContentInfoRecordsHash = contentInfoRecordsHash;
            this.RawContentChunkRecords = rawContentChunkRecords;
            this.ContentChunkRecords = contentChunkRecords;
            this.ContentInfoRecords = contentInfoRecords;
            this.Issuer = issuer;
            this.CaCrlVersion = caCrlVersion;
            this.SignerCrlVersion = signerCrlVersion;
            this.SystemVersion = systemVersion;
            this.TitleType = titleType;
            this.GroupId = groupId;
            this.SrlFlag = srlFlag;
            this.AccessRights = accessRights;
            this.BootCount = bootCount;
        }

        public override string ToString()
        {
            string output =
                $"Signature Name: {this.SignatureInfo.Name}\n" +
                $"Signature Size: {this.SignatureInfo.Size} (0x{this.SignatureInfo.Size:X}) bytes\n" +
                $"Signature Padding: {this.SignatureInfo.PaddingSize} (0x{this.SignatureInfo.PaddingSize:X}) bytes\n" +
                $"Title ID: {this.TitleId.Hex()}\n" +
                $"Save Data Size: {this.SaveDataSize} (0x{this.SaveDataSize:X}) bytes\n" +
                $"SRL Save Data Size: {this.SrlSaveDataSize} (0x{this.SrlSaveDataSize:X}) bytes\n" +
                $"Title Version: {this.TitleVersion} ({this.RawTitleVersion})\n" +
                $"Amount of contents defined in TMD: {this.ContentCount}\n" +
                $"Content Info Records Hash: {this.ContentInfoRecordsHash.Hex()}\n" +
                $"Issuer: { this.Issuer}\n" +
                $"CA CRL Version: { this.CaCrlVersion.Hex()}\n" +
                $"Signer CRL Version: {this.SignerCrlVersion.Hex()}\n" +
                $"System Version: { this.SystemVersion.Hex()}\n" +
                $"Group ID: { this.GroupId.Hex()}\n" +
                $"SRL Flag: { this.SrlFlag.Hex()}\n" +
                $"Access Rights: { this.AccessRights.Hex()}\n" +
                $"Boot Count: { this.BootCount.Hex()}\n";

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

        public static int ChunkRecordSize = 0x30;

        public static TMDInfo Read(byte[] tmdData, bool verifyHashes = true)
        {
            MemoryStream tmdDataStream = new MemoryStream(tmdData);
            Signature sig = Signature.Parse(tmdDataStream.ReadBytes(0x4));

            if (sig.Size == 0)
            {
                Console.WriteLine("Could not determine Signature Type of TMD.");
            }

            byte[] signature = tmdDataStream.ReadBytes(sig.Size);

            tmdDataStream.ReadBytes(sig.PaddingSize);

            byte[] header = tmdDataStream.ReadBytes(0xC4);

            if (header.Length != 0xC4)
            {
                throw new ArgumentException($"TMD Header size is wrong, expected 0xC4 but got {header.Length:X4}");
            }

            byte[] titleId = header.TakeItems(0x4C, 0x54);
            int saveSize = header.TakeItems(0x5A, 0x5E).IntLE();
            int srlSaveSize = header.TakeItems(0x5E, 0x62).IntLE();
            int version = header.TakeItems(0x9C, 0x9E).IntBE();
            string versionstring = $"{(version >> 10) & 0x3F}.{(version >> 4) & 0x3F}.{version & 0xF}";
            int contentCount = header.TakeItems(0x9E, 0xA0).IntBE();
            byte[] contentInfoRecordsHash = header.TakeItems(0xA4, 0xC4);
            byte[] contentInfoRecordsRaw = tmdDataStream.ReadBytes(0x900);

            if (contentInfoRecordsRaw.Length != 0x900)
            {
                throw new ArgumentException("TMD Content Info Records size is invalid.");
            }

            if (verifyHashes)
            {
                if (Tools.HashSHA256(contentInfoRecordsRaw).Hex() != contentInfoRecordsHash.Hex())
                {
                    throw new ArgumentException("TMD Content Info Records Hash does not match.");
                }
            }

            byte[] contentChunkRecordsRaw = tmdDataStream.ReadBytes(contentCount * ChunkRecordSize);
            List<ContentChunkRecord> chunkRecords = new List<ContentChunkRecord>();

            for (int i = 0; i < contentCount * ChunkRecordSize; i += ChunkRecordSize)
            {
                byte[] contentChunk = contentChunkRecordsRaw.TakeItems(i, i + ChunkRecordSize);

                chunkRecords.Add(new ContentChunkRecord(contentChunk));
            }

            List<ContentInfoRecord> infoRecords = new List<ContentInfoRecord>();

            for (int i = 0; i < 0x900; i += 0x24)
            {
                byte[] infoRecord = contentInfoRecordsRaw.TakeItems(i, i + 0x24);

                if (!infoRecord.All(b => b == 0x0))
                {
                    infoRecords.Add(new ContentInfoRecord(infoRecord));
                }
            }

            if (verifyHashes)
            {
                List<ContentChunkRecord> hashedChunkRecords = new List<ContentChunkRecord>();

                foreach (ContentInfoRecord infoRecord in infoRecords)
                {
                    List<ContentChunkRecord> toHash = new List<ContentChunkRecord>();

                    foreach (ContentChunkRecord chunkRecord in chunkRecords)
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

            string issuer = Encoding.ASCII.GetString(header.TakeItems(0x0, 0x40)).Replace("\0", "");
            byte[] caCrlVersion = header.TakeItems(0x41, 0x42);
            byte[] signerCrlVersion = header.TakeItems(0x42, 0x43);
            byte[] systemVersion = header.TakeItems(0x44, 0x4C);
            byte[] titleType = header.TakeItems(0x54, 0x58);
            byte[] groupId = header.TakeItems(0x58, 0x5A);
            byte[] srlFlag = header.TakeItems(0x66, 0x67);
            byte[] accessRights = header.TakeItems(0x98, 0x9C);
            byte[] bootCount = header.TakeItems(0xA0, 0xA2);

            return new TMDInfo(tmdData, sig, signature, header, titleId, saveSize, srlSaveSize, version, versionstring, contentCount, contentInfoRecordsRaw, contentInfoRecordsHash, contentChunkRecordsRaw, chunkRecords, infoRecords, issuer, caCrlVersion, signerCrlVersion, systemVersion, titleType, groupId, srlFlag, accessRights, bootCount);
        }
    }

    public class ContentChunkRecord
    {
        public byte[] Raw { get; private set; }
        public byte[] ID { get; private set; }
        public byte[] ContentIndex { get; private set; }
        public ContentTypeFlags Flags { get; private set; }
        public long Size { get; private set; }
        public byte[] Hash { get; private set; }


        public ContentChunkRecord(byte[] contentChunk)
        {
            this.Raw = contentChunk;
            this.ID = contentChunk.TakeItems(0x0, 0x4);
            this.ContentIndex = contentChunk.TakeItems(0x4, 0x6);
            this.Flags = new ContentTypeFlags(contentChunk.TakeItems(0x6, 0x8).IntBE());
            this.Size = contentChunk.TakeItems(0x8, 0x10).FReverse().ToInt64();
            this.Hash = contentChunk.TakeItems(0x10, 0x30);
        }

        public override string ToString() =>
            $"--------------------------------\n" +
            $"Content Chunk Record - {this.ContentIndex.Hex()}.{this.ID.Hex()}:\n\n" +
            $"ID: {this.ID.Hex()}\n" +
            $"Content Index: {this.ContentIndex.IntBE()} ({this.ContentIndex.Hex()})\n\n" +
            $"{this.Flags}\n\n" +
            $"Content Size: {this.Size} (0x{this.Size:X}) bytes\n" +
            $"Hash: {this.Hash.Hex()}\n" +
            $"--------------------------------";
    }

    public class ContentInfoRecord
    {
        public byte[] Raw { get; private set; }
        public int IndexOffset { get; private set; }
        public int CommandCount { get; private set; }
        public byte[] Hash { get; private set; }

        public ContentInfoRecord(byte[] infoRecord)
        {
            this.Raw = infoRecord;
            this.IndexOffset = infoRecord.TakeItems(0x0, 0x2).IntBE();
            this.CommandCount = infoRecord.TakeItems(0x2, 0x4).IntBE();
            this.Hash = infoRecord.TakeItems(0x4, 0x24);
        }

        public override string ToString() => $"Content Info Record:\n\nIndex Offset: {this.IndexOffset}\nCommand Count: {this.CommandCount}\nHash: {this.Hash.Hex()}";
    }

    public class ContentTypeFlags
    {
        public int Raw { get; private set; }
        public bool Encrypted { get; private set; }
        public bool IsDisc { get; private set; }
        public bool Cfm { get; private set; }
        public bool Optional { get; private set; }
        public bool Shared { get; private set; }

        public ContentTypeFlags(int flags)
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