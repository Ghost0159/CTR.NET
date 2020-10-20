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
        public byte[] UnusedVersion { get; private set; }
        public byte[] CaCrlVersion { get; private set; }
        public byte[] SignerCrlVersion { get; private set; }
        public byte[] Reserved1 { get; private set; }
        public byte[] SystemVersion { get; private set; }
        public byte[] TitleType { get; private set; }
        public byte[] GroupId { get; private set; }
        public byte[] Reserved2 { get; private set; }
        public byte[] SrlFlag { get; private set; }
        public byte[] Reserved3 { get; private set; }
        public byte[] AccessRights { get; private set; }
        public byte[] BootCount { get; private set; }
        public byte[] UnusedPadding { get; private set; }

        public TMDInfo(byte[] rawData, Signature signature, byte[] signatureData, byte[] header, byte[] titleId, int saveDataSize, int srlSaveDataSize, int rawTitleVersion, string titleVersion, int contentCount, byte[] rawContentInfoRecords, byte[] contentInfoRecordsHash, byte[] rawContentChunkRecords, List<ContentChunkRecord> contentChunkRecords, List<ContentInfoRecord> contentInfoRecords, string issuer, byte[] unusedVersion, byte[] caCrlVersion, byte[] signerCrlVersion, byte[] reserved1, byte[] systemVersion, byte[] titleType, byte[] groupId, byte[] reserved2, byte[] srlFlag, byte[] reserved3, byte[] accessRights, byte[] bootCount, byte[] unusedPadding)
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
            this.UnusedVersion = unusedVersion;
            this.CaCrlVersion = caCrlVersion;
            this.SignerCrlVersion = signerCrlVersion;
            this.Reserved1 = reserved1;
            this.SystemVersion = systemVersion;
            this.TitleType = titleType;
            this.GroupId = groupId;
            this.Reserved2 = reserved2;
            this.SrlFlag = srlFlag;
            this.Reserved3 = reserved3;
            this.AccessRights = accessRights;
            this.BootCount = bootCount;
            this.UnusedPadding = unusedPadding;
        }

        public override string ToString()
        {
            string output =
                $"Signature Name: {this.SignatureInfo.Name}\n" +
                $"Signature Size: {this.SignatureInfo.Size} (0x{Convert.ToString(this.SignatureInfo.Size, 16)}) bytes\n" +
                $"Signature Padding: {this.SignatureInfo.PaddingSize} (0x{Convert.ToString(this.SignatureInfo.PaddingSize, 16)}) bytes\n" +
                $"Title ID: {this.TitleId.Hex()}\n" +
                $"Save Data Size: {this.SaveDataSize} (0x{Convert.ToString(this.SaveDataSize, 16)}) bytes\n" +
                $"SRL Save Data Size: {this.SrlSaveDataSize} (0x{Convert.ToString(this.SrlSaveDataSize, 16)}) bytes\n" +
                $"Title Version: {this.TitleVersion} ({this.RawTitleVersion})\n" +
                $"Amount of contents defined in TMD: {this.ContentCount}\n" +
                $"Content Info Records Hash: {this.ContentInfoRecordsHash.Hex()}\n" +
                $"Issuer: { this.Issuer}\n" +
                $"Unused Version: { this.UnusedVersion.Hex()}\n" +
                $"CA CRL Version: { this.CaCrlVersion.Hex()}\n" +
                $"Signer CRL Version: {this.SignerCrlVersion.Hex()}\n" +
                $"Reserved(1): { this.Reserved1.Hex()}\n" +
                $"System Version: { this.SystemVersion.Hex()}\n" +
                $"Group ID: { this.GroupId.Hex()}\n" +
                $"Reserved(2): { this.Reserved2.Hex()}\n" +
                $"SRL Flag: { this.SrlFlag.Hex()}\n" +
                $"Reserved(3): { this.Reserved3.Hex()}\n" +
                $"Access Rights: { this.AccessRights.Hex()}\n" +
                $"Boot Count: { this.BootCount.Hex()}\n" +
                $"Unused Padding: { this.UnusedPadding.Hex()}";

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

            byte[] titleId = header.TakeBytes(0x4C, 0x54);
            int saveSize = header.TakeBytes(0x5A, 0x5E).IntLE();
            int srlSaveSize = header.TakeBytes(0x5E, 0x62).IntLE();
            int version = header.TakeBytes(0x9C, 0x9E).IntBE();
            string versionstring = $"{(version >> 10) & 0x3F}.{(version >> 4) & 0x3F}.{version & 0xF}";
            int contentCount = header.TakeBytes(0x9E, 0xA0).IntBE();
            byte[] contentInfoRecordsHash = header.TakeBytes(0xA4, 0xC4);
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
                byte[] contentChunk = contentChunkRecordsRaw.TakeBytes(i, i + ChunkRecordSize);

                chunkRecords.Add(new ContentChunkRecord(
                  contentChunk.TakeBytes(0x0, 0x4).Hex(),
                  contentChunk.TakeBytes(0x4, 0x6).IntBE(),
                  ContentTypeFlags.GetFlags(contentChunk.TakeBytes(0x6, 0x8).IntBE()),
                  long.Parse(contentChunk.TakeBytes(0x8, 0x10).Hex(), System.Globalization.NumberStyles.HexNumber),
                  contentChunk.TakeBytes(0x10, 0x30)
                ));
            }

            List<ContentInfoRecord> infoRecords = new List<ContentInfoRecord>();

            for (int i = 0; i < 0x900; i += 0x24)
            {
                byte[] infoRecord = contentInfoRecordsRaw.TakeBytes(i, i + 0x24);

                if (infoRecord.Hex() != Enumerable.Repeat((byte)0x0, 0x24).ToArray().Hex())
                {
                    infoRecords.Add(new ContentInfoRecord(
                      infoRecord.TakeBytes(0x0, 0x2).IntBE(),
                      infoRecord.TakeBytes(0x2, 0x4).IntBE(),
                      infoRecord.TakeBytes(0x4, 0x24)
                    ));
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
                        dataToHash = dataToHash.Combine(cr.ToByteArray());
                    }

                    byte[] hash = Tools.HashSHA256(dataToHash);

                    if (hash.Hex() != infoRecord.Hash.Hex())
                    {
                        Console.WriteLine();
                        Console.WriteLine("Got: " + hash.Hex());
                        throw new ArgumentException($"Invalid Info Records Detected.\nExpected: {infoRecord.Hash.Hex()}\nGot: {hash.Hex()}");
                    }
                }
            }

            string issuer = Encoding.ASCII.GetString(header.TakeBytes(0x0, 0x40)).Replace("\0", "");
            byte[] versionUnused = header.TakeBytes(0x40, 0x41);
            byte[] caCrlVersion = header.TakeBytes(0x41, 0x42);
            byte[] signerCrlVersion = header.TakeBytes(0x42, 0x43);
            byte[] reserved1 = header.TakeBytes(0x43, 0x44);
            byte[] systemVersion = header.TakeBytes(0x44, 0x4C);
            byte[] titleType = header.TakeBytes(0x54, 0x58);
            byte[] groupId = header.TakeBytes(0x58, 0x5A);
            byte[] reserved2 = header.TakeBytes(0x62, 0x66);
            byte[] srlFlag = header.TakeBytes(0x66, 0x67);
            byte[] reserved3 = header.TakeBytes(0x67, 0x98);
            byte[] accessRights = header.TakeBytes(0x98, 0x9C);
            byte[] bootCount = header.TakeBytes(0xA0, 0xA2);
            byte[] unusedPadding = header.TakeBytes(0xA2, 0xA4);

            return new TMDInfo(tmdData, sig, signature, header, titleId, saveSize, srlSaveSize, version, versionstring, contentCount, contentInfoRecordsRaw, contentInfoRecordsHash, contentChunkRecordsRaw, chunkRecords, infoRecords, issuer, versionUnused, caCrlVersion, signerCrlVersion, reserved1, systemVersion, titleType, groupId, reserved2, srlFlag, reserved3, accessRights, bootCount, unusedPadding);
        }
    }

    public class ContentChunkRecord
    {
        public string ID { get; private set; }
        public int ContentIndex { get; private set; }
        public ContentTypeFlags Type { get; private set; }
        public long Size { get; private set; }
        public byte[] Hash { get; private set; }

        public ContentChunkRecord(string id, int contentIndex, ContentTypeFlags flags, long size, byte[] hash)
        {
            this.ID = id;
            this.ContentIndex = contentIndex;
            this.Type = flags;
            this.Size = size;
            this.Hash = hash;
        }

        public override string ToString() =>
            $"--------------------------------\n" +
            $"CONTENT CHUNK RECORD INFO FOR INDEX {this.ContentIndex:X4}.{this.ID}:\n\n" +
            $"ID: {this.ID}\n" +
            $"Content Index: {this.ContentIndex} ({this.ContentIndex:X4})\n\n" +
            $"{this.Type}\n\n" +
            $"Content Size: {this.Size} (0x{Convert.ToString(this.Size, 16).ToUpper()}) bytes\n" +
            $"Hash: {this.Hash.Hex()}\n" +
            $"--------------------------------";

        public byte[] ToByteArray()
        {
            return Tools.HexToBytes(this.ID)
                    .Combine(Tools.HexToBytes(this.ContentIndex.ToString("X4")))
                    .Combine(Tools.HexToBytes(this.Type.AsInt().ToString("X4")))
                    .Combine(Tools.HexToBytes(((int)this.Size).ToString("X16")))
                    .Combine(this.Hash);
        }
    }

    public class ContentInfoRecord
    {
        public int IndexOffset { get; private set; }
        public int CommandCount { get; private set; }
        public byte[] Hash { get; private set; }

        public ContentInfoRecord(int indexOffset, int commandCount, byte[] hash)
        {
            this.IndexOffset = indexOffset;
            this.CommandCount = commandCount;
            this.Hash = hash;
        }

        public override string ToString() => $"CONTENT INFO RECORD:\n\nIndex Offset: {this.IndexOffset}\nCommand Count: {this.CommandCount}\nHash: {this.Hash.Hex()}";
    }

    public class ContentTypeFlags
    {
        public bool Encrypted { get; private set; }
        public bool IsDisc { get; private set; }
        public bool Cfm { get; private set; }
        public bool Optional { get; private set; }
        public bool Shared { get; private set; }

        public ContentTypeFlags(bool enc, bool disc, bool cfm, bool opt, bool shared)
        {
            this.Encrypted = enc;
            this.IsDisc = disc;
            this.Cfm = cfm;
            this.Optional = opt;
            this.Shared = shared;
        }

        private static bool BoolFromInt(int input) => (input == 0) ? false : true;

        public override string ToString() =>
            $"================================\n" +
            $"CONTENT TYPE FLAGS:\n\n" +
            $"ENCRYPTED: {this.Encrypted}\n" +
            $"IS DISC: {this.IsDisc}\n" +
            $"CFM: {this.Cfm}\n" +
            $"OPTIONAL: {this.Optional}\n" +
            $"SHARED: {this.Shared}\n" +
            $"================================";

        public static ContentTypeFlags GetFlags(int flags)
        {
            return new ContentTypeFlags(
              BoolFromInt(flags & 1),
              BoolFromInt(flags & 2),
              BoolFromInt(flags & 4),
              BoolFromInt(flags & 0x4000),
              BoolFromInt(flags & 0x8000)
            );
        }

        public int AsInt() => (((this.Encrypted == true) ? 1 : 0) | (((this.IsDisc == true) ? 1 : 0) << 1) | (((this.Cfm == true) ? 1 : 0) << 2) | (((this.Optional == true) ? 1 : 0) << 14) | (((this.Shared == true) ? 1 : 0) << 15));
    }
}