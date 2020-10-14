using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace CTR.NET
{
    public static class TMDReader
    {
        public static Tuple<string, int, int> SignatureType(int sigData)
        {
            Tuple<string, int, int> output;
            switch (sigData)
            {
                case 0x00010000:
                    output = Tuple.Create("RSA_4096_SHA1", 0x200, 0x3C);
                    break;

                case 0x00010001:
                    output = Tuple.Create("RSA_2048_SHA1", 0x100, 0x3C);
                    break;

                case 0x00010002:
                    output = Tuple.Create("ECDSA_SHA1", 0x3C, 0x40);
                    break;

                case 0x00010003:
                    output = Tuple.Create("RSA_4096_SHA256", 0x200, 0x3C);
                    break;

                case 0x00010004:
                    output = Tuple.Create("RSA_2048_SHA256", 0x100, 0x3C);
                    break;

                case 0x00010005:
                    output = Tuple.Create("ECDSA_SHA256", 0x200, 0x3C);
                    break;

                default:
                    output = Tuple.Create("", 0x0, 0x0);
                    break;
            }
            return output;
        }

        public static int ChunkRecordSize = 0x30;

        public static TMD Read(byte[] tmdData, bool verifyHashes = true)
        {
            MemoryStream tmdDataStream = new MemoryStream(tmdData);
            Tuple<string, int, int> SigTypeData = SignatureType(Convert.ToInt32(Tools.ReadFromStream(tmdDataStream, 0x4).Hex(), 16));

            if (SigTypeData.Item2 == 0)
            {
                Console.WriteLine("Could not determine Signature Type of TMD.");
            }

            string sigName = SigTypeData.Item1;
            int sigSize = SigTypeData.Item2;
            int sigPadding = SigTypeData.Item3;
            byte[] signature = Tools.ReadFromStream(tmdDataStream, sigSize);

            Tools.ReadFromStream(tmdDataStream, sigPadding);

            byte[] header = Tools.ReadFromStream(tmdDataStream, 0xC4);

            if (header.Length != 0xC4)
            {
                throw new ArgumentException($"TMD Header size is wrong, expected 0xC4 but got {header.Length:X4}");
            }

            byte[] titleId = header.Copy(0x4C, 0x54);
            int saveSize = header.Copy(0x5A, 0x5E).IntLE();
            int srlSaveSize = header.Copy(0x5E, 0x62).IntLE();
            int version = header.Copy(0x9C, 0x9E).IntBE();
            string versionstring = $"{(version >> 10) & 0x3F}.{(version >> 4) & 0x3F}.{version & 0xF}";
            int contentCount = header.Copy(0x9E, 0xA0).IntBE();
            byte[] contentInfoRecordsHash = header.Copy(0xA4, 0xC4);
            byte[] contentInfoRecordsRaw = Tools.ReadFromStream(tmdDataStream, 0x900);

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

            byte[] contentChunkRecordsRaw = Tools.ReadFromStream(tmdDataStream, contentCount * ChunkRecordSize);
            List<ContentChunkRecord> chunkRecords = new List<ContentChunkRecord>();

            for (int i = 0; i < contentCount * ChunkRecordSize; i += ChunkRecordSize)
            {
                byte[] contentChunk = contentChunkRecordsRaw.Copy(i, i + ChunkRecordSize);
                chunkRecords.Add(new ContentChunkRecord(
                  contentChunk.Copy(0x0, 0x4).Hex(),
                  contentChunk.Copy(0x4, 0x6).IntBE(),
                  ContentTypeFlags.GetFlags(contentChunk.Copy(0x6, 0x8).IntBE()),
                  Convert.ToInt32(contentChunk.Copy(0x8, 0x10).Hex(), 16),
                  contentChunk.Copy(0x10, 0x30)
                ));
            }

            List<ContentInfoRecord> infoRecords = new List<ContentInfoRecord>();

            for (int i = 0; i < 0x900; i += 0x24)
            {
                byte[] infoRecord = contentInfoRecordsRaw.Copy(i, i + 0x24);

                if (infoRecord.Hex() != Enumerable.Repeat((byte)0x0, 0x24).ToArray().Hex())
                {
                    infoRecords.Add(new ContentInfoRecord(
                      infoRecord.Copy(0x0, 0x2).IntBE(),
                      infoRecord.Copy(0x2, 0x4).IntBE(),
                      infoRecord.Copy(0x4, 0x24)
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

            string issuer = Encoding.ASCII.GetString(header.Copy(0x0, 0x40)).Replace("\0", "");
            byte[] versionUnused = header.Copy(0x40, 0x41);
            byte[] caCrlVersion = header.Copy(0x41, 0x42);
            byte[] signerCrlVersion = header.Copy(0x42, 0x43);
            byte[] reserved1 = header.Copy(0x43, 0x44);
            byte[] systemVersion = header.Copy(0x44, 0x4C);
            byte[] titleType = header.Copy(0x54, 0x58);
            byte[] groupId = header.Copy(0x58, 0x5A);
            byte[] reserved2 = header.Copy(0x62, 0x66);
            byte[] srlFlag = header.Copy(0x66, 0x67);
            byte[] reserved3 = header.Copy(0x67, 0x98);
            byte[] accessRights = header.Copy(0x98, 0x9C);
            byte[] bootCount = header.Copy(0xA0, 0xA2);
            byte[] unusedPadding = header.Copy(0xA2, 0xA4);

            return new TMD(tmdData, sigName, sigSize, sigPadding, signature, header, titleId, saveSize, srlSaveSize, version, versionstring, contentCount, contentInfoRecordsRaw, contentInfoRecordsHash, contentChunkRecordsRaw, chunkRecords, infoRecords, issuer, versionUnused, caCrlVersion, signerCrlVersion, reserved1, systemVersion, titleType, groupId, reserved2, srlFlag, reserved3, accessRights, bootCount, unusedPadding);
        }
    }
}