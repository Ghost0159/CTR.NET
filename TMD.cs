using System;
using System.Collections.Generic;

namespace CTR_LIB
{
    public class TMD
    {
        public byte[] RawData { get; private set; }
        public string SignatureName { get; private set; }
        public int SignatureSize { get; private set; }
        public int SignaturePadding { get; private set; }
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

        public TMD(byte[] rawData, string signatureName, int signatureSize, int signaturePadding, byte[] signatureData, byte[] header, byte[] titleId, int saveDataSize, int srlSaveDataSize, int rawTitleVersion, string titleVersion, int contentCount, byte[] rawContentInfoRecords, byte[] contentInfoRecordsHash, byte[] rawContentChunkRecords, List<ContentChunkRecord> contentChunkRecords, List<ContentInfoRecord> contentInfoRecords, string issuer, byte[] unusedVersion, byte[] caCrlVersion, byte[] reserved1, byte[] systemVersion, byte[] titleType, byte[] groupId, byte[] reserved2, byte[] srlFlag, byte[] reserved3, byte[] accessRights, byte[] bootCount, byte[] unusedPadding)
        {
            this.RawData = rawData;
            this.SignatureName = signatureName;
            this.SignatureSize = signatureSize;
            this.SignaturePadding = signaturePadding;
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
                $"Signature Name: {this.SignatureName}\n" +
                $"Signature Size: {this.SignatureSize} (0x{Convert.ToString(this.SignatureSize, 16)}) bytes\n" +
                $"Signature Padding: {this.SignaturePadding} (0x{Convert.ToString(this.SignaturePadding, 16)}) bytes\n" +
                $"Title ID: {this.TitleId.Hex()}\n" +
                $"Save Data Size: {this.SaveDataSize} (0x{Convert.ToString(this.SaveDataSize, 16)}) bytes\n" +
                $"SRL Save Data Size: {this.SrlSaveDataSize} (0x{Convert.ToString(this.SrlSaveDataSize, 16)}) bytes\n" +
                $"Title Version: {this.TitleVersion} ({this.RawTitleVersion})\n" +
                $"Amount of contents defined in TMD: {this.ContentCount}\n" +
                $"Content Info Records Hash: {this.ContentInfoRecordsHash.Hex()}\n" +
                $"Issuer: { this.Issuer}\n" +
                $"Unused Version: { this.UnusedVersion.Hex()}\n" +
                $"CA CRL Version: { this.CaCrlVersion.Hex()}\n" +
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
    }
}