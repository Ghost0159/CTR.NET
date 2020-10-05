using System;
using System.Collections.Generic;

namespace CTR_LIB
{
  class TMD 
  {
    public byte[] RawData { get; private set; }
    public string SignatureName { get; private set; }
    public Int32 SignatureSize { get; private set; }
    public Int32 SignaturePadding { get; private set; }
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
  }
}