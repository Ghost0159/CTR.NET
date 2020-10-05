using System;
using System.Linq;
using System.IO;
using System.Collections.Generic;

namespace CTR_LIB
{
  class Program 
  {
    private static void Main(string[] args) 
    {
      string pathToCia = "";
      try 
      {
        pathToCia = args[0];
      }  
      catch (Exception e) 
      {
        Console.WriteLine(e.Message);
      }
      
      CIA c = new CIA(pathToCia);
      
      byte[] cert_chain = Tools.ReadBytes(pathToCia, c.CertificateChain.Offset, c.CertificateChain.Offset + c.CertificateChain.Size);
      byte[] ticket = Tools.ReadBytes(pathToCia, c.Ticket.Offset, c.Ticket.Offset + c.Ticket.Size);
      byte[] tmd = Tools.ReadBytes(pathToCia, c.TitleMetadata.Offset, c.TitleMetadata.Offset + c.TitleMetadata.Size);
      
      Console.WriteLine($"SECTION Archive Header:\nOffset: 0x0-0x2020\nSize: 8224 bytes");
      
      Console.WriteLine($"\nSECTION Certificate Chain:\nOffset: 0x{Convert.ToString(c.CertificateChain.Offset, 16).ToUpper()}-0x{Convert.ToString(c.CertificateChain.Offset + c.CertificateChain.Size, 16).ToUpper()}\nSize: {c.CertificateChain.Size} bytes");
      
      Console.WriteLine($"\nSECTION Ticket:\nOffset: 0x{Convert.ToString(c.Ticket.Offset, 16).ToUpper()}-0x{Convert.ToString(c.Ticket.Offset + c.Ticket.Size, 16).ToUpper()}\nSize: {c.Ticket.Size} bytes");
      
      Console.WriteLine($"\nSECTION Title Metadata (TMD):\nOffset: 0x{Convert.ToString(c.TitleMetadata.Offset, 16).ToUpper()}-0x{Convert.ToString(c.TitleMetadata.Offset + c.TitleMetadata.Size, 16).ToUpper()}\nSize: {c.TitleMetadata.Size} bytes");
      
      Console.WriteLine($"\nSECTION Contents:\nOffset: 0x{Convert.ToString(c.Application.Offset, 16).ToUpper()}-0x{Convert.ToString(c.Application.Offset + c.Application.Size, 16).ToUpper()}\nSize: {c.Application.Size} bytes");
      
      TMD TitleMetadata = TMDReader.Read(tmd, true);
      
      //byte[] rawData, string signatureName, int signatureSize, int signaturePadding, byte[] signatureData, byte[] header, byte[] titleId, int saveDataSize, int srlSaveDataSize, int rawTitleVersion, string titleVersion, int contentCount, byte[] rawContentInfoRecords, byte[] contentInfoRecordsHash, byte[] rawContentChunkRecords, List<ContentChunkRecord> contentChunkRecords, List<ContentInfoRecord> contentInfoRecords, string issuer, byte[] unusedVersion, byte[] caCrlVersion, byte[] reserved1, byte[] systemVersion, byte[] titleType, byte[] groupId, byte[] reserved2, byte[] srlFlag, byte[] reserved3, byte[] accessRights, byte[] bootCount, byte[] unusedPadding
      
      Console.WriteLine("BEGIN EXTENSIVE TMD DATA\n");
      Console.WriteLine($"Signature Name: {TitleMetadata.SignatureName}");
      Console.WriteLine($"Signature Size: {TitleMetadata.SignatureSize} (0x{Convert.ToString(TitleMetadata.SignatureSize, 16)}) bytes");
      Console.WriteLine($"Signature Padding: {TitleMetadata.SignaturePadding} (0x{Convert.ToString(TitleMetadata.SignaturePadding, 16)}) bytes");
      Console.WriteLine($"Title ID: {TitleMetadata.TitleId.Hex()}");
      Console.WriteLine($"Save Data Size: {TitleMetadata.SaveDataSize} (0x{Convert.ToString(TitleMetadata.SaveDataSize, 16)}) bytes");
      Console.WriteLine($"SRL Save Data Size: {TitleMetadata.SrlSaveDataSize} (0x{Convert.ToString(TitleMetadata.SrlSaveDataSize, 16)}) bytes");
      Console.WriteLine($"Title Version: {TitleMetadata.TitleVersion} ({TitleMetadata.RawTitleVersion})");
      Console.WriteLine($"Amount of contents defined in TMD: {TitleMetadata.ContentCount}");
      Console.WriteLine($"Content Info Records Hash: {TitleMetadata.ContentInfoRecordsHash.Hex()}\n");
      
      foreach (ContentChunkRecord ccr in TitleMetadata.ContentChunkRecords)
      {
        Console.WriteLine("--------------------------------\n");
        Console.WriteLine($"CHUNK INFO DATA FOR INDEX {ccr.ContentIndex.ToString("X4")}.{ccr.ID}:\n");
        Console.WriteLine($"ID: {ccr.ID}");
        Console.WriteLine($"Content Index: {ccr.ContentIndex} ({ccr.ContentIndex.ToString("X4")})\n");
        Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        Console.WriteLine("CONTENT TYPE FLAGS:\n");
        Console.WriteLine($"Encrypted: {ccr.Type.Encrypted}");
        Console.WriteLine($"Disc: {ccr.Type.IsDisc}");
        Console.WriteLine($"Cfm: {ccr.Type.Cfm}");
        Console.WriteLine($"Optinal: {ccr.Type.Optional}");
        Console.WriteLine($"Shared: {ccr.Type.Shared}\n");
        Console.WriteLine("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        Console.WriteLine($"Content Size: {ccr.Size} (0x{Convert.ToString(ccr.Size, 16)}) bytes");
        Console.WriteLine($"Chunk Info Hash: {ccr.Hash.Hex()}\n");
        Console.WriteLine("--------------------------------\n");
      }
      
      foreach (ContentInfoRecord cir in TitleMetadata.ContentInfoRecords)
      {
        Console.WriteLine($"CONTENT INFO DATA\n");
        Console.WriteLine("--------------------------------\n");
        Console.WriteLine($"Index Offset: {cir.IndexOffset}");
        Console.WriteLine($"Command Count: {cir.CommandCount}");
        Console.WriteLine($"Hash: {cir.Hash.Hex()}\n");
        Console.WriteLine("--------------------------------\n");
      }
      
      Console.WriteLine($"Issuer: {TitleMetadata.Issuer}");
      Console.WriteLine($"Unused Version: {TitleMetadata.UnusedVersion.Hex()}");
      Console.WriteLine($"CA CRL Version: {TitleMetadata.CaCrlVersion.Hex()}");
      Console.WriteLine($"Reserved (1): {TitleMetadata.Reserved1.Hex()}");
      Console.WriteLine($"System Version: {TitleMetadata.SystemVersion.Hex()}");
      Console.WriteLine($"Title Type: {TitleMetadata.TitleType.Hex()}");
      Console.WriteLine($"Group ID: {TitleMetadata.GroupId.Hex()}");
      Console.WriteLine($"Reserved (2): {TitleMetadata.Reserved2.Hex()}");
      Console.WriteLine($"SRL Flag: {TitleMetadata.SrlFlag.Hex()}");
      Console.WriteLine($"Reserved (3): {TitleMetadata.Reserved3.Hex()}");
      Console.WriteLine($"Access Rights: {TitleMetadata.AccessRights.Hex()}");
      Console.WriteLine($"Boot Count: {TitleMetadata.BootCount.Hex()}");
      Console.WriteLine($"Unused Padding: {TitleMetadata.UnusedPadding.Hex()}");
    }  
  }  
}