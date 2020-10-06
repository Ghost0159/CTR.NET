using System;
using System.IO;
using System.Collections.Generic;

namespace CTR_LIB
{
  class CIA
  {
    public enum ContentType
    {
      ArchiveHeader = -4,
      CertificateChain = -3, 
      Ticket = -2,
      TitleMetadata = -1,
      Application = 0,
      Manual = 1,
      DownloadPlayChild = 2,
      Meta = -5
    }
    
    public static int AlignSize = 64;
    
    public CIASectionInfo ArchiveHeaderInfo { get; private set; }
    public CIASectionInfo CertificateChainInfo { get; private set; }
    public CIASectionInfo TicketInfo { get; private set; }
    public CIASectionInfo TitleMetadataInfo { get; private set; }
    public CIASectionInfo ApplicationInfo { get; private set; }
    public CIASectionInfo ManualInfo { get; private set; }
    public CIASectionInfo DownloadPlayChildInfo { get; private set; }
    public CIASectionInfo MetaInfo { get; private set; }
    public TMD TitleMetadata { get; private set; }
    
    public CIA(string pathToCIA)
    {
      if (!File.Exists(pathToCIA)) 
      {
        throw new FileNotFoundException($"File at {pathToCIA} was not found.");
      }
      
      int header = Tools.ReadBytes(pathToCIA, 0x0, 0x4).IntLE();
        
      if(header.ToString("X4") != "2020")
      {
        throw new ArgumentException($"File (pathToCIA) is not a CIA, because the header is not 0x2020 (8224).");
      }
      
      int certChainSize = Tools.ReadBytes(pathToCIA, 0x8, 0xC).IntLE();
      int ticketSize = Tools.ReadBytes(pathToCIA, 0xC, 0x10).IntLE();
      int tmdSize = Tools.ReadBytes(pathToCIA, 0x10, 0x14).IntLE();
      int metaSize = Tools.ReadBytes(pathToCIA, 0x14, 0x18).IntLE();
      int contentSize = Tools.ReadBytes(pathToCIA, 0x18, 0x20).IntLE();
      
      byte[] contentIndex = Tools.ReadBytes(pathToCIA, 0x20, 0x2020);
      
      List<int> ActiveContents = new List<int>();
      
      for (int i = 0; i < contentIndex.Length; i++) 
      {
        int offset = i * 8;
        byte current = contentIndex[i];
        
        for (int j = 7; j > -1; j -= 1) 
        {
          if ((current & 1) == 1) 
          {
            ActiveContents.Add(offset + j);
          }
          
          current >>= 1;
        }
      }
      
      int certChainOffset = Tools.RoundUp(header, AlignSize);
      int ticketOffset = certChainOffset + Tools.RoundUp(certChainSize, AlignSize);
      int tmdOffset = ticketOffset + Tools.RoundUp(ticketSize, AlignSize);
      int contentOffset = tmdOffset + Tools.RoundUp(tmdSize, AlignSize);
      int metaOffset = contentOffset + Tools.RoundUp(contentSize, AlignSize);
      
      this.ArchiveHeaderInfo = new CIASectionInfo("Archive Header", (int)ContentType.ArchiveHeader, 0x0, header);
      this.CertificateChainInfo = new CIASectionInfo("Certificate Chain", (int)ContentType.CertificateChain, certChainOffset, certChainSize);
      this.TicketInfo = new CIASectionInfo("Ticket", (int)ContentType.Ticket, ticketOffset, ticketSize);
      this.TitleMetadataInfo = new CIASectionInfo("Title Metadata (TMD)", (int)ContentType.TitleMetadata, tmdOffset, tmdSize);
      this.ApplicationInfo = new CIASectionInfo("Contents", (int)ContentType.Application, contentOffset, contentSize);
      this.TitleMetadata = TMDReader.Read(Tools.ReadBytes(pathToCIA, tmdOffset, tmdOffset + tmdSize), true);
      
      if (metaSize > 0)
      {
        this.MetaInfo = new CIASectionInfo("Meta", (int)ContentType.Meta, metaOffset, metaSize);
      }
    }
  }
}