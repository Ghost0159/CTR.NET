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
    
    public CIASection ArchiveHeader { get; private set; }
    public CIASection CertificateChain { get; private set; }
    public CIASection Ticket { get; private set; }
    public CIASection TitleMetadata { get; private set; }
    public CIASection Application { get; private set; }
    public CIASection Manual { get; private set; }
    public CIASection DownloadPlayChild { get; private set; }
    public CIASection Meta { get; private set; }
    
    public CIA(string pathToCIA)
    {
      if (!File.Exists(pathToCIA)) 
      {
        throw new FileNotFoundException($"File at {pathToCIA} was not found.");
      }
      
      int header = Tools.IntLE(Tools.ReadBytes(pathToCIA, 0x0, 0x4));
        
      if(header.ToString("X4") != "2020")
      {
        throw new ArgumentException($"File (pathToCIA) is not a CIA.");
      }
      
      int cert_chain_size = Tools.IntLE(Tools.ReadBytes(pathToCIA, 0x8, 0xC));
      int ticket_size = Tools.IntLE(Tools.ReadBytes(pathToCIA, 0xC, 0x10));
      int tmd_size = Tools.IntLE(Tools.ReadBytes(pathToCIA, 0x10, 0x14));
      int meta_size = Tools.IntLE(Tools.ReadBytes(pathToCIA, 0x14, 0x18));
      int content_size = Tools.IntLE(Tools.ReadBytes(pathToCIA, 0x18, 0x20));
      
      byte[] content_index = Tools.ReadBytes(pathToCIA, 0x20, 0x2020);
      
      List<int> ActiveContents = new List<int>();
      
      for (int i = 0; i < content_index.Length; i++) 
      {
        int offset = i * 8;
        byte current = content_index[i];
        
        for (int j = 7; j > -1; j -= 1) 
        {
          if ((current & 1) == 1) 
          {
            ActiveContents.Add(offset + j);
          }
          
          current >>= 1;
        }
      }
      
      int cert_chain_offset = Tools.RoundUp(header, AlignSize);
      int ticket_offset = cert_chain_offset + Tools.RoundUp(cert_chain_size, AlignSize);
      int tmd_offset = ticket_offset + Tools.RoundUp(ticket_size, AlignSize);
      int content_offset = tmd_offset + Tools.RoundUp(tmd_size, AlignSize);
      int meta_offset = content_offset + Tools.RoundUp(content_size, AlignSize);
      
      this.ArchiveHeader = new CIASection((int)ContentType.ArchiveHeader, header, 0);
      this.CertificateChain = new CIASection((int)ContentType.CertificateChain, cert_chain_offset, cert_chain_size);
      this.Ticket = new CIASection((int)ContentType.Ticket, ticket_offset, ticket_size);
      this.TitleMetadata = new CIASection((int)ContentType.TitleMetadata, tmd_offset, tmd_size);
      this.Application = new CIASection((int)ContentType.Application, content_offset, content_size);
      if (meta_size > 0)
      {
        this.Meta = new CIASection((int)ContentType.Meta, meta_offset, meta_size);
      }
    }
  }
}