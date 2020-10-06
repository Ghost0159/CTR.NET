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
      
      byte[] cert_chain = Tools.ReadBytes(pathToCia, c.CertificateChainInfo.Offset, c.CertificateChainInfo.Offset + c.CertificateChainInfo.Size);
      byte[] ticket = Tools.ReadBytes(pathToCia, c.TicketInfo.Offset, c.TicketInfo.Offset + c.TicketInfo.Size);
      
      Console.WriteLine(c.ArchiveHeaderInfo);
      Console.WriteLine(c.CertificateChainInfo);
      Console.WriteLine(c.TicketInfo);
      Console.WriteLine(c.TitleMetadataInfo);
      Console.WriteLine(c.ApplicationInfo);
      Console.WriteLine(c.MetaInfo);
      
      Console.WriteLine("\nBEGIN EXTENSIVE TMD DATA");
      
      Console.WriteLine(c.TitleMetadata);
    }  
  }  
}