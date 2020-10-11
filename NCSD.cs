using System;
using System.IO;
using System.Collections.Generic;

namespace CTR_LIB
{
  public class NCSD
  {
    public enum NCSDSection
    {
      Header = -3,
      CardInfo = -2,
      DevInfo = -1,
      Application = 0,
      Manual = 1,
      DownloadPlayChild = 2,
      Unknown3 = 3,
      Unknown4 = 4,
      Unknown5 = 5,
      UpdateNew3DS = 6,
      UpdateOld3DS = 7
    }
    
    public enum PartitionSections
    {
      Application = 0,
      Manual = 1,
      DownloadPlayChild = 2,
      Unknown3 = 3,
      Unknown4 = 4,
      Unknown5 = 5,
      UpdateNew3DS = 6,
      UpdateOld3DS = 7
    }
    
    public static int NCSDMediaUnit = 0x200;
    
    public int ImageSize { get; private set; }
    public List<NCSDSectionInfo> Sections { get; private set; }
    public string MediaId { get; private set; }
    
    public NCSD(int imageSize, List<NCSDSectionInfo> sections, string mediaId)
    {
      this.ImageSize = imageSize;
      this.Sections = sections;
      this.MediaId = mediaId;
    }
    
    public static NCSD Read(string pathToNCSD, bool dev = false)
    {
      byte[] header;
      
      using (FileStream NCSDFileStream = File.OpenRead(pathToNCSD))
      {
        NCSDFileStream.Seek(0x100, SeekOrigin.Begin);
        header = Tools.ReadFromStream(NCSDFileStream, 0x100);
      }
      
      if (header.Copy(0x0, 0x4).Hex() != "4E435344") //if header at 0x0-0x4 doesn't have 'NCSD' 
      {
        throw new ArgumentException("NCSD magic not found in header of specified file.");
      }
      
      byte[] mediaIdBytes = header.Copy(0x8, 0x10);
      Array.Reverse(mediaIdBytes);
      string mediaId = Tools.BytesToString(mediaIdBytes, false, false);
      
      if (mediaId == "0000000000000000")
      {
        throw new ArgumentException("Specified file is a NAND, and not an NCSD Image.");
      }
      
      int imageSize = header.Copy(0x4, 0x8).IntLE() * NCSDMediaUnit;
      
      List<NCSDSectionInfo> sections = new List<NCSDSectionInfo>();
      
      byte[] partRaw = header.Copy(0x20, 0x60);
      
      int[] range = new int[] {0, 8, 16, 24, 32, 40, 48, 56};

      for (int i = 0; i < range.Length; i++)
      {
        byte[] partInfo = partRaw.Copy(range[i], range[i] + 8);
        int partOffset = partInfo.Copy(0x0, 0x4).IntLE() * NCSDMediaUnit;
        int partSize = partInfo.Copy(0x4, 0x8).IntLE() * NCSDMediaUnit;
        
        if (partOffset > 0) 
        {
          int sectionId = i;
          sections.Add(new NCSDSectionInfo(sectionId, partOffset, partSize));
        }
      }
      
      return new NCSD(imageSize, sections, mediaId);
    }
    
    public override string ToString()
    {
      string output = $"NCSD IMAGE\nMedia ID: {this.MediaId}\nImage Size: {this.ImageSize} (0x{this.ImageSize.ToString("X")}) bytes\n\n";
      
      foreach (NCSDSectionInfo s in this.Sections)
      {
        output += ($"{s.ToString()}\n\n");
      }
      
      return output;
    }
  }
}