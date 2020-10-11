using System;

namespace CTR_LIB
{
  public class NCSDSectionInfo
  {
    public int Section { get; private set; }
    public int Offset { get; private set; }
    public int Size { get; private set; }
    
    public NCSDSectionInfo(int section, int offset, int size)
    {
      this.Section = section;
      this.Offset = offset;
      this.Size = size;
    }
    
    public override string ToString()
    {
      return $"NCSD SECTION \nID: {this.Section}\nOffset: 0x{this.Offset.ToString("X")}\nSize: {this.Size} (0x{this.Size.ToString("X")}) bytes";
    }
  }
}