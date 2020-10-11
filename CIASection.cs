using System;

namespace CTR_LIB
{
  public class CIASectionInfo
  {
    public string SectionName { get; private set; }
    public int ContentType { get; private set; }
    public int Offset { get; private set; }
    public int Size  { get; private set; }
    public byte[] InitializationVector { get; private set; }
    
    public CIASectionInfo(string sectionName, int contentType, int offset, int size, byte[] initializationVector = null)
    {
      this.SectionName = sectionName;
      this.ContentType = contentType;
      this.Offset = offset;
      this.Size = size;
      this.InitializationVector = initializationVector;
    }
    
    public override string ToString()
    {
      return $"SECTION {this.SectionName.ToUpper()}:\n\nOffset: 0x{Convert.ToString(this.Offset, 16).ToUpper()}-0x{Convert.ToString(this.Offset + this.Size, 16).ToUpper()}\nSize: {this.Size} (0x{Convert.ToString(this.Size, 16).ToUpper()}) bytes";
    }
  }
}