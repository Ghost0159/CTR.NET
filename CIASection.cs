using System;

namespace CTR_LIB
{
  class CIASection
  {
    public int ContentType { get; private set; }
    public int Offset { get; private set; }
    public int Size  { get; private set; }
    public byte[] InitializationVector { get; private set; }
    
    public CIASection(int contentType, int offset, int size, byte[] initializationVector = null)
    {
      this.ContentType = contentType;
      this.Offset = offset;
      this.Size = size;
      this.InitializationVector = initializationVector;
    }
  }
}