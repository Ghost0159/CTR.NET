namespace CTR_LIB
{
  class ContentInfoRecord
  {
    public int IndexOffset { get; private set; }
    public int CommandCount  { get; private set; }
    public byte[] Hash { get; private set; }
    
    public ContentInfoRecord(int indexOffset, int commandCount, byte[] hash)
    {
      this.IndexOffset = indexOffset;
      this.CommandCount = commandCount;
      this.Hash = hash;
    }
  }
}