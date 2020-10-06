using System;
using System.Text;

namespace CTR_LIB
{
  class ContentChunkRecord
  {
    public string ID { get; private set; }
    public int ContentIndex { get; private set; }
    public ContentTypeFlags Type { get; private set; }
    public long Size { get; private set; }
    public byte[] Hash { get; private set; }
    
    public ContentChunkRecord(string id, int contentIndex, ContentTypeFlags flags, long size, byte[] hash)
    {
      this.ID = id;
      this.ContentIndex = contentIndex;
      this.Type = flags;
      this.Size = size;
      this.Hash = hash;
    }
    
    public override string ToString() => $"--------------------------------\nCONTENT CHUNK RECORD INFO FOR INDEX {this.ContentIndex.ToString("X4")}.{this.ID}:\n\nID: {this.ID}\nContent Index: {this.ContentIndex} ({this.ContentIndex.ToString("X4")})\n\n{this.Type.ToString()}\n\nContent Size: {this.Size} (0x{Convert.ToString(this.Size, 16)}) bytes\nHash: {this.Hash.Hex()}\n--------------------------------";
    
    public byte[] ToByteArray()
    {
      return Tools.HexToBytes(this.ID)
              .Combine(Tools.HexToBytes(this.ContentIndex.ToString("X4")))
              .Combine(Tools.HexToBytes(this.Type.AsInt().ToString("X4")))
              .Combine(Tools.HexToBytes(this.Size.ToString("X16")))
              .Combine(this.Hash);
    }
  }
}