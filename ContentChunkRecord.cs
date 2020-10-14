using System;

namespace CTR.NET
{
    public class ContentChunkRecord
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

        public override string ToString() =>
            $"--------------------------------\n" +
            $"CONTENT CHUNK RECORD INFO FOR INDEX {this.ContentIndex:X4}.{this.ID}:\n\n" +
            $"ID: {this.ID}\n" +
            $"Content Index: {this.ContentIndex} ({this.ContentIndex:X4})\n\n" +
            $"{this.Type}\n\n" +
            $"Content Size: {this.Size} (0x{Convert.ToString(this.Size, 16).ToUpper()}) bytes\n" +
            $"Hash: {this.Hash.Hex()}\n" +
            $"--------------------------------";

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