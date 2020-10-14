namespace CTR.NET
{
    public class NCSDSectionInfo
    {
        public int Section { get; private set; }
        public long Offset { get; private set; }
        public long Size { get; private set; }

        public NCSDSectionInfo(int section, long offset, long size)
        {
            this.Section = section;
            this.Offset = offset;
            this.Size = size;
        }

        public override string ToString()
        {
            return
                $"NCSD SECTION \n" +
                $"ID: {this.Section}\n" +
                $"Offset: 0x{this.Offset:X}\n" +
                $"Size: {this.Size} (0x{this.Size:X}) bytes";
        }
    }
}