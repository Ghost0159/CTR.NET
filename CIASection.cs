using System;

namespace CTR.NET
{
    public class CIASectionInfo
    {
        public string SectionName { get; private set; }
        public int ContentType { get; private set; }
        public long Offset { get; private set; }
        public long Size { get; private set; }
        public byte[] InitializationVector { get; private set; }

        public CIASectionInfo(string sectionName, int contentType, long offset, long size, byte[] initializationVector = null)
        {
            SectionName = sectionName;
            ContentType = contentType;
            Offset = offset;
            Size = size;
            InitializationVector = initializationVector;
        }

        public override string ToString()
        {
            Console.WriteLine(Size);
            return $"SECTION {SectionName.ToUpper()}:\n\nOffset: 0x{Offset.ToString("X").ToUpper()}-0x{(Offset + Size).ToString("X").ToUpper()}\nSize: {Size} (0x{Size.ToString("X").ToUpper()}) bytes";
        }
    }
}