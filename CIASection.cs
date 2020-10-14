using System;

namespace CTR.NET
{
    public class CIASectionInfo
    {
        public string SectionName { get; private set; }
        public int ContentType { get; private set; }
        public int Offset { get; private set; }
        public int Size { get; private set; }
        public byte[] InitializationVector { get; private set; }

        public CIASectionInfo(string sectionName, int contentType, int offset, int size, byte[] initializationVector = null)
        {
            SectionName = sectionName;
            ContentType = contentType;
            Offset = offset;
            Size = size;
            InitializationVector = initializationVector;
        }

        public override string ToString()
        {
            return $"SECTION {SectionName.ToUpper()}:\n\nOffset: 0x{Convert.ToString(Offset, 16).ToUpper()}-0x{Convert.ToString(Offset + Size, 16).ToUpper()}\nSize: {Size} (0x{Convert.ToString(Size, 16).ToUpper()}) bytes";
        }
    }
}