using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CTR.NET
{
    public class NCSDInfo
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

        private string FilePath { get; set; }
        public long ImageSize { get; private set; }
        public List<NCSDSectionInfo> Sections { get; private set; }
        public string MediaId { get; private set; }

        public NCSDInfo(long imageSize, List<NCSDSectionInfo> sections, string mediaId, string path)
        {
            this.ImageSize = imageSize;
            this.Sections = sections;
            this.MediaId = mediaId;
            this.FilePath = path;
        }

        public static NCSDInfo Read(string pathToNCSD, bool dev = false)
        {
            byte[] header;

            using (FileStream NCSDFileStream = File.OpenRead(pathToNCSD))
            {
                NCSDFileStream.Seek(0x100, SeekOrigin.Begin);
                header = NCSDFileStream.ReadBytes(0x100);
            }

            Console.WriteLine(header.TakeItems(0x0, 0x4).Hex());

            if (header.TakeItems(0x0, 0x4).Hex() != "4E435344") //if header at 0x0-0x4 doesn't have 'NCSD'
            {
                throw new ArgumentException("NCSD magic not found in header of specified file.");
            }

            byte[] mediaIdBytes = header.TakeItems(0x8, 0x10);
            Array.Reverse(mediaIdBytes);
            string mediaId = mediaIdBytes.Hex();

            if (mediaId == "0000000000000000")
            {
                throw new ArgumentException("Specified file is a NAND, and not an NCSD Image.");
            }

            long imageSize = (long)header.TakeItems(0x4, 0x8).IntLE() * (long)NCSDMediaUnit;

            List<NCSDSectionInfo> sections = new List<NCSDSectionInfo>();

            byte[] partRaw = header.TakeItems(0x20, 0x60);

            int[] range = new int[] { 0, 8, 16, 24, 32, 40, 48, 56 };

            for (int i = 0; i < range.Length; i++)
            {
                byte[] partInfo = partRaw.TakeItems(range[i], range[i] + 8);
                long partOffset = (long)partInfo.TakeItems(0x0, 0x4).IntLE() * (long)NCSDMediaUnit;
                long partSize = (long)partInfo.TakeItems(0x4, 0x8).IntLE() * (long)NCSDMediaUnit;

                if (partOffset > 0)
                {
                    int sectionId = i;
                    sections.Add(new NCSDSectionInfo(sectionId, partOffset, partSize));
                }
            }

            return new NCSDInfo(imageSize, sections, mediaId, pathToNCSD);
        }

        public void ExtractContent(FileStream outputFile, int id)
        {
            if (!this.Sections.Any(s => s.Section == id))
            {
                throw new ArgumentException($"Specified Section ID \"{id}\" was not found inside this NCSD.");
            }

            NCSDSectionInfo selectedSection = this.Sections.Find(s => s.Section == id);

            Tools.ExtractFromFile(new FileStream(this.FilePath, FileMode.Open, FileAccess.Read), outputFile, selectedSection.Offset, selectedSection.Offset + selectedSection.Size);
        }

        public void ExtractAllContents(DirectoryInfo outputDirectory)
        {
            foreach (NCSDSectionInfo section in this.Sections)
            {
                ExtractContent(File.Create($"{outputDirectory.FullName}/content_{section.Section}.ncch"), section.Section);
            }
        }

        public override string ToString()
        {
            string output =
                $"NCSD IMAGE\n" +
                $"Media ID: {this.MediaId}\n" +
                $"Image Size: {this.ImageSize} (0x{this.ImageSize:X}) bytes\n\n";

            foreach (NCSDSectionInfo s in this.Sections)
            {
                output += ($"{s}\n\n");
            }

            return output;
        }
    }

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