using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CTR.NET
{
    public class CIAInfo
    {
        public enum ContentType
        {
            ArchiveHeader = -4,
            CertificateChain = -3,
            Ticket = -2,
            TitleMetadata = -1,
            Contents = 0,
            Manual = 1,
            DownloadPlayChild = 2,
            Meta = -5
        }

        public static int AlignSize = 64;

        public CIASectionInfo ArchiveHeaderInfo { get; private set; }
        public CIASectionInfo CertificateChainInfo { get; private set; }
        public CIASectionInfo TicketInfo { get; private set; }
        public CIASectionInfo TitleMetadataInfo { get; private set; }
        public CIASectionInfo ContentInfo { get; private set; }
        public CIASectionInfo MetaInfo { get; private set; }
        public List<ContentChunkRecord> ActiveContentsInfo { get; private set; }
        public List<CIASectionInfo> Contents { get; private set; }
        public TMDInfo TitleMetadata { get; private set; }
        private string FilePath { get; set; }

        public CIAInfo(string pathToCIA)
        {
            if (!File.Exists(pathToCIA))
            {
                throw new FileNotFoundException($"File at {pathToCIA} was not found.");
            }

            using (FileStream fs = File.OpenRead(pathToCIA))
            {
                byte[] header = fs.ReadBytes(0x20);

                if (header.TakeItems(0x0, 0x2).Hex() != "2020")
                {
                    throw new ArgumentException("CIA Header size is not 0x2020");
                }

                int certChainSize = header.TakeItems(0x8, 0xC).ToInt32();
                int ticketSize = header.TakeItems(0xC, 0x10).ToInt32();
                int tmdSize = header.TakeItems(0x10, 0x14).ToInt32();
                int metaSize = header.TakeItems(0x14, 0x18).ToInt32();
                long contentSize = header.TakeItems(0x18, 0x20).ToInt64();

                byte[] contentIndex = fs.ReadBytes(0x2000);

                List<int> ActiveContents = new List<int>();

                for (int i = 0; i < contentIndex.Length; i++)
                {
                    int offset = i * 8;
                    byte current = contentIndex[i];

                    for (int j = 7; j > -1; j += -1)
                    {
                        if ((current & 1) == 1)
                        {
                            ActiveContents.Add(offset + j);
                        }

                        current >>= 1;
                    }
                }

                int certChainOffset = Tools.RoundUp(0x2020, AlignSize);
                int ticketOffset = certChainOffset + Tools.RoundUp(certChainSize, AlignSize);
                int tmdOffset = ticketOffset + Tools.RoundUp(ticketSize, AlignSize);
                long contentOffset = tmdOffset + Tools.RoundUp(tmdSize, AlignSize);
                long metaOffset = contentOffset + Tools.RoundUp(contentSize, AlignSize);

                List<int> ActiveContentsInTmd = new List<int>();
                this.ActiveContentsInfo = new List<ContentChunkRecord>();

                fs.Seek(tmdOffset, SeekOrigin.Begin);

                TMDInfo tmdData = TMDInfo.Read(fs.ReadBytes(tmdSize), true);

                this.TitleMetadata = tmdData;

                foreach (ContentChunkRecord ccr in tmdData.ContentChunkRecords)
                {
                    if (ActiveContents.Contains(ccr.ContentIndex))
                    {
                        this.ActiveContentsInfo.Add(ccr);
                        ActiveContentsInTmd.Add(ccr.ContentIndex);
                    }
                }

                ActiveContents.Sort();

                if (!Enumerable.SequenceEqual(ActiveContents, ActiveContentsInTmd))
                {
                    throw new ArgumentException("Invalid CIA Detected, contents defined in TMD do not match the contents defined in CIA.");
                }

                this.ArchiveHeaderInfo = new CIASectionInfo("Archive Header", (int)ContentType.ArchiveHeader, 0x0, 0x2020);
                this.CertificateChainInfo = new CIASectionInfo("Certificate Chain", (int)ContentType.CertificateChain, certChainOffset, certChainSize);
                this.TicketInfo = new CIASectionInfo("Ticket", (int)ContentType.Ticket, ticketOffset, ticketSize);
                this.TitleMetadataInfo = new CIASectionInfo("Title Metadata (TMD)", (int)ContentType.TitleMetadata, tmdOffset, tmdSize);
                this.ContentInfo = new CIASectionInfo("Contents", (int)ContentType.Contents, contentOffset, contentSize);

                if (metaSize > 0)
                {
                    this.MetaInfo = new CIASectionInfo("Meta", (int)ContentType.Meta, metaOffset, metaSize);
                }

                this.FilePath = pathToCIA;
                this.Contents = new List<CIASectionInfo>();

                long ncchOffset = this.ContentInfo.Offset;

                foreach (ContentChunkRecord ccr in this.ActiveContentsInfo)
                {
                    this.Contents.Add(new CIASectionInfo($"{ccr.ContentIndex:X4}.{ccr.ID}", (int)ContentType.Contents, ncchOffset, ccr.Size));
                    ncchOffset += ccr.Size;
                }
            }

        }

        public void ExtractContent(string ncchIndex, FileStream outputFile)
        {
            if (!this.ActiveContentsInfo.Any(ac => $"{ac.ContentIndex:X4}.{ac.ID}" != ncchIndex))
            {
                throw new ArgumentException($"Specified NCCH Index {ncchIndex} does not exist in the current CIA.");
            }

            CIASectionInfo selectedContent = this.Contents.Find(c => c.SectionName == ncchIndex);

            Tools.ExtractFromFile(new FileStream(this.FilePath, FileMode.Open, FileAccess.Read), outputFile, selectedContent.Offset, selectedContent.Size);
        }

        public void ExtractAllContents(DirectoryInfo outputDirectory)
        {
            foreach (CIASectionInfo content in this.Contents)
            {
                Tools.ExtractFromFile(new FileStream(this.FilePath, FileMode.Open, FileAccess.Read), File.Create($"{outputDirectory.FullName}/{content.SectionName}.ncch"), content.Offset, content.Size);
            }
        }
    }

    public class CIASectionInfo
    {
        public string SectionName { get; private set; }
        public int ContentType { get; private set; }
        public long Offset { get; private set; }
        public long Size { get; private set; }

        public CIASectionInfo(string sectionName, int contentType, long offset, long size)
        {
            SectionName = sectionName;
            ContentType = contentType;
            Offset = offset;
            Size = size;
        }

        public override string ToString()
        {
            return $"SECTION {SectionName.ToUpper()}:\n\nOffset: 0x{Offset.ToString("X").ToUpper()}-0x{(Offset + Size).ToString("X").ToUpper()}\nSize: {Size} (0x{Size.ToString("X").ToUpper()}) bytes";
        }
    }
}