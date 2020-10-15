using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CTR.NET
{
    public class CIA
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
        public TMD TitleMetadata { get; private set; }
        private string FilePath { get; set; }

        public CIA(string pathToCIA)
        {
            if (!File.Exists(pathToCIA))
            {
                throw new FileNotFoundException($"File at {pathToCIA} was not found.");
            }

            int header = Tools.ReadBytes(pathToCIA, 0x0, 0x4).IntLE();

            if (header.ToString("X4") != "2020")
            {
                throw new ArgumentException($"File (pathToCIA) is not a CIA, because the header is not 0x2020 (8224).");
            }

            int certChainSize = BitConverter.ToInt32(Tools.ReadBytes(pathToCIA, 0x8, 0xC));
            int ticketSize = BitConverter.ToInt32(Tools.ReadBytes(pathToCIA, 0xC, 0x10));
            int tmdSize = BitConverter.ToInt32(Tools.ReadBytes(pathToCIA, 0x10, 0x14));
            int metaSize = BitConverter.ToInt32(Tools.ReadBytes(pathToCIA, 0x14, 0x18));
            long contentSize = BitConverter.ToInt64(Tools.ReadBytes(pathToCIA, 0x18, 0x20), 0);

            byte[] contentIndex = Tools.ReadBytes(pathToCIA, 0x20, 0x2020);

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

            int certChainOffset = Tools.RoundUp(header, AlignSize);
            int ticketOffset = certChainOffset + Tools.RoundUp(certChainSize, AlignSize);
            int tmdOffset = ticketOffset + Tools.RoundUp(ticketSize, AlignSize);
            long contentOffset = tmdOffset + Tools.RoundUp(tmdSize, AlignSize);
            long metaOffset = contentOffset + Tools.RoundUp(contentSize, AlignSize);
            //titlkey loading go here

            List<int> ActiveContentsInTmd = new List<int>();
            this.ActiveContentsInfo = new List<ContentChunkRecord>();

            TMD tmdData = TMDReader.Read(Tools.ReadBytes(pathToCIA, tmdOffset, tmdOffset + tmdSize), true);
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

            this.ArchiveHeaderInfo = new CIASectionInfo("Archive Header", (int)ContentType.ArchiveHeader, 0x0, header);
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
}