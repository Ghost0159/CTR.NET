using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using CTR.NET.Crypto;

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


        public List<ContentChunkRecord> ActiveContentsInfo { get; private set; }
        public CIASections Sections { get; private set; }
        public TicketInfo TicketData { get; private set; }
        public TMDInfo TMDData { get; private set; }
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

                this.TMDData = TMDInfo.Read(fs.ReadBytes(tmdSize), true);

                fs.Seek(ticketOffset, SeekOrigin.Begin);

                this.TicketData = new TicketInfo(fs.ReadBytes(ticketSize));

                foreach (ContentChunkRecord ccr in this.TMDData.ContentChunkRecords)
                {
                    if (ActiveContents.Contains(ccr.ContentIndex.IntBE()))
                    {
                        this.ActiveContentsInfo.Add(ccr);
                        ActiveContentsInTmd.Add(ccr.ContentIndex.IntBE());
                    }
                }

                ActiveContents.Sort();

                if (!Enumerable.SequenceEqual(ActiveContents, ActiveContentsInTmd))
                {
                    throw new ArgumentException("Invalid CIA Detected, contents defined in TMD do not match the contents defined in CIA.");
                }

                this.Sections = new CIASections(
                    new CIASectionInfo("Archive Header", (int)ContentType.ArchiveHeader, 0x0, 0x2020),
                    new CIASectionInfo("Certificate Chain", (int)ContentType.CertificateChain, certChainOffset, certChainSize),
                    new CIASectionInfo("Ticket", (int)ContentType.Ticket, ticketOffset, ticketSize),
                    new CIASectionInfo("Title Metadata (TMD)", (int)ContentType.TitleMetadata, tmdOffset, tmdSize),
                    new CIASectionInfo("Contents", (int)ContentType.Contents, contentOffset, contentSize),
                    new CIASectionInfo("Meta", (int)ContentType.Meta, metaOffset, metaSize)
                    );

                this.FilePath = pathToCIA;

                long ncchOffset = this.Sections.Contents.Offset;
            }

        }

        public void ExtractAllContents(DirectoryInfo outputDirectory)
        {
            if (this.ActiveContentsInfo.Any(ac => ac.Flags.Encrypted) && !File.Exists("boot9.bin"))
            {
                throw new FileNotFoundException("ARM9 BootROM was not found. Please make sure that you have \"boot9.bin\" in the same directory.");
            }

            long offset = this.Sections.Contents.Offset;

            CryptoEngine ce = new CryptoEngine(File.ReadAllBytes("boot9.bin"), false);

            ce.LoadTitleKeyFromTicket(this.TicketData.Raw);

            using (FileStream fs = File.OpenRead(this.FilePath))
            {
                for (int i = 0; i < this.ActiveContentsInfo.Count; i++)
                {
                    long size = this.ActiveContentsInfo[i].Size;

                    string id = this.ActiveContentsInfo[i].ID.Hex();
                    string index = this.ActiveContentsInfo[i].ContentIndex.Hex();

                    Tools.ExtractFromFile(fs, File.Create($"{outputDirectory.FullName}/{index}.{id}.ncch"), offset, size);

                    if (this.ActiveContentsInfo[i].Flags.Encrypted)
                    {
                        ce.DecryptCIAContent($"{outputDirectory.FullName}/{index}.{id}.ncch", this.ActiveContentsInfo[i]);
                    }

                    offset += size;
                }
            }
        }
    }

    public class CIASections
    {
        public CIASectionInfo ArchiveHeader { get; protected set; }
        public CIASectionInfo CertificateChain { get; private set; }
        public CIASectionInfo Ticket { get; private set; }
        public CIASectionInfo TMD { get; private set; }
        public CIASectionInfo Contents { get; private set; }
        public CIASectionInfo Meta { get; private set; }

        public CIASections(CIASectionInfo archiveHeader, CIASectionInfo certChain, CIASectionInfo ticket, CIASectionInfo tmd, CIASectionInfo contents, CIASectionInfo meta)
        {
            this.ArchiveHeader = archiveHeader;
            this.CertificateChain = certChain;
            this.Ticket = ticket;
            this.TMD = tmd;
            this.Contents = contents;
            this.Meta = meta;
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