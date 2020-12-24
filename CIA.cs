using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Security.Cryptography;
using CTR.NET.Crypto;

namespace CTR.NET
{
    public class CIA : IDisposable
    {
        private CryptoEngine Cryptor { get; set; }
        public MemoryMappedFile CIAMemoryMappedFile { get; private set; }
        public CIAInfo Info { get; private set; }


        public CIA(FileStream cia, CryptoEngine ce = null)
        {
            if (!cia.CanWrite)
            {
                throw new ArgumentException("Stream must be writable.");
            }

            this.CIAMemoryMappedFile = MemoryMappedFile.CreateFromFile(cia, null, cia.Length, MemoryMappedFileAccess.ReadWrite, HandleInheritability.Inheritable, true);

            using (MemoryMappedViewStream viewStream = this.CIAMemoryMappedFile.CreateViewStream(0, cia.Length))
            {
                this.Info = new CIAInfo(viewStream);
            }

            this.Cryptor = ce;
        }

        public CIA(string pathToCIA, CryptoEngine ce = null)
        {
            if (!File.Exists(pathToCIA))
            {
                throw new FileNotFoundException($"File at {pathToCIA} does not exist.");
            }

            FileStream fs = File.Open(pathToCIA, FileMode.Open, FileAccess.ReadWrite);

            this.CIAMemoryMappedFile = MemoryMappedFile.CreateFromFile(fs, null, fs.Length, MemoryMappedFileAccess.ReadWrite, HandleInheritability.Inheritable, true);

            using (MemoryMappedViewStream viewStream = this.CIAMemoryMappedFile.CreateViewStream(0, fs.Length))
            {
                this.Info = new CIAInfo(viewStream);
            }

            this.Cryptor = ce;
        }

        public void ExtractContent(Stream outputStream, ContentChunkRecord contentRecord)
        {
            if (!this.Cryptor.NormalKey.ContainsKey(0x40))
            {
                this.Cryptor.LoadTitleKeyFromTicket(this.Info.TicketData.Raw);
            }

            if (!this.Info.ActiveContents.Contains(contentRecord))
            {
                throw new ArgumentException($"The specified CIA does not contain content {contentRecord.GetContentName()}");
            }

            long offset = this.Info.Regions.Find(r => r.Type == CIASection.Contents).Offset;

            for (int i = 0; i < this.Info.ActiveContents.Count; i++)
            {
                if (this.Info.ActiveContents[i] == contentRecord)
                {
                    break;
                }

                offset += this.Info.ActiveContents[i].Size;
            }

            if (contentRecord.Flags.Encrypted)
            {
                if (this.Cryptor == null)
                {
                    throw new ArgumentException($"Current content ({contentRecord.GetContentName()}) is encrypted, and no Crypto Engine was passed to the method.");
                }

                using (Aes aes = Aes.Create())
                {
                    aes.Key = this.Cryptor.NormalKey[0x40];
                    aes.IV = BitConverter.GetBytes(contentRecord.ContentIndex).PadRight(0, 16);
                    aes.Padding = PaddingMode.Zeros;
                    aes.Mode = CipherMode.CBC;

                    Tools.CryptFileStreamPart(this.CIAMemoryMappedFile, outputStream, aes.CreateDecryptor(), offset, contentRecord.Size);
                }
            }
            else
            {
                using (outputStream)
                {
                    Tools.ExtractFileStreamPart(this.CIAMemoryMappedFile, outputStream, offset, contentRecord.Size);
                }
            }
        }

        public void ExtractAllContents(DirectoryInfo outputDirectory)
        {
            if (this.Info.ActiveContents.Any(ac => ac.Flags.Encrypted) && this.Cryptor == null)
            {
                throw new FileNotFoundException("Some contents in the CIA are encrypted, but no crypto engine to decrypt them has been passed to the method.");
            }

            for (int i = 0; i < this.Info.ActiveContents.Count; i++)
            {
                ContentChunkRecord currentRecord = this.Info.ActiveContents[i];

                ExtractContent(File.Create($"{outputDirectory.FullName}/{currentRecord.GetContentName()}"), currentRecord);
            }
        }

        public void Dispose()
        {
            this.CIAMemoryMappedFile.Dispose();
        }
    }
    public class CIAInfo
    {
        public static int AlignSize = 64;
        public List<ContentChunkRecord> ActiveContents { get; private set; }
        public List<CIARegion> Regions { get; private set; }
        public TicketInfo TicketData { get; private set; }
        public TMDInfo TMD { get; private set; }
        private string FilePath { get; set; }

        public CIAInfo(Stream ciaStream)
        {
            byte[] header = ciaStream.ReadBytes(0x20);

            short archiveHeaderSize = header.TakeItems(0x0, 0x2).ToInt16();

            if (archiveHeaderSize != 0x2020)
            {
                throw new ArgumentException("CIA Header size is not 0x2020");
            }

            int certChainSize = header.TakeItems(0x8, 0xC).ToInt32();
            int ticketSize = header.TakeItems(0xC, 0x10).ToInt32();
            int tmdSize = header.TakeItems(0x10, 0x14).ToInt32();
            int metaSize = header.TakeItems(0x14, 0x18).ToInt32();
            long contentSize = header.TakeItems(0x18, 0x20).ToInt64();

            byte[] contentIndex = ciaStream.ReadBytes(0x2000);

            List<short> ActiveContents = new List<short>();

            for (int i = 0; i < contentIndex.Length; i++)
            {
                int offset = i * 8;
                byte current = contentIndex[i];

                for (int j = 7; j > -1; j += -1)
                {
                    if ((current & 1) == 1)
                    {
                        ActiveContents.Add(Convert.ToInt16(offset + j));
                    }

                    current >>= 1;
                }
            }

            int certChainOffset = Tools.RoundUp(archiveHeaderSize, AlignSize);
            int ticketOffset = certChainOffset + Tools.RoundUp(certChainSize, AlignSize);
            int tmdOffset = ticketOffset + Tools.RoundUp(ticketSize, AlignSize);
            long contentOffset = tmdOffset + Tools.RoundUp(tmdSize, AlignSize);
            long metaOffset = contentOffset + Tools.RoundUp(contentSize, AlignSize);

            List<short> ActiveContentsInTmd = new List<short>();
            this.ActiveContents = new List<ContentChunkRecord>();

            ciaStream.Seek(tmdOffset, SeekOrigin.Begin);

            this.TMD = new TMDInfo(ciaStream.ReadBytes(tmdSize));

            ciaStream.Seek(ticketOffset, SeekOrigin.Begin);

            this.TicketData = new TicketInfo(ciaStream.ReadBytes(ticketSize));

            foreach (ContentChunkRecord ccr in this.TMD.ContentChunkRecords)
            {
                if (ActiveContents.Contains(ccr.ContentIndex))
                {
                    this.ActiveContents.Add(ccr);
                    ActiveContentsInTmd.Add(ccr.ContentIndex);
                }
            }

            ActiveContents.Sort();

            if (!Enumerable.SequenceEqual(ActiveContents, ActiveContentsInTmd))
            {
                throw new ArgumentException("Invalid CIA Detected, contents defined in TMD do not match the contents defined in CIA.");
            }

            this.Regions = new List<CIARegion>();

            this.Regions.AddIfExists(new CIARegion(CIASection.ArchiveHeader, 0x0, archiveHeaderSize));
            this.Regions.AddIfExists(new CIARegion(CIASection.CertificateChain, certChainOffset, certChainSize));
            this.Regions.AddIfExists(new CIARegion(CIASection.Ticket, ticketOffset, ticketSize));
            this.Regions.AddIfExists(new CIARegion(CIASection.TitleMetadata, tmdOffset, tmdSize));
            this.Regions.AddIfExists(new CIARegion(CIASection.Contents, contentOffset, contentSize));
            this.Regions.AddIfExists(new CIARegion(CIASection.Meta, metaOffset, metaSize));
        }

        public static TMDInfo GetTMD(byte[] header)
        {
            int certChainSize = header.TakeItems(0x8, 0xC).ToInt32();
            int ticketSize = header.TakeItems(0xC, 0x10).ToInt32();
            int tmdSize = header.TakeItems(0x10, 0x14).ToInt32();

            int certChainOffset = Tools.RoundUp(0x2020, AlignSize);
            int ticketOffset = certChainOffset + Tools.RoundUp(certChainSize, AlignSize);
            int tmdOffset = ticketOffset + Tools.RoundUp(ticketSize, AlignSize);

            return new TMDInfo(header.TakeItems(tmdOffset, tmdOffset + tmdSize), true);
        }
    }

    public class CIARegion
    {
        public CIASection Type { get; set; }
        public long Offset { get; private set; }
        public long Size { get; private set; }

        public CIARegion(CIASection type, long offset, long size)
        {
            this.Type = type;
            this.Offset = offset;
            this.Size = size;
        }

        public override string ToString()
        {
            return $"SECTION {Enum.GetName(typeof(CIASection), this.Type)}:\n\nOffset: 0x{Offset.ToString("X").ToUpper()}-0x{(Offset + Size).ToString("X").ToUpper()}\nSize: {Size} (0x{Size.ToString("X").ToUpper()}) bytes";
        }
    }

    public enum CIASection
    {
        ArchiveHeader = 0,
        CertificateChain = 1,
        Ticket = 2,
        TitleMetadata = 3,
        Contents = 4,
        Meta = 5
    }
}