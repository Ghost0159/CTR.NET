using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using CTR.NET.Crypto;

namespace CTR.NET
{
    public class NCSD : IDisposable
    {
        public NCSDInfo Info { get; private set; }
        private MemoryMappedFile NCSDMemoryMappedFile { get; set; }

        public NCSD(FileStream ncsdStream)
        {
            Load(ncsdStream);
        }

        public NCSD(string pathToNcsd)
        {
            if (!File.Exists(pathToNcsd))
                throw new ArgumentException("The specified file was not found.");

            Load(File.Open(pathToNcsd, FileMode.Open, FileAccess.ReadWrite));
        }

        private void Load(FileStream fs)
        {
            this.NCSDMemoryMappedFile = Tools.LoadFileMapped(fs);

            using (MemoryMappedViewStream viewStream = this.NCSDMemoryMappedFile.CreateViewStream(0x100, 0x100))
            {
                this.Info = new NCSDInfo(viewStream.ReadBytes(0x100));
            }
        }

        public void ExtractPartition(FileStream outputFile, NCSDSection partition)
        {
            if (!this.Info.Partitions.Any(part => part.ID == partition))
            {
                throw new ArgumentException($"Specified partition ID {Enum.GetName(typeof(NCSDSection), partition)} {(int)partition} was not found inside this NCSD.");
            }

            Extract(this.Info.Partitions.Find(part => part.ID == partition), outputFile);
        }

        public void ExtractPartition(string outputFilePath, NCSDSection partition)
        {
            if (!this.Info.Partitions.Any(part => part.ID == partition))
            {
                throw new ArgumentException($"Specified partition ID {Enum.GetName(typeof(NCSDSection), partition)} {(int)partition} was not found inside this NCSD.");
            }

            Extract(this.Info.Partitions.Find(part => part.ID == partition), File.Create(outputFilePath));
        }

        public void ExtractAllPartitions(DirectoryInfo outputDirectory)
        {
            foreach (NCSDPartition partition in this.Info.Partitions)
            {
                Extract(partition, File.Create($"{outputDirectory.FullName}/content_{Enum.GetName(typeof(NCSDSection), partition.ID)}.ncch"));
            }
        }

        private void Extract(NCSDPartition section, Stream outputStream)
        {
            using (outputStream)
            {
                Tools.ExtractFileStreamPart(this.NCSDMemoryMappedFile, outputStream, section.Offset, section.Size);
            }
        }

        public void Decrypt(FileStream outputStream, CryptoEngine ce = null, SeedDatabase seedDb = null, bool trim = true)
        {
            long size;

            if (!trim)
            {
                outputStream.SetLength(this.Info.ImageSize);
            }
            else 
            {
                size = this.Info.Partitions[0].Offset;

                foreach (NCSDPartition partition in this.Info.Partitions)
                {
                    size += partition.Size;
                }

                outputStream.SetLength(size);
            }

            outputStream.Seek(0, SeekOrigin.Begin);

            MemoryMappedFile outputFile = Tools.LoadFileMapped(outputStream);

            using (MemoryMappedViewStream srcHeaderViewStream = this.NCSDMemoryMappedFile.CreateViewStream(0x0, this.Info.Partitions[0].Offset))
            {
                using (MemoryMappedViewStream destHeaderViewStream = outputFile.CreateViewStream(0x0, this.Info.Partitions[0].Offset))
                {
                    srcHeaderViewStream.CopyTo(destHeaderViewStream);
                    destHeaderViewStream.Seek(0x1188, SeekOrigin.Begin);

                    byte[] flags = destHeaderViewStream.ReadBytes(0x8);
                    flags[3] = 0x0;
                    flags[7] = 0x4;

                    destHeaderViewStream.Seek(0x1188, SeekOrigin.Begin);
                    destHeaderViewStream.Write(flags);

                }
            }

            foreach (NCSDPartition partition in this.Info.Partitions)
            {
                using (MemoryMappedViewStream destPartitionViewStream = outputFile.CreateViewStream(partition.Offset, partition.Size))
                {
                    NCCH ncch = new NCCH(this.NCSDMemoryMappedFile, partition.Offset, ce, seedDb);

                    ncch.Decrypt(outputFile);
                }
            }
        }

        public void Dispose()
        {
            this.NCSDMemoryMappedFile.Dispose();
        }
    }
    public class NCSDInfo
    {
        public long ImageSize { get; private set; }
        public List<NCSDPartition> Partitions { get; private set; }
        public byte[] MediaId { get; private set; }

        public NCSDInfo(byte[] header)
        {
            if (header.TakeItems(0x0, 0x4).Hex() != "4E435344") //if header at 0x0-0x4 isn't 'NCSD'
            {
                throw new ArgumentException("NCSD magic not found in header of specified file.");
            }

            this.MediaId = header.TakeItems(0x8, 0x10);

            if (this.MediaId.All(b => b == 0x0))
            {
                throw new ArgumentException("Specified file is a NAND, and not an NCSD Image.");
            }

            this.ImageSize = header.TakeItems(0x4, 0x8).ToInt32() * 0x200;

            this.Partitions = new List<NCSDPartition>();

            byte[] partRaw = header.TakeItems(0x20, 0x60);

            for (int i = 0; i < 64; i += 8)
            {
                byte[] partInfo = partRaw.TakeItems(i, i + 8);
                int partOffset = partInfo.TakeItems(0x0, 0x4).ToInt32() * 0x200;
                int partSize = partInfo.TakeItems(0x4, 0x8).ToInt32() * 0x200;

                if (partOffset > 0)
                {
                    this.Partitions.Add(new NCSDPartition(partOffset, partSize, i / 8));
                }
            }
        }

        public override string ToString()
        {
            string output =
                $"NCSD IMAGE\n" +
                $"Media ID: {this.MediaId.Hex(true)}\n" +
                $"Image Size: {this.ImageSize} (0x{this.ImageSize:X}) bytes\n\n";

            foreach (NCSDPartition s in this.Partitions)
            {
                output += ($"{s}\n\n");
            }

            return output;
        }
    }

    public class NCSDPartition
    {
        public long Offset { get; private set; }
        public long Size { get; private set; }
        public NCSDSection ID { get; set; }

        public NCSDPartition(long offset, long size, int id)
        {
            this.Offset = offset;
            this.Size = size;
            this.ID = (NCSDSection)id;
        }

        public override string ToString()
        {
            return
                $"NCSD SECTION \n" +
                $"ID: {(int)this.ID} ({Enum.GetName(typeof(NCSDSection), this.ID)})\n" +
                $"Offset: 0x{this.Offset:X}\n" +
                $"Size: {this.Size} (0x{this.Size:X}) bytes";
        }
    }

    public enum NCSDSection
    {
        Application = 0,
        Manual = 1,
        DownloadPlayChild = 2,
        Partition3 = 3,
        Partition4 = 4,
        Partition5 = 5,
        UpdateNew3DS = 6,
        UpdateOld3DS = 7
    }
}